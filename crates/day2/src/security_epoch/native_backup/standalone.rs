//! SQLite owns the journal conversion of an already captured historical copy.
//! No raw-source opener, filename input, header edit or authority factory.
use super::super::restore_staging::{
    MAX_BYTES, image_shape, memory_shape, require_no_runtime_generation_objects,
};
use super::files::{Identity, PrivateTree};
use super::{CopyProgress, Disposition, STEP_PAGES, SnapshotContent, SnapshotImage};
use anyhow::{Context, Result, ensure};
use rusqlite::{
    Connection, MAIN_DB, OpenFlags,
    backup::{Backup, StepResult},
};
use std::{
    cell::Cell,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

pub(super) struct StandaloneSnapshot {
    tree: PrivateTree,
    file: File,
    creator: Identity,
    current: Cell<Identity>,
    expected_pages: String,
    expected_schema: u32,
    db: Connection,
    source: Option<SnapshotContent>,
    disposition: Cell<Disposition>,
    expected_bytes: usize,
}

pub(super) struct ImageCopy<'a> {
    backup: Option<Backup<'a, 'a>>,
    source: &'a SnapshotContent,
    tree: &'a PrivateTree,
    file: &'a File,
    creator: Identity,
    current: &'a Cell<Identity>,
    disposition: &'a Cell<Disposition>,
    pages: i32,
    remaining: i32,
    steps: usize,
    limit: usize,
}

impl StandaloneSnapshot {
    pub(super) fn new() -> Result<Self> {
        let tree = PrivateTree::new()?;
        let file = tree.create_file(Path::new("app.sqlite"), false)?;
        let creator = Identity::of(&file.metadata()?);
        ensure!(
            file.metadata()?.len() == 0,
            "backup_image_destination_not_fresh"
        );
        tree.check_file(Path::new("app.sqlite"), &file, creator)?;
        // This path can only name the fresh file made above. No caller path,
        // CREATE/truncate flag or fallback to a live source exists.
        let mut db = Connection::open_with_flags(
            tree.path().join("app.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        crate::store::NativeSqliteKeeper::require_creator_main(&db, &file)?;
        db.pragma_update(None, "temp_store", "MEMORY")?;
        crate::store::configure_connection(&mut db)?;
        db.busy_timeout(Duration::ZERO)?;
        tree.check_file(Path::new("app.sqlite"), &file, creator)?;
        let current = Cell::new(Identity::of(&file.metadata()?));
        Ok(Self {
            tree,
            file,
            creator,
            current,
            expected_pages: String::new(),
            expected_schema: 0,
            db,
            source: None,
            disposition: Cell::new(Disposition::Fresh),
            expected_bytes: 0,
        })
    }

    pub(super) fn start(&mut self, mut source: SnapshotContent) -> Result<ImageCopy<'_>> {
        let previous = self.disposition.replace(Disposition::Refused);
        ensure!(previous == Disposition::Fresh, "backup_image_spent");
        self.tree
            .check_file(Path::new("app.sqlite"), &self.file, self.creator)?;
        crate::store::NativeSqliteKeeper::require_original_main(&self.db, &self.file)?;
        let bytes = memory_shape(&source.db, Some(source.expected_bytes))?;
        require_no_runtime_generation_objects(&source.db)?;
        ensure!(
            source.db.is_autocommit(),
            "backup_image_historical_transaction"
        );
        let page_size: i64 = source
            .db
            .pragma_query_value(None, "page_size", |r| r.get(0))?;
        let pages = i32::try_from(bytes / usize::try_from(page_size)?)?;
        ensure!(pages > 0, "backup_image_empty");
        self.db.pragma_update(None, "page_size", page_size)?;
        self.db.pragma_update(
            None,
            "max_page_count",
            i64::try_from(MAX_BYTES)? / page_size,
        )?;
        let serialized = source.db.serialize(MAIN_DB)?;
        ensure!(serialized.len() == bytes, "backup_image_source_length");
        self.expected_pages = page_contents(&serialized)?;
        drop(serialized);
        let initial: i64 = self
            .db
            .pragma_query_value(None, "schema_version", |r| r.get(0))?;
        ensure!(
            initial == 0 && self.file.metadata()?.len() == 0,
            "backup_image_destination_not_fresh"
        );
        self.expected_schema = u32::try_from(initial)?.wrapping_add(1);
        self.expected_bytes = bytes;
        self.source = Some(source);
        let source = self
            .source
            .as_ref()
            .context("backup_image_source_missing")?;
        self.current.set(Identity::of(&self.file.metadata()?));
        let backup = Backup::new(&source.db, &mut self.db)?;
        self.disposition.set(Disposition::Copying);
        Ok(ImageCopy {
            backup: Some(backup),
            source,
            tree: &self.tree,
            file: &self.file,
            creator: self.creator,
            current: &self.current,
            disposition: &self.disposition,
            pages,
            remaining: pages,
            steps: 0,
            limit: usize::try_from(pages)?.div_ceil(usize::try_from(STEP_PAGES)?),
        })
    }

    pub(super) fn finish(mut self) -> Result<SnapshotImage> {
        ensure!(
            self.disposition.replace(Disposition::Refused) == Disposition::Copied,
            "backup_image_incomplete"
        );
        self.tree
            .check_file(Path::new("app.sqlite"), &self.file, self.creator)?;
        ensure!(
            Identity::of(&self.file.metadata()?) == self.current.get(),
            "backup_image_external_change"
        );
        crate::store::NativeSqliteKeeper::require_original_main(&self.db, &self.file)?;
        let source = self.source.take().context("backup_image_source_missing")?;
        source.db.close().map_err(|(db, _)| {
            drop(db);
            anyhow::anyhow!("backup_image_memory_close")
        })?;
        // Loading the copied schema makes SQLite observe its actual WAL header.
        // Only SQLite's normal journal-mode transaction changes it to 1/1.
        let _: i64 = self
            .db
            .query_row("SELECT count(*) FROM main.sqlite_schema", [], |r| r.get(0))?;
        let mode: String = self
            .db
            .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))?;
        ensure!(mode == "delete", "backup_image_journal_conversion");
        crate::store::NativeSqliteKeeper::require_original_main(&self.db, &self.file)?;
        require_no_runtime_generation_objects(&self.db)?;
        let integrity: String = self
            .db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        ensure!(integrity == "ok", "backup_image_integrity");
        self.tree
            .check_file(Path::new("app.sqlite"), &self.file, self.creator)?;
        self.db.close().map_err(|(db, _)| {
            drop(db);
            anyhow::anyhow!("backup_image_destination_close")
        })?;
        self.tree
            .check_file(Path::new("app.sqlite"), &self.file, self.creator)?;
        let mut names = std::collections::BTreeSet::new();
        for item in rustix::fs::Dir::read_from(&self.tree.root)? {
            let item = item?;
            let name = item.file_name().to_bytes();
            if name != b"." && name != b".." {
                ensure!(names.len() < 2, "backup_image_sidecar");
                names.insert(name.to_vec());
            }
        }
        ensure!(
            names == std::collections::BTreeSet::from([b"app.sqlite".to_vec()]),
            "backup_image_sidecar"
        );
        let metadata = self.file.metadata()?;
        ensure!(
            metadata.len() == u64::try_from(self.expected_bytes)?,
            "backup_image_length"
        );
        let identity = Identity::of(&metadata);
        let mut bytes = Zeroizing::new(Vec::new());
        self.file.seek(SeekFrom::Start(0))?;
        (&mut self.file)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() == self.expected_bytes && Identity::of(&self.file.metadata()?) == identity,
            "backup_image_changed"
        );
        self.tree
            .check_file(Path::new("app.sqlite"), &self.file, self.creator)?;
        conversion_header(&bytes, self.expected_schema)?;
        ensure!(
            page_contents(&bytes)? == self.expected_pages,
            "backup_image_page_contents_changed"
        );
        Ok(SnapshotImage { bytes })
    }
}

impl ImageCopy<'_> {
    pub(super) fn step(&mut self) -> Result<CopyProgress> {
        ensure!(
            self.disposition.replace(Disposition::Refused) == Disposition::Copying,
            "backup_image_refused"
        );
        ensure!(
            self.source.db.is_autocommit() && self.steps < self.limit,
            "backup_image_source_or_work_changed"
        );
        self.tree
            .check_file(Path::new("app.sqlite"), self.file, self.creator)?;
        ensure!(
            Identity::of(&self.file.metadata()?) == self.current.get(),
            "backup_image_external_change"
        );
        self.steps += 1;
        let copy = self.backup.as_ref().context("backup_image_closed")?;
        let done = match copy.step(STEP_PAGES)? {
            StepResult::Done => true,
            StepResult::More => false,
            StepResult::Busy => anyhow::bail!("backup_image_busy"),
            StepResult::Locked => anyhow::bail!("backup_image_locked"),
            _ => anyhow::bail!("backup_image_step_unsupported"),
        };
        let progress = copy.progress();
        ensure!(
            progress.pagecount == self.pages
                && progress.remaining >= 0
                && progress.remaining < self.remaining,
            "backup_image_progress_changed"
        );
        self.remaining = progress.remaining;
        self.tree
            .check_file(Path::new("app.sqlite"), self.file, self.creator)?;
        self.current.set(Identity::of(&self.file.metadata()?));
        if done {
            ensure!(progress.remaining == 0, "backup_image_incomplete");
            self.backup.take();
            self.disposition.set(Disposition::Copied);
            Ok(CopyProgress::Complete)
        } else {
            ensure!(progress.remaining > 0, "backup_image_progress_changed");
            self.disposition.set(Disposition::Copying);
            Ok(CopyProgress::More)
        }
    }
}

impl Drop for ImageCopy<'_> {
    fn drop(&mut self) {
        if self.disposition.get() != Disposition::Copied {
            self.disposition.set(Disposition::Refused)
        }
    }
}

/// Compare page contents without rewriting any output bytes. SQLite owns
/// journal flags (18..20), file-change counter (24..28), destination schema
/// cookie (40..44) and version-valid-for counter (92..96). Every other byte,
/// including application/user versions, rowids, history and free pages, must
/// remain identical. The final image separately requires the strict1/1 header.
fn page_contents(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len() >= 100
            && bytes.len() <= MAX_BYTES as usize
            && &bytes[..16] == b"SQLite format 3\0",
        "backup_image_page_format"
    );
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    for part in [
        &bytes[..18],
        &bytes[20..24],
        &bytes[28..40],
        &bytes[44..92],
        &bytes[96..],
    ] {
        hash.update(part);
    }
    let sum = hash.finish();
    Ok(format!(
        "sha256:{}",
        sum.as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}

#[cfg(test)]
#[path = "standalone_tests.rs"]
mod tests;

/// Validate the bookkeeping excluded from page_contents. These words are not
/// arbitrary: SQLite writes a matching change-counter pair and increments the
/// known initial destination schema cookie once during backup completion.
fn conversion_header(bytes: &[u8], expected_schema: u32) -> Result<()> {
    image_shape(bytes)?;
    let word = |at: usize| -> Result<u32> {
        Ok(u32::from_be_bytes(
            bytes[at..at + 4]
                .try_into()
                .context("backup_image_header_word")?,
        ))
    };
    ensure!(
        word(24)? == word(92)? && word(40)? == expected_schema,
        "backup_image_header_transition"
    );
    Ok(())
}
