//! Mechanical snapshot DATA only. There is deliberately no native requester,
//! authorization constructor, enrolled owner or operational entrypoint here.
//! A future fixed native driver must retain its genuine source/transaction,
//! check the real loan around EVERY step, close that transaction before archive
//! I/O, and retain/close the source Connection before releasing its actual peer.
//! These components cannot supply any of those permissions or completions.
use anyhow::{Context, Result, ensure};
use rusqlite::{
    Connection, MAIN_DB, Transaction,
    backup::{Backup, StepResult},
};
use std::cell::Cell;
use zeroize::Zeroizing;

use super::restore_staging::{
    MAX_BYTES, image_shape, memory_shape, require_no_runtime_generation_objects,
};

mod archive;
mod files;
mod standalone;

const STEP_PAGES: i32 = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Fresh,
    Copying,
    Copied,
    Refused,
}

/// Owns only a new memory database, never the source/native Connection.
struct MemorySnapshot {
    db: Connection,
    disposition: Cell<Disposition>,
    expected_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyProgress {
    More,
    Complete,
}

/// The SQLite backup handle borrows the actual transaction and destination;
/// neither can escape or be replaced through this API. It is not a read loan.
struct SnapshotCopy<'source, 'transaction, 'target> {
    backup: Option<Backup<'source, 'target>>,
    source: &'source Transaction<'transaction>,
    disposition: &'target Cell<Disposition>,
    pages: i32,
    previous_remaining: i32,
    steps: usize,
    limit: usize,
}

/// Completed logical snapshot only. It has no Connection/callback getter and
/// cannot attest native origin, approval or a standalone archive format.
struct SnapshotContent {
    db: Connection,
    expected_bytes: usize,
}

/// Private bounded standalone bytes. Historical DATA does not attest native origin.
struct SnapshotImage {
    bytes: Zeroizing<Vec<u8>>,
}

impl MemorySnapshot {
    fn new() -> Result<Self> {
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "temp_store", "MEMORY")?;
        crate::store::configure_connection(&mut db)?;
        db.pragma_update(None, "journal_mode", "MEMORY")?;
        Ok(Self {
            db,
            disposition: Cell::new(Disposition::Fresh),
            expected_bytes: 0,
        })
    }

    fn start<'source, 'transaction, 'target>(
        &'target mut self,
        source: &'source mut Transaction<'transaction>,
    ) -> Result<SnapshotCopy<'source, 'transaction, 'target>> {
        // Keep the exclusive borrow in the returned handle. The caller cannot
        // ROLLBACK; BEGIN through Transaction between start and a later step.
        let source: &'source Transaction<'transaction> = source;
        let previous = self.disposition.replace(Disposition::Refused);
        ensure!(previous == Disposition::Fresh, "backup_snapshot_spent");
        // Every failure, including an unwound caller, leaves this target spent.
        self.disposition.set(Disposition::Refused);
        ensure!(
            !source.is_autocommit() && source.is_readonly(MAIN_DB)?,
            "backup_source_read_transaction_required"
        );
        let mut attached = source.prepare("PRAGMA database_list")?;
        let names = attached.query_map([], |row| row.get::<_, String>(1))?;
        for name in names {
            ensure!(
                matches!(name?.as_str(), "main" | "temp"),
                "backup_source_attached_database"
            );
        }
        drop(attached);
        // A real main-schema read pins this transaction before selecting pages.
        let _: i64 = source.query_row("SELECT count(*) FROM main.sqlite_schema", [], |row| {
            row.get(0)
        })?;
        let pages: i64 = source.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let page_size: i64 = source.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let bytes = pages
            .checked_mul(page_size)
            .context("backup_snapshot_size")?;
        ensure!(
            pages > 0 && page_size >= 512 && bytes > 0 && u64::try_from(bytes)? <= MAX_BYTES,
            "backup_snapshot_bound"
        );
        require_no_runtime_generation_objects(source)?;
        self.expected_bytes = usize::try_from(bytes)?;
        self.db.pragma_update(None, "page_size", page_size)?;
        self.db.pragma_update(
            None,
            "max_page_count",
            i64::try_from(MAX_BYTES)? / page_size,
        )?;
        let pages = i32::try_from(pages)?;
        let limit = usize::try_from(pages)?.div_ceil(usize::try_from(STEP_PAGES)?);
        let backup = Backup::new(source, &mut self.db)?;
        self.disposition.set(Disposition::Copying);
        Ok(SnapshotCopy {
            backup: Some(backup),
            source,
            disposition: &self.disposition,
            pages,
            previous_remaining: pages,
            steps: 0,
            limit,
        })
    }

    fn finish(self) -> Result<SnapshotContent> {
        ensure!(
            self.disposition.get() == Disposition::Copied,
            "backup_snapshot_incomplete"
        );
        memory_shape(&self.db, Some(self.expected_bytes))?;
        require_no_runtime_generation_objects(&self.db)?;
        let integrity: String = self
            .db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        ensure!(integrity == "ok", "backup_snapshot_integrity");
        Ok(SnapshotContent {
            db: self.db,
            expected_bytes: self.expected_bytes,
        })
    }
}

impl SnapshotCopy<'_, '_, '_> {
    /// One bounded SQLite step, with no sleep or Busy/Locked retry. The future
    /// native caller must independently evaluate its real pre AND post guards.
    fn step(&mut self) -> Result<CopyProgress> {
        let previous = self.disposition.replace(Disposition::Refused);
        ensure!(previous == Disposition::Copying, "backup_snapshot_refused");
        ensure!(
            !self.source.is_autocommit() && self.steps < self.limit,
            "backup_snapshot_source_or_work_changed"
        );
        self.steps += 1;
        let backup = self.backup.as_ref().context("backup_snapshot_closed")?;
        let complete = match backup.step(STEP_PAGES)? {
            StepResult::Done => true,
            StepResult::More => false,
            StepResult::Busy => anyhow::bail!("backup_snapshot_busy"),
            StepResult::Locked => anyhow::bail!("backup_snapshot_locked"),
            _ => anyhow::bail!("backup_snapshot_step_unsupported"),
        };
        let progress = backup.progress();
        ensure!(
            !self.source.is_autocommit()
                && progress.pagecount == self.pages
                && progress.remaining >= 0
                && progress.remaining < self.previous_remaining,
            "backup_snapshot_progress_changed"
        );
        self.previous_remaining = progress.remaining;
        if complete {
            ensure!(progress.remaining == 0, "backup_snapshot_incomplete");
            // Finish the actual backup handle before marking the DATA copy.
            self.backup.take();
            self.disposition.set(Disposition::Copied);
            Ok(CopyProgress::Complete)
        } else {
            ensure!(progress.remaining > 0, "backup_snapshot_progress_changed");
            self.disposition.set(Disposition::Copying);
            Ok(CopyProgress::More)
        }
    }
}

impl Drop for SnapshotCopy<'_, '_, '_> {
    fn drop(&mut self) {
        if self.disposition.get() != Disposition::Copied {
            self.disposition.set(Disposition::Refused);
        }
    }
}

impl SnapshotImage {
    /// Canonical complete-image consistency only. Neither this check nor its
    /// success manufactures an enrolled source, archive provenance or approval.
    fn verify(
        &self,
        manifest: &crate::backup_archive::Manifest,
        artifact: &crate::artifact::LoadedArtifact,
    ) -> Result<()> {
        image_shape(&self.bytes)?;
        super::restore_staging::require_native_archive_graph(manifest)?;
        ensure!(
            crate::digest(&self.bytes) == manifest.database,
            "backup_snapshot_manifest_changed"
        );
        let mut db = Connection::open_in_memory()?;
        db.pragma_update(None, "temp_store", "MEMORY")?;
        crate::store::configure_connection(&mut db)?;
        db.deserialize_read_exact(MAIN_DB, &self.bytes[..], self.bytes.len(), false)?;
        memory_shape(&db, Some(self.bytes.len()))?;
        require_no_runtime_generation_objects(&db)?;
        let result =
            crate::backup_archive::verify_snapshot(manifest, artifact, &mut db).map(|_| ());
        let closed = match db.close() {
            Ok(()) => Ok(()),
            Err((db, _)) => {
                drop(db);
                Err(anyhow::anyhow!("backup_snapshot_verifier_close"))
            }
        };
        result?;
        closed
    }
}

#[cfg(test)]
mod fixture;
#[cfg(test)]
mod tests;
