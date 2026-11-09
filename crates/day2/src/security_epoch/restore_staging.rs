//! Mechanical unpublished staging leaf. No accepting constructor, native
//! factory, public command, adoption or publication path exists here.
//! The future genuine owner must PRECEDE creation and keep this same State and
//! actual creator FD through reset, SQL close, sync and final target admission.
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, credentials::Namespace};
use ring::digest::{Context as Hash, SHA256};
use rusqlite::{Connection, MAIN_DB, Transaction, TransactionBehavior};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    rc::Rc,
};
use writer::StagingContext;
use zeroize::Zeroizing;

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

mod application;

/// Continuous ownership of the one configured scratch connection. Only the
/// fixed image builder constructs this in production, before deserialize or
/// other SQL work. It is not native storage or restore authority.
pub(crate) struct MemoryAdmission<'db> {
    db: &'db mut Connection,
    begun: Cell<bool>,
    local: std::marker::PhantomData<Rc<()>>,
}

/// A one-use admission borrow, tied to the actual still-held configured owner.
/// Neither memory PRAGMA data nor a connection address can construct it.
pub(crate) struct MemoryHook<'db> {
    db: &'db Connection,
    used: Cell<bool>,
}

impl<'db> MemoryAdmission<'db> {
    fn configure(db: &'db mut Connection) -> Result<Self> {
        ensure!(
            db.is_autocommit(),
            "restore_memory_configuration_inside_transaction"
        );
        ensure!(
            db.path().is_none_or(str::is_empty),
            "restore_memory_connection_required"
        );
        ensure!(
            db.pragma_query_value(None, "temp_store", |row| row.get::<_, i64>(0))? == 2,
            "restore_memory_temp_required"
        );
        crate::store::configure_connection(db)?;
        Ok(Self {
            db,
            begun: Cell::new(false),
            local: std::marker::PhantomData,
        })
    }

    fn begin(&self) -> Result<(Transaction<'_>, MemoryHook<'_>)> {
        ensure!(
            !self.begun.replace(true),
            "restore_memory_transaction_spent"
        );
        ensure!(
            self.db.is_autocommit(),
            "restore_memory_transaction_already_open"
        );
        let db: &Connection = &*self.db;
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        Ok((
            tx,
            MemoryHook {
                db,
                used: Cell::new(false),
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn configure_for_tests(db: &'db mut Connection) -> Result<Self> {
        Self::configure(db)
    }

    #[cfg(test)]
    pub(crate) fn begin_for_tests(&self) -> Result<(Transaction<'_>, MemoryHook<'_>)> {
        self.begin()
    }
}

impl MemoryHook<'_> {
    pub(crate) fn enter(&self, tx: &Transaction<'_>) -> Result<()> {
        ensure!(!self.used.replace(true), "restore_memory_admission_spent");
        ensure!(
            std::ptr::eq(self.db, &**tx),
            "restore_memory_admission_connection_changed"
        );
        ensure!(!tx.is_autocommit(), "restore_memory_transaction_required");
        memory_shape(tx, None)?;
        Ok(())
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty,$bound:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(MemoryAdmission<'static>, Clone);
    assert_not_impl!(MemoryAdmission<'static>, Copy);
    assert_not_impl!(MemoryAdmission<'static>, Default);
    assert_not_impl!(MemoryAdmission<'static>, std::fmt::Debug);
    assert_not_impl!(MemoryAdmission<'static>, Send);
    assert_not_impl!(MemoryAdmission<'static>, Sync);
    assert_not_impl!(MemoryAdmission<'static>, serde::Serialize);
    assert_not_impl!(MemoryAdmission<'static>, serde::Deserialize<'static>);
    assert_not_impl!(MemoryAdmission<'static>, std::ops::Deref);
    assert_not_impl!(MemoryAdmission<'static>, AsRef<Connection>);
    assert_not_impl!(MemoryAdmission<'static>, std::borrow::Borrow<Connection>);
    assert_not_impl!(MemoryHook<'static>, Clone);
    assert_not_impl!(MemoryHook<'static>, Copy);
    assert_not_impl!(MemoryHook<'static>, Default);
    assert_not_impl!(MemoryHook<'static>, std::fmt::Debug);
    assert_not_impl!(MemoryHook<'static>, Send);
    assert_not_impl!(MemoryHook<'static>, Sync);
    assert_not_impl!(MemoryHook<'static>, serde::Serialize);
    assert_not_impl!(MemoryHook<'static>, serde::Deserialize<'static>);
    assert_not_impl!(MemoryHook<'static>, std::ops::Deref);
    assert_not_impl!(MemoryHook<'static>, AsRef<Connection>);
    assert_not_impl!(MemoryHook<'static>, std::borrow::Borrow<Connection>);
};

mod sealed {
    pub(super) trait Sealed {}
}
/// Closed portable check source with no production implementation. Actual
/// native staging uses the concrete StagingContext branch instead of a manual
/// trait implementation on an opaque material owner. No accepting Parent
/// constructor exists; fixtures alone construct staging owners today.
trait Checks: sealed::Sealed {
    fn state(&mut self) -> &mut State;
    fn current(&mut self) -> Result<()>;
    /// Local current checks only, with no provider/key IO inside SQL.
    fn local_sql(&mut self) -> Result<()>;
    /// SQL validation against the already-held admitted app/profile, BEFORE
    /// creation. A future NativeImpl must retain that actual artifact/bundle
    /// and lend its same prepared fence/profile/cut without doing external IO.
    /// Fixture admission is unqualified.
    fn application(&mut self, source: &Transaction<'_>) -> Result<application::Selection<'_>>;
    fn refuse(&mut self);
}

struct Input {
    source: PathBuf,
    operation: Digest,
    namespace: Namespace,
    source_epoch: u64,
    database: Digest,
    target_incarnation: Digest,
}

struct State {
    input: Input,
    root_path: PathBuf,
    root: File,
    // Local scope identity is not authority. Only the actual owner can lend
    // Checks; no caller can turn this pointer or any projection into NativeImpl.
    scope: Rc<()>,
    expected_scope: Rc<()>,
    attempted: bool,
    refused: bool,
    directory_may_exist: bool,
    directory: Option<File>,
    creator: Option<File>,
    creator_identity: Option<(u64, u64)>,
    frozen_image: Option<(Digest, u64)>,
    birth_original: Option<super::restore_fencing::ApprovalIdentity>,
    source: Option<File>,
    sql: Option<Connection>,
    consumed: u64,
    written: u64,
    complete: bool,
    writer_attempted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Projection {
    image: Digest,
    bytes: u64,
    target_incarnation: Digest,
    reset: application::Summary,
}

impl State {
    fn target_dir(&self) -> Result<PathBuf> {
        Ok(self.root_path.join(self.target_component()?))
    }
    fn target_component(&self) -> Result<String> {
        let suffix = self
            .input
            .operation
            .as_str()
            .strip_prefix("sha256:")
            .context("restore_operation_digest")?;
        Ok(format!("restore-{suffix}"))
    }
    fn target_path(&self) -> Result<PathBuf> {
        Ok(self.target_dir()?.join("app.sqlite"))
    }
    fn join(&self) -> Result<()> {
        ensure!(
            !self.refused && Rc::ptr_eq(&self.scope, &self.expected_scope),
            "restore_staging_owner_refused"
        );
        ensure!(
            self.root_path.is_absolute() && self.root_path.canonicalize()? == self.root_path,
            "restore_staging_root_alias"
        );
        let named = std::fs::symlink_metadata(&self.root_path)?;
        let held = self.root.metadata()?;
        ensure!(
            named.is_dir()
                && named.dev() == held.dev()
                && named.ino() == held.ino()
                && named.mode() & 0o777 == 0o700,
            "restore_staging_root_changed"
        );
        if let Some(dir) = &self.directory {
            let named = std::fs::symlink_metadata(self.target_dir()?)?;
            let held = dir.metadata()?;
            ensure!(
                named.is_dir()
                    && named.dev() == held.dev()
                    && named.ino() == held.ino()
                    && named.mode() & 0o777 == 0o700,
                "restore_staging_directory_changed"
            );
        }
        if let Some(file) = &self.creator {
            let named = std::fs::symlink_metadata(self.target_path()?)?;
            let held = file.metadata()?;
            ensure!(
                named.is_file()
                    && named.dev() == held.dev()
                    && named.ino() == held.ino()
                    && self.creator_identity == Some((held.dev(), held.ino()))
                    && named.mode() & 0o777 == 0o600,
                "restore_staging_creator_changed"
            );
        }
        Ok(())
    }
}

/// Keep the actual owner/state refused on every early return and unwind. No
/// Err removes owned files, reconstructs a handle, or reports completion.
struct Attempt<'a, 'owner, 'borrow, 'metadata, 'storage, 'role, 'selection> {
    owner: &'a mut StagingContext<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>,
    done: bool,
}
impl Drop for Attempt<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.owner.state().refused = true;
            self.owner.refuse();
        }
    }
}

fn boundary<T>(
    owner: &mut StagingContext<'_, '_, '_, '_, '_, '_>,
    operation: impl FnOnce(&mut State) -> Result<T>,
) -> Result<T> {
    owner.current()?;
    owner.state().join()?;
    let result = operation(owner.state());
    // Mandatory postcheck also runs on primary IO failure. It cannot replace
    // that primary cause or turn an uncertain operation into a positive result.
    let post = owner.current().and_then(|_| owner.state().join());
    match result {
        Err(error) => Err(error),
        Ok(value) => post.map(|()| value),
    }
}

fn sum(context: Hash) -> Result<Digest> {
    Digest::try_from(format!("sha256:{}", crate::hex(context.finish().as_ref())))
}

fn hash_file(
    owner: &mut StagingContext<'_, '_, '_, '_, '_, '_>,
    source: bool,
) -> Result<(Digest, u64)> {
    boundary(owner, |s| {
        let file = if source {
            s.source.as_mut()
        } else {
            s.creator.as_mut()
        }
        .context("restore_file_missing")?;
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    })?;
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
    let mut context = Hash::new(&SHA256);
    let mut bytes = 0u64;
    loop {
        let count = boundary(owner, |s| {
            let file = if source {
                s.source.as_mut()
            } else {
                s.creator.as_mut()
            }
            .context("restore_file_missing")?;
            let limit = usize::try_from(MAX_BYTES.saturating_sub(bytes).saturating_add(1))?
                .min(buffer.len());
            let n = file.read(&mut buffer[..limit])?;
            if source {
                s.consumed = s
                    .consumed
                    .checked_add(n as u64)
                    .context("restore_byte_count")?;
            }
            Ok(n)
        })?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .context("restore_byte_count")?;
        ensure!(bytes <= MAX_BYTES, "restore_staging_image_bound");
        context.update(&buffer[..count]);
    }
    Ok((sum(context)?, bytes))
}

fn close_sql_context(owner: &mut StagingContext<'_, '_, '_, '_, '_, '_>) -> Result<()> {
    boundary(owner, |s| {
        let Some(db) = s.sql.take() else {
            return Ok(());
        };
        match db.close() {
            Ok(()) => Ok(()),
            Err((db, error)) => {
                s.sql = Some(db);
                Err(error.into())
            }
        }
    })
}

// Returning the connection to its actual owning State is unconditional, even
// when a test fault or a future owner panics. No close/adoption is inferred.
struct SqlLoan<'a, 'owner, 'borrow, 'metadata, 'storage, 'role, 'selection> {
    owner: &'a mut StagingContext<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>,
    db: Option<Connection>,
}
impl<'a, 'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>
    SqlLoan<'a, 'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>
{
    fn new(
        owner: &'a mut StagingContext<'owner, 'borrow, 'metadata, 'storage, 'role, 'selection>,
    ) -> Result<Self> {
        let s = owner.state();
        let slot = &mut s.sql;
        let db = slot.take().context("restore_sql_missing")?;
        Ok(Self {
            owner,
            db: Some(db),
        })
    }
}
impl Drop for SqlLoan<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        let s = self.owner.state();
        let slot = &mut s.sql;
        // The sealed implementation cannot replace a lent slot. If it ever
        // does, refuse rather than displacing the new connection silently.
        if slot.is_some() {
            s.refused = true;
            self.owner.refuse();
        } else {
            *slot = self.db.take();
        }
    }
}

fn image_shape(bytes: &[u8]) -> Result<()> {
    ensure!(
        (100..=usize::try_from(MAX_BYTES)?).contains(&bytes.len())
            && &bytes[..16] == b"SQLite format 3\0"
            && bytes[18] == 1
            && bytes[19] == 1,
        "restore_image_format"
    );
    Ok(())
}
fn memory_shape(db: &Connection, expected: Option<usize>) -> Result<usize> {
    ensure!(
        db.path().is_none_or(str::is_empty),
        "restore_memory_image_required"
    );
    ensure!(
        db.pragma_query_value(None, "temp_store", |r| r.get::<_, i64>(0))? == 2,
        "restore_memory_temp_required"
    );
    let mut query = db.prepare("PRAGMA database_list")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        let file: String = row.get(2)?;
        ensure!(
            matches!(name.as_str(), "main" | "temp") && file.is_empty(),
            "restore_attached_database_refused"
        );
    }
    let pages: i64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
    let size: i64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    ensure!(pages > 0 && size > 0, "restore_empty_image");
    let bytes = usize::try_from(pages)?
        .checked_mul(usize::try_from(size)?)
        .context("restore_image_bound")?;
    ensure!(
        bytes <= usize::try_from(MAX_BYTES)? && expected.is_none_or(|e| e == bytes),
        "restore_image_length"
    );
    Ok(bytes)
}
fn require_single_image(source: &std::path::Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = source.as_os_str().to_os_string();
        name.push(suffix);
        match std::fs::symlink_metadata(PathBuf::from(name)) {
            Ok(_) => anyhow::bail!("restore_staging_source_sidecar"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Fixed fresh-memory DATA builder. It accepts no raw connection or callback;
/// the entire function is reviewed/pinned for its sole serialize operation.
fn prepare_image(
    owner: &mut StagingContext<'_, '_, '_, '_, '_, '_>,
    image: &mut Zeroizing<Vec<u8>>,
) -> Result<application::Summary> {
    // This is always a fresh scratch connection. No filename, physical owner,
    // database_list result or caller-supplied Connection can construct it.
    boundary(owner, |s| {
        let db = Connection::open_in_memory()?;
        ensure!(s.sql.is_none(), "restore_sql_owner_spent");
        s.sql = Some(db);
        Ok(())
    })?;
    owner.local_sql()?;
    let mut loan = SqlLoan::new(owner)?;
    let reset = {
        let current = &mut *loan.owner;
        let db = loan.db.as_mut().context("restore_sql_missing")?;
        (|| -> Result<application::Summary> {
            db.pragma_update(None, "temp_store", "MEMORY")?;
            let memory = MemoryAdmission::configure(db)?;
            {
                let db = &mut *memory.db;
                // Safe pinned API reads a complete in-memory slice, not a fallible FD
                // stream; exact source bytes were hashed above, before any SQL admit.
                db.deserialize_read_exact(MAIN_DB, &image[..], image.len(), false)?;
                memory_shape(db, Some(image.len()))?;
                let page_size: i64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
                db.pragma_update(
                    None,
                    "max_page_count",
                    i64::try_from(MAX_BYTES)? / page_size,
                )?;
                db.pragma_update(None, "foreign_keys", true)?;
                db.pragma_update(None, "journal_mode", "MEMORY")?;
                ensure!(
                    db.pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))?
                        == "memory",
                    "restore_memory_journal_required"
                );
                ensure!(
                    db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))? == "ok",
                    "restore_image_integrity"
                );
            }
            current.local_sql()?;
            let (tx, hook) = memory.begin()?;
            let (ns, epoch) = {
                let s = current.state();
                (s.input.namespace.clone(), s.input.source_epoch)
            };
            let reset = {
                let selected = current.application(&tx)?;
                application::reset_in(&tx, &hook, &selected, &ns, epoch)?
            };
            #[cfg(test)]
            tests::cut(tests::Point::BeforeCommit)?;
            current.local_sql()?;
            tx.commit()?;
            #[cfg(test)]
            tests::cut(tests::Point::AfterCommit)?;
            current.local_sql()?;
            let db = &mut *memory.db;
            ensure!(db.is_autocommit(), "restore_uncommitted_image");
            let bytes = memory_shape(db, None)?;
            let serialized = db.serialize(MAIN_DB)?;
            ensure!(serialized.len() == bytes, "restore_image_length");
            image_shape(&serialized)?;
            // Replace the scratch owner only after the returned NOCOPY view has
            // been frozen. Neither memory COMMIT nor this DATA permits publication.
            *image = Zeroizing::new(serialized.to_vec());
            drop(serialized);
            Ok(reset)
        })()
    };
    drop(loan);
    let post = owner.local_sql();
    let reset = reset?;
    post?;
    close_sql_context(owner)?;
    Ok(reset)
}

fn execute<A: Checks>(owner: &mut A) -> Result<Projection> {
    execute_context(&mut StagingContext::portable(owner))
}

fn close_sql<A: Checks>(owner: &mut A) -> Result<()> {
    close_sql_context(&mut StagingContext::portable(owner))
}

fn execute_context(owner: &mut StagingContext<'_, '_, '_, '_, '_, '_>) -> Result<Projection> {
    let mut attempt = Attempt { owner, done: false };
    let owner = &mut *attempt.owner;
    ensure!(!owner.state().attempted, "restore_staging_attempt_spent");
    owner.state().attempted = true;
    boundary(owner, |s| {
        ensure!(
            s.input.source.is_absolute() && s.input.source.canonicalize()? == s.input.source,
            "restore_staging_source_alias"
        );
        require_single_image(&s.input.source)?;
        let named = std::fs::symlink_metadata(&s.input.source)?;
        ensure!(
            named.is_file() && named.len() <= MAX_BYTES,
            "restore_staging_source_bound"
        );
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())?)
            .open(&s.input.source)?;
        let held = fd.metadata()?;
        ensure!(
            held.dev() == named.dev() && held.ino() == named.ino(),
            "restore_staging_source_changed"
        );
        s.source = Some(fd);
        Ok(())
    })?;
    let mut image = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK]);
    loop {
        let n = boundary(owner, |s| {
            let limit = (MAX_BYTES as usize)
                .saturating_sub(image.len())
                .saturating_add(1)
                .min(buffer.len());
            let n = s
                .source
                .as_mut()
                .context("restore_source_missing")?
                .read(&mut buffer[..limit])?;
            s.consumed = s
                .consumed
                .checked_add(n as u64)
                .context("restore_byte_count")?;
            Ok(n)
        })?;
        if n == 0 {
            break;
        }
        ensure!(
            image
                .len()
                .checked_add(n)
                .is_some_and(|v| v <= MAX_BYTES as usize),
            "restore_staging_source_bound"
        );
        image.extend_from_slice(&buffer[..n]);
    }
    boundary(owner, |s| require_single_image(&s.input.source))?;
    // Absence is a refusal gate, not committed-snapshot authority. A genuine
    // supplier must bind this exact cold archive; no implementation exists yet.
    image_shape(&image)?;
    ensure!(
        Digest::new(&image) == owner.state().input.database,
        "restore_staging_source_digest"
    );
    #[cfg(test)]
    tests::cut(tests::Point::Captured)?;
    let reset = prepare_image(owner, &mut image)?;
    #[cfg(test)]
    tests::cut(tests::Point::Closed)?;
    let expected = Digest::new(&image);
    let length = u64::try_from(image.len())?;
    // Freeze the reset image BEFORE any creation. A later projection or current
    // pathname cannot supply this commitment to new-writer admission.
    owner.state().frozen_image = Some((expected.clone(), length));
    // Reset precedes creation. A crash never leaves a complete active source
    // image at the target; any partial or uncertain write stays unpublished.
    boundary(owner, |s| {
        s.directory_may_exist = true;
        #[cfg(test)]
        tests::before_create(s)?;
        let name = s.target_component()?;
        rustix::fs::mkdirat(&s.root, &name, rustix::fs::Mode::from_raw_mode(0o700))?;
        s.directory = Some(File::from(rustix::fs::openat(
            &s.root,
            &name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?));
        #[cfg(test)]
        tests::after_create(s)?;
        Ok(())
    })?;
    #[cfg(test)]
    tests::cut(tests::Point::Directory)?;
    boundary(owner, |s| {
        #[cfg(test)]
        tests::before_create(s)?;
        let directory = s.directory.as_ref().context("restore_directory_missing")?;
        s.creator = Some(File::from(rustix::fs::openat(
            directory,
            "app.sqlite",
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )?));
        let created = s
            .creator
            .as_ref()
            .context("restore_creator_missing")?
            .metadata()?;
        s.creator_identity = Some((created.dev(), created.ino()));
        #[cfg(test)]
        tests::after_create(s)?;
        Ok(())
    })?;
    let mut offset = 0;
    while offset < image.len() {
        let end = image.len().min(offset + CHUNK);
        let n = boundary(owner, |s| {
            #[cfg(test)]
            tests::before_write(s)?;
            let n = s
                .creator
                .as_mut()
                .context("restore_creator_missing")?
                .write(&image[offset..end])?;
            s.written = s
                .written
                .checked_add(n as u64)
                .context("restore_byte_count")?;
            #[cfg(test)]
            tests::after_write(s)?;
            ensure!(n > 0, "restore_staging_write_zero");
            Ok(n)
        })?;
        offset += n;
        #[cfg(test)]
        tests::cut(tests::Point::FirstWrite)?;
    }
    #[cfg(test)]
    tests::cut(tests::Point::Copied)?;
    boundary(owner, |s| {
        s.creator
            .as_ref()
            .context("restore_creator_missing")?
            .sync_all()?;
        Ok(())
    })?;
    boundary(owner, |s| {
        s.directory
            .as_ref()
            .context("restore_directory_missing")?
            .sync_all()?;
        Ok(())
    })?;
    boundary(owner, |s| {
        s.root.sync_all()?;
        Ok(())
    })?;
    #[cfg(test)]
    tests::cut(tests::Point::Synced)?;
    ensure!(
        hash_file(owner, false)? == (expected.clone(), length),
        "restore_staging_readback_changed"
    );
    owner.current()?;
    owner.state().join()?;
    let result = Projection {
        image: expected,
        bytes: length,
        target_incarnation: owner.state().input.target_incarnation.clone(),
        reset,
    };
    owner.state().complete = true;
    attempt.done = true;
    Ok(result)
}

#[cfg(test)]
pub(super) mod tests;

mod writer;
pub(in crate::security_epoch) use writer::{Disposition, Flight};
