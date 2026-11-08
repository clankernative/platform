//! One owned, bounded archive input. Nothing here can mint an executor, an
//! original, exclusion or a restored writer from manifest/path DATA.
use super::{CHUNK, MAX_BYTES, image_shape};
use crate::{
    artifact::LoadedArtifact,
    backup_archive::Manifest,
    security_epoch::{bootstrap::AuthenticatedRestoreExecution, kernel::restore::Intent},
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;

const MANIFEST_BYTES: u64 = 1024 * 1024;
const ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const ARTIFACT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 8;

mod installation;
pub(super) use installation::InstalledRestoreArtifact;

/// A retained borrow of the same admitted archive, never a pathname source.
/// Only ArchivePrepared lends it into the fixed native writer composition.
pub(super) struct CapturedRestoreArtifact<'archive> {
    snapshot: &'archive Snapshot,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// Only the actual moved executor constructs the native input. An unwind
/// drops its real original/source/file owners; no caller retains an executor
/// that can resume the failed capture as healthy.
pub(super) struct NativeArchive<'metadata, 'storage, 'role> {
    executor: Option<AuthenticatedRestoreExecution<'metadata, 'storage, 'role>>,
    intent: Intent,
    snapshot: Snapshot,
}

pub(super) struct ArchivePrepared<'metadata, 'storage, 'role> {
    executor: Option<AuthenticatedRestoreExecution<'metadata, 'storage, 'role>>,
    intent: Intent,
    snapshot: Snapshot,
    preparation: Preparation,
    attempted: bool,
}

struct Preparation {
    namespace: day2_capabilities::credentials::Namespace,
    root_path: PathBuf,
    root: Option<File>,
    fence: crate::security_epoch::restore_authority::PreparedRestoreFence,
    authority_schema: crate::security_epoch::restore_authority::RestoreFenceSchema,
    oauth_schema: crate::oauth::restore::Profile,
    cut: crate::security_epoch::restore_cut::Cut,
}

struct Snapshot {
    manifest: Manifest,
    image: Zeroizing<Vec<u8>>,
    source: Option<File>,
    artifact: LoadedArtifact,
    previous: crate::authority_state::ActiveAuthority,
    directory: Arc<tempfile::TempDir>,
    tree: CapturedTree,
    inventory: Digest,
    full_archive: Digest,
}

struct SourceFile {
    bytes: Zeroizing<Vec<u8>>,
    mode: u32,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ArchiveMember {
    File {
        bytes: u64,
        sha256: Digest,
        mode: u32,
    },
    Directory {
        mode: u32,
    },
}

fn file_member(file: &SourceFile) -> ArchiveMember {
    ArchiveMember::File {
        bytes: file.bytes.len() as u64,
        sha256: Digest::new(&file.bytes[..]),
        mode: file.mode,
    }
}

// Portable full-capture DATA, distinct from semantic backup metadata. Exact
// observed permission bits are committed; uid/ino/times remain native identity
// checks and cannot become portable authority. All names/kinds are closed by
// the native profile before this record can be compared with approval.
fn full_archive_commitment(
    manifest: &Manifest,
    inventory: &BTreeMap<String, ArchiveMember>,
) -> Result<Digest> {
    Digest::of(&(
        "day2-native-restore-archive-v1",
        "sqlite-current-artifact-only",
        manifest.security_restore_digest()?,
        inventory,
    ))
}

struct HeldFile {
    file: File,
    identity: Identity,
}

struct HeldDirectory {
    file: File,
    identity: Identity,
    names: BTreeSet<String>,
}

struct CapturedTree {
    root: PathBuf,
    files: BTreeMap<PathBuf, HeldFile>,
    directories: BTreeMap<PathBuf, HeldDirectory>,
}

impl CapturedTree {
    fn from_created(
        root: &Path,
        files: BTreeMap<PathBuf, HeldFile>,
        mut created: BTreeMap<PathBuf, File>,
    ) -> Result<Self> {
        let mut expected: BTreeMap<_, BTreeSet<String>> = created
            .keys()
            .map(|path| (path.clone(), BTreeSet::new()))
            .collect();
        ensure!(
            expected.contains_key(Path::new("")),
            "restore_archive_cache_root_missing"
        );
        for path in created
            .keys()
            .filter(|path| !path.as_os_str().is_empty())
            .chain(files.keys())
        {
            let parent = path.parent().context("restore_archive_member_parent")?;
            let name = path
                .file_name()
                .context("restore_archive_member_name")?
                .to_str()
                .context("restore_archive_member_utf8")?;
            ensure!(
                expected
                    .get_mut(parent)
                    .context("restore_archive_uncaptured_directory")?
                    .insert(name.to_owned()),
                "restore_archive_duplicate_cache_member"
            );
        }
        let mut directories = BTreeMap::new();
        for (relative, names) in expected {
            let file = created
                .remove(&relative)
                .context("restore_archive_directory_not_created")?;
            let identity = Identity::of(&file.metadata()?);
            let mut count = 0;
            ensure!(
                entries(&file, &mut count)? == names,
                "restore_archive_captured_inventory_changed"
            );
            directories.insert(
                relative,
                HeldDirectory {
                    file,
                    identity,
                    names,
                },
            );
        }
        ensure!(created.is_empty(), "restore_archive_extra_cache_directory");
        let tree = Self {
            root: root.to_owned(),
            files,
            directories,
        };
        tree.check()?;
        Ok(tree)
    }

    #[cfg(test)]
    fn pin(root: &Path, files: BTreeMap<PathBuf, HeldFile>) -> Result<Self> {
        // Fixture-only resource observation. Native capture supplies its own
        // ACTUAL create-new file and directory descriptors to from_created.
        let mut names = BTreeSet::from([PathBuf::new()]);
        for path in files.keys() {
            let mut parent = path.parent();
            while let Some(path) = parent {
                names.insert(path.to_owned());
                if path.as_os_str().is_empty() {
                    break;
                }
                parent = path.parent();
            }
        }
        let mut directories = BTreeMap::<PathBuf, File>::new();
        for path in names {
            let file = if path.as_os_str().is_empty() {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(i32::try_from(
                        (rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC)
                            .bits(),
                    )?)
                    .open(root)?
            } else {
                let parent = directories
                    .get(path.parent().context("fixture directory parent")?)
                    .context("fixture parent directory")?;
                directory_at(
                    parent,
                    path.file_name()
                        .context("fixture directory name")?
                        .to_str()
                        .context("fixture directory utf8")?,
                )?
            };
            directories.insert(path, file);
        }
        Self::from_created(root, files, directories)
    }

    fn check(&self) -> Result<()> {
        for (relative, held) in &self.directories {
            let named = std::fs::symlink_metadata(self.root.join(relative))?;
            let mut count = 0;
            ensure!(
                named.is_dir()
                    && Identity::of(&named) == held.identity
                    && Identity::of(&held.file.metadata()?) == held.identity
                    && entries(&held.file, &mut count)? == held.names,
                "restore_archive_captured_directory_changed"
            );
        }
        check_captured_files(&self.root, &self.files)
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Identity {
    fn of(value: &std::fs::Metadata) -> Self {
        Self {
            device: value.dev(),
            inode: value.ino(),
            length: value.len(),
            mode: value.mode(),
            uid: value.uid(),
            gid: value.gid(),
            modified: (value.mtime(), value.mtime_nsec()),
            changed: (value.ctime(), value.ctime_nsec()),
        }
    }
}

// This enum is closed. Tests drive the SAME descriptor/capture body, but their
// schedule cannot construct the production variant or any native executor.
enum Capture<'borrow, 'metadata, 'storage, 'role> {
    Native {
        executor: &'borrow mut AuthenticatedRestoreExecution<'metadata, 'storage, 'role>,
        intent: &'borrow Intent,
    },
    #[cfg(test)]
    Fixture(&'borrow mut tests::Schedule),
}

impl Capture<'_, '_, '_, '_> {
    fn check(&mut self) -> Result<()> {
        match self {
            Self::Native { executor, intent } => executor.check_archive_local(intent).map(|_| ()),
            #[cfg(test)]
            Self::Fixture(schedule) => schedule.check(),
        }
    }

    fn worker_remaining(&mut self) -> Result<Duration> {
        let result = match self {
            Self::Native { executor, intent } => {
                executor.require_historical_keys(intent)?;
                let observation = executor.check()?;
                let (_, _, deadline) = observation.interval_data();
                let now = observation.observation_data().1;
                let remaining = deadline
                    .checked_sub(now)
                    .context("restore_archive_original_expired")?;
                ensure!(remaining > 0, "restore_archive_original_expired");
                Ok(Duration::from_nanos(remaining))
            }
            #[cfg(test)]
            Self::Fixture(schedule) => schedule.remaining(),
        };
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn refuse(&mut self) {
        match self {
            Self::Native { executor, .. } => executor.refuse(),
            #[cfg(test)]
            Self::Fixture(schedule) => schedule.refused = true,
        }
    }

    fn observe<T>(&mut self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        self.check()?;
        let requested = operation();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let value = requested?;
        checked?;
        Ok(value)
    }
}

/// A nonescaping borrow created only while capturing the one unpublished
/// archive. It owns no replacement clock or authority and exposes no file,
/// stage or original getter. The artifact validator cannot select this path
/// from a manifest, directory, timeout or callback.
pub(crate) struct RestoreArtifactAdmission<'capture, 'owner, 'metadata, 'storage, 'role> {
    capture: &'capture mut Capture<'owner, 'metadata, 'storage, 'role>,
    tree: &'capture CapturedTree,
    worker: Option<crate::worker::Worker>,
}

impl RestoreArtifactAdmission<'_, '_, '_, '_, '_> {
    fn check(&mut self) -> Result<Duration> {
        let requested = self.tree.check();
        let checked = self.capture.worker_remaining();
        if requested.is_err() || checked.is_err() {
            self.capture.refuse();
            self.worker.take();
        }
        requested?;
        checked
    }

    pub(crate) fn start(&mut self, artifact: &LoadedArtifact) -> Result<Arc<tempfile::TempPath>> {
        self.check()?;
        let requested = (|| {
            ensure!(
                self.worker.is_none(),
                "restore_archive_worker_already_started"
            );
            ensure!(
                artifact.directory() == self.tree.root,
                "restore_archive_worker_source_changed"
            );
            let executable = artifact.materialize_worker()?;
            Ok((crate::worker::Worker::start(&executable)?, executable))
        })();
        // Even a failed spawn/materialization must evaluate the actual owner
        // postcheck. A late spawn is dropped before any artifact can escape.
        let (worker, executable) = self.finish(requested)?;
        self.worker = Some(worker);
        Ok(executable)
    }

    pub(crate) fn exchange(&mut self, query: crate::artifact::ContractQuery) -> Result<Vec<u8>> {
        let remaining = self.check()?;
        let requested = (|| {
            self.worker
                .as_mut()
                .context("restore_archive_worker_not_started")?
                .exchange_bounded(
                    query.bytes(),
                    crate::worker::MAX_FRAME,
                    remaining.min(Duration::from_secs(3)),
                )
        })();
        self.finish(requested)
    }

    fn finish<T>(&mut self, requested: Result<T>) -> Result<T> {
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.capture.refuse();
            self.worker.take();
        }
        let bytes = requested?;
        checked?;
        Ok(bytes)
    }
}

impl<'metadata, 'storage, 'role> NativeArchive<'metadata, 'storage, 'role> {
    pub(super) fn capture(
        mut executor: AuthenticatedRestoreExecution<'metadata, 'storage, 'role>,
        directory: &Path,
        intent: &Intent,
    ) -> Result<Self> {
        let requested = executor.retain_historical_keys(intent);
        let checked = executor.check();
        if requested.is_err() || checked.is_err() {
            executor.refuse();
        }
        requested?;
        checked?;
        let requested = capture_snapshot(
            &mut Capture::Native {
                executor: &mut executor,
                intent,
            },
            directory,
            intent,
        );
        let checked = executor.require_historical_keys(intent);
        if requested.is_err() || checked.is_err() {
            executor.refuse();
        }
        let snapshot = requested?;
        checked?;
        Ok(Self {
            executor: Some(executor),
            intent: intent.clone(),
            snapshot,
        })
    }

    pub(super) fn prepare(mut self) -> Result<ArchivePrepared<'metadata, 'storage, 'role>> {
        let mut executor = self
            .executor
            .take()
            .context("restore_archive_executor_closed")?;
        let requested: Result<Preparation> = (|| {
            let (selection, namespace, not_before, root_path) =
                executor.restore_archive_binding_data(&self.intent)?;
            self.snapshot.tree.check()?;
            let mut capture = Capture::Native {
                executor: &mut executor,
                intent: &self.intent,
            };
            let mut entropy = zeroize::Zeroizing::new([0u8; 32]);
            capture.observe(|| {
                getrandom::fill(&mut entropy[..])
                    .map_err(|_| anyhow::anyhow!("restore_archive_entropy"))
            })?;
            let fresh_epoch = Digest::of(&(
                "day2-restored-application-authority-v1",
                &self.intent.operation,
                &entropy[..],
            ))?;
            let component = format!(
                "restore-{}",
                self.intent
                    .operation
                    .as_str()
                    .strip_prefix("sha256:")
                    .context("restore_operation_digest")?
            );
            let relocated = root_path
                .join(component)
                .join(self.snapshot.manifest.artifact_relative()?);
            let root = capture.observe(|| {
                ensure!(
                    root_path.is_absolute() && root_path.canonicalize()? == root_path,
                    "restore_archive_staging_root_alias"
                );
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(i32::try_from(
                        (rustix::fs::OFlags::DIRECTORY
                            | rustix::fs::OFlags::NOFOLLOW
                            | rustix::fs::OFlags::CLOEXEC)
                            .bits(),
                    )?)
                    .open(&root_path)?;
                ensure!(
                    file.metadata()?.is_dir() && file.metadata()?.mode() & 0o7777 == 0o700,
                    "restore_archive_staging_root_profile"
                );
                Ok(file)
            })?;
            let fence = capture.observe(|| {
                crate::security_epoch::restore_authority::PreparedRestoreFence::new(
                    self.snapshot.previous.clone(),
                    &relocated,
                    fresh_epoch,
                    not_before,
                )
            })?;
            let authority_schema = capture
                .observe(crate::security_epoch::restore_authority::RestoreFenceSchema::prepare)?;
            let oauth_schema = capture.observe(crate::oauth::restore::Profile::prepare)?;
            let custody = self
                .intent
                .archive
                .required_keys
                .iter()
                .find(|key| {
                    key.purpose
                        == crate::security_epoch::kernel::restore::KeyPurpose::CustodyEncryption
                })
                .context("restore_archive_custody_key_missing")?
                .binding
                .clone();
            let cut = crate::security_epoch::restore_cut::Cut::new(
                &selection,
                namespace.clone(),
                self.intent.clone(),
                self.intent.archive.full_archive_digest.clone(),
                custody,
                self.snapshot.inventory.clone(),
            )?;
            cut.require_artifact(&self.snapshot.artifact)?;
            self.snapshot.tree.check()?;
            Ok(Preparation {
                namespace,
                root_path,
                root: Some(root),
                fence,
                authority_schema,
                oauth_schema,
                cut,
            })
        })();
        let checked = executor.require_historical_keys(&self.intent);
        if requested.is_err() || checked.is_err() {
            executor.refuse();
        }
        let preparation = requested?;
        checked?;
        Ok(ArchivePrepared {
            executor: Some(executor),
            intent: self.intent,
            snapshot: self.snapshot,
            preparation,
            attempted: false,
        })
    }
}

impl<'metadata, 'storage, 'role> ArchivePrepared<'metadata, 'storage, 'role> {
    /// The only production State construction is here, before any creator
    /// effect, consuming the captured immutable FD and the SAME actual executor.
    /// The private writer return keeps every real loan and selection borrow.
    pub(super) fn start_native(
        &mut self,
    ) -> Result<super::writer::NativeRestore<'metadata, 'storage, 'role, '_>> {
        if self.attempted {
            if let Some(executor) = self.executor.as_mut() {
                executor.refuse();
            }
            anyhow::bail!("restore_archive_attempt_spent");
        }
        self.attempted = true;
        let mut executor = self
            .executor
            .take()
            .context("restore_archive_executor_closed")?;
        let requested: Result<super::State> = (|| {
            executor.require_historical_keys(&self.intent)?;
            self.snapshot.tree.check()?;
            let source = self
                .snapshot
                .source
                .take()
                .context("restore_archive_source_spent")?;
            let root = self
                .preparation
                .root
                .take()
                .context("restore_archive_root_spent")?;
            let scope = std::rc::Rc::new(());
            let state = super::State {
                input: super::Input {
                    source,
                    operation: self.intent.operation.clone(),
                    namespace: self.preparation.namespace.clone(),
                    source_epoch: self.intent.archive.security_epoch,
                    database: self.intent.archive.image.clone(),
                    target_incarnation: self.intent.target_incarnation.clone(),
                },
                root_path: self.preparation.root_path.clone(),
                root,
                scope: std::rc::Rc::clone(&scope),
                expected_scope: scope,
                attempted: false,
                refused: false,
                directory_may_exist: false,
                directory: None,
                creator: None,
                creator_identity: None,
                frozen_image: None,
                birth_original: None,
                source: None,
                sql: None,
                consumed: 0,
                written: 0,
                complete: false,
                writer_attempted: false,
            };
            state.require_unstarted()?;
            Ok(state)
        })();
        let checked = executor.require_historical_keys(&self.intent);
        if requested.is_err() || checked.is_err() {
            executor.refuse();
        }
        let state = requested?;
        checked?;
        let selection = super::application::Selection::prepared(
            &self.preparation.namespace,
            self.intent.archive.security_epoch,
            &self.snapshot.artifact,
            &self.preparation.fence,
            &self.preparation.authority_schema,
            &self.preparation.oauth_schema,
            &self.preparation.cut,
        )?;
        super::writer::NativeRestore::consume(
            executor,
            &self.intent,
            state,
            selection,
            CapturedRestoreArtifact {
                snapshot: &self.snapshot,
                local: std::marker::PhantomData,
            },
        )
    }
}

fn directory_at(parent: &File, name: &str) -> Result<File> {
    Ok(File::from(rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?))
}

fn entries(directory: &File, budget: &mut usize) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        *budget = budget
            .checked_add(1)
            .context("restore_archive_entry_count")?;
        ensure!(*budget <= MAX_ENTRIES, "restore_archive_entry_bound");
        let name = std::str::from_utf8(name)?;
        ensure!(
            !name.is_empty()
                && name.len() <= 255
                && !name
                    .bytes()
                    .any(|byte| matches!(byte, b'/' | b'\\' | b'\0'))
                && names.insert(name.to_owned()),
            "restore_archive_entry_name"
        );
    }
    Ok(names)
}

fn read_file(
    capture: &mut Capture<'_, '_, '_, '_>,
    parent: &File,
    name: &str,
    maximum: u64,
) -> Result<SourceFile> {
    let (mut file, identity) = capture.observe(|| {
        let file = File::from(rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= maximum,
            "restore_archive_regular_bounded_file"
        );
        Ok((file, Identity::of(&metadata)))
    })?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    loop {
        let count = capture.observe(|| {
            ensure!(
                Identity::of(&file.metadata()?) == identity,
                "restore_archive_file_changed"
            );
            let limit =
                usize::try_from(maximum.saturating_sub(bytes.len() as u64).saturating_add(1))?
                    .min(buffer.len());
            let count = file.read(&mut buffer[..limit])?;
            ensure!(
                Identity::of(&file.metadata()?) == identity,
                "restore_archive_file_changed"
            );
            Ok(count)
        })?;
        if count == 0 {
            break;
        }
        ensure!(
            bytes
                .len()
                .checked_add(count)
                .is_some_and(|n| n as u64 <= maximum),
            "restore_archive_file_bound"
        );
        bytes.extend_from_slice(&buffer[..count]);
    }
    capture.observe(|| {
        let named = File::from(rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        ensure!(
            Identity::of(&file.metadata()?) == identity
                && Identity::of(&named.metadata()?) == identity
                && bytes.len() as u64 == identity.length,
            "restore_archive_named_file_changed"
        );
        Ok(())
    })?;
    Ok(SourceFile {
        bytes,
        mode: identity.mode & 0o7777,
    })
}

/// The same cumulative archive counters span every recursive child. These
/// borrowed numbers are DATA bounds, not a source, executor or native owner.
struct TreeBudget<'budget> {
    count: &'budget mut usize,
    bytes: &'budget mut u64,
}

fn read_tree(
    capture: &mut Capture<'_, '_, '_, '_>,
    directory: &File,
    prefix: &Path,
    depth: usize,
    budget: &mut TreeBudget<'_>,
    output: &mut BTreeMap<PathBuf, SourceFile>,
    directories: &mut BTreeMap<PathBuf, u32>,
) -> Result<()> {
    ensure!(depth <= MAX_DEPTH, "restore_archive_depth_bound");
    let before = capture.observe(|| Ok(Identity::of(&directory.metadata()?)))?;
    let names = capture.observe(|| entries(directory, budget.count))?;
    for name in &names {
        let stat = capture.observe(|| {
            Ok(rustix::fs::statat(
                directory,
                name.as_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?)
        })?;
        let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        let relative = prefix.join(name);
        if kind == rustix::fs::FileType::Directory {
            let child = capture.observe(|| directory_at(directory, name))?;
            let mode = capture.observe(|| Ok(child.metadata()?.mode() & 0o7777))?;
            ensure!(
                directories.insert(relative.clone(), mode).is_none(),
                "restore_archive_duplicate_directory"
            );
            read_tree(
                capture,
                &child,
                &relative,
                depth + 1,
                budget,
                output,
                directories,
            )?;
            capture.observe(|| {
                let named = directory_at(directory, name)?;
                ensure!(
                    Identity::of(&child.metadata()?) == Identity::of(&named.metadata()?),
                    "restore_archive_directory_changed"
                );
                Ok(())
            })?;
        } else {
            ensure!(
                kind == rustix::fs::FileType::RegularFile,
                "restore_archive_special_file"
            );
            let remaining = ARTIFACT_BYTES
                .checked_sub(*budget.bytes)
                .context("restore_archive_artifact_bound")?;
            let contents = read_file(capture, directory, name, ARTIFACT_FILE_BYTES.min(remaining))?;
            *budget.bytes = budget
                .bytes
                .checked_add(contents.bytes.len() as u64)
                .context("restore_archive_artifact_bound")?;
            ensure!(
                *budget.bytes <= ARTIFACT_BYTES,
                "restore_archive_artifact_bound"
            );
            ensure!(
                output.insert(relative, contents).is_none(),
                "restore_archive_duplicate_member"
            );
        }
    }
    capture.observe(|| {
        let mut recount = 0;
        ensure!(
            entries(directory, &mut recount)? == names
                && Identity::of(&directory.metadata()?) == before,
            "restore_archive_directory_changed"
        );
        Ok(())
    })
}

fn require_root_members(names: &BTreeSet<String>) -> Result<()> {
    ensure!(
        names
            == &BTreeSet::from([
                "app.sqlite".into(),
                "artifacts".into(),
                "backup.json".into()
            ]),
        "restore_archive_unhandled_member"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn sealed_source(capture: &mut Capture<'_, '_, '_, '_>, image: &[u8]) -> Result<File> {
    use rustix::fs::{MemfdFlags, SealFlags};
    use std::io::{Seek, SeekFrom};
    let mut file = capture.observe(|| {
        Ok(File::from(rustix::fs::memfd_create(
            "day2-restore-captured-sqlite",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        )?))
    })?;
    for chunk in image.chunks(CHUNK) {
        capture.observe(|| {
            file.write_all(chunk)?;
            Ok(())
        })?;
    }
    capture.observe(|| {
        let seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
        rustix::fs::fcntl_add_seals(&file, seals)?;
        ensure!(
            rustix::fs::fcntl_get_seals(&file)?.contains(seals)
                && file.metadata()?.is_file()
                && file.metadata()?.len() == image.len() as u64,
            "restore_archive_source_not_sealed"
        );
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    })?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn sealed_source(_capture: &mut Capture<'_, '_, '_, '_>, _image: &[u8]) -> Result<File> {
    anyhow::bail!("restore_archive_native_sealed_source_required")
}

fn create_cache_file(
    capture: &mut Capture<'_, '_, '_, '_>,
    parent: &File,
    name: &str,
    contents: &[u8],
) -> Result<HeldFile> {
    use std::io::{Seek, SeekFrom};
    let mut file = capture.observe(|| {
        Ok(File::from(rustix::fs::openat(
            parent,
            name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )?))
    })?;
    for chunk in contents.chunks(CHUNK) {
        capture.observe(|| {
            file.write_all(chunk)?;
            Ok(())
        })?;
    }
    let identity = capture.observe(|| {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.len() == contents.len() as u64
                && metadata.mode() & 0o7777 == 0o600,
            "restore_archive_cache_creator_changed"
        );
        Ok(Identity::of(&metadata))
    })?;
    capture.observe(|| {
        file.seek(SeekFrom::Start(0))?;
        Ok(())
    })?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    let mut count = 0usize;
    loop {
        let read = capture.observe(|| {
            ensure!(
                Identity::of(&file.metadata()?) == identity,
                "restore_archive_cache_creator_changed"
            );
            let read = file.read(&mut buffer[..])?;
            ensure!(
                Identity::of(&file.metadata()?) == identity,
                "restore_archive_cache_creator_changed"
            );
            Ok(read)
        })?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read)
            .context("restore_archive_cache_bound")?;
        ensure!(count <= contents.len(), "restore_archive_cache_bound");
        hash.update(&buffer[..read]);
    }
    ensure!(
        count == contents.len() && super::sum(hash)? == Digest::new(contents),
        "restore_archive_cache_bytes_changed"
    );
    capture.observe(|| {
        file.seek(SeekFrom::Start(0))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && Identity::of(&metadata) == identity,
            "restore_archive_cache_creator_changed"
        );
        Ok(())
    })?;
    Ok(HeldFile { file, identity })
}

fn create_cache(
    capture: &mut Capture<'_, '_, '_, '_>,
    artifact_relative: &str,
    files: &BTreeMap<PathBuf, SourceFile>,
    source_directories: &BTreeMap<PathBuf, u32>,
) -> Result<(Arc<tempfile::TempDir>, CapturedTree)> {
    let directory = Arc::new(capture.observe(|| {
        Ok(tempfile::Builder::new()
            .prefix("day2-restore-archive-")
            .tempdir()?)
    })?);
    let base = capture.observe(|| {
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(i32::try_from(
                (rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC)
                    .bits(),
            )?)
            .open(directory.path())?)
    })?;
    let components: Vec<_> = Path::new(artifact_relative).components().collect();
    ensure!(
        components.len() == 2 && components[0].as_os_str() == "artifacts",
        "restore_archive_artifact_directory"
    );
    let name = components[1]
        .as_os_str()
        .to_str()
        .context("restore_archive_artifact_name")?;
    ensure!(
        name.len() == 64
            && name
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "restore_archive_artifact_name"
    );
    let artifacts = capture.observe(|| {
        rustix::fs::mkdirat(&base, "artifacts", rustix::fs::Mode::from_raw_mode(0o700))?;
        directory_at(&base, "artifacts")
    })?;
    let root = capture.observe(|| {
        rustix::fs::mkdirat(&artifacts, name, rustix::fs::Mode::from_raw_mode(0o700))?;
        directory_at(&artifacts, name)
    })?;
    let mut expected = BTreeSet::from([PathBuf::new()]);
    expected.extend(source_directories.keys().cloned());
    for file in files.keys() {
        let mut parent = file.parent();
        while let Some(path) = parent {
            expected.insert(path.to_owned());
            if path.as_os_str().is_empty() {
                break;
            }
            parent = path.parent();
        }
    }
    let mut created = BTreeMap::from([(PathBuf::new(), root)]);
    for relative in expected
        .into_iter()
        .filter(|path| !path.as_os_str().is_empty())
    {
        let parent = created
            .get(relative.parent().context("restore_archive_cache_parent")?)
            .context("restore_archive_cache_parent_missing")?;
        let name = relative
            .file_name()
            .context("restore_archive_cache_name")?
            .to_str()
            .context("restore_archive_cache_utf8")?;
        let file = capture.observe(|| {
            rustix::fs::mkdirat(parent, name, rustix::fs::Mode::from_raw_mode(0o700))?;
            directory_at(parent, name)
        })?;
        created.insert(relative, file);
    }
    let mut held = BTreeMap::new();
    for (path, source) in files {
        let parent = created
            .get(path.parent().context("restore_archive_cache_file_parent")?)
            .context("restore_archive_cache_file_parent_missing")?;
        let name = path
            .file_name()
            .context("restore_archive_cache_file_name")?
            .to_str()
            .context("restore_archive_cache_file_utf8")?;
        held.insert(
            path.clone(),
            create_cache_file(capture, parent, name, &source.bytes)?,
        );
    }
    let target =
        capture.observe(|| Ok(directory.path().canonicalize()?.join(artifact_relative)))?;
    let tree = capture.observe(|| CapturedTree::from_created(&target, held, created))?;
    Ok((directory, tree))
}

fn capture_snapshot(
    capture: &mut Capture<'_, '_, '_, '_>,
    selected: &Path,
    intent: &Intent,
) -> Result<Snapshot> {
    let root = capture.observe(|| {
        ensure!(
            selected.is_absolute() && selected.canonicalize()? == selected,
            "restore_archive_root_alias"
        );
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(i32::try_from(
                (rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC)
                    .bits(),
            )?)
            .open(selected)?)
    })?;
    let root_identity = capture.observe(|| Ok(Identity::of(&root.metadata()?)))?;
    let mut count = 0;
    let names = capture.observe(|| entries(&root, &mut count))?;
    require_root_members(&names)?;
    let encoded = read_file(capture, &root, "backup.json", MANIFEST_BYTES)?;
    let manifest: Manifest = serde_json::from_slice(&encoded.bytes)?;
    let artifact_relative = manifest.artifact_relative()?;
    ensure!(
        manifest.provider_databases.is_empty()
            && manifest.rollout_artifacts.is_none()
            && manifest.companion_state.is_empty(),
        "restore_archive_unhandled_graph"
    );
    ensure!(
        manifest.artifact == intent.archive.artifact.as_str()
            && manifest.database == intent.archive.image.as_str()
            && manifest.scope
                == format!(
                    "{}/{}/{}",
                    intent.archive.scope.installation.as_str(),
                    intent.archive.scope.environment.as_str(),
                    intent.archive.scope.app.as_str()
                )
            && manifest.app == intent.archive.scope.app.as_str(),
        "restore_archive_approval_changed"
    );
    let image = read_file(capture, &root, "app.sqlite", MAX_BYTES)?;
    image_shape(&image.bytes)?;
    ensure!(
        Digest::new(&image.bytes[..]) == intent.archive.image,
        "restore_archive_database_changed"
    );
    let artifacts = capture.observe(|| directory_at(&root, "artifacts"))?;
    let artifacts_identity = capture.observe(|| Ok(Identity::of(&artifacts.metadata()?)))?;
    let artifact_name = day2_assets::hash_part(&manifest.artifact)?;
    ensure!(
        capture.observe(|| entries(&artifacts, &mut count))?
            == BTreeSet::from([artifact_name.to_owned()]),
        "restore_archive_unhandled_artifact"
    );
    let artifact_root = capture.observe(|| directory_at(&artifacts, artifact_name))?;
    let artifact_root_identity =
        capture.observe(|| Ok(Identity::of(&artifact_root.metadata()?)))?;
    let mut files = BTreeMap::new();
    let mut directories = BTreeMap::new();
    let mut artifact_bytes = 0;
    read_tree(
        capture,
        &artifact_root,
        Path::new(""),
        0,
        &mut TreeBudget {
            count: &mut count,
            bytes: &mut artifact_bytes,
        },
        &mut files,
        &mut directories,
    )?;
    capture.observe(|| {
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(i32::try_from(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits(),
            )?)
            .open(selected)?;
        let named_artifacts = directory_at(&root, "artifacts")?;
        let named_artifact = directory_at(&artifacts, artifact_name)?;
        ensure!(
            Identity::of(&named_artifacts.metadata()?) == artifacts_identity
                && Identity::of(&artifacts.metadata()?) == artifacts_identity
                && Identity::of(&named_artifact.metadata()?) == artifact_root_identity
                && Identity::of(&artifact_root.metadata()?) == artifact_root_identity,
            "restore_archive_artifact_directory_changed"
        );
        let mut recount = 0;
        ensure!(
            Identity::of(&named.metadata()?) == root_identity
                && Identity::of(&root.metadata()?) == root_identity
                && entries(&root, &mut recount)? == names,
            "restore_archive_root_changed"
        );
        Ok(())
    })?;

    let mut inventory = BTreeMap::from([
        (
            String::new(),
            ArchiveMember::Directory {
                mode: root_identity.mode & 0o7777,
            },
        ),
        ("backup.json".into(), file_member(&encoded)),
        ("app.sqlite".into(), file_member(&image)),
        (
            "artifacts".into(),
            ArchiveMember::Directory {
                mode: artifacts_identity.mode & 0o7777,
            },
        ),
        (
            artifact_relative.clone(),
            ArchiveMember::Directory {
                mode: artifact_root_identity.mode & 0o7777,
            },
        ),
    ]);
    for (relative, file) in &files {
        let name = Path::new(&artifact_relative)
            .join(relative)
            .to_str()
            .context("restore_archive_inventory_utf8")?
            .to_owned();
        ensure!(
            inventory.insert(name, file_member(file)).is_none(),
            "restore_archive_inventory_duplicate"
        );
    }
    for (relative, mode) in &directories {
        let name = Path::new(&artifact_relative)
            .join(relative)
            .to_str()
            .context("restore_archive_inventory_utf8")?
            .to_owned();
        ensure!(
            inventory
                .insert(name, ArchiveMember::Directory { mode: *mode })
                .is_none(),
            "restore_archive_inventory_duplicate"
        );
    }
    let full_archive = full_archive_commitment(&manifest, &inventory)?;
    ensure!(
        full_archive == intent.archive.full_archive_digest,
        "restore_archive_full_capture_changed"
    );
    capture.check()?;

    // Only captured bytes enter this private retained tree. The original
    // archive path is never handed to LoadedArtifact or a SQLite opener.
    let (directory, tree) = create_cache(capture, &artifact_relative, &files, &directories)?;
    let target = tree.root.clone();
    let mut artifact = LoadedArtifact::load_restore(
        &target,
        &mut RestoreArtifactAdmission {
            capture,
            tree: &tree,
            worker: None,
        },
    )?;
    capture.check()?;
    artifact.require_current_api()?;
    ensure!(
        artifact.id() == intent.archive.artifact.as_str()
            && artifact.contract().schema_digest == intent.archive.schema.as_str(),
        "restore_archive_artifact_binding_changed"
    );
    ensure!(
        files.keys().cloned().collect::<BTreeSet<_>>()
            == crate::backup_archive::artifact_files(&artifact)?,
        "restore_archive_unhandled_artifact_member"
    );
    let mut allowed_directories = BTreeSet::from([
        PathBuf::from("assets"),
        PathBuf::from("web_resources"),
        PathBuf::from("web_templates"),
        PathBuf::from(crate::public_downloads::SOURCE_DIRECTORY),
    ]);
    for path in files.keys() {
        let mut parent = path.parent();
        while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
            allowed_directories.insert(path.to_owned());
            parent = path.parent();
        }
    }
    ensure!(
        directories
            .keys()
            .all(|path| allowed_directories.contains(path)),
        "restore_archive_unhandled_artifact_directory"
    );
    artifact.retain(Arc::clone(&directory));
    let image = image.bytes;
    let previous = capture.observe(|| {
        let mut db = rusqlite::Connection::open_in_memory()?;
        db.pragma_update(None, "temp_store", "MEMORY")?;
        let memory = super::MemoryAdmission::configure(&mut db)?;
        memory
            .db
            .deserialize_read_exact(rusqlite::MAIN_DB, &image[..], image.len(), false)?;
        super::memory_shape(memory.db, Some(image.len()))?;
        crate::backup_archive::verify_snapshot(&manifest, &artifact, memory.db)
    })?;
    let inventory = Digest::of(&("day2-native-restore-inventory-v1", &inventory))?;
    let source = Some(sealed_source(capture, &image)?);
    Ok(Snapshot {
        manifest,
        image,
        source,
        artifact,
        previous,
        directory,
        tree,
        inventory,
        full_archive,
    })
}

fn check_captured_files(root: &Path, files: &BTreeMap<PathBuf, HeldFile>) -> Result<()> {
    for (name, held) in files {
        let named = std::fs::symlink_metadata(root.join(name))?;
        ensure!(
            named.is_file()
                && named.nlink() == 1
                && Identity::of(&named) == held.identity
                && Identity::of(&held.file.metadata()?) == held.identity,
            "restore_archive_captured_member_changed"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
