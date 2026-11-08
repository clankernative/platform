//! Fixed artifact installation into the actual reset target. Neither a path,
//! completed projection nor captured archive DATA supplies the native loan.
use super::{
    CapturedRestoreArtifact, CapturedTree, HeldDirectory, HeldFile, Identity, directory_at, entries,
};
use crate::security_epoch::{
    bootstrap::RestoreWriteLoan,
    kernel::restore::Intent,
    restore_staging::{CHUNK, State},
    storage_authority::RestoreCreatorRoot,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// All installed creator descriptors remain owned through the real keeper
/// handoff. This is physical custody only, never P3, a writer or Current.
pub(in crate::security_epoch::restore_staging) struct InstalledRestoreArtifact {
    tree: CapturedTree,
    parent: File,
    artifacts: HeldDirectory,
    artifact: Digest,
    refused: bool,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

struct Installation<'check, 'borrow, 'metadata, 'storage, 'role> {
    source: &'check CapturedTree,
    owner: InstallationOwner<'check, 'borrow, 'metadata, 'storage, 'role>,
}

enum InstallationOwner<'check, 'borrow, 'metadata, 'storage, 'role> {
    Native {
        loan: &'check mut RestoreWriteLoan<'borrow, 'metadata, 'storage, 'role>,
        root: &'check mut RestoreCreatorRoot,
        state: &'check mut State,
    },
    #[cfg(test)]
    Fixture(&'check mut super::tests::Schedule),
}

impl Installation<'_, '_, '_, '_, '_> {
    fn current(&mut self) -> Result<()> {
        match &mut self.owner {
            InstallationOwner::Native { loan, .. } => loan.check_current().map(|_| ()),
            #[cfg(test)]
            InstallationOwner::Fixture(schedule) => schedule.check(),
        }
    }

    fn check(&mut self) -> Result<()> {
        let pre = self.current();
        if pre.is_err() {
            self.refuse();
        }
        pre?;
        let requested = (|| {
            self.source.check()?;
            match &mut self.owner {
                InstallationOwner::Native { root, state, .. } => {
                    state.join().and_then(|()| root.check(&state.root))
                }
                #[cfg(test)]
                InstallationOwner::Fixture(_) => Ok(()),
            }
        })();
        let checked = self.current();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    fn refuse(&mut self) {
        match &mut self.owner {
            InstallationOwner::Native { loan, state, .. } => {
                state.refused = true;
                loan.refuse();
            }
            #[cfg(test)]
            InstallationOwner::Fixture(schedule) => schedule.refused = true,
        }
    }

    // Private atomic filesystem operation, never a caller-supplied effect
    // table or an SQL-unit callback. Both results are evaluated on every path.
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

fn created_directory(
    check: &mut Installation<'_, '_, '_, '_, '_>,
    parent: &File,
    name: &str,
) -> Result<File> {
    check.observe(|| {
        rustix::fs::mkdirat(parent, name, rustix::fs::Mode::from_raw_mode(0o700))?;
        directory_at(parent, name)
    })
}

fn copy_file(
    check: &mut Installation<'_, '_, '_, '_, '_>,
    source: &HeldFile,
    parent: &File,
    name: &str,
) -> Result<HeldFile> {
    let mut file = check.observe(|| {
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
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    let mut offset = 0u64;
    let mut source_hash = ring::digest::Context::new(&ring::digest::SHA256);
    loop {
        let read = check.observe(|| {
            ensure!(
                Identity::of(&source.file.metadata()?) == source.identity,
                "restore_install_source_changed"
            );
            let read = rustix::io::pread(&source.file, &mut buffer[..], offset)?;
            ensure!(
                Identity::of(&source.file.metadata()?) == source.identity,
                "restore_install_source_changed"
            );
            Ok(read)
        })?;
        if read == 0 {
            break;
        }
        offset = offset
            .checked_add(read as u64)
            .context("restore_install_length")?;
        ensure!(
            offset <= source.identity.length,
            "restore_install_source_grew"
        );
        source_hash.update(&buffer[..read]);
        check.observe(|| {
            file.write_all(&buffer[..read])?;
            Ok(())
        })?;
    }
    ensure!(
        offset == source.identity.length,
        "restore_install_source_short"
    );
    let expected = super::super::sum(source_hash)?;
    let identity = check.observe(|| {
        file.sync_all()?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.nlink() == 1
                && metadata.len() == offset
                && metadata.mode() & 0o7777 == 0o600,
            "restore_install_creator_changed"
        );
        file.seek(SeekFrom::Start(0))?;
        Ok(Identity::of(&metadata))
    })?;
    let mut copied_hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut count = 0u64;
    loop {
        let read = check.observe(|| {
            ensure!(
                Identity::of(&file.metadata()?) == identity,
                "restore_install_creator_changed"
            );
            let read = file.read(&mut buffer[..])?;
            ensure!(
                Identity::of(&file.metadata()?) == identity,
                "restore_install_creator_changed"
            );
            Ok(read)
        })?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .context("restore_install_length")?;
        ensure!(count <= offset, "restore_install_target_grew");
        copied_hash.update(&buffer[..read]);
    }
    ensure!(
        count == offset && super::super::sum(copied_hash)? == expected,
        "restore_install_bytes_changed"
    );
    check.observe(|| {
        ensure!(
            Identity::of(&file.metadata()?) == identity,
            "restore_install_creator_changed"
        );
        Ok(())
    })?;
    Ok(HeldFile { file, identity })
}

// Same filesystem body is exercised by unqualified descriptor fixtures. Only
// the actual loan-consuming method below constructs InstalledRestoreArtifact.
fn copy_tree(
    check: &mut Installation<'_, '_, '_, '_, '_>,
    parent: &File,
    target_path: &Path,
    artifact: &Digest,
) -> Result<(CapturedTree, HeldDirectory)> {
    let artifacts = created_directory(check, parent, "artifacts")?;
    let name = day2_assets::hash_part(artifact.as_str())?;
    let root = created_directory(check, &artifacts, name)?;
    let mut directories = BTreeMap::from([(PathBuf::new(), root)]);
    let names = check.source.directories.keys().cloned().collect::<Vec<_>>();
    for relative in names
        .into_iter()
        .filter(|path| !path.as_os_str().is_empty())
    {
        let parent = directories
            .get(relative.parent().context("restore_install_parent")?)
            .context("restore_install_missing_parent")?;
        let name = relative
            .file_name()
            .context("restore_install_name")?
            .to_str()
            .context("restore_install_utf8")?;
        let file = created_directory(check, parent, name)?;
        directories.insert(relative, file);
    }
    let mut files = BTreeMap::new();
    let source_tree = check.source;
    let names = source_tree.files.keys().cloned().collect::<Vec<_>>();
    for relative in names {
        // A local shared reference to this same captured source, not a getter
        // that can replace it or lend a creator to arbitrary code.
        let source = &source_tree.files[&relative];
        let parent = directories
            .get(relative.parent().context("restore_install_parent")?)
            .context("restore_install_missing_parent")?;
        let name = relative
            .file_name()
            .context("restore_install_name")?
            .to_str()
            .context("restore_install_utf8")?;
        let copied = copy_file(check, source, parent, name)?;
        files.insert(relative, copied);
    }
    // Children first, then their containing directory and the actual target.
    for directory in directories.values().rev() {
        check.observe(|| {
            directory.sync_all()?;
            Ok(())
        })?;
    }
    check.observe(|| {
        artifacts.sync_all()?;
        parent.sync_all()?;
        Ok(())
    })?;
    let identity = check.observe(|| Ok(Identity::of(&artifacts.metadata()?)))?;
    let mut count = 0;
    let actual_names = check.observe(|| entries(&artifacts, &mut count))?;
    ensure!(
        actual_names == BTreeSet::from([name.to_owned()]),
        "restore_install_extra_artifact"
    );
    let tree = check.observe(|| {
        CapturedTree::from_created(
            &target_path.join("artifacts").join(name),
            files,
            directories,
        )
    })?;
    Ok((
        tree,
        HeldDirectory {
            file: artifacts,
            identity,
            names: actual_names,
        },
    ))
}

impl CapturedRestoreArtifact<'_> {
    pub(in crate::security_epoch::restore_staging) fn require_input(
        &self,
        intent: &Intent,
    ) -> Result<()> {
        ensure!(
            self.snapshot.full_archive == intent.archive.full_archive_digest
                && self.snapshot.manifest.artifact == intent.archive.artifact.as_str()
                && self.snapshot.manifest.database == intent.archive.image.as_str(),
            "restore_install_archive_binding_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch::restore_staging) fn install(
        &self,
        loan: &mut RestoreWriteLoan<'_, '_, '_, '_>,
        root: &mut RestoreCreatorRoot,
        state: &mut State,
        intent: &Intent,
    ) -> Result<InstalledRestoreArtifact> {
        let requested: Result<InstalledRestoreArtifact> = (|| {
            loan.require_staging_input(intent, &state.input.namespace)?;
            state.join()?;
            state.input.require_intent(intent)?;
            self.require_input(intent)?;
            ensure!(
                state.complete && state.sql.is_none() && !state.writer_attempted,
                "restore_install_target_not_prepared"
            );
            root.check(&state.root)?;
            let parent = state
                .directory
                .as_ref()
                .context("restore_install_target_missing")?
                .try_clone()?;
            let path = state.target_dir()?;
            let artifact = intent.archive.artifact.clone();
            let mut check = Installation {
                source: &self.snapshot.tree,
                owner: InstallationOwner::Native {
                    loan: &mut *loan,
                    root: &mut *root,
                    state: &mut *state,
                },
            };
            let (tree, artifacts) = copy_tree(&mut check, &parent, &path, &artifact)?;
            check.check()?;
            Ok(InstalledRestoreArtifact {
                tree,
                parent,
                artifacts,
                artifact,
                refused: false,
                local: std::marker::PhantomData,
            })
        })();
        let checked = loan.check_current();
        if requested.is_err() || checked.is_err() {
            state.refused = true;
            loan.refuse();
        }
        let installed = requested?;
        checked?;
        Ok(installed)
    }
}

impl InstalledRestoreArtifact {
    pub(in crate::security_epoch::restore_staging) fn check(
        &mut self,
        state: &State,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(!self.refused, "restore_install_refused");
            state.join()?;
            let current = state
                .directory
                .as_ref()
                .context("restore_install_target_missing")?
                .metadata()?;
            let retained = self.parent.metadata()?;
            ensure!(
                current.dev() == retained.dev() && current.ino() == retained.ino(),
                "restore_install_parent_changed"
            );
            let named = directory_at(&self.parent, "artifacts")?;
            let mut count = 0;
            ensure!(
                Identity::of(&named.metadata()?) == self.artifacts.identity
                    && Identity::of(&self.artifacts.file.metadata()?) == self.artifacts.identity
                    && entries(&self.artifacts.file, &mut count)? == self.artifacts.names
                    && self.tree.root
                        == state
                            .target_dir()?
                            .join("artifacts")
                            .join(day2_assets::hash_part(self.artifact.as_str())?),
                "restore_install_directory_changed"
            );
            self.tree.check()
        })();
        if requested.is_err() {
            self.refused = true;
        }
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::restore_staging::archive::{
        Capture, SourceFile, create_cache, tests::Schedule,
    };

    // These are actual descriptor/copy outcomes, not native loan, writer or
    // keeper fixtures. Only the genuine native method constructs the latter.
    fn source() -> Result<(
        std::sync::Arc<tempfile::TempDir>,
        CapturedTree,
        Digest,
        Vec<u8>,
    )> {
        let artifact = Digest::new(b"synthetic-artifact-resource-fixture");
        let bytes = vec![37; CHUNK + 19];
        let files = BTreeMap::from([(
            PathBuf::from("nested/worker"),
            SourceFile {
                bytes: Zeroizing::new(bytes.clone()),
                mode: 0o500,
            },
        )]);
        let directories = BTreeMap::from([
            (PathBuf::from("nested"), 0o700),
            (PathBuf::from("empty"), 0o700),
        ]);
        let mut schedule = Schedule::default();
        let (root, tree) = create_cache(
            &mut Capture::Fixture(&mut schedule),
            &format!("artifacts/{}", day2_assets::hash_part(artifact.as_str())?),
            &files,
            &directories,
        )?;
        Ok((root, tree, artifact, bytes))
    }

    fn target(path: &Path) -> Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(i32::try_from(
                (rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC)
                    .bits(),
            )?)
            .open(path)?)
    }

    #[test]
    fn copied_artifact_retains_actual_creators_exact_bytes_and_empty_directories() -> Result<()> {
        let (_source_root, source, artifact, expected) = source()?;
        let directory = tempfile::tempdir()?;
        let parent = target(directory.path())?;
        let canonical = directory.path().canonicalize()?;
        let mut schedule = Schedule::default();
        let mut check = Installation {
            source: &source,
            owner: InstallationOwner::Fixture(&mut schedule),
        };
        let (tree, artifacts) = copy_tree(&mut check, &parent, &canonical, &artifact)?;
        tree.check()?;
        assert!(tree.directories.contains_key(Path::new("empty")));
        let file = &tree.files[Path::new("nested/worker")];
        assert_eq!(file.identity.mode & 0o7777, 0o600);
        assert_eq!(std::fs::read(tree.root.join("nested/worker"))?, expected);
        assert!(file.identity == Identity::of(&file.file.metadata()?));
        assert_eq!(artifacts.names.len(), 1);
        let path = tree.root.join("nested/worker");
        std::fs::rename(&path, path.with_extension("old"))?;
        std::fs::write(&path, &expected)?;
        assert!(tree.check().is_err());
        assert_ne!(file.file.metadata()?.ino(), std::fs::metadata(path)?.ino());
        Ok(())
    }

    #[test]
    fn every_copy_guard_expiry_refuses_without_publishing_a_tree_or_adopting_partial_work()
    -> Result<()> {
        let (_source_root, source, artifact, _expected) = source()?;
        let directory = tempfile::tempdir()?;
        let mut schedule = Schedule::default();
        copy_tree(
            &mut Installation {
                source: &source,
                owner: InstallationOwner::Fixture(&mut schedule),
            },
            &target(directory.path())?,
            &directory.path().canonicalize()?,
            &artifact,
        )?;
        let checks = schedule.check_count();
        assert!(checks > 10);
        for cut in 1..=checks {
            let directory = tempfile::tempdir()?;
            let mut schedule = Schedule::expire_on(cut);
            let result = copy_tree(
                &mut Installation {
                    source: &source,
                    owner: InstallationOwner::Fixture(&mut schedule),
                },
                &target(directory.path())?,
                &directory.path().canonicalize()?,
                &artifact,
            );
            assert!(result.is_err(), "cut {cut}");
            assert!(schedule.refused, "cut {cut}");
            assert!(schedule.check().is_err());
        }
        Ok(())
    }

    #[test]
    fn preexisting_or_replaced_artifact_paths_never_become_a_created_tree() -> Result<()> {
        let (_source_root, source, artifact, _expected) = source()?;
        let directory = tempfile::tempdir()?;
        std::fs::create_dir(directory.path().join("artifacts"))?;
        let sentinel = directory.path().join("artifacts/operator-owned");
        std::fs::write(&sentinel, b"unchanged")?;
        let mut schedule = Schedule::default();
        let result = copy_tree(
            &mut Installation {
                source: &source,
                owner: InstallationOwner::Fixture(&mut schedule),
            },
            &target(directory.path())?,
            &directory.path().canonicalize()?,
            &artifact,
        );
        assert!(result.is_err());
        assert!(schedule.refused);
        assert_eq!(std::fs::read(sentinel)?, b"unchanged");
        Ok(())
    }
}
