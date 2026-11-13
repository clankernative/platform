//! Installed artifact custody for the actual restored App. The ordinary
//! artifact validator is shared; neither report DATA nor a path admits one.
#[cfg(target_os = "linux")]
use super::RestoredObservationOwner;
use super::{
    ActiveRestoredReadIdentity, RestoredActiveKeeperInput, RestoredArtifactAdmission,
    RestoredKeeperInput, RestoredMaterialBorrow, RestoredObservation, RestoredReadIdentity,
};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context, ensure};
#[cfg(target_os = "linux")]
use day2_capabilities::Digest;
#[cfg(target_os = "linux")]
use rustix::fs::{AtFlags, FileType, Mode, OFlags, StatxFlags};
#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, fs::File, path::Path};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};

const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 8;
const FILE_BYTES: u64 = 64 * 1024 * 1024;
const TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

// Shape DATA only, used on the ACTUAL held inventory before any worker is
// materialized. Passing this function never creates a native owner or loan.
fn require_members(
    expected: &BTreeSet<PathBuf>,
    actual: &BTreeSet<PathBuf>,
    directories: &BTreeSet<PathBuf>,
) -> Result<()> {
    anyhow::ensure!(expected == actual, "restore_app_unhandled_artifact_member");
    let mut allowed = BTreeSet::from([
        PathBuf::new(),
        PathBuf::from("assets"),
        PathBuf::from("web_resources"),
        PathBuf::from("web_templates"),
        PathBuf::from(crate::public_downloads::SOURCE_DIRECTORY),
    ]);
    for path in actual {
        let mut parent = path.parent();
        while let Some(path) = parent {
            allowed.insert(path.to_owned());
            parent = path.parent();
        }
    }
    anyhow::ensure!(
        directories.iter().all(|path| allowed.contains(path)),
        "restore_app_unhandled_artifact_directory"
    );
    Ok(())
}

#[derive(PartialEq, Eq)]
struct Identity {
    device: (u32, u32),
    mount: u64,
    inode: u64,
    user: u32,
    group: u32,
    mode: u16,
    links: u32,
    bytes: u64,
}

struct HeldFile {
    #[cfg(target_os = "linux")]
    file: File,
    identity: Identity,
    #[cfg(target_os = "linux")]
    digest: Digest,
}
struct HeldDirectory {
    #[cfg(target_os = "linux")]
    file: File,
    identity: Identity,
    names: std::collections::BTreeSet<String>,
}

pub(super) struct InstalledArtifact {
    #[cfg(target_os = "linux")]
    artifacts: HeldDirectory,
    #[cfg(target_os = "linux")]
    directories: BTreeMap<PathBuf, HeldDirectory>,
    #[cfg(target_os = "linux")]
    files: BTreeMap<PathBuf, HeldFile>,
    #[cfg(target_os = "linux")]
    name: String,
    path: PathBuf,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

fn identity(file: &std::fs::File, name: &str, empty: bool) -> Result<Identity> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, name, empty);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mask = StatxFlags::TYPE
            | StatxFlags::MODE
            | StatxFlags::NLINK
            | StatxFlags::UID
            | StatxFlags::GID
            | StatxFlags::INO
            | StatxFlags::SIZE
            | StatxFlags::MNT_ID;
        let flags = if empty {
            AtFlags::EMPTY_PATH
        } else {
            AtFlags::SYMLINK_NOFOLLOW
        };
        let stat = rustix::fs::statx(file, name, flags, mask)?;
        ensure!(
            stat.stx_mask & mask.bits() == mask.bits() && stat.stx_ino > 0 && stat.stx_mnt_id > 0,
            "restore_app_artifact_identity_missing"
        );
        Ok(Identity {
            device: (stat.stx_dev_major, stat.stx_dev_minor),
            mount: stat.stx_mnt_id,
            inode: stat.stx_ino,
            user: stat.stx_uid,
            group: stat.stx_gid,
            mode: stat.stx_mode,
            links: stat.stx_nlink,
            bytes: stat.stx_size,
        })
    }
}

fn directory(parent: &std::fs::File, name: &str) -> Result<std::fs::File> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, name);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        Ok(File::from(rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::empty(),
        )?))
    }
}

fn entries(file: &std::fs::File, count: &mut usize) -> Result<std::collections::BTreeSet<String>> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, count);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mut names = BTreeSet::new();
        for entry in rustix::fs::Dir::read_from(file)? {
            let entry = entry?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            *count = count
                .checked_add(1)
                .context("restore_app_artifact_entry_count")?;
            ensure!(*count <= MAX_ENTRIES, "restore_app_artifact_entry_bound");
            let name = std::str::from_utf8(name)?;
            ensure!(
                !name.is_empty()
                    && name.len() <= 255
                    && !name
                        .bytes()
                        .any(|byte| matches!(byte, b'/' | b'\\' | b'\0'))
                    && names.insert(name.to_owned()),
                "restore_app_artifact_name"
            );
        }
        Ok(names)
    }
}

fn hash_file(
    owner: &mut RestoredObservation<'_>,
    file: &std::fs::File,
    expected: &Identity,
) -> Result<day2_capabilities::Digest> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (owner, file, expected);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buffer = zeroize::Zeroizing::new(vec![0; CHUNK]);
        let mut offset = 0u64;
        loop {
            owner.check()?;
            let requested = (|| {
                ensure!(
                    identity(file, "", true)? == *expected,
                    "restore_app_artifact_file_changed"
                );
                rustix::io::pread(file, &mut buffer[..], offset).map_err(anyhow::Error::from)
            })();
            let checked = owner.check();
            let read = requested?;
            checked?;
            ensure!(
                identity(file, "", true)? == *expected,
                "restore_app_artifact_file_changed"
            );
            if read == 0 {
                break;
            }
            offset = offset
                .checked_add(read as u64)
                .context("restore_app_artifact_length")?;
            ensure!(
                offset <= expected.bytes && offset <= FILE_BYTES,
                "restore_app_artifact_grew"
            );
            hash.update(&buffer[..read]);
        }
        ensure!(offset == expected.bytes, "restore_app_artifact_short");
        Digest::try_from(format!("sha256:{}", crate::hex(hash.finish().as_ref())))
    }
}

impl RestoredReadIdentity {
    /// Consume the actual post-Activated App. Artifact admission runs before
    /// keeper birth; no successful result here opens SQLite or authorizes RW.
    pub(in crate::security_epoch::native_enrollment) fn admit_installed_artifact(
        mut self,
    ) -> Result<RestoredKeeperInput> {
        let installed = InstalledArtifact::capture(&mut self)?;
        let mut guard = RestoredArtifactAdmission {
            owner: &mut self,
            installed: &installed,
            worker: None,
            completed: false,
        };
        let requested =
            crate::artifact::LoadedArtifact::load_restored_app(&installed.path, &mut guard);
        let checked = guard.check();
        if requested.is_err() || checked.is_err() {
            guard.owner.refuse();
        }
        let artifact = requested?;
        checked?;
        artifact.require_current_api()?;
        installed.require_inventory(&artifact)?;
        guard.completed = true;
        drop(guard);
        Ok(RestoredKeeperInput {
            owner: self,
            artifact,
            installed,
        })
    }
}

impl RestoredKeeperInput {
    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = (|| {
                self.installed
                    .check(&mut RestoredObservation::frozen(&mut self.owner))?;
                let target = &self.owner.owner.captured.peer.projection.selection.target;
                self.installed.require_selection(&self.artifact, target)
            })();
            let checked = self.owner.check();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
            }
            requested?;
            checked
        }
    }
}

impl RestoredActiveKeeperInput {
    pub(super) fn check_artifact(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = (|| {
                self.installed
                    .check(&mut RestoredObservation::active(&mut self.owner))?;
                self.installed.require_selection(
                    &self.artifact,
                    &self.owner.captured.peer.projection.selection.target,
                )
            })();
            let checked = self.owner.check();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
            }
            requested?;
            checked
        }
    }
}

impl<'borrow> RestoredMaterialBorrow<'borrow> {
    pub(super) fn frozen(input: &'borrow mut RestoredKeeperInput) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = input;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                owner: RestoredObservation::frozen(&mut input.owner),
                artifact: &input.artifact,
                installed: &input.installed,
            })
        }
    }

    pub(super) fn active(
        owner: &'borrow mut ActiveRestoredReadIdentity,
        artifact: &'borrow crate::artifact::LoadedArtifact,
        installed: &'borrow InstalledArtifact,
    ) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (owner, artifact, installed);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                owner: RestoredObservation::active(owner),
                artifact,
                installed,
            })
        }
    }

    pub(super) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = (|| {
                self.installed.check(&mut self.owner)?;
                let target = match &self.owner.owner {
                    RestoredObservationOwner::Frozen(owner) => {
                        &owner.owner.captured.peer.projection.selection.target
                    }
                    RestoredObservationOwner::Active(owner) => {
                        &owner.captured.peer.projection.selection.target
                    }
                };
                self.installed.require_selection(self.artifact, target)
            })();
            let checked = self.owner.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked
        }
    }

    pub(super) fn refuse(&mut self) {
        self.owner.refuse();
    }
}

impl RestoredArtifactAdmission<'_> {
    fn check(&mut self) -> Result<Duration> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = self
                .installed
                .check(&mut RestoredObservation::frozen(self.owner));
            let checked = self.owner.original.remaining();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
                self.worker.take();
            }
            requested?;
            checked
        }
    }

    /// Reject a substituted path before the shared loader performs even its
    /// first canonicalize/read. This returns no path or transferable permit.
    pub(crate) fn require_directory(&mut self, directory: &std::path::Path) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested = (|| {
                ensure!(
                    directory == self.installed.path,
                    "restore_app_artifact_loader_path_changed"
                );
                Ok(())
            })();
            self.finish(requested)
        }
    }

    pub(crate) fn start(
        &mut self,
        artifact: &crate::artifact::LoadedArtifact,
    ) -> Result<Arc<tempfile::TempPath>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = artifact;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested = (|| {
                let target = &self.owner.owner.captured.peer.projection.selection.target;
                // This binding is checked BEFORE materializing or executing
                // the worker, rather than discovering a wrong artifact later.
                ensure!(
                    artifact.id() == target.artifact.as_str()
                        && artifact.contract().schema_digest == target.schema.as_str()
                        && artifact.directory() == self.installed.path
                        && self.worker.is_none(),
                    "restore_app_artifact_binding_changed"
                );
                artifact.require_current_api()?;
                self.installed.require_inventory(artifact)?;
                let executable = self.finish(artifact.materialize_worker())?;
                let worker = self.finish(crate::worker::Worker::start(&executable))?;
                Ok((worker, executable))
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.owner.refuse();
            }
            let (worker, executable) = requested?;
            checked?;
            self.worker = Some(worker);
            Ok(executable)
        }
    }

    pub(crate) fn exchange(&mut self, query: crate::artifact::ContractQuery) -> Result<Vec<u8>> {
        let remaining = self.check()?;
        let requested = (|| {
            self.worker
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_app_artifact_worker_missing"))?
                .exchange_bounded(
                    query.bytes(),
                    crate::worker::MAX_FRAME,
                    remaining.min(Duration::from_secs(3)),
                )
        })();
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
        }
        let response = requested?;
        checked?;
        Ok(response)
    }

    fn finish<T>(&mut self, requested: Result<T>) -> Result<T> {
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.owner.refuse();
        }
        let value = requested?;
        checked?;
        Ok(value)
    }
}

impl InstalledArtifact {
    fn require_selection(
        &self,
        artifact: &crate::artifact::LoadedArtifact,
        target: &crate::security_epoch::restore_approval::TargetBinding,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (artifact, target);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            artifact.require_current_api()?;
            ensure!(
                artifact.id() == target.artifact.as_str()
                    && artifact.contract().schema_digest == target.schema.as_str()
                    && artifact.directory() == self.path,
                "restore_app_retained_artifact_changed"
            );
            Ok(())
        }
    }

    fn require_inventory(&self, artifact: &crate::artifact::LoadedArtifact) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = artifact;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            require_members(
                &crate::backup_archive::artifact_files(artifact)?,
                &self.files.keys().cloned().collect(),
                &self.directories.keys().cloned().collect(),
            )
        }
    }

    fn capture(owner: &mut RestoredReadIdentity) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = owner;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            owner.check()?;
            let requested = (|| {
                let captured = &owner.owner.captured;
                let name = day2_assets::hash_part(
                    captured.peer.projection.selection.target.artifact.as_str(),
                )?
                .to_owned();
                let component = captured.component.clone();
                let parent = identity(&captured.directory, "", true)?;
                let artifacts = directory(&captured.directory, "artifacts")?;
                let artifacts_id = identity(&artifacts, "", true)?;
                ensure!(
                    FileType::from_raw_mode(u32::from(artifacts_id.mode)) == FileType::Directory
                        && artifacts_id.mode & 0o7777 == 0o700
                        && artifacts_id.user == 10001
                        && artifacts_id.mount == parent.mount
                        && artifacts_id.device == parent.device,
                    "restore_app_artifacts_directory_profile"
                );
                let mut count = 0;
                let names = entries(&artifacts, &mut count)?;
                ensure!(
                    names == BTreeSet::from([name.clone()]),
                    "restore_app_artifact_selection_changed"
                );
                let root = directory(&artifacts, &name)?;
                let mut pending = vec![(PathBuf::new(), root)];
                let mut directories = BTreeMap::new();
                let mut files = BTreeMap::new();
                let mut total = 0u64;
                while let Some((relative, file)) = pending.pop() {
                    owner.check()?;
                    ensure!(
                        relative.components().count() <= MAX_DEPTH,
                        "restore_app_artifact_depth"
                    );
                    let stamp = identity(&file, "", true)?;
                    ensure!(
                        FileType::from_raw_mode(u32::from(stamp.mode)) == FileType::Directory
                            && stamp.mode & 0o7777 == 0o700
                            && stamp.user == 10001
                            && stamp.mount == parent.mount
                            && stamp.device == parent.device,
                        "restore_app_artifact_directory_profile"
                    );
                    let names = entries(&file, &mut count)?;
                    for name in &names {
                        owner.check()?;
                        let selected = identity(&file, name, false)?;
                        let path = relative.join(name);
                        ensure!(
                            path.components().count() <= MAX_DEPTH,
                            "restore_app_artifact_depth"
                        );
                        if FileType::from_raw_mode(u32::from(selected.mode)) == FileType::Directory
                        {
                            pending.push((path, directory(&file, name)?));
                        } else {
                            ensure!(
                                FileType::from_raw_mode(u32::from(selected.mode))
                                    == FileType::RegularFile
                                    && selected.mode & 0o7777 == 0o600
                                    && selected.user == 10001
                                    && selected.links == 1
                                    && selected.mount == parent.mount
                                    && selected.device == parent.device
                                    && selected.bytes <= FILE_BYTES,
                                "restore_app_artifact_file_profile"
                            );
                            total = total
                                .checked_add(selected.bytes)
                                .context("restore_app_artifact_total")?;
                            ensure!(total <= TOTAL_BYTES, "restore_app_artifact_total_bound");
                            let opened = File::from(rustix::fs::openat(
                                &file,
                                name.as_str(),
                                OFlags::RDONLY
                                    | OFlags::NOFOLLOW
                                    | OFlags::NONBLOCK
                                    | OFlags::CLOEXEC,
                                Mode::empty(),
                            )?);
                            ensure!(
                                identity(&opened, "", true)? == selected,
                                "restore_app_artifact_open_changed"
                            );
                            let digest = hash_file(
                                &mut RestoredObservation::frozen(owner),
                                &opened,
                                &selected,
                            )?;
                            // Keep the owning construction visible to the
                            // exact proof-factory scanner, outside macro tokens.
                            let held = HeldFile {
                                file: opened,
                                identity: selected,
                                digest,
                            };
                            ensure!(
                                files.insert(path, held).is_none(),
                                "restore_app_artifact_duplicate_file"
                            );
                        }
                    }
                    ensure!(
                        directories
                            .insert(
                                relative,
                                HeldDirectory {
                                    file,
                                    identity: stamp,
                                    names
                                }
                            )
                            .is_none(),
                        "restore_app_artifact_duplicate_directory"
                    );
                }
                ensure!(
                    files.contains_key(Path::new("artifact.json"))
                        && files.contains_key(Path::new("worker")),
                    "restore_app_artifact_material_missing"
                );
                Ok(Self {
                    artifacts: HeldDirectory {
                        file: artifacts,
                        identity: artifacts_id,
                        names,
                    },
                    directories,
                    files,
                    name,
                    path: Path::new("/state/day2-native")
                        .join(component)
                        .join("artifacts")
                        .join(day2_assets::hash_part(
                            owner
                                .owner
                                .captured
                                .peer
                                .projection
                                .selection
                                .target
                                .artifact
                                .as_str(),
                        )?),
                    local: std::marker::PhantomData,
                })
            })();
            let checked = owner.check();
            if requested.is_err() || checked.is_err() {
                owner.refuse();
            }
            let installed = requested?;
            checked?;
            installed.check(&mut RestoredObservation::frozen(owner))?;
            Ok(installed)
        }
    }

    fn check(&self, owner: &mut RestoredObservation<'_>) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = owner;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            owner.check()?;
            let requested = (|| {
                let directory = match &owner.owner {
                    RestoredObservationOwner::Frozen(owner) => &owner.owner.captured.directory,
                    RestoredObservationOwner::Active(owner) => &owner.captured.directory,
                };
                ensure!(
                    identity(directory, "artifacts", false)? == self.artifacts.identity
                        && identity(&self.artifacts.file, "", true)? == self.artifacts.identity,
                    "restore_app_artifacts_anchor_changed"
                );
                let mut count = 0;
                ensure!(
                    entries(&self.artifacts.file, &mut count)? == self.artifacts.names
                        && identity(&self.artifacts.file, &self.name, false)?
                            == self.directories[Path::new("")].identity,
                    "restore_app_artifact_root_changed"
                );
                for (relative, directory) in &self.directories {
                    owner.check()?;
                    ensure!(
                        identity(&directory.file, "", true)? == directory.identity
                            && entries(&directory.file, &mut count)? == directory.names,
                        "restore_app_artifact_directory_changed"
                    );
                    if !relative.as_os_str().is_empty() {
                        let parent = self
                            .directories
                            .get(relative.parent().context("restore_app_artifact_parent")?)
                            .context("restore_app_artifact_parent_missing")?;
                        ensure!(
                            identity(
                                &parent.file,
                                relative
                                    .file_name()
                                    .context("restore_app_artifact_name")?
                                    .to_str()
                                    .context("restore_app_artifact_utf8")?,
                                false
                            )? == directory.identity,
                            "restore_app_artifact_directory_replaced"
                        );
                    }
                }
                for (relative, file) in &self.files {
                    let parent = self
                        .directories
                        .get(relative.parent().context("restore_app_artifact_parent")?)
                        .context("restore_app_artifact_parent_missing")?;
                    ensure!(
                        identity(
                            &parent.file,
                            relative
                                .file_name()
                                .context("restore_app_artifact_name")?
                                .to_str()
                                .context("restore_app_artifact_utf8")?,
                            false
                        )? == file.identity,
                        "restore_app_artifact_file_replaced"
                    );
                    ensure!(
                        hash_file(owner, &file.file, &file.identity)? == file.digest,
                        "restore_app_artifact_bytes_changed"
                    );
                }
                Ok(())
            })();
            let checked = owner.check();
            if requested.is_err() || checked.is_err() {
                owner.refuse();
            }
            requested?;
            checked
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::{parse::Parser, visit::Visit};

    fn expression_name(expression: &syn::Expr) -> Option<String> {
        match expression {
            syn::Expr::Path(path) if path.qself.is_none() => Some(
                path.path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            ),
            syn::Expr::Field(field) => {
                let syn::Member::Named(member) = &field.member else {
                    return None;
                };
                Some(format!("{}.{}", expression_name(&field.base)?, member))
            }
            syn::Expr::MethodCall(call) if call.args.is_empty() => Some(format!(
                "{}.{}()",
                expression_name(&call.receiver)?,
                call.method
            )),
            syn::Expr::Reference(reference) => expression_name(&reference.expr),
            _ => None,
        }
    }

    fn admission_method<'a>(file: &'a mut syn::File, name: &str) -> &'a mut syn::ImplItemFn {
        file.items
            .iter_mut()
            .find_map(|item| {
                let syn::Item::Impl(implementation) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*implementation.self_ty else {
                    return None;
                };
                if path.qself.is_some()
                    || path.path.segments.len() != 1
                    || path.path.segments[0].ident != "RestoredArtifactAdmission"
                {
                    return None;
                }
                implementation.items.iter_mut().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                    _ => None,
                })
            })
            .unwrap()
    }

    fn linux_body(method: &mut syn::ImplItemFn) -> &mut syn::Block {
        method
            .block
            .stmts
            .iter_mut()
            .find_map(|statement| {
                let syn::Stmt::Expr(syn::Expr::Block(block), _) = statement else {
                    return None;
                };
                let linux = block.attrs.iter().any(|attribute| {
                    if !attribute.path().is_ident("cfg") {
                        return false;
                    }
                    matches!(attribute.parse_args::<syn::Meta>(),Ok(syn::Meta::NameValue(meta))
                    if meta.path.is_ident("target_os") && matches!(&meta.value,syn::Expr::Lit(value)
                        if matches!(&value.lit,syn::Lit::Str(value) if value.value()=="linux")))
                });
                linux.then_some(&mut block.block)
            })
            .unwrap()
    }

    fn requested_body(body: &mut syn::Block) -> &mut syn::Block {
        let syn::Stmt::Local(local) = &mut body.stmts[1] else {
            panic!("actual requested local");
        };
        let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
            panic!("actual closure call");
        };
        let syn::Expr::Paren(paren) = &mut *call.func else {
            panic!("actual closure parens");
        };
        let syn::Expr::Closure(closure) = &mut *paren.expr else {
            panic!("actual closure");
        };
        let syn::Expr::Block(block) = &mut *closure.body else {
            panic!("actual closure body");
        };
        &mut block.block
    }

    #[derive(Default)]
    struct Facts {
        events: Vec<String>,
        equalities: Vec<(String, String)>,
        unsafe_condition: bool,
        worker_empty: bool,
        actual_inventory: bool,
        renewed: bool,
    }

    impl<'ast> Visit<'ast> for Facts {
        fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
            self.unsafe_condition |= matches!(expression.op, syn::BinOp::Or(_));
            if matches!(expression.op, syn::BinOp::Eq(_))
                && let (Some(left), Some(right)) = (
                    expression_name(&expression.left),
                    expression_name(&expression.right),
                )
            {
                self.equalities.push((left, right));
            }
            syn::visit::visit_expr_binary(self, expression);
        }
        fn visit_expr_unary(&mut self, expression: &'ast syn::ExprUnary) {
            self.unsafe_condition |= matches!(expression.op, syn::UnOp::Not(_));
            syn::visit::visit_expr_unary(self, expression);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.events.push(call.method.to_string());
            self.worker_empty |= expression_name(&call.receiver).as_deref() == Some("self.worker")
                && call.method == "is_none";
            self.actual_inventory |= expression_name(&call.receiver).as_deref()
                == Some("self.installed")
                && call.method == "require_inventory"
                && call.args.len() == 1
                && expression_name(&call.args[0]).as_deref() == Some("artifact");
            self.renewed |= call.method == "narrow";
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "start")
                {
                    self.events.push("start".into());
                }
                self.renewed |= path
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "begin");
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("ensure") {
                let parser =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
                let arguments = parser.parse2(mac.tokens.clone()).unwrap();
                self.events.push("binding".into());
                let mut parsed = Facts::default();
                parsed.visit_expr(arguments.first().unwrap());
                self.events.extend(parsed.events);
                self.equalities.extend(parsed.equalities);
                self.unsafe_condition |= parsed.unsafe_condition;
                self.worker_empty |= parsed.worker_empty;
                self.actual_inventory |= parsed.actual_inventory;
                self.renewed |= parsed.renewed;
            }
            syn::visit::visit_macro(self, mac);
        }
    }

    fn worker_contract(method: &mut syn::ImplItemFn) -> bool {
        let body = linux_body(method);
        if body.stmts.len() != 8 {
            return false;
        }
        let propagated_check = matches!(&body.stmts[0],syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
            if expression_name(&tried.expr).as_deref()==Some("self.check()"));
        let independent_post = matches!(&body.stmts[2],syn::Stmt::Local(local)
            if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="checked")
                && local.init.as_ref().is_some_and(|init|expression_name(&init.expr).as_deref()==Some("self.check()")));
        let primary = matches!(&body.stmts[4],syn::Stmt::Local(local)
            if matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::Try(tried))
                if expression_name(&tried.expr).as_deref()==Some("requested")));
        let post = matches!(&body.stmts[5],syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
            if expression_name(&tried.expr).as_deref()==Some("checked"));
        let requested = requested_body(body);
        let actual_target = matches!(&requested.stmts[0],syn::Stmt::Local(local)
            if local.init.as_ref().is_some_and(|init|expression_name(&init.expr).as_deref()
                ==Some("self.owner.owner.captured.peer.projection.selection.target")));
        let mut facts = Facts::default();
        facts.visit_block(requested);
        let selected = [
            ("artifact.id()", "target.artifact.as_str()"),
            (
                "artifact.contract().schema_digest",
                "target.schema.as_str()",
            ),
            ("artifact.directory()", "self.installed.path"),
        ];
        let binding = facts.events.iter().position(|event| event == "binding");
        let materialize = facts
            .events
            .iter()
            .position(|event| event == "materialize_worker");
        let inventory = facts
            .events
            .iter()
            .position(|event| event == "require_inventory");
        let start = facts.events.iter().position(|event| event == "start");
        propagated_check
            && independent_post
            && primary
            && post
            && actual_target
            && !facts.renewed
            && !facts.unsafe_condition
            && facts.worker_empty
            && facts
                .events
                .iter()
                .filter(|event| event.as_str() == "finish")
                .count()
                == 2
            && facts.actual_inventory
            && matches!((inventory,materialize),(Some(inventory),Some(materialize)) if inventory<materialize)
            && selected.iter().all(|(left, right)| {
                facts
                    .equalities
                    .iter()
                    .any(|pair| pair.0 == *left && pair.1 == *right)
            })
            && matches!((binding,materialize,start),(Some(binding),Some(materialize),Some(start)) if binding<materialize && materialize<start)
    }

    #[test]
    fn actual_installed_worker_uses_selected_material_and_independent_original_posts() {
        let mut file = syn::parse_file(include_str!("artifact.rs")).unwrap();
        let actual = admission_method(&mut file, "start").clone();
        assert!(worker_contract(&mut actual.clone()));
        let mut no_post = actual.clone();
        linux_body(&mut no_post).stmts[2] = syn::parse_quote!(let checked: Result<()> = Ok(()););
        assert!(!worker_contract(&mut no_post));
        let mut ignored_pre = actual.clone();
        linux_body(&mut ignored_pre).stmts[0] = syn::parse_quote!(let _ = self.check(););
        assert!(!worker_contract(&mut ignored_pre));
        let mut wrong_target = actual.clone();
        requested_body(linux_body(&mut wrong_target)).stmts[0] =
            syn::parse_quote!(let target=&caller.target;);
        assert!(!worker_contract(&mut wrong_target));
        let mut no_schema = actual.clone();
        requested_body(linux_body(&mut no_schema)).stmts[1] = syn::parse_quote!(ensure!(artifact.id()==target.artifact.as_str()
            && artifact.directory()==self.installed.path && self.worker.is_none(),"missing_schema"););
        assert!(!worker_contract(&mut no_schema));
        let mut optional_binding = actual.clone();
        requested_body(linux_body(&mut optional_binding)).stmts[1] = syn::parse_quote!(ensure!(true || (artifact.id()==target.artifact.as_str()
            && artifact.contract().schema_digest==target.schema.as_str() && artifact.directory()==self.installed.path && self.worker.is_none()),"optional_binding"););
        assert!(!worker_contract(&mut optional_binding));
        let mut no_materialization_post = actual.clone();
        requested_body(linux_body(&mut no_materialization_post)).stmts[4] =
            syn::parse_quote!(let executable=artifact.materialize_worker()?;);
        assert!(!worker_contract(&mut no_materialization_post));
        let mut late = actual.clone();
        requested_body(linux_body(&mut late)).stmts.swap(1, 5);
        assert!(!worker_contract(&mut late), "binding after execution");
        let mut no_inventory = actual.clone();
        requested_body(linux_body(&mut no_inventory)).stmts[3] = syn::parse_quote!(let _ = true;);
        assert!(
            !worker_contract(&mut no_inventory),
            "extra held member cannot reach worker execution"
        );
        let mut ignored_post = actual.clone();
        linux_body(&mut ignored_post).stmts[5] = syn::parse_quote!(let _ = checked;);
        assert!(!worker_contract(&mut ignored_post));
        let mut renewed = actual.clone();
        requested_body(linux_body(&mut renewed)).stmts.insert(
            0,
            syn::parse_quote!(let _fresh=NativeAcquisition::begin(5)?;),
        );
        assert!(!worker_contract(&mut renewed));
    }

    fn finish_contract(method: &syn::ImplItemFn) -> bool {
        let statements = &method.block.stmts;
        statements.len() == 5
            && matches!(&statements[0],syn::Stmt::Local(local)
                if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="checked")
                    && local.init.as_ref().is_some_and(|init|expression_name(&init.expr).as_deref()==Some("self.check()")))
            && matches!(&statements[1],syn::Stmt::Expr(syn::Expr::If(branch),_)
                if branch.else_branch.is_none() && matches!(&*branch.cond,syn::Expr::Binary(condition)
                    if matches!(condition.op,syn::BinOp::Or(_))
                        && expression_name(&condition.left).as_deref()==Some("requested.is_err()")
                        && expression_name(&condition.right).as_deref()==Some("checked.is_err()"))
                    && branch.then_branch.stmts.len()==1
                    && matches!(&branch.then_branch.stmts[0],syn::Stmt::Expr(expression,Some(_))
                        if expression_name(expression).as_deref()==Some("self.owner.refuse()")))
            && matches!(&statements[2],syn::Stmt::Local(local)
                if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="value")
                    && matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::Try(tried))
                        if expression_name(&tried.expr).as_deref()==Some("requested")))
            && matches!(&statements[3],syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
                if expression_name(&tried.expr).as_deref()==Some("checked"))
    }

    #[test]
    fn actual_artifact_result_helper_checks_even_failed_operations_and_keeps_the_primary() {
        let mut file = syn::parse_file(include_str!("artifact.rs")).unwrap();
        let actual = admission_method(&mut file, "finish").clone();
        assert!(finish_contract(&actual));
        let mut no_post = actual.clone();
        no_post.block.stmts[0] = syn::parse_quote!(let checked: Result<()> = Ok(()););
        assert!(!finish_contract(&no_post));
        let mut early = actual.clone();
        early.block.stmts.insert(0, syn::parse_quote!(requested?;));
        assert!(!finish_contract(&early));
        let mut swapped = actual.clone();
        swapped.block.stmts.swap(2, 3);
        assert!(!finish_contract(&swapped));
        let mut ignored = actual.clone();
        ignored.block.stmts[3] = syn::parse_quote!(let _ = checked;);
        assert!(!finish_contract(&ignored));
        let mut not_refused = actual.clone();
        not_refused.block.stmts[1] = syn::parse_quote!(if false {
            self.owner.refuse();
        });
        assert!(!finish_contract(&not_refused));
    }

    #[test]
    fn exact_member_shape_refuses_extra_files_and_unhandled_directories() -> anyhow::Result<()> {
        use std::{collections::BTreeSet, path::PathBuf};
        let expected = BTreeSet::from([PathBuf::from("artifact.json"), PathBuf::from("worker")]);
        let directories = BTreeSet::from([PathBuf::new()]);
        super::require_members(&expected, &expected, &directories)?;
        let mut extra = expected.clone();
        extra.insert(PathBuf::from("unreviewed"));
        assert!(super::require_members(&expected, &extra, &directories).is_err());
        let mut unhandled = directories.clone();
        unhandled.insert(PathBuf::from("unreviewed"));
        assert!(super::require_members(&expected, &expected, &unhandled).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_anchor_controls_refuse_symlinks_and_same_bytes_on_a_replacement_inode()
    -> anyhow::Result<()> {
        use super::{directory, identity};
        use std::{
            fs,
            os::unix::fs::{OpenOptionsExt, symlink},
        };
        let temporary = tempfile::tempdir()?;
        fs::create_dir(temporary.path().join("actual"))?;
        symlink("actual", temporary.path().join("alias"))?;
        let root = fs::File::open(temporary.path())?;
        assert!(directory(&root, "alias").is_err());
        let actual = directory(&root, "actual")?;
        let path = temporary.path().join("actual/material");
        let held = fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        fs::write(&path, b"same bytes")?;
        let original = identity(&held, "", true)?;
        assert!(identity(&actual, "material", false)? == original);
        fs::remove_file(&path)?;
        fs::write(&path, b"same bytes")?;
        assert!(identity(&actual, "material", false)? != original);
        assert!(
            identity(&held, "", true)? != original,
            "unlink changes the held link count"
        );
        Ok(())
    }
}
