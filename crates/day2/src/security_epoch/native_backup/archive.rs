//! Canonical archive encoding of already captured historical DATA. No requester,
//! native authority, ordinary worker admission, signing or offsite publication.
use super::files::{Identity, PrivateTree, parent_at};
use super::{CopyProgress, Disposition, SnapshotImage};
use crate::{
    artifact::LoadedArtifact,
    backup_archive::{Manifest, NativeArchiveMember, native_archive_commitment},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use rustix::fs::{Mode, OFlags};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const CHUNK: usize = 64 * 1024;
const MANIFEST_LIMIT: u64 = 1024 * 1024;
const FILE_LIMIT: u64 = 64 * 1024 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const ENTRY_LIMIT: usize = 4096;
mod immutable;

#[cfg(all(test, target_os = "linux"))]
pub(super) fn immutable_fixture_cuts(
    image: &SnapshotImage,
    manifest: &Manifest,
    artifact: &LoadedArtifact,
) -> Result<()> {
    immutable::fixture_cuts(image, manifest, artifact)
}
// Two bounded byte passes plus per-member open/finish/check transitions.
const STEP_LIMIT: usize = 2
    * ((ARTIFACT_LIMIT as usize + 16 * 1024 * 1024 + MANIFEST_LIMIT as usize).div_ceil(CHUNK))
    + 6 * ENTRY_LIMIT
    + 8;

#[derive(Clone)]
enum Expected {
    Bytes(String),
    ArtifactJson(String),
}

struct ArtifactSource {
    root: File,
    path: PathBuf,
    identity: Identity,
}

impl ArtifactSource {
    fn check(&self) -> Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        ensure!(
            named.is_dir()
                && Identity::of(&named) == self.identity
                && Identity::of(&self.root.metadata()?) == self.identity,
            "backup_artifact_root_changed"
        );
        Ok(())
    }

    fn open(&self, path: &Path) -> Result<(File, Identity)> {
        self.check()?;
        let (parent, name) = parent_at(&self.root, path)?;
        let file = File::from(rustix::fs::openat(
            &parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= FILE_LIMIT,
            "backup_artifact_file_profile"
        );
        let identity = Identity::of(&metadata);
        self.check()?;
        Ok((file, identity))
    }
}

fn hash_text(value: ring::digest::Digest) -> String {
    format!(
        "sha256:{}",
        value
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn artifact_members(artifact: &LoadedArtifact) -> Result<BTreeMap<PathBuf, Expected>> {
    artifact.require_current_api()?;
    let contract = artifact.contract();
    let mut files = BTreeMap::from([
        (
            PathBuf::from("artifact.json"),
            Expected::ArtifactJson(artifact.id().into()),
        ),
        (
            PathBuf::from("worker"),
            Expected::Bytes(contract.worker_digest.clone()),
        ),
        (
            PathBuf::from("checked-types.json"),
            Expected::Bytes(contract.checked_types_digest.clone()),
        ),
        (
            PathBuf::from(crate::identity::REGISTRY_FILE),
            Expected::Bytes(
                contract
                    .sources
                    .get(&format!("app/{}", crate::identity::REGISTRY_FILE))
                    .context("backup_artifact_registry_digest")?
                    .clone(),
            ),
        ),
    ]);
    for asset in contract.assets.values() {
        files.insert(
            PathBuf::from("assets").join(format!("{}.png", day2_assets::hash_part(&asset.digest)?)),
            Expected::Bytes(asset.digest.clone()),
        );
    }
    for resource in contract.web_resources.values() {
        files.insert(
            PathBuf::from("web_resources").join(crate::web_resources::blob_name(resource)?),
            Expected::Bytes(resource.digest.clone()),
        );
    }
    for template in contract.templates.values() {
        files.insert(
            PathBuf::from("web_templates").join(crate::web_templates::blob_name(template)?),
            Expected::Bytes(template.digest.clone()),
        );
    }
    for download in contract.public_downloads.values() {
        files.insert(
            PathBuf::from(crate::public_downloads::SOURCE_DIRECTORY)
                .join(crate::public_downloads::blob_name(download)?),
            Expected::Bytes(download.digest.clone()),
        );
    }
    ensure!(
        files.keys().cloned().collect::<BTreeSet<_>>()
            == crate::backup_archive::artifact_files(artifact)?
            && files.len() <= ENTRY_LIMIT,
        "backup_artifact_members"
    );
    for expected in files.values() {
        let (Expected::Bytes(value) | Expected::ArtifactJson(value)) = expected;
        day2_assets::hash_part(value)?;
    }
    Ok(files)
}

fn scan(
    root: &File,
    relative: &Path,
    depth: usize,
    count: &mut usize,
    files: &mut BTreeSet<PathBuf>,
    dirs: &mut BTreeMap<PathBuf, (File, Identity)>,
) -> Result<()> {
    ensure!(depth <= 8, "backup_archive_depth");
    let before = Identity::of(&root.metadata()?);
    let mut names = BTreeSet::new();
    for entry in rustix::fs::Dir::read_from(root)? {
        let entry = entry?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        *count = count.checked_add(1).context("backup_archive_count")?;
        ensure!(*count <= ENTRY_LIMIT, "backup_archive_entries");
        let name = std::str::from_utf8(raw)?;
        ensure!(
            !name.is_empty()
                && name.len() <= 255
                && !name.contains(['\\', '\0'])
                && names.insert(name.to_owned()),
            "backup_archive_name"
        );
        let file = File::from(rustix::fs::openat(
            root,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let m = file.metadata()?;
        let path = relative.join(name);
        if m.is_dir() {
            scan(&file, &path, depth + 1, count, files, dirs)?;
        } else {
            ensure!(
                m.is_file() && m.nlink() == 1 && m.len() <= FILE_LIMIT,
                "backup_archive_member_kind"
            );
            files.insert(path);
        }
    }
    ensure!(
        Identity::of(&root.metadata()?) == before,
        "backup_archive_directory_changed"
    );
    ensure!(
        dirs.insert(relative.to_owned(), (root.try_clone()?, before))
            .is_none(),
        "backup_archive_duplicate_directory"
    );
    Ok(())
}

fn parents(files: impl Iterator<Item = PathBuf>) -> BTreeSet<PathBuf> {
    let mut result = BTreeSet::from([PathBuf::new()]);
    for file in files {
        let mut parent = file.parent();
        while let Some(path) = parent {
            result.insert(path.to_owned());
            if path.as_os_str().is_empty() {
                break;
            }
            parent = path.parent();
        }
    }
    result
}

enum Input {
    Bytes {
        bytes: Zeroizing<Vec<u8>>,
        position: usize,
    },
    Artifact {
        relative: PathBuf,
        expected: Expected,
    },
}

struct Member {
    path: PathBuf,
    input: Input,
}

struct Writing {
    path: PathBuf,
    target: File,
    creator: Identity,
    identity: Identity,
    input: Reading,
    hash: ring::digest::Context,
    size: u64,
}

enum Reading {
    Bytes {
        bytes: Zeroizing<Vec<u8>>,
        position: usize,
    },
    Artifact {
        relative: PathBuf,
        file: File,
        identity: Identity,
        expected: Expected,
        json: Zeroizing<Vec<u8>>,
    },
}

struct HeldFile {
    file: File,
    identity: Identity,
    digest: String,
}
struct Checking {
    path: PathBuf,
    hash: ring::digest::Context,
    size: u64,
}

pub(super) struct ArchiveWriter {
    tree: Option<PrivateTree>,
    source: ArtifactSource,
    manifest: Manifest,
    pending: VecDeque<Member>,
    writing: Option<Writing>,
    files: BTreeMap<PathBuf, HeldFile>,
    directories: BTreeSet<PathBuf>,
    checking: Option<Checking>,
    remaining_checks: VecDeque<PathBuf>,
    verifying: bool,
    artifact_bytes: u64,
    steps: usize,
    disposition: Disposition,
}

/// Historical output custody only. Its path/digests are DATA, not a native
/// source/permission, handoff witness, current epoch or restore approval.
pub(super) struct HistoricalArchive {
    tree: PrivateTree,
    files: BTreeMap<PathBuf, HeldFile>,
    directories: BTreeMap<PathBuf, (File, Identity)>,
    manifest: Manifest,
    commitment: Digest,
    refused: Cell<bool>,
}

impl ArchiveWriter {
    pub(super) fn new(
        image: SnapshotImage,
        manifest: Manifest,
        artifact: &LoadedArtifact,
    ) -> Result<Self> {
        image.verify(&manifest, artifact)?;
        let encoded = Zeroizing::new(serde_json::to_vec_pretty(&manifest)?);
        ensure!(
            encoded.len() as u64 <= MANIFEST_LIMIT,
            "backup_archive_manifest_bound"
        );
        let selected = artifact_members(artifact)?;
        let root = File::from(rustix::fs::open(
            artifact.directory(),
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NONBLOCK
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let source = ArtifactSource {
            identity: Identity::of(&root.metadata()?),
            root,
            path: artifact.directory().into(),
        };
        source.check()?;
        let mut observed = BTreeSet::new();
        let mut dirs = BTreeMap::new();
        scan(
            &source.root,
            Path::new(""),
            0,
            &mut 0,
            &mut observed,
            &mut dirs,
        )?;
        // Normal Build retains two diagnostics beside the admitted runtime
        // members. They are not runtime inputs or verification authority and
        // never enter the canonical archive. Every other extra file refuses.
        let diagnostics = BTreeSet::from([
            PathBuf::from("schema.sql"),
            PathBuf::from("verification.json"),
        ]);
        ensure!(
            observed
                .difference(&diagnostics)
                .cloned()
                .collect::<BTreeSet<_>>()
                == selected.keys().cloned().collect(),
            "backup_artifact_extra_or_missing_file"
        );
        if observed.contains(Path::new("schema.sql")) {
            let (mut file, identity) = source.open(Path::new("schema.sql"))?;
            let mut bytes = Zeroizing::new(Vec::new());
            (&mut file)
                .take(MANIFEST_LIMIT + 1)
                .read_to_end(&mut bytes)?;
            let expected = artifact.contract().schema.ddl()?.join(";\n") + ";\n";
            ensure!(
                bytes.len() as u64 <= MANIFEST_LIMIT
                    && bytes.as_slice() == expected.as_bytes()
                    && Identity::of(&file.metadata()?) == identity,
                "backup_artifact_schema_diagnostic_changed"
            );
        }
        let required = parents(selected.keys().cloned());
        let mut allowed = required.clone();
        allowed.extend(
            [
                "assets",
                "web_resources",
                "web_templates",
                crate::public_downloads::SOURCE_DIRECTORY,
            ]
            .into_iter()
            .map(PathBuf::from),
        );
        ensure!(
            required.iter().all(|p| dirs.contains_key(p))
                && dirs.keys().all(|p| allowed.contains(p)),
            "backup_artifact_extra_or_missing_directory"
        );
        let artifact_relative = PathBuf::from(manifest.artifact_relative()?);
        let mut pending = VecDeque::from([Member {
            path: "app.sqlite".into(),
            input: Input::Bytes {
                bytes: image.bytes,
                position: 0,
            },
        }]);
        for (relative, expected) in selected {
            pending.push_back(Member {
                path: artifact_relative.join(&relative),
                input: Input::Artifact { relative, expected },
            });
        }
        pending.push_back(Member {
            path: "backup.json".into(),
            input: Input::Bytes {
                bytes: encoded,
                position: 0,
            },
        });
        let directories = parents(pending.iter().map(|m| m.path.clone()));
        ensure!(
            pending.len() + directories.len() <= ENTRY_LIMIT,
            "backup_archive_entries"
        );
        let tree = PrivateTree::new()?;
        for path in directories.iter().filter(|p| !p.as_os_str().is_empty()) {
            tree.create_directory(path)?;
        }
        Ok(Self {
            tree: Some(tree),
            source,
            manifest,
            pending,
            writing: None,
            files: BTreeMap::new(),
            directories,
            checking: None,
            remaining_checks: VecDeque::new(),
            verifying: false,
            artifact_bytes: 0,
            steps: 0,
            disposition: Disposition::Copying,
        })
    }

    pub(super) fn step(&mut self) -> Result<CopyProgress> {
        let old = std::mem::replace(&mut self.disposition, Disposition::Refused);
        ensure!(
            old == Disposition::Copying && self.steps < STEP_LIMIT,
            "backup_archive_spent_or_work_bound"
        );
        self.steps += 1;
        let result = if self.verifying {
            self.check_step()
        } else {
            self.write_step()
        };
        if let Ok(progress) = &result {
            self.disposition = if *progress == CopyProgress::Complete {
                Disposition::Copied
            } else {
                Disposition::Copying
            };
        }
        result
    }

    fn write_step(&mut self) -> Result<CopyProgress> {
        let tree = self.tree.as_ref().context("backup_archive_tree_missing")?;
        tree.check()?;
        self.source.check()?;
        if self.writing.is_none() {
            let Some(member) = self.pending.pop_front() else {
                self.verifying = true;
                self.remaining_checks = self.files.keys().cloned().collect();
                return Ok(CopyProgress::More);
            };
            let input = match member.input {
                Input::Bytes { bytes, position } => Reading::Bytes { bytes, position },
                Input::Artifact { relative, expected } => {
                    let (file, identity) = self.source.open(&relative)?;
                    Reading::Artifact {
                        relative,
                        file,
                        identity,
                        expected,
                        json: Zeroizing::new(Vec::new()),
                    }
                }
            };
            let target = tree.create_file(
                &member.path,
                member.path.file_name() == Some(std::ffi::OsStr::new("worker")),
            )?;
            let identity = Identity::of(&target.metadata()?);
            self.writing = Some(Writing {
                path: member.path,
                target,
                creator: identity,
                identity,
                input,
                hash: ring::digest::Context::new(&ring::digest::SHA256),
                size: 0,
            });
            return Ok(CopyProgress::More);
        }
        let current = self
            .writing
            .as_mut()
            .context("backup_archive_writer_missing")?;
        tree.check_file(&current.path, &current.target, current.creator)?;
        ensure!(
            Identity::of(&current.target.metadata()?) == current.identity,
            "backup_archive_output_changed"
        );
        let mut buffer = Zeroizing::new([0u8; CHUNK]);
        let count = match &mut current.input {
            Reading::Bytes { bytes, position } => {
                let count = (bytes.len() - *position).min(CHUNK);
                buffer[..count].copy_from_slice(&bytes[*position..*position + count]);
                *position += count;
                count
            }
            Reading::Artifact {
                relative,
                file,
                identity,
                expected,
                json,
            } => {
                let (named, named_identity) = self.source.open(relative)?;
                drop(named);
                ensure!(
                    named_identity == *identity && Identity::of(&file.metadata()?) == *identity,
                    "backup_artifact_input_changed"
                );
                let count = file.read(&mut buffer[..])?;
                ensure!(
                    Identity::of(&file.metadata()?) == *identity,
                    "backup_artifact_input_changed"
                );
                self.artifact_bytes = self
                    .artifact_bytes
                    .checked_add(count as u64)
                    .context("backup_artifact_bound")?;
                ensure!(
                    self.artifact_bytes <= ARTIFACT_LIMIT,
                    "backup_artifact_bound"
                );
                if matches!(expected, Expected::ArtifactJson(_)) {
                    ensure!(
                        json.len() + count <= MANIFEST_LIMIT as usize,
                        "backup_artifact_metadata_bound"
                    );
                    json.extend_from_slice(&buffer[..count]);
                }
                count
            }
        };
        if count > 0 {
            current.size = current
                .size
                .checked_add(count as u64)
                .context("backup_archive_file_bound")?;
            ensure!(current.size <= FILE_LIMIT, "backup_archive_file_bound");
            current.target.write_all(&buffer[..count])?;
            current.hash.update(&buffer[..count]);
            tree.check_file(&current.path, &current.target, current.creator)?;
            current.identity = Identity::of(&current.target.metadata()?);
            return Ok(CopyProgress::More);
        }
        let mut current = self
            .writing
            .take()
            .context("backup_archive_writer_missing")?;
        let digest = hash_text(current.hash.finish());
        if let Reading::Artifact { expected, json, .. } = &current.input {
            match expected {
                Expected::Bytes(value) => {
                    ensure!(&digest == value, "backup_artifact_digest_changed")
                }
                Expected::ArtifactJson(value) => {
                    let parsed: serde_json::Value = crate::json::decode(json)
                        .map_err(|_| anyhow::anyhow!("backup_artifact_metadata"))?;
                    ensure!(
                        crate::digest(&serde_json::to_vec(&parsed)?) == *value,
                        "backup_artifact_identity_changed"
                    );
                }
            }
        }
        current.target.sync_all()?;
        ensure!(
            current.target.metadata()?.len() == current.size,
            "backup_archive_output_size"
        );
        tree.check_file(&current.path, &current.target, current.creator)?;
        current.target.seek(SeekFrom::Start(0))?;
        let identity = Identity::of(&current.target.metadata()?);
        ensure!(
            self.files
                .insert(
                    current.path,
                    HeldFile {
                        file: current.target,
                        identity,
                        digest
                    }
                )
                .is_none(),
            "backup_archive_duplicate_output"
        );
        self.source.check()?;
        Ok(CopyProgress::More)
    }

    fn check_step(&mut self) -> Result<CopyProgress> {
        let tree = self.tree.as_ref().context("backup_archive_tree_missing")?;
        if self.checking.is_none() {
            let Some(path) = self.remaining_checks.pop_front() else {
                return Ok(CopyProgress::Complete);
            };
            self.checking = Some(Checking {
                path,
                hash: ring::digest::Context::new(&ring::digest::SHA256),
                size: 0,
            });
        }
        let checking = self
            .checking
            .as_mut()
            .context("backup_archive_check_missing")?;
        let held = self
            .files
            .get_mut(&checking.path)
            .context("backup_archive_check_file_missing")?;
        tree.check_file(&checking.path, &held.file, held.identity)?;
        ensure!(
            Identity::of(&held.file.metadata()?) == held.identity,
            "backup_archive_output_changed"
        );
        let mut buffer = Zeroizing::new([0u8; CHUNK]);
        let count = held.file.read(&mut buffer[..])?;
        ensure!(
            Identity::of(&held.file.metadata()?) == held.identity,
            "backup_archive_output_changed"
        );
        checking.size = checking
            .size
            .checked_add(count as u64)
            .context("backup_archive_check_bound")?;
        ensure!(
            checking.size <= held.file.metadata()?.len() && checking.size <= FILE_LIMIT,
            "backup_archive_check_bound"
        );
        checking.hash.update(&buffer[..count]);
        if count == 0 {
            let checking = self
                .checking
                .take()
                .context("backup_archive_check_missing")?;
            ensure!(
                checking.size == held.file.metadata()?.len()
                    && hash_text(checking.hash.finish()) == held.digest,
                "backup_archive_output_digest_changed"
            );
        }
        Ok(CopyProgress::More)
    }

    pub(super) fn finish(mut self) -> Result<HistoricalArchive> {
        ensure!(
            self.disposition == Disposition::Copied,
            "backup_archive_incomplete"
        );
        let tree = self.tree.take().context("backup_archive_tree_missing")?;
        let mut names = BTreeSet::new();
        let mut directories = BTreeMap::new();
        scan(
            &tree.root,
            Path::new(""),
            0,
            &mut 0,
            &mut names,
            &mut directories,
        )?;
        ensure!(
            names == self.files.keys().cloned().collect()
                && directories.keys().cloned().collect::<BTreeSet<_>>() == self.directories,
            "backup_archive_inventory_changed"
        );
        for (path, held) in &self.files {
            tree.check_file(path, &held.file, held.identity)?;
            ensure!(
                Identity::of(&held.file.metadata()?) == held.identity,
                "backup_archive_output_changed"
            );
        }
        for (file, _) in directories.values() {
            file.sync_all()?;
        }
        let mut inventory = BTreeMap::new();
        for (path, (file, identity)) in &directories {
            ensure!(
                Identity::of(&file.metadata()?) == *identity
                    && file.metadata()?.mode() & 0o7777 == 0o700,
                "backup_archive_directory_changed"
            );
            inventory.insert(
                path.to_str().context("backup_archive_utf8")?.to_owned(),
                NativeArchiveMember::Directory { mode: 0o700 },
            );
        }
        for (path, held) in &self.files {
            let metadata = held.file.metadata()?;
            inventory.insert(
                path.to_str().context("backup_archive_utf8")?.to_owned(),
                NativeArchiveMember::File {
                    bytes: metadata.len(),
                    sha256: Digest::try_from(held.digest.clone())?,
                    mode: metadata.mode() & 0o7777,
                },
            );
        }
        let commitment = native_archive_commitment(&self.manifest, &inventory)?;
        let output = HistoricalArchive {
            tree,
            files: self.files,
            directories,
            manifest: self.manifest,
            commitment,
            refused: Cell::new(false),
        };
        output.check()?;
        Ok(output)
    }
}

impl HistoricalArchive {
    pub(super) fn directory(&self) -> &Path {
        self.tree.path()
    }
    pub(super) fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub(super) fn commitment(&self) -> &Digest {
        &self.commitment
    }

    pub(super) fn check(&self) -> Result<()> {
        ensure!(!self.refused.replace(true), "backup_archive_refused");
        self.tree.check()?;
        let mut names = BTreeSet::new();
        let mut directories = BTreeMap::new();
        scan(
            &self.tree.root,
            Path::new(""),
            0,
            &mut 0,
            &mut names,
            &mut directories,
        )?;
        ensure!(
            names == self.files.keys().cloned().collect()
                && directories.keys().eq(self.directories.keys()),
            "backup_archive_inventory_changed"
        );
        for (path, (_, identity)) in &directories {
            let (held, expected) = self
                .directories
                .get(path)
                .context("backup_archive_directory_missing")?;
            ensure!(
                expected == identity && Identity::of(&held.metadata()?) == *expected,
                "backup_archive_directory_changed"
            );
        }
        for (path, held) in &self.files {
            self.tree.check_file(path, &held.file, held.identity)?;
            ensure!(
                Identity::of(&held.file.metadata()?) == held.identity,
                "backup_archive_output_changed"
            );
            let mut file = held.file.try_clone()?;
            file.seek(SeekFrom::Start(0))?;
            let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
            let mut buffer = Zeroizing::new([0u8; CHUNK]);
            let mut bytes = 0u64;
            loop {
                let n = file.read(&mut buffer[..])?;
                if n == 0 {
                    break;
                }
                bytes = bytes
                    .checked_add(n as u64)
                    .context("backup_archive_check_bound")?;
                ensure!(
                    bytes <= FILE_LIMIT && bytes <= held.file.metadata()?.len(),
                    "backup_archive_check_bound"
                );
                hash.update(&buffer[..n]);
            }
            ensure!(
                bytes == held.file.metadata()?.len()
                    && Identity::of(&held.file.metadata()?) == held.identity
                    && hash_text(hash.finish()) == held.digest,
                "backup_archive_output_changed"
            );
        }
        self.refused.set(false);
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn refusal_cuts(
    image: &SnapshotImage,
    manifest: &Manifest,
    artifact: &LoadedArtifact,
) -> Result<()> {
    let fresh = || -> Result<ArchiveWriter> {
        ArchiveWriter::new(
            SnapshotImage {
                bytes: Zeroizing::new(image.bytes.to_vec()),
            },
            crate::json::decode(&serde_json::to_vec(manifest)?)?,
            artifact,
        )
    };
    for _ in 0..2 {
        // Partial output has no re-open/adopt path and cannot be completed.
        let partial = fresh()?;
        let path = partial.tree.as_ref().unwrap().path().to_owned();
        assert!(partial.finish().is_err());
        assert!(!path.exists());
        let mut abandoned = fresh()?;
        abandoned.step()?;
        let path = abandoned.tree.as_ref().unwrap().path().to_owned();
        drop(abandoned);
        assert!(!path.exists());
        // A physical output change is absorbing even after a repair.
        let mut changed = fresh()?;
        changed.step()?;
        let file = changed.tree.as_ref().unwrap().path().join("app.sqlite");
        std::fs::write(&file, b"changed")?;
        assert!(changed.step().is_err());
        std::fs::write(&file, b"")?;
        assert!(changed.step().is_err());
        assert!(changed.finish().is_err());
        let mut bounded = fresh()?;
        bounded.steps = STEP_LIMIT;
        assert!(bounded.step().is_err());
        bounded.steps = 0;
        assert!(bounded.step().is_err());
        assert!(bounded.finish().is_err());
        let mut extra = fresh()?;
        while extra.step()? != CopyProgress::Complete {}
        std::fs::write(
            extra.tree.as_ref().unwrap().path().join("extra"),
            b"unknown",
        )?;
        assert!(extra.finish().is_err());
        let mut spent = fresh()?;
        while spent.step()? != CopyProgress::Complete {}
        assert!(spent.step().is_err());
        assert!(spent.finish().is_err());
    }
    Ok(())
}
