//! The checked source inputs of an app: the identity of every app file in a
//! forge source archive, as the earlier build tooling computed it by
//! extracting the archive and hashing the extracted files. Computed in memory
//! here, with the same refusals, so
//! the deploy job and the build host agree with each other, with the earlier
//! tooling and with the receipt app CI publishes. App CI unpacks the same
//! archive through the same walk ([`unpack`]), so the tree `day2 ci check`
//! reads has the source inputs deploy computes.
//!
//! - Members are read as `instance_source::read_tar` reads them (Python's
//!   tarfile, refusing the shapes it reads differently). Names are
//!   `PurePosixPath` parts below the archive's one root directory.
//! - A member is in the app when the directory is `.` or the member is the
//!   directory or lies below it; a top-level `.ci/` or `.gitea/` member never
//!   is. Every member counts against the budgets (16 MiB each, 128 MiB in all,
//!   8192 entries). Directories, regular files and links outside the app are
//!   allowed; anything else is refused.
//! - An in-app file is written where its relative path says: a second file at
//!   the same path, a file where an earlier file made a directory, or a file
//!   below an earlier file is refused.
//! - The identity is `crate::source_inputs` over the files below the app
//!   directory, the one implementation app CI uses for a source tree. Names
//!   are tarfile's (surrogateescape).
use crate::{
    instance_source::{
        ARTIFACT_LIMIT, ENTRY_LIMIT, Kind, MEMBER_LIMIT, STREAM_LIMIT, TarText, ascii, read_tar,
    },
    source_inputs::SourceFile,
};
use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

const TEXT: TarText = TarText {
    unreadable: "unreadable source archive",
    unsupported: "unsupported source archive entry",
    global: "unsupported source archive pax global header",
    budget: "source archive exceeds budget",
};

/// `sha256:<hex>` of the app's files in `archive` below `directory` (`.` or
/// `[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*`).
pub fn source_inputs(archive: &[u8], directory: &str) -> Result<String> {
    let files = extract(archive, directory)?;
    let selected = parts(directory);
    let app_roc = [selected.clone(), vec![code_points("App.roc")]].concat();
    ensure!(files.contains_key(&app_roc), "app entrypoint missing");
    let below = files
        .iter()
        .filter(|(path, _)| path.len() > selected.len() && path.starts_with(&selected))
        .map(|(path, (size, hex))| SourceFile {
            name: path[selected.len()..].join(&u32::from(b'/')),
            size: *size,
            hex: hex.clone(),
        })
        .collect();
    Ok(crate::source_inputs::digest(below))
}

fn code_points(text: &str) -> Vec<u32> {
    text.chars().map(u32::from).collect()
}

fn parts(directory: &str) -> Vec<Vec<u32>> {
    if directory == "." {
        Vec::new()
    } else {
        directory.split('/').map(code_points).collect()
    }
}

/// Each in-app file by its path parts below the root: its size and sha256 hex.
type Files = BTreeMap<Vec<Vec<u32>>, (u64, String)>;

/// One member [`walk`] accepted, below the archive's one root directory.
struct Walked<'a> {
    /// Path parts below the root; empty for the root directory itself.
    relative: &'a [Vec<u32>],
    kind: Kind,
    /// The header's mode field.
    mode: u32,
    /// A symlink's target.
    link: &'a [u8],
    /// A regular file's bytes: always for an in-app file, and for every file
    /// when the walk reads all data.
    data: Option<Vec<u8>>,
}

/// Every member of `archive` with deploy's refusals, the app being below
/// `app` (no member is in the app without one): safe paths below one root,
/// the budgets, only directories, regular files and (outside the app) links,
/// and in-app files at distinct paths, never below another file. `everything`
/// reads every regular file's bytes, not only the app's.
fn walk(
    archive: &[u8],
    app: Option<&str>,
    everything: bool,
    mut visit: impl FnMut(Walked<'_>) -> Result<()>,
) -> Result<()> {
    ensure!(
        app.is_none_or(crate::instance_source::directory),
        "invalid source subdirectory"
    );
    let selected = app.map(parts);
    let mut files: BTreeSet<Vec<Vec<u32>>> = BTreeSet::new();
    let mut directories: BTreeSet<Vec<Vec<u32>>> = BTreeSet::new();
    let mut root: Option<Vec<u32>> = None;
    let (mut total, mut entries) = (0_u64, 0_usize);
    read_tar(archive, STREAM_LIMIT, &TEXT, |member, data| {
        let parts = &member.parts;
        ensure!(
            !parts.is_empty()
                && parts[0][0] != u32::from(b'/')
                && !parts.iter().any(|part| ascii(part, "..")),
            "unsafe source archive path"
        );
        let first = root.get_or_insert_with(|| parts[0].clone());
        ensure!(*first == parts[0], "source archive has multiple roots");
        let relative = &parts[1..];
        let controls = relative
            .first()
            .is_some_and(|part| ascii(part, ".ci") || ascii(part, ".gitea"));
        let in_app = selected
            .as_ref()
            .is_some_and(|selected| selected.is_empty() || relative.starts_with(selected))
            && !controls;
        total = total.saturating_add(member.size);
        entries += 1;
        ensure!(
            member.size <= MEMBER_LIMIT && total <= ARTIFACT_LIMIT && entries <= ENTRY_LIMIT,
            TEXT.budget
        );
        ensure!(
            matches!(member.kind, Kind::Directory | Kind::Regular)
                || (member.kind == Kind::Symlink && !in_app),
            "source archive links/special files refused"
        );
        if in_app && member.kind != Kind::Directory {
            ensure!(
                parts.len() > 1,
                "source archive needs a repository directory"
            );
            let path = relative.to_vec();
            ensure!(
                !files.contains(&path) && !directories.contains(&path),
                "duplicate source archive file"
            );
            for end in 1..path.len() {
                let parent = path[..end].to_vec();
                ensure!(
                    !files.contains(&parent),
                    "source archive file below another file"
                );
                directories.insert(parent);
            }
            files.insert(path);
        }
        let read = member.kind == Kind::Regular && (in_app || everything);
        let data = if read {
            let mut bytes = Vec::new();
            data.take(member.size)
                .read_to_end(&mut bytes)
                .map_err(|_| anyhow!(TEXT.unreadable))?;
            ensure!(bytes.len() as u64 == member.size, TEXT.unreadable);
            Some(bytes)
        } else {
            None
        };
        visit(Walked {
            relative,
            kind: member.kind,
            mode: member.mode,
            link: &member.link,
            data,
        })
    })
}

/// Each in-app file's path parts below the root, size and sha256 hex, as an
/// extraction to disk would leave them.
fn extract(archive: &[u8], directory: &str) -> Result<Files> {
    let mut files = Files::new();
    // Without `everything`, only an in-app file's bytes are read.
    walk(archive, Some(directory), false, |walked| {
        if let Some(bytes) = &walked.data {
            let digest = day2::digest(bytes);
            files.insert(
                walked.relative.to_vec(),
                (bytes.len() as u64, digest["sha256:".len()..].to_owned()),
            );
        }
        Ok(())
    })?;
    ensure!(!files.is_empty(), "source archive is empty");
    Ok(files)
}

/// What [`unpack`] wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unpacked {
    pub files: u64,
    pub bytes: u64,
    pub directories: u64,
    pub links: u64,
}

/// The source tree of `archive` below its one root directory, written to the
/// new directory `destination` with the refusals [`source_inputs`] applies
/// for the app in `app`, if any, so `ci_check::source_inputs` over the written
/// app is the archive's. Beyond them, every path is written once and nothing
/// is written below a file or a link, so no entry can leave `destination`; a
/// name must be UTF-8. A regular file is 0755 when any execute bit is set and
/// 0644 otherwise, a directory 0755; a link keeps its target unresolved.
pub fn unpack(archive: &[u8], app: Option<&str>, destination: &Path) -> Result<Unpacked> {
    let mut built = fs::DirBuilder::new();
    built.mode(0o755);
    built
        .create(destination)
        .with_context(|| format!("unpack requires a new directory: {}", destination.display()))?;
    let mut written: BTreeMap<Vec<String>, Kind> = BTreeMap::new();
    let mut unpacked = Unpacked::default();
    walk(archive, app, true, |walked| {
        let path = walked
            .relative
            .iter()
            .map(|part| {
                part.iter()
                    .map(|code| char::from_u32(*code))
                    .collect::<Option<String>>()
                    .context("source archive names must be UTF-8")
            })
            .collect::<Result<Vec<String>>>()?;
        if path.is_empty() {
            ensure!(
                walked.kind == Kind::Directory,
                "source archive needs a repository directory"
            );
            return Ok(());
        }
        for end in 1..path.len() {
            match written.get(&path[..end]) {
                Some(Kind::Directory) => {}
                Some(_) => anyhow::bail!("source archive entry below a file or link"),
                None => {
                    built.create(join(destination, &path[..end]))?;
                    written.insert(path[..end].to_vec(), Kind::Directory);
                    unpacked.directories += 1;
                }
            }
        }
        let target = join(destination, &path);
        match (written.get(&path), walked.kind) {
            (Some(Kind::Directory), Kind::Directory) => return Ok(()),
            (Some(_), _) => anyhow::bail!("duplicate source archive entry"),
            (None, Kind::Directory) => {
                built.create(&target)?;
                unpacked.directories += 1;
            }
            (None, Kind::Regular) => {
                let bytes = walked.data.as_deref().context("source archive file data")?;
                let executable = walked.mode & 0o111 != 0;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(if executable { 0o755 } else { 0o644 })
                    .open(&target)?;
                file.write_all(bytes)?;
                file.sync_all()?;
                unpacked.files += 1;
                unpacked.bytes += bytes.len() as u64;
            }
            (None, Kind::Symlink) => {
                ensure!(
                    !walked.link.is_empty(),
                    "source archive link without a target"
                );
                std::os::unix::fs::symlink(OsStr::from_bytes(walked.link), &target)?;
                unpacked.links += 1;
            }
            (None, Kind::Other) => anyhow::bail!("source archive links/special files refused"),
        }
        written.insert(path, walked.kind);
        Ok(())
    })?;
    ensure!(unpacked.files > 0, "source archive is empty");
    Ok(unpacked)
}

fn join(root: &Path, parts: &[String]) -> PathBuf {
    parts
        .iter()
        .fold(root.to_path_buf(), |path, part| path.join(part))
}
