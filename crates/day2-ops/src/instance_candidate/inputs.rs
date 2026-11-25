//! The checked source inputs of an app: the identity of every app file in a
//! forge source archive, as the earlier build tooling computed it by
//! extracting the archive and hashing the extracted files. Computed in memory
//! here, with the same refusals, so
//! the deploy job and the build host agree with each other, with the earlier
//! tooling and with the receipt app CI publishes.
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
use anyhow::{Result, anyhow, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
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

/// Each in-app file's path parts below the root, size and sha256 hex, as an
/// extraction to disk would leave them.
fn extract(archive: &[u8], directory: &str) -> Result<Files> {
    ensure!(
        crate::instance_source::directory(directory),
        "invalid source subdirectory"
    );
    let selected = parts(directory);
    let mut files = Files::new();
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
        let in_app = (selected.is_empty() || relative.starts_with(&selected)) && !controls;
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
        if !in_app || member.kind == Kind::Directory {
            return Ok(());
        }
        ensure!(
            parts.len() > 1,
            "source archive needs a repository directory"
        );
        let path = relative.to_vec();
        ensure!(
            !files.contains_key(&path) && !directories.contains(&path),
            "duplicate source archive file"
        );
        for end in 1..path.len() {
            let parent = path[..end].to_vec();
            ensure!(
                !files.contains_key(&parent),
                "source archive file below another file"
            );
            directories.insert(parent);
        }
        let mut bytes = Vec::new();
        data.take(member.size)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow!(TEXT.unreadable))?;
        ensure!(bytes.len() as u64 == member.size, TEXT.unreadable);
        let digest = day2::digest(&bytes);
        files.insert(path, (member.size, digest["sha256:".len()..].to_owned()));
        Ok(())
    })?;
    ensure!(!files.is_empty(), "source archive is empty");
    Ok(files)
}
