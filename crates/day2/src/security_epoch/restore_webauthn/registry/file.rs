//! Retained configuration handles and bounded fresh reads. These are FILE DATA,
//! never native admission, current administrator authority or an approval.
use anyhow::{Result, ensure};
use rustix::fs::{Mode, OFlags};
use serde::Serialize;
use std::{
    fs::File,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};
const MAX_BYTES: u64 = 1_048_576;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(super) struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    owner: u32,
    group: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
fn stamp(file: &File) -> Result<Stamp> {
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && (1..=MAX_BYTES).contains(&m.len())
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "restore_registry_config_file_refused"
    );
    Ok(Stamp {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        mode: m.mode(),
        owner: m.uid(),
        group: m.gid(),
        links: m.nlink(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}
#[derive(Clone, PartialEq, Eq, Serialize)]
struct Directory {
    device: u64,
    inode: u64,
}
fn directory(file: &File) -> Result<Directory> {
    let m = file.metadata()?;
    ensure!(m.is_dir(), "restore_registry_config_directory_refused");
    Ok(Directory {
        device: m.dev(),
        inode: m.ino(),
    })
}
fn parent_change(parents: &[File]) -> Result<(i64, i64)> {
    let m = parents.last().expect("root retained").metadata()?;
    Ok((m.ctime(), m.ctime_nsec()))
}

fn open(path: &Path) -> Result<(Vec<File>, File)> {
    ensure!(
        path.is_absolute() && path.as_os_str().as_bytes().len() <= 4096,
        "restore_registry_config_path"
    );
    let parts = path.components().collect::<Vec<_>>();
    ensure!(
        (2..=32).contains(&parts.len())
            && parts[0] == Component::RootDir
            && parts[1..].iter().all(|p| matches!(p, Component::Normal(_))),
        "restore_registry_config_path"
    );
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let mut parents = vec![File::from(rustix::fs::open(
        "/",
        flags | OFlags::DIRECTORY,
        Mode::empty(),
    )?)];
    for (i, component) in parts[1..].iter().enumerate() {
        let Component::Normal(name) = *component else {
            unreachable!()
        };
        let last = i == parts.len() - 2;
        let file = File::from(rustix::fs::openat(
            parents.last().expect("root retained"),
            name,
            if last {
                flags
            } else {
                flags | OFlags::DIRECTORY
            },
            Mode::empty(),
        )?);
        if last {
            return Ok((parents, file));
        }
        parents.push(file);
    }
    anyhow::bail!("restore_registry_config_path")
}

pub(super) struct Held {
    path: PathBuf,
    parents: Vec<File>,
    directories: Vec<Directory>,
    parent_change: (i64, i64),
    file: File,
    stamp: Stamp,
}
impl Held {
    pub(super) fn require_path(&self, path: &Path) -> Result<()> {
        ensure!(self.path == path, "restore_registry_config_path_changed");
        Ok(())
    }

    pub(super) fn open(path: &Path) -> Result<Self> {
        let (parents, file) =
            open(path).map_err(|_| anyhow::anyhow!("restore_registry_config_unavailable"))?;
        let directories = parents.iter().map(directory).collect::<Result<_>>()?;
        let parent_change = parent_change(&parents)?;
        let stamp = stamp(&file)?;
        let held = Self {
            path: path.to_owned(),
            parents,
            directories,
            parent_change,
            file,
            stamp,
        };
        held.check_local()?;
        Ok(held)
    }

    pub(super) fn binding(&self) -> Result<day2_capabilities::Digest> {
        day2_capabilities::Digest::of(&(
            "day2-restore-registry-held-file-v1",
            &self.path,
            &self.directories,
            &self.parent_change,
            &self.stamp,
        ))
    }

    pub(super) fn check_local(&self) -> Result<()> {
        let (current_parents, current) =
            open(&self.path).map_err(|_| anyhow::anyhow!("restore_registry_config_unavailable"))?;
        ensure!(
            stamp(&self.file)? == self.stamp && stamp(&current)? == self.stamp,
            "restore_registry_config_replaced_or_changed"
        );
        ensure!(
            self.parents
                .iter()
                .map(directory)
                .collect::<Result<Vec<_>>>()?
                == self.directories
                && current_parents
                    .iter()
                    .map(directory)
                    .collect::<Result<Vec<_>>>()?
                    == self.directories,
            "restore_registry_config_parent_changed"
        );
        ensure!(
            parent_change(&self.parents)? == self.parent_change
                && parent_change(&current_parents)? == self.parent_change,
            "restore_registry_config_parent_changed"
        );
        Ok(())
    }

    pub(super) fn read(&self) -> Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        self.check_local()?;
        let mut bytes = vec![0; usize::try_from(self.stamp.length)?];
        self.file.read_exact_at(&mut bytes, 0)?;
        let mut extra = [0];
        ensure!(
            self.file.read_at(&mut extra, self.stamp.length)? == 0,
            "restore_registry_config_grew"
        );
        self.check_local()?;
        Ok(bytes)
    }
}
