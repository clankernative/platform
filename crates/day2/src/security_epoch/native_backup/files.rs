//! Private historical-DATA custody. No native permission or source descriptor.
use anyhow::{Context, Result, ensure};
use rustix::fs::{Mode, OFlags};
use std::{
    fs::{File, Metadata},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    uid: u32,
    links: u64,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
}

impl Identity {
    pub(super) fn of(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            size: m.len(),
            mode: m.mode(),
            uid: m.uid(),
            links: m.nlink(),
            modified: m.mtime(),
            modified_ns: m.mtime_nsec(),
            changed: m.ctime(),
            changed_ns: m.ctime_nsec(),
        }
    }

    fn same_creator(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.mode == other.mode
            && self.uid == other.uid
            && self.links == other.links
    }
}

fn number(value: impl TryInto<u64>) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("backup_identity_width"))
}

pub(super) fn directory_at(parent: &File, name: &str) -> Result<File> {
    Ok(File::from(rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

pub(super) fn parent_at(root: &File, path: &Path) -> Result<(File, String)> {
    let parts: Vec<_> = path.components().collect();
    ensure!(!parts.is_empty() && parts.len() <= 8, "backup_member_path");
    let mut lexical = std::path::PathBuf::new();
    for part in &parts {
        let Component::Normal(part) = part else {
            anyhow::bail!("backup_member_path")
        };
        lexical.push(part);
    }
    ensure!(
        lexical.as_os_str() == path.as_os_str(),
        "backup_member_alias"
    );
    let mut directory = root.try_clone()?;
    let mut name = String::new();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(part) = part else {
            anyhow::bail!("backup_member_path")
        };
        let part = part.to_str().context("backup_member_utf8")?;
        ensure!(
            !part.is_empty() && part.len() <= 255 && !part.contains(['\\', '\0']),
            "backup_member_name"
        );
        if index + 1 == parts.len() {
            name = part.to_owned();
        } else {
            directory = directory_at(&directory, part)?;
        }
    }
    Ok((directory, name))
}

/// Its pathname is only a private scratch DATA locator; it grants no app access.
pub(super) struct PrivateTree {
    directory: tempfile::TempDir,
    pub(super) root: File,
    creator: Identity,
}

impl PrivateTree {
    pub(super) fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("day2-backup-data-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let root = File::from(rustix::fs::open(
            directory.path(),
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NONBLOCK
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = root.metadata()?;
        ensure!(
            metadata.is_dir() && metadata.mode() & 0o7777 == 0o700,
            "backup_private_root_profile"
        );
        let value = Self {
            directory,
            root,
            creator: Identity::of(&metadata),
        };
        value.check()?;
        Ok(value)
    }

    pub(super) fn path(&self) -> &Path {
        self.directory.path()
    }

    pub(super) fn check(&self) -> Result<()> {
        let named = std::fs::symlink_metadata(self.directory.path())?;
        let held = self.root.metadata()?;
        // Child creation legitimately changes directory times/link count. The
        // completed archive separately pins its whole exact directory tree.
        ensure!(
            named.is_dir()
                && held.is_dir()
                && named.dev() == self.creator.device
                && named.ino() == self.creator.inode
                && held.dev() == self.creator.device
                && held.ino() == self.creator.inode
                && named.uid() == self.creator.uid
                && held.uid() == self.creator.uid
                && named.mode() & 0o7777 == 0o700
                && held.mode() & 0o7777 == 0o700,
            "backup_private_root_changed"
        );
        Ok(())
    }

    pub(super) fn create_directory(&self, path: &Path) -> Result<()> {
        self.check()?;
        let (parent, name) = parent_at(&self.root, path)?;
        rustix::fs::mkdirat(&parent, name.as_str(), Mode::from_raw_mode(0o700))?;
        let made = directory_at(&parent, &name)?;
        ensure!(
            made.metadata()?.mode() & 0o7777 == 0o700,
            "backup_directory_mode"
        );
        self.check()
    }

    pub(super) fn create_file(&self, path: &Path, executable: bool) -> Result<File> {
        self.check()?;
        let (parent, name) = parent_at(&self.root, path)?;
        let mode = if executable { 0o700 } else { 0o600 };
        let file = File::from(rustix::fs::openat(
            &parent,
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode),
        )?);
        let m = file.metadata()?;
        ensure!(
            m.is_file() && m.nlink() == 1 && m.mode() & 0o7777 == u32::from(mode),
            "backup_file_creator"
        );
        self.check()?;
        Ok(file)
    }

    pub(super) fn check_file(&self, path: &Path, file: &File, creator: Identity) -> Result<()> {
        self.check()?;
        let (parent, name) = parent_at(&self.root, path)?;
        // Never open/close a second descriptor for SQLite's database inode:
        // POSIX close can release that process's outstanding database locks.
        let named = rustix::fs::statat(
            &parent,
            name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        let a = file.metadata()?;
        ensure!(
            a.is_file()
                && a.nlink() == 1
                && creator.same_creator(&Identity::of(&a))
                && rustix::fs::FileType::from_raw_mode(named.st_mode)
                    == rustix::fs::FileType::RegularFile
                && number(named.st_dev)? == creator.device
                && number(named.st_ino)? == creator.inode
                && named.st_uid == creator.uid
                && number(named.st_nlink)? == creator.links
                && number(named.st_mode)? == u64::from(creator.mode),
            "backup_file_creator_changed"
        );
        Ok(())
    }
}
