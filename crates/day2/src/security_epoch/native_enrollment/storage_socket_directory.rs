//! Fixed controller-owned socket directory beneath the root-owned issuer path.
//! This filesystem owner grants no role, file preparation or storage authority.

use anyhow::{Result, ensure};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use std::{fs::File, os::unix::fs::MetadataExt};

const CHILD: &str = "storage";
const CONTROLLER: u32 = 10001;

pub(super) struct StorageSocketDirectory {
    directory: File,
    identity: (u64, u64),
    root_identity: (u64, u64),
}

impl StorageSocketDirectory {
    /// Observe only the provisioner's existing selected directory. A client or
    /// controller cannot create, repair or adopt an incorrectly owned child.
    pub(super) fn observe(root: &File) -> Result<Self> {
        let root_identity = root_identity(root)?;
        let directory = open_child(root)?;
        let identity = child_identity(&directory)?;
        let owner = Self {
            directory,
            identity,
            root_identity,
        };
        owner.check(root)?;
        Ok(owner)
    }

    pub(super) fn prepare(root: &File) -> Result<Self> {
        let root_identity = root_identity(root)?;
        let created = match rustix::fs::mkdirat(root, CHILD, Mode::RWXU) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(error.into()),
        };
        if created {
            // This read-capable descriptor is acquired while UID0 still owns
            // the new inode, then closed after the ownership transfer.
            let directory = open_initial_child(root)?;
            // Set the exact mode while the provisioner still owns the inode.
            // Transferring ownership needs CHOWN, not an additional FOWNER grant.
            rustix::fs::fchmod(&directory, Mode::RWXU)?;
            rustix::fs::fchown(
                &directory,
                Some(rustix::process::Uid::from_raw_unchecked(CONTROLLER)),
                Some(rustix::process::Gid::from_raw_unchecked(CONTROLLER)),
            )?;
        }
        let directory = open_child(root)?;
        let identity = child_identity(&directory)?;
        let owner = Self {
            directory,
            identity,
            root_identity,
        };
        owner.check(root)?;
        Ok(owner)
    }

    pub(super) fn check(&self, root: &File) -> Result<()> {
        ensure!(
            root_identity(root)? == self.root_identity
                && child_identity(&self.directory)? == self.identity
                && child_identity(&open_child(root)?)? == self.identity,
            "native_enrollment_storage_socket_directory_changed"
        );
        Ok(())
    }
}

fn root_identity(root: &File) -> Result<(u64, u64)> {
    let metadata = root.metadata()?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o755,
        "native_enrollment_operator_directory"
    );
    Ok((metadata.dev(), metadata.ino()))
}

fn open_child(root: &File) -> Result<File> {
    open_with(root, OFlags::PATH)
}

fn open_initial_child(root: &File) -> Result<File> {
    open_with(root, OFlags::RDONLY)
}

fn open_with(root: &File, access: OFlags) -> Result<File> {
    // After chown, UID0 without DAC_OVERRIDE cannot open this 0700 directory
    // for reading. Identity checks need only O_PATH, never directory contents.
    Ok(File::from(rustix::fs::openat2(
        root,
        CHILD,
        access | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?))
}

fn child_identity(directory: &File) -> Result<(u64, u64)> {
    let metadata = directory.metadata()?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == CONTROLLER
            && metadata.gid() == CONTROLLER
            && metadata.mode() & 0o7777 == 0o700,
        "native_enrollment_storage_socket_directory_selection"
    );
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    #[ignore = "run isolated Linux UID0 with cap-drop ALL and only CHOWN"]
    fn chown_only_provisioner_checks_existing_private_child_without_read_access() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = File::open(parent.path()).unwrap();
        let owner = StorageSocketDirectory::prepare(&root).unwrap();
        assert!(File::open(parent.path().join(CHILD)).is_err());
        owner.check(&root).unwrap();
        StorageSocketDirectory::prepare(&root)
            .unwrap()
            .check(&root)
            .unwrap();
        // Test-only cleanup/negative mutation. The production constructor never
        // repairs an existing wrong owner or opens the child's contents.
        std::os::unix::fs::chown(parent.path().join(CHILD), Some(0), Some(0)).unwrap();
        assert!(owner.check(&root).is_err());
        assert!(StorageSocketDirectory::prepare(&root).is_err());
    }

    #[test]
    #[ignore = "requires an isolated root-owned Linux filesystem; run explicitly"]
    fn root_creates_and_retains_exact_controller_socket_directory() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let root = File::open(parent.path()).unwrap();
        let owner = StorageSocketDirectory::prepare(&root).unwrap();
        owner.check(&root).unwrap();
        let metadata = std::fs::metadata(parent.path().join(CHILD)).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
            (10001, 10001, 0o700)
        );
        assert_eq!(root.metadata().unwrap().mode() & 0o7777, 0o755);
        StorageSocketDirectory::prepare(&root)
            .unwrap()
            .check(&root)
            .unwrap();

        std::fs::set_permissions(
            parent.path().join(CHILD),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(owner.check(&root).is_err());
        assert!(StorageSocketDirectory::prepare(&root).is_err());
        std::fs::set_permissions(
            parent.path().join(CHILD),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::rename(parent.path().join(CHILD), parent.path().join("original")).unwrap();
        StorageSocketDirectory::prepare(&root).unwrap();
        assert!(owner.check(&root).is_err());
    }

    #[test]
    #[ignore = "requires an isolated root-owned Linux filesystem; run explicitly"]
    fn root_refuses_unsafe_parent_symlink_and_existing_child_owner() {
        assert_eq!(rustix::process::geteuid().as_raw(), 0);
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = File::open(parent.path()).unwrap();
        assert!(StorageSocketDirectory::prepare(&root).is_err());
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), parent.path().join(CHILD)).unwrap();
        assert!(StorageSocketDirectory::prepare(&root).is_err());
        std::fs::remove_file(parent.path().join(CHILD)).unwrap();
        std::fs::create_dir(parent.path().join(CHILD)).unwrap();
        assert!(StorageSocketDirectory::prepare(&root).is_err());
        assert_eq!(
            std::fs::metadata(parent.path().join(CHILD)).unwrap().uid(),
            0
        );
    }
}
