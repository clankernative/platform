//! Fixed controller-owned socket directory beneath the root-owned issuer path.
//! This filesystem owner grants no role, file preparation or storage authority.

use anyhow::{Result, ensure};
use rustix::fs::{Mode, OFlags, ResolveFlags, StatVfsMountFlags};
use std::{fs::File, os::unix::fs::MetadataExt};

const CHILD: &str = "storage";
const CONTROLLER: u32 = 10001;
const REFERENCE: &str = "/run/day2-native-enrollment-reference";

enum Placement {
    Provisioner,
    Controller { root: File, child: File },
}

pub(super) struct StorageSocketDirectory {
    directory: File,
    identity: (u64, u64),
    root_identity: (u64, u64),
    placement: Placement,
}

impl StorageSocketDirectory {
    /// The Controller has a read-only parent and a writable child bind mount.
    /// Resolve the actual child strictly through a second unoverlaid, read-only
    /// view of the SAME parent, then join the writable view to that descriptor.
    /// Missing or foreign references refuse; there is no unrestricted fallback.
    pub(super) fn observe(root: &File) -> Result<Self> {
        let root_identity = root_identity(root)?;
        require_read_only(root)?;
        let reference = File::from(rustix::fs::open(
            REFERENCE,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        ensure!(
            self::root_identity(&reference)? == root_identity,
            "native_enrollment_storage_reference_changed"
        );
        require_read_only(&reference)?;
        // NO_XDEV still forbids every crossing in the unoverlaid reference.
        let child = open_child(&reference)?;
        let identity = child_identity(&child)?;
        let directory = open_mounted_child(root)?;
        ensure!(
            child_identity(&directory)? == identity,
            "native_enrollment_storage_child_changed"
        );
        let owner = Self {
            directory,
            identity,
            root_identity,
            placement: Placement::Controller {
                root: reference,
                child,
            },
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
            placement: Placement::Provisioner,
        };
        owner.check(root)?;
        Ok(owner)
    }

    pub(super) fn check(&self, root: &File) -> Result<()> {
        ensure!(
            root_identity(root)? == self.root_identity
                && child_identity(&self.directory)? == self.identity,
            "native_enrollment_storage_socket_directory_changed"
        );
        match &self.placement {
            Placement::Provisioner => ensure!(
                child_identity(&open_child(root)?)? == self.identity,
                "native_enrollment_storage_socket_directory_changed"
            ),
            Placement::Controller {
                root: reference,
                child,
            } => {
                require_read_only(root)?;
                require_read_only(reference)?;
                require_writable(&self.directory)?;
                ensure!(
                    root_identity(reference)? == self.root_identity
                        && child_identity(child)? == self.identity
                        && child_identity(&open_child(reference)?)? == self.identity
                        && child_identity(&open_mounted_child(root)?)? == self.identity,
                    "native_enrollment_storage_socket_directory_changed"
                );
            }
        }
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

fn require_read_only(file: &File) -> Result<()> {
    ensure!(
        rustix::fs::fstatvfs(file)?
            .f_flag
            .contains(StatVfsMountFlags::RDONLY),
        "native_enrollment_storage_parent_writable"
    );
    Ok(())
}

fn require_writable(file: &File) -> Result<()> {
    ensure!(
        !rustix::fs::fstatvfs(file)?
            .f_flag
            .contains(StatVfsMountFlags::RDONLY),
        "native_enrollment_storage_child_readonly"
    );
    Ok(())
}

/// Only the fixed child component may cross its explicitly joined bind mount.
/// Callers must join its native identity to the strict reference before use.
fn open_mounted_child(root: &File) -> Result<File> {
    let directory = File::from(rustix::fs::openat2(
        root,
        CHILD,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?);
    require_writable(&directory)?;
    Ok(directory)
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

    fn controller_root() -> File {
        assert_eq!(rustix::process::geteuid().as_raw(), CONTROLLER);
        File::open("/run/day2-native-enrollment").unwrap()
    }

    #[test]
    #[ignore = "isolated Linux UID10001, RO parent/reference and exact RW child bind"]
    fn mounted_controller_child_joins_strict_read_only_reference() {
        let root = controller_root();
        let owner = StorageSocketDirectory::observe(&root).unwrap();
        owner.check(&root).unwrap();
    }

    #[test]
    #[ignore = "isolated Linux UID10001, foreign RW child under selected RO parent/reference"]
    fn mounted_controller_refuses_another_same_filesystem_private_child() {
        let error = StorageSocketDirectory::observe(&controller_root())
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "native_enrollment_storage_child_changed");
    }

    #[test]
    #[ignore = "isolated Linux UID10001, reference bound from a different RO parent"]
    fn mounted_controller_refuses_another_reference_parent() {
        let error = StorageSocketDirectory::observe(&controller_root())
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "native_enrollment_storage_reference_changed"
        );
    }

    #[test]
    #[ignore = "isolated Linux UID10001, parent or reference mounted writable"]
    fn mounted_controller_refuses_a_writable_parent_or_reference() {
        let error = StorageSocketDirectory::observe(&controller_root())
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "native_enrollment_storage_parent_writable"
        );
    }

    #[test]
    #[ignore = "isolated Linux UID10001, child mounted read-only under RO parent/reference"]
    fn mounted_controller_refuses_a_read_only_child_mount() {
        let error = StorageSocketDirectory::observe(&controller_root())
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "native_enrollment_storage_child_readonly"
        );
    }

    #[test]
    #[ignore = "isolated Linux UID10001, reference child has an extra nested bind mount"]
    fn mounted_controller_keeps_no_xdev_on_the_reference_child() {
        let error = StorageSocketDirectory::observe(&controller_root())
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::XDEV)
        );
    }

    #[test]
    #[ignore = "isolated Linux UID10001, no reference mount supplied"]
    fn mounted_controller_has_no_missing_reference_fallback() {
        let error = StorageSocketDirectory::observe(&controller_root())
            .err()
            .unwrap();
        assert_eq!(
            error.downcast_ref::<rustix::io::Errno>(),
            Some(&rustix::io::Errno::NOENT)
        );
    }

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
