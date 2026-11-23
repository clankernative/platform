//! Fixed private-directory mechanics only. These retained files do not prove
//! native admission, immutable external birth, activation or nonrollback history.
use super::{AttemptFile, CreatorData, RootBindingData, require_parent};
use crate::security_epoch::scheduled_backup::requester::RequesterPolicy;
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use rustix::fs::{AtFlags, Mode, OFlags};
use std::fs::File;

/// No path/FD/lock getter, positive reopen, activation or backup permission.
/// The actual native parent must remain live around every mechanical use.
pub(in crate::security_epoch) struct PendingRootFiles {
    parent: File,
    directory: File,
    file: File,
    parent_identity: CreatorData,
    directory_identity: CreatorData,
    file_identity: CreatorData,
    binding: RootBindingData,
    name: String,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl PendingRootFiles {
    /// Called under the fixed native creator. File ownership by itself is not
    /// permission: the whole physical/counter/lineage parent is retained outside.
    pub(in crate::security_epoch) fn create_pending(
        parent: &File,
        policy: &RequesterPolicy,
        physical_disk: Digest,
        creator_nonce: Digest,
    ) -> Result<Self> {
        policy.validate_data()?;
        let binding = RootBindingData {
            scope: policy.scope.clone(),
            cron_job_uid: policy.cron_job.uid.clone().try_into()?,
            physical_disk,
            creator_nonce,
        };
        Self::create_binding(parent, binding)
    }

    fn create_binding(parent: &File, binding: RootBindingData) -> Result<Self> {
        let name = format!("scheduled-backup-{}", &binding.key_data()?.as_str()[7..]);
        require_parent(parent)?;
        let selected_parent = CreatorData::of(&parent.metadata()?);
        // EEXIST, orphaned state or any later failure stays refused. Do not
        // remove, adopt, reset or retry a previously named root.
        rustix::fs::mkdirat(parent, name.as_str(), Mode::from_raw_mode(0o700))?;
        let directory = File::from(rustix::fs::openat(
            parent,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )?);
        require_parent(&directory)?;
        let directory_identity = CreatorData::of(&directory.metadata()?);
        ensure!(
            directory_identity.device == selected_parent.device
                && directory_identity.uid == selected_parent.uid,
            "backup_root_private_domain_changed"
        );
        let attempt = AttemptFile::create_new(&directory, binding.clone())?;
        // APFS counts regular entries in a directory's link count. Bind the
        // completed private directory after our own fixed file creation; all
        // later changes, including replacement, remain refused.
        let directory_identity = CreatorData::of(&directory.metadata()?);
        let file_identity = attempt.creator;
        // Transfer the SAME opened, locked descriptor, not a pathname reopen.
        let AttemptFile { file, .. } = attempt;
        parent.sync_all()?;
        let parent_identity = CreatorData::of(&parent.metadata()?);
        let mut root = Self {
            parent: parent.try_clone()?,
            directory,
            file,
            parent_identity,
            directory_identity,
            file_identity,
            binding,
            name,
            local: std::marker::PhantomData,
        };
        root.check_pending()?;
        Ok(root)
    }

    pub(in crate::security_epoch) fn birth_turn_data(
        &self,
        selection: &EpochStore,
    ) -> Result<super::birth::BirthTurn> {
        super::birth::BirthTurn::new_data(selection, self.binding.clone())
    }

    pub(in crate::security_epoch) fn check_pending(&mut self) -> Result<()> {
        ensure!(
            CreatorData::of(&self.parent.metadata()?) == self.parent_identity
                && CreatorData::of(&self.directory.metadata()?) == self.directory_identity
                && CreatorData::of(&self.file.metadata()?) == self.file_identity,
            "backup_root_held_changed"
        );
        let named =
            rustix::fs::statat(&self.parent, self.name.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        ensure!(
            super::number(named.st_dev)? == self.directory_identity.device
                && super::number(named.st_ino)? == self.directory_identity.inode
                && super::number(named.st_mode)? == u64::from(self.directory_identity.mode)
                && super::number(named.st_uid)? == u64::from(self.directory_identity.uid)
                && super::number(named.st_nlink)? == self.directory_identity.links,
            "backup_root_named_changed"
        );
        let mut file = AttemptFile::hold(
            &self.directory,
            self.file.try_clone()?,
            super::ImageData::new_data(self.binding.clone())?,
        )?;
        file.require_identity()?;
        file.require_image()?;
        file.require_identity()
    }
}

// Genuine concrete owner compiler controls: no serialization/getter/transfer.
const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$type as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(PendingRootFiles, Clone);
    assert_not_impl!(PendingRootFiles, Copy);
    assert_not_impl!(PendingRootFiles, Default);
    assert_not_impl!(PendingRootFiles, std::fmt::Debug);
    assert_not_impl!(PendingRootFiles, Send);
    assert_not_impl!(PendingRootFiles, Sync);
    assert_not_impl!(PendingRootFiles, serde::Serialize);
    assert_not_impl!(PendingRootFiles, serde::Deserialize<'static>);
    assert_not_impl!(PendingRootFiles, std::os::fd::AsFd);
    assert_not_impl!(PendingRootFiles, std::os::fd::AsRawFd);
    assert_not_impl!(PendingRootFiles, std::os::fd::IntoRawFd);
    assert_not_impl!(PendingRootFiles, std::ops::Deref);
    assert_not_impl!(PendingRootFiles, AsRef<std::fs::File>);
    assert_not_impl!(PendingRootFiles, std::borrow::Borrow<std::fs::File>);
};

#[cfg(test)]
mod tests {
    use super::*;
    use day2_capabilities::security_epoch::AuthorityScope;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Result<Self> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "day2-root-files-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p)?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?;
            Ok(Self(p))
        }
        fn open(&self) -> Result<File> {
            Ok(File::open(&self.0)?)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn binding() -> RootBindingData {
        RootBindingData {
            scope: AuthorityScope {
                installation: "fixture".to_owned().try_into().unwrap(),
                environment: "test".to_owned().try_into().unwrap(),
                app: "app".to_owned().try_into().unwrap(),
            },
            cron_job_uid: "00000000-0000-0000-0000-000000000001"
                .to_owned()
                .try_into()
                .unwrap(),
            physical_disk: Digest::new(b"physical fixture"),
            creator_nonce: Digest::new(b"public fixture nonce"),
        }
    }

    #[test]
    fn actual_pending_root_is_create_only_and_keeps_the_original_locked_descriptor() -> Result<()> {
        let temp = Temp::new()?;
        let parent = temp.open()?;
        let mut root = PendingRootFiles::create_binding(&parent, binding())?;
        root.check_pending()?;
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(temp.0.join(&root.name).join(super::super::FILE_NAME))?;
        assert!(matches!(
            other.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        assert!(PendingRootFiles::create_binding(&parent, binding()).is_err());
        root.check_pending()?;
        drop(root);
        // A released local descriptor does not authorize a fresh creation or
        // adoption, even when every canonical byte and root address matches.
        assert!(PendingRootFiles::create_binding(&parent, binding()).is_err());
        Ok(())
    }

    #[test]
    fn actual_pending_root_refuses_replaced_names_headers_modes_and_partial_orphans() -> Result<()>
    {
        for cut in 0..5 {
            let temp = Temp::new()?;
            let parent = temp.open()?;
            let mut root = PendingRootFiles::create_binding(&parent, binding())?;
            let dir = temp.0.join(&root.name);
            match cut {
                0 => {
                    std::fs::rename(&dir, temp.0.join("retained"))?;
                    std::fs::create_dir(&dir)?;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
                }
                1 => {
                    std::fs::rename(dir.join(super::super::FILE_NAME), dir.join("retained"))?;
                    std::fs::write(dir.join(super::super::FILE_NAME), b"replacement")?;
                }
                2 => std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?,
                3 => {
                    use std::io::Write;
                    root.file.write_all(b"partial")?;
                    root.file.sync_all()?;
                }
                _ => std::fs::set_permissions(&temp.0, std::fs::Permissions::from_mode(0o755))?,
            }
            assert!(root.check_pending().is_err(), "cut {cut}");
            assert!(PendingRootFiles::create_binding(&parent, binding()).is_err());
        }
        let temp = Temp::new()?;
        let parent = temp.open()?;
        let b = binding();
        let name = format!("scheduled-backup-{}", &b.key_data()?.as_str()[7..]);
        std::fs::create_dir(temp.0.join(&name))?;
        std::fs::set_permissions(temp.0.join(&name), std::fs::Permissions::from_mode(0o700))?;
        assert!(PendingRootFiles::create_binding(&parent, b).is_err());
        assert!(temp.0.join(name).is_dir());
        Ok(())
    }
}
