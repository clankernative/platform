//! Actual admitted-volume fixed purpose. No bootstrap/full-durability alias.
use super::{CurrentVolumePhase, DirectoryIdentity, ProviderAuthentication, VolumeAdmission};
use crate::security_epoch::{
    native_enrollment::SameEnrolledOwner,
    scheduled_backup::journal::{PendingRootFiles, birth::BirthTurn},
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use std::fs::File;

/// Pending actual resources only. No positive settlement, recovery, source grant
/// or descriptor/stage getter exists. The outer counter/physical parent is held.
pub(in crate::security_epoch) struct PendingBackupRoot {
    files: PendingRootFiles,
    owner: SameEnrolledOwner,
    birth: Option<BirthTurn>,
    refused: bool,
}

impl PendingBackupRoot {
    /// Fixed comparison payload only. The real writer and parent must remain
    /// current; this function grants neither dispatch nor native completion.
    pub(in crate::security_epoch) fn submit_birth_data(
        &mut self,
        selection: &EpochStore,
    ) -> Result<serde_json::Value> {
        ensure!(
            !std::mem::replace(&mut self.refused, true) && self.birth.is_none(),
            "backup_root_birth_spent"
        );
        self.files.check_pending()?;
        let mut birth = self.files.birth_turn_data(selection)?;
        let body = birth.submit_data()?;
        self.birth = Some(birth);
        self.refused = false;
        Ok(body)
    }

    pub(in crate::security_epoch) fn observe_birth_data(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            !std::mem::replace(&mut self.refused, true),
            "backup_root_birth_refused"
        );
        self.birth
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("backup_root_birth_missing"))?
            .observe_data(200, bytes)?;
        self.files.check_pending()?;
        self.refused = false;
        Ok(())
    }

    /// DATA preparation only under the actual creator's retained native parent.
    pub(in crate::security_epoch) fn begin_confirmation_data(
        &mut self,
        selected: &EpochStore,
    ) -> Result<serde_json::Value> {
        ensure!(!std::mem::replace(&mut self.refused, true), "backup_root_birth_refused");
        self.files.check_pending()?;
        let body = self.birth.as_mut().ok_or_else(|| anyhow::anyhow!("backup_root_birth_missing"))?
            .begin_confirmation_data(selected)?;
        self.files.check_pending()?;
        self.refused = false;
        Ok(body)
    }

    pub(in crate::security_epoch) fn observe_confirmation_data(
        &mut self,
        selected: &EpochStore,
        bytes: &[u8],
    ) -> Result<()> {
        ensure!(!std::mem::replace(&mut self.refused, true), "backup_root_birth_refused");
        self.birth.as_mut().ok_or_else(|| anyhow::anyhow!("backup_root_birth_missing"))?
            .observe_confirmation_data(selected, 200, bytes)?;
        self.files.check_pending()?;
        self.refused = false;
        Ok(())
    }

    pub(in crate::security_epoch) fn require_confirmed_data(&self) -> Result<()> {
        ensure!(!self.refused, "backup_root_birth_refused");
        self.birth.as_ref().ok_or_else(|| anyhow::anyhow!("backup_root_birth_missing"))?
            .require_confirmed_data()
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.files.refuse();
        if let Some(birth) = &mut self.birth {
            birth.lose_data();
        }
    }
}

impl CurrentVolumePhase<'_, '_> {
    pub(in crate::security_epoch::storage_authority) fn prepare_scheduled_backup_root(
        &mut self,
        directory: &File,
        anchor: &DirectoryIdentity,
    ) -> Result<PendingBackupRoot> {
        let requested = (|| {
            ensure!(
                self.resources.admission == VolumeAdmission::Admitted
                    && matches!(
                        self.reader.authentication,
                        ProviderAuthentication::ConnectionRequest
                    ),
                "backup_root_requires_admitted_current_volume"
            );
            self.check_directory(directory, anchor)?;
            let selected = self
                .reader
                .stage
                .storage()?
                .scheduled_backup_root_selection()?;
            ensure!(
                selected.scope == self.reader.store.scope,
                "backup_root_native_scope_changed"
            );
            let owner = self.reader.stage.capture_same_owner()?;
            let disk = self.reader.profile.digest()?;
            let mut nonce = [0u8; 32];
            getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("backup_root_entropy"))?;
            self.check_directory(directory, anchor)?;
            let files =
                PendingRootFiles::create_pending(directory, &selected, disk, Digest::new(&nonce))?;
            self.check_directory(directory, anchor)?;
            Ok(PendingBackupRoot {
                files,
                owner,
                birth: None,
                refused: false,
            })
        })();
        let checked = self.resources.check_current(&mut self.reader);
        if requested.is_err() || checked.is_err() {
            self.resources.admission = VolumeAdmission::Refused;
            self.reader.acquisition.refuse();
        }
        let pending = requested?;
        checked?;
        Ok(pending)
    }

    pub(in crate::security_epoch::storage_authority) fn check_scheduled_backup_root(
        &mut self,
        directory: &File,
        anchor: &DirectoryIdentity,
        pending: &mut PendingBackupRoot,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(!pending.refused, "backup_root_birth_refused");
            self.check_directory(directory, anchor)?;
            pending.owner.check(&mut self.reader.stage)?;
            pending.files.check_pending()?;
            self.check_directory(directory, anchor)
        })();
        let checked = self.resources.check_current(&mut self.reader);
        if requested.is_err() || checked.is_err() {
            self.resources.admission = VolumeAdmission::Refused;
            self.reader.acquisition.refuse();
        }
        requested?;
        checked
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
    assert_not_impl!(PendingBackupRoot, Clone);
    assert_not_impl!(PendingBackupRoot, Copy);
    assert_not_impl!(PendingBackupRoot, Default);
    assert_not_impl!(PendingBackupRoot, std::fmt::Debug);
    assert_not_impl!(PendingBackupRoot, Send);
    assert_not_impl!(PendingBackupRoot, Sync);
    assert_not_impl!(PendingBackupRoot, serde::Serialize);
    assert_not_impl!(PendingBackupRoot, serde::Deserialize<'static>);
    assert_not_impl!(PendingBackupRoot, std::os::fd::AsFd);
    assert_not_impl!(PendingBackupRoot, std::os::fd::AsRawFd);
    assert_not_impl!(PendingBackupRoot, std::os::fd::IntoRawFd);
    assert_not_impl!(PendingBackupRoot, std::ops::Deref);
    assert_not_impl!(PendingBackupRoot, AsRef<std::fs::File>);
    assert_not_impl!(PendingBackupRoot, std::borrow::Borrow<std::fs::File>);
};
