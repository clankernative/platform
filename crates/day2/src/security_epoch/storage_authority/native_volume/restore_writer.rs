//! Source interface for G1's actual retained physical root. The fields match
//! its owned-resource implementation; this is not a P3 or writer placeholder.
//! No accepting constructor exists in this interface-only commit.
use crate::security_epoch::{
    native_clock::NativeAcquisition, storage_authority::DirectoryIdentity,
};
use anyhow::Result;
use std::fs::File;

pub(in crate::security_epoch) struct RestoreCreatorRoot {
    volume: File,
    directory: File,
    volume_identity: DirectoryIdentity,
    directory_identity: DirectoryIdentity,
    original: NativeAcquisition,
}

impl RestoreCreatorRoot {
    /// Keep the same signature as the actual physical implementation. Until
    /// that implementation is installed, no supplied FD can pass this check.
    pub(in crate::security_epoch) fn check(&mut self, _held_root: &File) -> Result<()> {
        self.original.refuse();
        anyhow::bail!("native_restore_creator_root_check_unavailable")
    }
}

impl Drop for RestoreCreatorRoot {
    fn drop(&mut self) {
        self.original.refuse();
    }
}
