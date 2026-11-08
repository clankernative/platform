//! Existing authentication-ledger file admission. The fixed sibling is outside
//! the App image. No CREATE, initializer, generic path or new writer is exposed.
use super::{CurrentVolumePhase, ProviderAuthentication};
use crate::security_epoch::{native_clock::NativeAcquisition, native_enrollment::SqliteCohort};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{fs::File, path::PathBuf};

const AUTH_DIRECTORY: &str = ".day2-restore-auth";
const MAIN: &str = "approval.sqlite";
const WAL: &str = "approval.sqlite-wal";
const SHM: &str = "approval.sqlite-shm";

/// Actual pins and original; fields have no public resource/permission getter.
/// O_PATH descriptors do not close a POSIX-lock-bearing regular-file alias.
/// The actual SQLite connection must close before this owner is released.
pub(crate) struct AuthenticationStoreFiles {
    root: File,
    app: File,
    directory: File,
    authority: File,
    main: File,
    wal: Option<File>,
    shm: Option<File>,
    identities: Vec<Identity>,
    wal_identity: Option<Identity>,
    shm_identity: Option<Identity>,
    key: Digest,
    app_cohort: SqliteCohort,
    original: NativeAcquisition,
    opened: Option<OpenedCohort>,
    finished: bool,
}

// VFS observation DATA only: no constructor can make a native file owner.
#[derive(PartialEq, Eq)]
struct OpenedCohort {
    main: (i32, u64, u64),
    wal: Option<(i32, u64, u64)>,
    shm: Option<(i32, u64, u64)>,
}

impl OpenedCohort {
    fn require_continuation(&self, current: &Self) -> Result<()> {
        ensure!(
            self.main == current.main
                && self.wal.is_none_or(|held| Some(held) == current.wal)
                && self.shm.is_none_or(|held| Some(held) == current.shm),
            "restore_auth_opened_descriptor_changed"
        );
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mount: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

#[cfg(target_os = "linux")]
fn identity(file: &File, directory: bool) -> Result<Identity> {
    use rustix::fs::{AtFlags, FileType, StatxFlags};
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    let flags = StatxFlags::BASIC_STATS | StatxFlags::MNT_ID;
    let value = rustix::fs::statx(file, "", AtFlags::EMPTY_PATH, flags)?;
    ensure!(
        value.stx_mask & flags.bits() == flags.bits() && value.stx_mnt_id != 0,
        "restore_auth_file_identity_missing"
    );
    ensure!(
        FileType::from_raw_mode(metadata.mode())
            == if directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
        "restore_auth_file_type"
    );
    ensure!(
        metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }
            && (directory || metadata.nlink() == 1),
        "restore_auth_file_profile"
    );
    Ok(Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount: value.stx_mnt_id,
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

#[cfg(not(target_os = "linux"))]
fn identity(_: &File, _: bool) -> Result<Identity> {
    anyhow::bail!("restore_auth_native_platform_unsupported")
}

#[cfg(target_os = "linux")]
fn pin(parent: &File, name: &str, directory: bool) -> Result<File> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    let kind = if directory {
        OFlags::DIRECTORY
    } else {
        OFlags::empty()
    };
    let file = File::from(rustix::fs::openat2(
        parent,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW | kind,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?);
    // O_PATH|NOFOLLOW may return a final symlink descriptor. Never let
    // that kernel exception stand in for a regular/directory admission.
    identity(&file, directory)?;
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn pin(_: &File, _: &str, _: bool) -> Result<File> {
    anyhow::bail!("restore_auth_native_platform_unsupported")
}

fn optional_pin(parent: &File, name: &str) -> Result<Option<File>> {
    match pin(parent, name, false) {
        Ok(file) => Ok(Some(file)),
        Err(error)
            if error.downcast_ref::<rustix::io::Errno>() == Some(&rustix::io::Errno::NOENT) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn require_named(
    parent: &File,
    name: &str,
    held: &File,
    expected: &Identity,
    directory: bool,
) -> Result<()> {
    ensure!(
        identity(held, directory)? == *expected,
        "restore_auth_held_file_changed"
    );
    let named = pin(parent, name, directory)?;
    ensure!(
        identity(&named, directory)? == *expected,
        "restore_auth_named_file_changed"
    );
    Ok(())
}

impl CurrentVolumePhase<'_, '_> {
    pub(in crate::security_epoch::storage_authority) fn admit_authentication_store(
        &mut self,
        app: &File,
        anchor: &super::super::DirectoryIdentity,
        app_cohort: &SqliteCohort,
    ) -> Result<AuthenticationStoreFiles> {
        let result = (|| {
            self.reader.stage.require_purpose(
                crate::security_epoch::native_enrollment::StagePurpose::CurrentRole,
            )?;
            self.check_directory(app, anchor)?;
            ensure!(
                matches!(
                    self.reader.authentication,
                    ProviderAuthentication::ConnectionRequest
                ),
                "restore_auth_current_reader_required"
            );
            // Acquire actual provider material on THIS original. No warm-purpose
            // relabel, new stage, renewed clock or metadata-only profile witness.
            let provider_original = self
                .reader
                .stage
                .narrow_io_acquisition(self.reader.store.max_lease_seconds)?;
            // The retained HTTP view must meet the actual post-peer ceiling
            // BEFORE the first credential/provider read, not merely afterwards.
            meet_authentication_original(provider_original, &mut self.reader.acquisition)?;
            let material = self.reader.acquire_material()?;
            self.reader.authentication = ProviderAuthentication::Acquired(Box::new(material));
            self.check_durability_profile()?;
            self.check_directory(app, anchor)?;
            let key = self.reader.store.authority_key()?;
            let current = self
                .reader
                .stage
                .narrow_io_acquisition(self.reader.store.max_lease_seconds)?;
            let original = meet_authentication_original(current, &mut self.reader.acquisition)?;
            let root = self.resources.directory.try_clone()?;
            let app = pin(&root, super::PRIVATE_DIRECTORY, true)?;
            ensure!(
                super::super::directory_identity(&app)? == *anchor,
                "restore_auth_app_directory_changed"
            );
            let directory = pin(&app, AUTH_DIRECTORY, true)?;
            let authority = pin(&directory, key_hex(&key)?, true)?;
            let main = pin(&authority, MAIN, false)?;
            let wal = optional_pin(&authority, WAL)?;
            let shm = optional_pin(&authority, SHM)?;
            let identities = [&app, &directory, &authority, &main]
                .into_iter()
                .enumerate()
                .map(|(index, file)| identity(file, index < 3))
                .collect::<Result<Vec<_>>>()?;
            let wal_identity = wal.as_ref().map(|file| identity(file, false)).transpose()?;
            let shm_identity = shm.as_ref().map(|file| identity(file, false)).transpose()?;
            let mut files = AuthenticationStoreFiles {
                root,
                app,
                directory,
                authority,
                main,
                wal,
                shm,
                wal_identity,
                shm_identity,
                identities,
                key,
                app_cohort: app_cohort.clone(),
                original,
                opened: None,
                finished: false,
            };
            files.check()?;
            // Qualification material is not a persistent provider grant for a
            // warm SQL unit. Local resource checks retain the same real stage.
            self.reader.authentication = ProviderAuthentication::ConnectionRequest;
            self.check_directory(&files.app, anchor)?;
            Ok(files)
        })();
        if result.is_err() {
            self.resources.admission = super::VolumeAdmission::Refused;
            self.reader.acquisition.refuse();
        }
        result
    }
}

// Deadlines are per actual view. Join the post-peer stage and retained
// volume-reader ceilings, preserving their shared original and the smaller cap.
fn meet_authentication_original(
    mut current: NativeAcquisition,
    retained: &mut NativeAcquisition,
) -> Result<NativeAcquisition> {
    current.exchange_current_views(retained)?;
    Ok(current)
}

fn key_hex(key: &Digest) -> Result<&str> {
    key.as_str()
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64)
        .ok_or_else(|| anyhow::anyhow!("restore_auth_authority_shape"))
}

impl AuthenticationStoreFiles {
    // Fixed leaf DATA only. No caller path, descriptor or connection escapes.
    pub(crate) fn path(&self) -> Result<PathBuf> {
        Ok(PathBuf::from("/state/day2-native")
            .join(AUTH_DIRECTORY)
            .join(key_hex(&self.key)?)
            .join(MAIN))
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.original.remaining()?;
            ensure!(!self.finished, "restore_auth_files_closed");
            let names = [
                super::PRIVATE_DIRECTORY,
                AUTH_DIRECTORY,
                key_hex(&self.key)?,
                MAIN,
            ];
            let parents = [&self.root, &self.app, &self.directory, &self.authority];
            let held = [&self.app, &self.directory, &self.authority, &self.main];
            for index in 0..4 {
                let current = identity(held[index], index < 3)?;
                ensure!(
                    current == self.identities[index],
                    "restore_auth_held_file_changed"
                );
                require_named(
                    parents[index],
                    names[index],
                    held[index],
                    &self.identities[index],
                    index < 3,
                )?;
                ensure!(
                    current.device == self.identities[0].device
                        && current.mount == self.identities[0].mount,
                    "restore_auth_file_mount_changed"
                );
            }
            for (held, retained, name) in [
                (&self.wal, &self.wal_identity, WAL),
                (&self.shm, &self.shm_identity, SHM),
            ] {
                match (held, optional_pin(&self.authority, name)?) {
                    (Some(file), Some(named)) => {
                        let observed = identity(file, false)?;
                        ensure!(
                            Some(&observed) == retained.as_ref()
                                && identity(&named, false)? == observed,
                            "restore_auth_sidecar_changed"
                        );
                    }
                    (None, None) => (),
                    _ => anyhow::bail!("restore_auth_sidecar_changed"),
                }
            }
            ensure!(
                optional_pin(&self.authority, "approval.sqlite-journal")?.is_none(),
                "restore_auth_rollback_journal_refused"
            );
            self.original.remaining()?;
            Ok(())
        })();
        if result.is_err() {
            self.original.refuse();
        }
        result
    }

    pub(crate) fn capture_cohort(&mut self) -> Result<()> {
        // Only lazy absence may become an actual pinned sidecar during SQLite
        // activation. An existing member is never replaced or adopted.
        for (held, retained, name) in [
            (&mut self.wal, &mut self.wal_identity, WAL),
            (&mut self.shm, &mut self.shm_identity, SHM),
        ] {
            if held.is_none() {
                let file = pin(&self.authority, name, false)?;
                *retained = Some(identity(&file, false)?);
                *held = Some(file);
            }
        }
        self.check()
    }

    pub(crate) fn require_opened(
        &mut self,
        main: (i32, u64, u64),
        wal: Option<(i32, u64, u64)>,
        shm: Option<(i32, u64, u64)>,
        complete: bool,
    ) -> Result<()> {
        self.check()?;
        let current = OpenedCohort { main, wal, shm };
        if let Some(previous) = &self.opened {
            previous.require_continuation(&current)?;
        }
        let actual = [
            &self.main,
            self.wal.as_ref().unwrap_or(&self.main),
            self.shm.as_ref().unwrap_or(&self.main),
        ];
        for (index, observed) in [Some(main), wal, shm].into_iter().enumerate() {
            if let Some(observed) = observed {
                let held = identity(actual[index], false)?;
                ensure!(
                    observed.0 >= 0 && (observed.1, observed.2) == (held.device, held.inode),
                    "restore_auth_sqlite_opened_foreign_file"
                );
            }
        }
        ensure!(
            !complete
                || (wal.is_some() && shm.is_some() && self.wal.is_some() && self.shm.is_some()),
            "restore_auth_complete_cohort_required"
        );
        self.app_cohort.require_disjoint_members(
            (main.1, main.2),
            wal.map(|f| (f.1, f.2)),
            shm.map(|f| (f.1, f.2)),
        )?;
        self.check()?;
        self.opened = Some(current);
        Ok(())
    }

    pub(crate) fn finish_checked(mut self) -> Result<()> {
        self.check()?;
        self.finished = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        self.original.refuse();
    }
}

impl Drop for AuthenticationStoreFiles {
    fn drop(&mut self) {
        if !self.finished {
            self.original.refuse();
        }
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(AuthenticationStoreFiles, Clone);
    assert_not_impl!(AuthenticationStoreFiles, Copy);
    assert_not_impl!(AuthenticationStoreFiles, Default);
    assert_not_impl!(AuthenticationStoreFiles, std::fmt::Debug);
    assert_not_impl!(AuthenticationStoreFiles, Send);
    assert_not_impl!(AuthenticationStoreFiles, Sync);
    assert_not_impl!(AuthenticationStoreFiles, serde::Serialize);
    assert_not_impl!(AuthenticationStoreFiles, serde::Deserialize<'static>);
    assert_not_impl!(super::RestoreCreatorRoot, Clone);
    assert_not_impl!(super::RestoreCreatorRoot, Copy);
    assert_not_impl!(super::RestoreCreatorRoot, Default);
    assert_not_impl!(super::RestoreCreatorRoot, std::fmt::Debug);
    assert_not_impl!(super::RestoreCreatorRoot, Send);
    assert_not_impl!(super::RestoreCreatorRoot, Sync);
    assert_not_impl!(super::RestoreCreatorRoot, serde::Serialize);
    assert_not_impl!(super::RestoreCreatorRoot, serde::Deserialize<'static>);
    assert_not_impl!(super::RestoreCreatorRoot, std::ops::Deref);
    assert_not_impl!(super::RestoreCreatorRoot, AsRef<File>);
    assert_not_impl!(super::RestoreCreatorRoot, std::borrow::Borrow<File>);
};

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn held_path_pin_refuses_named_replacement_and_keeps_old_inode_alive() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let parent = File::open(temporary.path())?;
        let path = temporary.path().join(MAIN);
        std::fs::write(&path, b"original")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let held = pin(&parent, MAIN, false)?;
        let expected = identity(&held, false)?;
        require_named(&parent, MAIN, &held, &expected, false)?;
        let saved = temporary.path().join("saved");
        std::fs::rename(&path, &saved)?;
        std::fs::write(&path, b"replacement")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(require_named(&parent, MAIN, &held, &expected, false).is_err());
        std::fs::remove_file(&path)?;
        std::fs::rename(&saved, &path)?;
        require_named(&parent, MAIN, &held, &expected, false)?;
        std::fs::remove_file(&path)?;
        assert!(
            identity(&held, false).is_err(),
            "unlink changes retained nlink even while inode is pinned"
        );
        Ok(())
    }

    #[test]
    fn fixed_path_pin_refuses_symlinks_foreign_modes_and_hardlink_aliases() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let parent = File::open(temporary.path())?;
        let main = temporary.path().join(MAIN);
        std::fs::write(&main, b"original")?;
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::symlink(MAIN, temporary.path().join("linked"))?;
        assert!(pin(&parent, "linked", false).is_err());
        let held = pin(&parent, MAIN, false)?;
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o644))?;
        assert!(identity(&held, false).is_err());
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o600))?;
        identity(&held, false)?;
        std::fs::hard_link(&main, temporary.path().join("alias"))?;
        assert!(identity(&held, false).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;

    // Actual VFS observation DATA for the comparison control only. No native
    // File/Stage/Action is constructed by a temporary SQLite fixture.
    fn sqlite_observation(db: &rusqlite::Connection) -> Result<OpenedCohort> {
        let _: i64 = db.query_row("SELECT count(*) FROM main.sqlite_schema", [], |row| {
            row.get(0)
        })?;
        let text: String =
            db.query_row("SELECT substr(sqlite_filestat('main'),1,8193)", [], |row| {
                row.get(0)
            })?;
        let value: serde_json::Value = crate::json::decode(text.as_bytes())?;
        fn member(value: &serde_json::Value) -> Result<(i32, u64, u64)> {
            Ok((
                i32::try_from(
                    value["h"]
                        .as_i64()
                        .ok_or_else(|| anyhow::anyhow!("fixture_fd"))?,
                )?,
                value["identity"]["device"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("fixture_device"))?,
                value["identity"]["inode"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("fixture_inode"))?,
            ))
        }
        Ok(OpenedCohort {
            main: member(&value["db"])?,
            wal: value.get("journal").map(member).transpose()?,
            shm: value["db"].get("shm").map(member).transpose()?,
        })
    }

    #[test]
    fn actual_sqlite_fd_replacement_and_restored_named_path_never_replace_the_observed_connection()
    -> Result<()> {
        use rusqlite::{Connection, OpenFlags};
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let path = root.join("auth.sqlite");
        let original = Connection::open(&path)?;
        original.pragma_update(None, "journal_mode", "WAL")?;
        original.execute_batch("CREATE TABLE fixture(value INTEGER)")?;
        let expected = sqlite_observation(&original)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let other = Connection::open_with_flags(&path, flags)?;
        let same_file = sqlite_observation(&other)?;
        assert_eq!(
            (expected.main.1, expected.main.2),
            (same_file.main.1, same_file.main.2)
        );
        assert_ne!(expected.main.0, same_file.main.0);
        assert!(expected.require_continuation(&same_file).is_err());
        drop(other);
        let aba_path = root.join("aba.sqlite");
        let aba_original = Connection::open(&aba_path)?;
        aba_original.execute_batch("CREATE TABLE fixture(value INTEGER)")?;
        let expected_aba = sqlite_observation(&aba_original)?;
        let foreign_path = root.join("foreign.sqlite");
        let foreign = Connection::open(&foreign_path)?;
        foreign.execute_batch("CREATE TABLE fixture(value INTEGER)")?;
        // Keep both genuine fixture connections alive while the fixed name is
        // exchanged. Opening an alias is not evidence for the original owner.
        let saved = root.join("saved.sqlite");
        std::fs::rename(&aba_path, &saved)?;
        std::fs::rename(&foreign_path, &aba_path)?;
        let replaced = Connection::open_with_flags(&aba_path, flags)?;
        let observed = sqlite_observation(&replaced)?;
        std::fs::rename(&aba_path, &foreign_path)?;
        std::fs::rename(&saved, &aba_path)?;
        assert_ne!(
            (expected_aba.main.1, expected_aba.main.2),
            (observed.main.1, observed.main.2)
        );
        assert!(expected_aba.require_continuation(&observed).is_err());
        expected_aba.require_continuation(&sqlite_observation(&aba_original)?)?;
        expected.require_continuation(&sqlite_observation(&original)?)?;
        Ok(())
    }

    #[test]
    fn actual_stage_cap_meets_reader_before_provider_io_and_again_before_file_admission() {
        use quote::ToTokens;
        fn wired(source: &str) -> bool {
            let Ok(file) = syn::parse_file(source) else {
                return false;
            };
            let Some(admit) = file.items.iter().find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if !item
                    .self_ty
                    .to_token_stream()
                    .to_string()
                    .starts_with("CurrentVolumePhase")
                {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(function)
                        if function.sig.ident == "admit_authentication_store" =>
                    {
                        Some(function)
                    }
                    _ => None,
                })
            }) else {
                return false;
            };
            let text = admit.block.to_token_stream().to_string();
            let required = [
                "let provider_original = self . reader . stage . narrow_io_acquisition (self . reader . store . max_lease_seconds) ? ;",
                "meet_authentication_original (provider_original , & mut self . reader . acquisition) ? ;",
                "let material = self . reader . acquire_material () ? ;",
                "self . check_durability_profile () ? ;",
                "let current = self . reader . stage . narrow_io_acquisition (self . reader . store . max_lease_seconds) ? ;",
                "let original = meet_authentication_original (current , & mut self . reader . acquisition) ? ;",
                "let root = self . resources . directory . try_clone () ? ;",
            ];
            let mut previous = None;
            for target in required {
                let Some(index) = text.find(target) else {
                    return false;
                };
                if previous.is_some_and(|last| last >= index) {
                    return false;
                }
                previous = Some(index);
            }
            let Some(helper) = file.items.iter().find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "meet_authentication_original" => {
                    Some(item)
                }
                _ => None,
            }) else {
                return false;
            };
            let expected: syn::Block = syn::parse_quote!({
                current.exchange_current_views(retained)?;
                Ok(current)
            });
            text.matches("meet_authentication_original").count() == 2
                && helper.block.to_token_stream().to_string()
                    == expected.to_token_stream().to_string()
        }
        let source = include_str!("authentication_store.rs");
        assert!(wired(source));
        let normalized = syn::parse_file(source)
            .unwrap()
            .to_token_stream()
            .to_string();
        let before = "meet_authentication_original (provider_original , & mut self . reader . acquisition) ? ;";
        let acquire = "let material = self . reader . acquire_material () ? ;";
        let removed = normalized.replacen(before, "", 1);
        assert_ne!(removed, normalized);
        assert!(!wired(&removed));
        let ordered = format!("{before} {acquire}");
        let reordered = normalized.replacen(&ordered, &format!("{acquire} {before}"), 1);
        assert_ne!(reordered, normalized, "mutate actual pre-provider ordering");
        assert!(!wired(&reordered));
        let skipped_meet =
            normalized.replacen("current . exchange_current_views (retained) ? ;", "", 1);
        assert_ne!(skipped_meet, normalized);
        assert!(!wired(&skipped_meet));
    }

    #[test]
    fn auth_files_meet_both_actual_clock_views_without_discarding_an_earlier_cap() -> Result<()> {
        use std::time::Duration;
        for (stage_cap, reader_cap) in [(1, 5), (5, 1), (2, 3)] {
            let origin = Duration::from_secs(100);
            let mut original = NativeAcquisition::fixture(
                Digest::new(b"auth-original"),
                std::process::id(),
                origin,
                Duration::from_secs(5),
            );
            let current = original.narrow(5, origin + Duration::from_secs(stage_cap))?;
            let mut retained = original.narrow(5, origin + Duration::from_secs(reader_cap))?;
            let mut joined = meet_authentication_original(current, &mut retained)?;
            let expected = Duration::from_secs(stage_cap.min(reader_cap));
            assert_eq!(joined.remaining()?, expected);
            assert_eq!(retained.remaining()?, expected);
            joined.refuse();
            assert!(retained.remaining().is_err());
            assert!(original.remaining().is_err());
        }
        Ok(())
    }

    #[test]
    fn opened_cohort_keeps_every_actual_descriptor_even_for_same_file_identity() -> Result<()> {
        let actual = OpenedCohort {
            main: (10, 9, 20),
            wal: Some((11, 9, 21)),
            shm: Some((12, 9, 22)),
        };
        actual.require_continuation(&actual)?;
        for changed in [
            OpenedCohort {
                main: (13, 9, 20),
                wal: actual.wal,
                shm: actual.shm,
            },
            OpenedCohort {
                main: actual.main,
                wal: Some((13, 9, 21)),
                shm: actual.shm,
            },
            OpenedCohort {
                main: actual.main,
                wal: actual.wal,
                shm: Some((13, 9, 22)),
            },
            OpenedCohort {
                main: actual.main,
                wal: None,
                shm: actual.shm,
            },
            OpenedCohort {
                main: actual.main,
                wal: actual.wal,
                shm: None,
            },
            OpenedCohort {
                main: (10, 19, 20),
                wal: actual.wal,
                shm: actual.shm,
            },
        ] {
            assert!(actual.require_continuation(&changed).is_err());
        }
        let partial = OpenedCohort {
            main: actual.main,
            wal: None,
            shm: None,
        };
        partial.require_continuation(&actual)?;
        Ok(())
    }
}
