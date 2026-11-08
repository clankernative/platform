//! Same-owned physical observation of the reset file, before any SQLite open.
//! An offer, descriptor or hash alone cannot construct this actual process,
//! channel, file and original lifetime. No P3/current-writer factory is here.
use super::{ActiveRestoredFile, CapturedRestoredFile, RestoredAppPeer};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context, ensure};
#[cfg(target_os = "linux")]
use day2_capabilities::Digest;
#[cfg(target_os = "linux")]
use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxFlags};
use std::fs::File;
use zeroize::Zeroizing;

const MAX_BYTES: u64 = 16 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;

#[derive(PartialEq, Eq)]
pub(super) struct Stamp {
    device: (u32, u32),
    mount: u64,
    inode: u64,
    user: u32,
    group: u32,
    mode: u16,
    links: u32,
    length: u64,
}

// Only the distinct consumed active-file owner uses this comparison. SQLite
// may change length and contents; dev/mount/inode/owner/mode/link identity may
// never drift. Frozen owners continue using complete Stamp equality + SHA.
fn require_active_identity(retained: &Stamp, actual: &Stamp) -> Result<()> {
    anyhow::ensure!(
        retained.device == actual.device
            && retained.mount == actual.mount
            && retained.inode == actual.inode
            && retained.user == actual.user
            && retained.group == actual.group
            && retained.mode == actual.mode
            && retained.links == actual.links
            && actual.links == 1
            && actual.mode & 0o7777 == 0o600,
        "restore_active_file_creator_changed"
    );
    Ok(())
}

fn stamp_at(file: &File, name: &str, empty: bool) -> Result<Stamp> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, name, empty);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mask = StatxFlags::TYPE
            | StatxFlags::MODE
            | StatxFlags::NLINK
            | StatxFlags::UID
            | StatxFlags::GID
            | StatxFlags::INO
            | StatxFlags::SIZE
            | StatxFlags::MNT_ID;
        let flags = if empty {
            AtFlags::EMPTY_PATH
        } else {
            AtFlags::SYMLINK_NOFOLLOW
        };
        let stat = rustix::fs::statx(file, name, flags, mask)?;
        ensure!(
            stat.stx_mask & mask.bits() == mask.bits() && stat.stx_ino > 0 && stat.stx_mnt_id > 0,
            "restore_file_identity_missing"
        );
        Ok(Stamp {
            device: (stat.stx_dev_major, stat.stx_dev_minor),
            mount: stat.stx_mnt_id,
            inode: stat.stx_ino,
            user: stat.stx_uid,
            group: stat.stx_gid,
            mode: stat.stx_mode,
            links: stat.stx_nlink,
            length: stat.stx_size,
        })
    }
}

fn directory_stamp(file: &File, private: bool) -> Result<Stamp> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, private);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mut stamp = stamp_at(file, "", true)?;
        ensure!(
            FileType::from_raw_mode(u32::from(stamp.mode)) == FileType::Directory
                && (!private || (stamp.mode & 0o7777 == 0o700 && stamp.user == 10001)),
            "restore_file_directory_profile"
        );
        // Directory contents can gain the later keeper sidecars. Identity and
        // ownership remain exact; size/link count are not file-content authority.
        stamp.links = 0;
        stamp.length = 0;
        Ok(stamp)
    }
}

fn open_child(parent: &File, name: &str, directory: bool) -> Result<File> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, name, directory);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        if directory {
            flags |= OFlags::DIRECTORY;
        }
        Ok(File::from(rustix::fs::openat2(
            parent,
            name,
            flags,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?))
    }
}

fn same_named_directory(parent: &File, name: &str, held: &Stamp) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, name, held);
        anyhow::bail!("native_restore_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mut named = stamp_at(parent, name, false)?;
        named.links = 0;
        named.length = 0;
        ensure!(named == *held, "restore_file_named_directory_changed");
        Ok(())
    }
}

impl RestoredAppPeer {
    /// The actual offer is authenticated before any open or parse. The fixed
    /// path derives only from that exact signed operation; no path/FD argument
    /// or ordinary initial-file fallback exists.
    pub(in crate::security_epoch::native_enrollment) fn capture_reset_file(
        mut self,
    ) -> Result<CapturedRestoredFile> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&mut self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<_> = (|| {
                let operation = &self.process.authorization.statement.data.operation;
                let component = format!("restore-{}", day2_assets::hash_part(operation.as_str())?);
                let root = File::from(rustix::fs::open(
                    "/state",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?);
                self.check()?;
                let root_stamp = directory_stamp(&root, false)?;
                self.check()?;
                let private = open_child(&root, "day2-native", true);
                let checked = self.check();
                let private = private?;
                checked?;
                let private_stamp = directory_stamp(&private, true)?;
                let directory = open_child(&private, &component, true);
                let checked = self.check();
                let directory = directory?;
                checked?;
                let directory_stamp = directory_stamp(&directory, true)?;
                let file = open_child(&directory, "app.sqlite", false);
                let checked = self.check();
                let file = file?;
                checked?;
                let file_stamp = stamp_at(&file, "", true)?;
                ensure!(
                    FileType::from_raw_mode(u32::from(file_stamp.mode)) == FileType::RegularFile
                        && file_stamp.mode & 0o7777 == 0o600
                        && file_stamp.links == 1
                        && file_stamp.user == 10001
                        && (100..=MAX_BYTES).contains(&file_stamp.length)
                        && file_stamp.device == directory_stamp.device
                        && file_stamp.mount == directory_stamp.mount,
                    "restore_file_creator_profile"
                );
                let creator = &self.projection.creator;
                ensure!(
                    file_stamp.device == (creator.device_major, creator.device_minor)
                        && file_stamp.inode == creator.inode
                        && file_stamp.user == creator.user
                        && file_stamp.group == creator.group
                        && file_stamp.length == creator.length,
                    "restore_file_not_selected_creator"
                );
                Ok((
                    root,
                    private,
                    directory,
                    file,
                    root_stamp,
                    private_stamp,
                    directory_stamp,
                    file_stamp,
                    component,
                ))
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                self.process.receiver.refuse();
            }
            let (
                root,
                private,
                directory,
                file,
                root_stamp,
                private_stamp,
                directory_stamp,
                file_stamp,
                component,
            ) = requested?;
            checked?;
            let mut captured = CapturedRestoredFile {
                peer: self,
                root,
                private,
                directory,
                file,
                root_stamp,
                private_stamp,
                directory_stamp,
                file_stamp,
                component,
                image: Zeroizing::new(Vec::new()),
                refused: false,
                local_only: std::marker::PhantomData,
            };
            let requested = captured.read_image();
            let checked = captured.check_identity();
            if requested.is_err() || checked.is_err() {
                captured.refused = true;
                captured.peer.process.receiver.refuse();
            }
            let image = requested?;
            checked?;
            captured.image = image;
            Ok(captured)
        }
    }
}

impl CapturedRestoredFile {
    /// Pre-RW only: reread the exact reset image under the same actual peer
    /// and original before Confirm/Accepted. Identity checks alone cannot
    /// detect same-length writes. The later keeper must consume this file
    /// state through an explicit authorized transition, not drop this check.
    pub(in crate::security_epoch::native_enrollment) fn check_image(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested = self.read_image();
            let checked = self.check_identity();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                self.peer.process.receiver.refuse();
            }
            let image = requested?;
            checked?;
            if image != self.image {
                self.refused = true;
                self.peer.process.receiver.refuse();
                anyhow::bail!("restore_file_observed_image_changed");
            }
            Ok(())
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check_identity(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.peer.check()?;
            let requested: Result<()> = (|| {
                ensure!(!self.refused, "restore_file_refused");
                ensure!(
                    directory_stamp(&self.root, false)? == self.root_stamp
                        && directory_stamp(&self.private, true)? == self.private_stamp
                        && directory_stamp(&self.directory, true)? == self.directory_stamp,
                    "restore_file_held_directory_changed"
                );
                // Join the actual fixed root path to the same held inode. Later
                // directory/name checks use statx, never another MAIN descriptor
                // whose close could release an outstanding SQLite unit's locks.
                let named_root = File::from(rustix::fs::open(
                    "/state",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )?);
                ensure!(
                    directory_stamp(&named_root, false)? == self.root_stamp,
                    "restore_file_root_path_changed"
                );
                same_named_directory(&self.root, "day2-native", &self.private_stamp)?;
                same_named_directory(&self.private, &self.component, &self.directory_stamp)?;
                ensure!(
                    stamp_at(&self.file, "", true)? == self.file_stamp
                        && stamp_at(&self.directory, "app.sqlite", false)? == self.file_stamp,
                    "restore_file_creator_changed"
                );
                Ok(())
            })();
            let checked = self.peer.check();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                self.peer.process.receiver.refuse();
            }
            requested?;
            checked
        }
    }

    fn read_image(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check_identity()?;
            let mut bytes = Zeroizing::new(vec![0u8; usize::try_from(self.file_stamp.length)?]);
            let mut offset = 0usize;
            while offset < bytes.len() {
                self.check_identity()?;
                let end = bytes.len().min(
                    offset
                        .checked_add(CHUNK)
                        .context("restore_file_read_bound")?,
                );
                let requested =
                    rustix::io::pread(&self.file, &mut bytes[offset..end], offset as u64);
                let checked = self.check_identity();
                let read = requested?;
                checked?;
                ensure!(
                    read > 0 && read <= end - offset,
                    "restore_file_read_progress"
                );
                offset += read;
            }
            self.check_identity()?;
            let mut extra = [0u8; 1];
            let requested = rustix::io::pread(&self.file, &mut extra, offset as u64);
            let checked = self.check_identity();
            ensure!(requested? == 0, "restore_file_image_grew");
            checked?;
            ensure!(
                bytes.starts_with(b"SQLite format 3\0")
                    && Digest::new(&bytes[..]) == self.peer.projection.report.image,
                "restore_file_reset_image_changed"
            );
            Ok(bytes)
        }
    }
}

impl ActiveRestoredFile {
    /// Final immutable reset-image verification for the FIRST SQLite open.
    /// Kept separate from post-RW identity checks: no caller flag disables it,
    /// and later legitimate SQLite writes are never compared to old bytes.
    pub(super) fn require_unopened_image(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<()> = (|| {
                let expected = self.peer.projection.report.image.clone();
                let length = self.file_stamp.length;
                ensure!(length <= MAX_BYTES, "restore_file_image_bound");
                let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
                let mut bytes = Zeroizing::new(vec![0; CHUNK]);
                let mut offset = 0u64;
                while offset < length {
                    self.check()?;
                    let actual = stamp_at(&self.file, "", true)?;
                    ensure!(actual == self.file_stamp, "restore_unopened_file_changed");
                    let size = usize::try_from(length - offset)?.min(bytes.len());
                    let read = rustix::io::pread(&self.file, &mut bytes[..size], offset);
                    let checked = self.check();
                    let read = read?;
                    checked?;
                    ensure!(
                        read > 0 && read <= size,
                        "restore_unopened_file_read_progress"
                    );
                    offset = offset
                        .checked_add(read as u64)
                        .context("restore_unopened_file_length")?;
                    hash.update(&bytes[..read]);
                }
                self.check()?;
                let mut extra = [0u8; 1];
                let read = rustix::io::pread(&self.file, &mut extra, offset);
                let checked = self.check();
                ensure!(read? == 0, "restore_unopened_file_grew");
                checked?;
                ensure!(
                    stamp_at(&self.file, "", true)? == self.file_stamp,
                    "restore_unopened_file_changed"
                );
                let digest =
                    Digest::try_from(format!("sha256:{}", crate::hex(hash.finish().as_ref())))?;
                ensure!(digest == expected, "restore_unopened_file_image_changed");
                Ok(())
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                self.peer.refused = true;
                self.peer.process.receiver.refuse();
            }
            requested?;
            checked
        }
    }

    /// Fixed named and retained anchors only. This does not touch the old peer,
    /// original, transcript or lease, and never opens/closes a second MAIN.
    pub(super) fn check_anchors(&self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            ensure!(!self.refused, "restore_active_file_refused");
            ensure!(
                directory_stamp(&self.root, false)? == self.root_stamp
                    && directory_stamp(&self.private, true)? == self.private_stamp
                    && directory_stamp(&self.directory, true)? == self.directory_stamp,
                "restore_active_file_held_directory_changed"
            );
            let named_root = File::from(rustix::fs::open(
                "/state",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )?);
            ensure!(
                directory_stamp(&named_root, false)? == self.root_stamp,
                "restore_active_file_root_path_changed"
            );
            same_named_directory(&self.root, "day2-native", &self.private_stamp)?;
            same_named_directory(&self.private, &self.component, &self.directory_stamp)?;
            // statx through the existing MAIN and directory descriptors:
            // never open/close a second MAIN and release SQLite's locks.
            require_active_identity(&self.file_stamp, &stamp_at(&self.file, "", true)?)?;
            require_active_identity(
                &self.file_stamp,
                &stamp_at(&self.directory, "app.sqlite", false)?,
            )
        }
    }

    pub(super) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.peer.check()?;
            let requested = self.check_anchors();
            let checked = self.peer.check();
            if requested.is_err() || checked.is_err() {
                self.refused = true;
                self.peer.refused = true;
                self.peer.process.receiver.refuse();
            }
            requested?;
            checked
        }
    }
}

#[cfg(test)]
mod active_identity_tests {
    use super::*;
    use quote::ToTokens;

    fn tokens(source: &str) -> String {
        fn without_commas(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), without_commas(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        without_commas(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    fn actual_check() -> String {
        actual_file_method("check")
    }

    fn actual_file_method(name: &str) -> String {
        let file = syn::parse_file(include_str!("file.rs")).unwrap();
        file.items.into_iter().find_map(|item| {
            let syn::Item::Impl(owner)=item else{return None};
            if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident("ActiveRestoredFile")){return None;}
            owner.items.into_iter().find_map(|item|match item {
                syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(tokens(&method.into_token_stream().to_string())),_=>None,
            })
        }).unwrap()
    }

    fn anchors_are_live(body: &str) -> bool {
        let mut rest = body;
        for part in [
            "!self.refused",
            "directory_stamp(&self.root,false)?==self.root_stamp",
            "directory_stamp(&self.private,true)?==self.private_stamp",
            "directory_stamp(&self.directory,true)?==self.directory_stamp",
            "directory_stamp(&named_root,false)?==self.root_stamp",
            "same_named_directory(&self.root,\"day2-native\",&self.private_stamp)?;",
            "same_named_directory(&self.private,&self.component,&self.directory_stamp)?;",
            "require_active_identity(&self.file_stamp,&stamp_at(&self.file,\"\",true)?)?;",
            "require_active_identity(&self.file_stamp,&stamp_at(&self.directory,\"app.sqlite\",false)?)",
        ] {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        body.matches(&tokens("require_active_identity")).count() == 2
            && !body.contains(&tokens("self.peer.check"))
            && !body.contains("try_clone")
            && !body.contains("NativeAcquisition")
            && !body.contains("remaining")
    }

    fn actual_guard_is_live(body: &str, anchors: &str) -> bool {
        let mut rest = body;
        for part in [
            "self.peer.check()?;",
            "let requested=self.check_anchors();",
            "let checked=self.peer.check();",
            "self.refused=true;",
            "self.peer.refused=true;",
            "self.peer.process.receiver.refuse();",
            "requested?;checked",
        ] {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        anchors_are_live(anchors)
            && body.matches(&tokens("self.peer.check()")).count() == 2
            && body.matches(&tokens("self.check_anchors()")).count() == 1
    }

    #[test]
    fn actual_active_file_guard_checks_real_held_and_named_files_and_refuses_after_failed_checks() {
        assert_eq!(
            tokens("self.peer.check()?;"),
            tokens("self.peer.check() ? ;")
        );
        assert_ne!(tokens("self.peer.check()?;"), tokens("self.peer.check();"));
        let actual = actual_check();
        let anchors = actual_file_method("check_anchors");
        assert!(actual_guard_is_live(&actual, &anchors));
        for (before, after) in [
            (
                "let requested=self.check_anchors();",
                "let requested:Result<()>=Ok(());",
            ),
            (
                "let checked=self.peer.check();",
                "let checked:Result<()>=Ok(());",
            ),
            ("requested?;checked", "checked?;requested"),
            ("self.refused=true;", "let _unchanged=();"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1);
            assert!(!actual_guard_is_live(
                &actual.replacen(&before, &tokens(after), 1),
                &anchors
            ));
        }
        for (before, after) in [
            (
                "require_active_identity(&self.file_stamp,&stamp_at(&self.file,\"\",true)?)?;",
                "let _unchecked=();",
            ),
            (
                "require_active_identity(&self.file_stamp,&stamp_at(&self.directory,\"app.sqlite\",false)?)",
                "Ok(())",
            ),
            (
                "same_named_directory(&self.private,&self.component,&self.directory_stamp)?;",
                "",
            ),
            (
                "directory_stamp(&named_root,false)?==self.root_stamp",
                "true",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(anchors.matches(&before).count(), 1);
            assert!(!actual_guard_is_live(
                &actual,
                &anchors.replacen(&before, &tokens(after), 1)
            ));
        }
    }

    fn raw_image_is_bound(body: &str) -> bool {
        let mut rest = body;
        for part in [
            "self.check()?;",
            "let expected=self.peer.projection.report.image.clone();",
            "let length=self.file_stamp.length;",
            "length<=MAX_BYTES",
            "while offset<length",
            "let actual=stamp_at(&self.file,\"\",true)?;",
            "actual==self.file_stamp",
            "let read=rustix::io::pread(&self.file,&mut bytes[..size],offset);",
            "let checked=self.check();",
            "let read=read?;checked?;",
            "hash.update(&bytes[..read]);",
            "let read=rustix::io::pread(&self.file,&mut extra,offset);",
            "let checked=self.check();",
            "read?==0",
            "stamp_at(&self.file,\"\",true)?==self.file_stamp",
            "digest==expected",
            "let checked=self.check();",
            "self.refused=true;",
            "requested?;checked",
        ] {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        !body.contains(&tokens("File::open")) && !body.contains("try_clone")
    }

    #[test]
    fn actual_preopen_image_guard_hashes_only_the_retained_main_and_preserves_error_posts() {
        let actual = actual_file_method("require_unopened_image");
        assert!(raw_image_is_bound(&actual));
        for (before, after) in [
            ("self.peer.projection.report.image.clone()", "caller_digest"),
            ("self.file_stamp.length", "caller_length"),
            (
                "let read=rustix::io::pread(&self.file,&mut bytes[..size],offset);",
                "let read=rustix::io::pread(&other_file,&mut bytes[..size],offset);",
            ),
            (
                "let checked=self.check();",
                "let checked:Result<()>=Ok(());",
            ),
            ("digest==expected", "true"),
            ("requested?;checked", "checked?;requested"),
        ] {
            let before = tokens(before);
            assert!(actual.contains(&before));
            assert!(!raw_image_is_bound(&actual.replacen(
                &before,
                &tokens(after),
                1
            )));
        }
    }

    fn fixture() -> Stamp {
        Stamp {
            device: (8, 1),
            mount: 22,
            inode: 300,
            user: 10001,
            group: 10001,
            mode: 0o100600,
            links: 1,
            length: 4096,
        }
    }

    #[test]
    fn consumed_active_file_allows_sqlite_length_change_but_refuses_every_identity_change()
    -> Result<()> {
        let retained = fixture();
        let mut resized = fixture();
        resized.length += 4096;
        require_active_identity(&retained, &resized)?;
        for field in 0..8 {
            let mut changed = fixture();
            match field {
                0 => changed.device.0 += 1,
                1 => changed.device.1 += 1,
                2 => changed.mount += 1,
                3 => changed.inode += 1,
                4 => changed.user += 1,
                5 => changed.group += 1,
                6 => changed.mode ^= 0o040,
                _ => changed.links += 1,
            }
            assert!(
                require_active_identity(&retained, &changed).is_err(),
                "field {field}"
            );
        }
        // Even a corrupt retained profile cannot turn a shared hardlink or
        // widened mode into a legal post-RW identity.
        let mut linked = fixture();
        linked.links = 2;
        assert!(require_active_identity(&linked, &linked).is_err());
        let mut wide = fixture();
        wide.mode = 0o100640;
        assert!(require_active_identity(&wide, &wide).is_err());
        Ok(())
    }
}
