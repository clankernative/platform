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
    image: super::ImageData,
    refused: bool,
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
        let AttemptFile { file, image, .. } = attempt;
        parent.sync_all()?;
        let parent_identity = CreatorData::of(&parent.metadata()?);
        let mut root = Self {
            parent: parent.try_clone()?,
            directory,
            file,
            parent_identity,
            directory_identity,
            file_identity,
            image,
            refused: false,
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
        super::birth::BirthTurn::new_data(selection, self.image.binding.clone())
    }

    pub(in crate::security_epoch) fn check_pending(&mut self) -> Result<()> {
        ensure!(
            !std::mem::replace(&mut self.refused, true),
            "backup_root_files_refused"
        );
        let checked = (|| {
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
                super::ImageData::decode_data(&self.image.bytes, &self.image.binding)?,
            )?;
            file.require_identity()?;
            file.require_image()?;
            file.require_identity()
        })();
        if checked.is_ok() {
            self.refused = false;
        }
        checked
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
    }

    /// Intermediate historical durability DATA only. The actual admitted request
    /// and SAME whole native parent must remain held outside this mechanical
    /// operation through counter May, source, transfer and consuming settlement.
    /// A complete record remains spent even if every later ACK/post is lost.
    pub(in crate::security_epoch) fn append_attempt_data(
        &mut self,
        intent_bytes: &[u8],
    ) -> Result<Digest> {
        self.check_pending()?;
        ensure!(
            !std::mem::replace(&mut self.refused, true),
            "backup_root_files_refused"
        );
        let intent: super::Intent = super::super::decode_canonical(intent_bytes)?;
        let expected = super::ImageData::decode_data(&self.image.bytes, &self.image.binding)?;
        let mut held = AttemptFile::hold(&self.directory, self.file.try_clone()?, expected)?;
        held.require_identity()?;
        held.require_image()?;
        held.refused.set(false);
        let commitment = held.append(&intent)?;
        self.image = held.image;
        self.refused = false;
        self.check_pending()?;
        Ok(commitment)
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
        super::super::tests::binding()
    }

    fn append_wiring(source: &str) -> bool {
        use quote::ToTokens;
        let file = syn::parse_file(source).unwrap();
        let mut selected = std::collections::BTreeMap::new();
        for item in file.items {
            if let syn::Item::Impl(item) = item
                && item.self_ty.to_token_stream().to_string() == "PendingRootFiles"
            {
                for member in item.items {
                    if let syn::ImplItem::Fn(f) = member {
                        selected.insert(
                            f.sig.ident.to_string(),
                            f.block.to_token_stream().to_string(),
                        );
                    }
                }
            }
        }
        let Some(body) = selected.get("append_attempt_data") else {
            return false;
        };
        let Some(check) = selected.get("check_pending") else {
            return false;
        };
        let mut tail = body.as_str();
        for target in [
            "self . check_pending () ? ;",
            "std :: mem :: replace (& mut self . refused , true)",
            "let intent : super :: Intent = super :: super :: decode_canonical (intent_bytes) ? ;",
            "ImageData :: decode_data (& self . image . bytes , & self . image . binding)",
            "AttemptFile :: hold",
            "held . require_identity",
            "held . require_image",
            "held . refused . set (false)",
            "held . append (& intent)",
            "self . image = held . image",
            "self . refused = false",
            "self . check_pending () ? ;",
            "Ok (commitment)",
        ] {
            let Some((_, rest)) = tail.split_once(target) else {
                return false;
            };
            tail = rest;
        }
        let refused: syn::Block = syn::parse_quote!({
            self.refused = true;
        });
        selected.get("refuse") == Some(&refused.to_token_stream().to_string())
            && check.contains("std :: mem :: replace (& mut self . refused , true)")
            && check.contains("if checked . is_ok () { self . refused = false ; }")
            && !body.contains("open_existing")
    }

    #[test]
    fn actual_retained_append_keeps_sticky_guard_durability_image_and_negative_native_bridge() {
        use quote::ToTokens;
        let source = include_str!("root_files.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(append_wiring(source));
        for (old, new) in [
            (
                "let commitment = held.append(&intent)?;",
                "let commitment = self.image.tail.clone();",
            ),
            (
                "self.image = held.image;",
                "self.image = super::ImageData::new_data(self.image.binding.clone())?;",
            ),
            ("if checked.is_ok()", "if checked.is_err()"),
        ] {
            assert_eq!(source.matches(old).count(), 1);
            assert!(!append_wiring(&source.replacen(old, new, 1)));
        }
        // Remove the first actual append precheck rather than a fixture check.
        let mut parsed = syn::parse_file(source).unwrap();
        for item in &mut parsed.items {
            if let syn::Item::Impl(item) = item
                && item.self_ty.to_token_stream().to_string() == "PendingRootFiles"
            {
                for member in &mut item.items {
                    if let syn::ImplItem::Fn(f) = member
                        && f.sig.ident == "append_attempt_data"
                    {
                        f.block.stmts.remove(0);
                    }
                }
            }
        }
        assert!(!append_wiring(&parsed.to_token_stream().to_string()));
        let mut parsed = syn::parse_file(source).unwrap();
        let mut changed = 0;
        for item in &mut parsed.items {
            if let syn::Item::Impl(item) = item
                && item.self_ty.to_token_stream().to_string() == "PendingRootFiles"
            {
                for member in &mut item.items {
                    if let syn::ImplItem::Fn(f) = member
                        && f.sig.ident == "append_attempt_data"
                    {
                        for statement in &mut f.block.stmts {
                            if let syn::Stmt::Local(local) = statement
                                && matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "held")
                                && let Some(init) = &mut local.init
                                && let syn::Expr::Try(tried) = &mut *init.expr
                                && let syn::Expr::Call(call) = &mut *tried.expr
                            {
                                *call.func = syn::parse_quote!(AttemptFile::open_existing);
                                changed += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(changed, 1);
        assert!(!append_wiring(&parsed.to_token_stream().to_string()));
        let native = include_str!("../../storage_authority/native_volume/scheduled_backup.rs");
        let native_bridge = |text: &str| {
            let parsed = syn::parse_file(text).unwrap();
            let mut bodies = Vec::new();
            for item in parsed.items {
                if let syn::Item::Impl(item) = item
                    && item.self_ty.to_token_stream().to_string() == "PendingBackupRoot"
                {
                    for member in item.items {
                        if let syn::ImplItem::Fn(f) = member
                            && f.sig.ident == "refuse"
                        {
                            bodies.push(f.block.to_token_stream().to_string());
                        }
                    }
                }
            }
            bodies.len() == 1 && bodies[0].matches("self . files . refuse ()").count() == 1
        };
        assert!(native_bridge(native));
        assert_eq!(native.matches("self.files.refuse();").count(), 1);
        assert!(!native_bridge(&native.replacen(
            "self.files.refuse();",
            "",
            1
        )));
    }

    #[test]
    fn retained_image_advances_only_after_actual_append_and_never_repairs_a_refused_root()
    -> Result<()> {
        let temp = Temp::new()?;
        let parent = temp.open()?;
        let mut root = PendingRootFiles::create_binding(&parent, binding())?;
        let first = super::super::tests::intent(0, 0);
        let second = super::super::tests::intent(1, 1);
        let one = root.append_attempt_data(&serde_json::to_vec(&first)?)?;
        let two = root.append_attempt_data(&serde_json::to_vec(&second)?)?;
        assert_ne!(one, two);
        root.check_pending()?;
        assert_eq!(root.image.slots.len(), 2);
        // Changing policy, epoch, Job and operation cannot rearm slot zero.
        assert!(
            root.append_attempt_data(&serde_json::to_vec(&super::super::tests::intent(0, 4))?)
                .is_err()
        );
        assert!(root.check_pending().is_err());
        assert!(
            root.append_attempt_data(&serde_json::to_vec(&super::super::tests::intent(2, 0))?)
                .is_err()
        );
        drop(root);
        assert!(PendingRootFiles::create_binding(&parent, binding()).is_err());
        Ok(())
    }

    #[test]
    fn explicit_post_refusal_and_partial_disk_tail_cannot_be_cleared_by_a_temporary_hold()
    -> Result<()> {
        for partial in [false, true] {
            let temp = Temp::new()?;
            let parent = temp.open()?;
            let mut root = PendingRootFiles::create_binding(&parent, binding())?;
            root.append_attempt_data(&serde_json::to_vec(&super::super::tests::intent(0, 0))?)?;
            if partial {
                use std::io::Write;
                root.file.write_all(b"{")?;
                root.file.sync_all()?;
                assert!(root.check_pending().is_err());
            } else {
                // The caller's mandatory later native post can fail after
                // local durability. This is a negative mechanical latch only.
                root.refuse();
            }
            for _ in 0..3 {
                assert!(root.check_pending().is_err());
                assert!(
                    root.append_attempt_data(&serde_json::to_vec(&super::super::tests::intent(
                        1, 0
                    ))?)
                    .is_err()
                );
            }
        }
        Ok(())
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

    mod histories {
        use super::*;
        use crate::security_epoch::scheduled_backup::{
            journal::tests as fixtures,
            reservation::{CreateTurn, tests as remote_fixtures},
        };
        use serde::{Deserialize, Serialize};
        use std::{
            collections::BTreeSet,
            io::{Read, Write},
            os::unix::fs::OpenOptionsExt,
        };

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Cut {
            Known,
            BeforeMayPost,
            LostAck,
            UnappliedUnknown,
            AfterAckPost,
            WrongStatus,
            PartialTail,
            Crash,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Event {
            minute: u8,
            revision: u8,
            cut: Cut,
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Program {
            version: u8,
            source: Digest,
            events: Vec<Event>,
            wrong: Option<usize>,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        // `may` records the DATA codec's send-encoding transition. No real
        // counter/provider dispatch, native post or source permission is tested.
        struct Observation {
            append: bool,
            may: bool,
            ack: bool,
            open: bool,
            disk_valid: bool,
            spent: Option<usize>,
            intents: Option<Vec<Digest>>,
            remote: usize,
        }

        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum FailureKind {
            Setup,
            Step,
            Panic,
            Mismatch,
        }

        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Failure {
            step: Option<usize>,
            kind: FailureKind,
        }

        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Run {
            observations: Vec<Observation>,
            failure: Option<Failure>,
        }

        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Bundle {
            program: Program,
            first: Run,
            second: Run,
        }

        fn validate(program: &Program) -> Result<()> {
            ensure!(
                program.version == 1
                    && program.source == fixtures::source()?
                    && !program.events.is_empty()
                    && program.events.len() <= 40
                    && program
                        .events
                        .iter()
                        .all(|e| e.minute < 8 && e.revision < 12)
                    && program.wrong.is_none_or(|n| n < program.events.len()),
                "backup_held_history_program"
            );
            Ok(())
        }

        fn run(program: &Program) -> Run {
            let mut run = Run {
                observations: Vec::new(),
                failure: None,
            };
            let setup = (|| -> Result<_> {
                let temp = Temp::new()?;
                let parent = temp.open()?;
                let root = PendingRootFiles::create_binding(&parent, binding())?;
                Ok((temp, parent, root))
            })();
            let Ok((temp, parent, first)) = setup else {
                run.failure = Some(Failure {
                    step: None,
                    kind: FailureKind::Setup,
                });
                return run;
            };
            let path = temp
                .0
                .join(&first.name)
                .join(super::super::super::FILE_NAME);
            let mut root = Some(first);
            let selection = remote_fixtures::selection();
            let mut actual_remote = BTreeSet::new();
            // Independent numeric-slot oracle: no implementation hash, image,
            // disposition, decoder result or observation determines expectations.
            let mut spent = BTreeSet::new();
            let mut intent_commitments = Vec::new();
            let mut remote = BTreeSet::new();
            let mut closed = false;
            let mut malformed = false;
            for (step, event) in program.events.iter().enumerate() {
                let append = !closed && !spent.contains(&event.minute) && event.cut != Cut::Crash;
                let may = append && !matches!(event.cut, Cut::BeforeMayPost | Cut::PartialTail);
                let ack = may && matches!(event.cut, Cut::Known | Cut::AfterAckPost);
                if append {
                    spent.insert(event.minute);
                    let mut input = fixtures::intent(event.minute, event.revision);
                    input.source.store = Digest::of(&selection).unwrap();
                    // Independent literal domain and complete fixture input,
                    // not Intent::commitment_data or any observed journal row.
                    intent_commitments
                        .push(Digest::of(&("day2-scheduled-backup-intent-v1", &input)).unwrap());
                }
                if may && event.cut != Cut::UnappliedUnknown {
                    remote.insert(event.minute);
                }
                malformed |= append && event.cut == Cut::PartialTail;
                closed |= event.cut == Cut::Crash || !append || event.cut != Cut::Known;
                let mut expected = Observation {
                    append,
                    may,
                    ack,
                    open: !closed,
                    disk_valid: !malformed,
                    spent: (!malformed).then_some(spent.len()),
                    intents: (!malformed).then(|| intent_commitments.clone()),
                    remote: remote.len(),
                };
                if program.wrong == Some(step) {
                    expected.open = !expected.open;
                }
                let mut actual = Observation {
                    append: false,
                    may: false,
                    ack: false,
                    open: false,
                    disk_valid: false,
                    spent: None,
                    intents: None,
                    remote: actual_remote.len(),
                };
                let attempted =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                        if event.cut == Cut::Crash {
                            drop(root.take());
                            ensure!(
                                PendingRootFiles::create_binding(&parent, binding()).is_err(),
                                "backup_held_history_recreated"
                            );
                        } else if let Some(held) = &mut root {
                            let mut intent = fixtures::intent(event.minute, event.revision);
                            intent.source.store = Digest::of(&selection)?;
                            actual.append = held
                                .append_attempt_data(&serde_json::to_vec(&intent)?)
                                .is_ok();
                            if actual.append {
                                match event.cut {
                                    Cut::BeforeMayPost => held.refuse(),
                                    Cut::PartialTail => {
                                        held.file.write_all(b"{")?;
                                        held.file.sync_all()?;
                                        ensure!(
                                            held.check_pending().is_err(),
                                            "backup_held_history_tail_accepted"
                                        );
                                    }
                                    _ => {
                                        let mut turn = CreateTurn::new_data(&selection, intent)?;
                                        let write = turn.submit_data()?;
                                        actual.may = true;
                                        let payload =
                                            write["writes"][0]["update"]["fields"]["attempt_json"]
                                                ["stringValue"]
                                                .as_str()
                                                .ok_or_else(|| {
                                                    anyhow::anyhow!("backup_held_history_payload")
                                                })?;
                                        let row: serde_json::Value =
                                            crate::json::decode(payload.as_bytes())?;
                                        let mut input =
                                            fixtures::intent(event.minute, event.revision);
                                        input.source.store = Digest::of(&selection)?;
                                        ensure!(
                                            row["intent"] == serde_json::to_value(&input)?
                                                && row["commitment"]
                                                    == serde_json::to_value(Digest::of(&(
                                                        "day2-scheduled-backup-intent-v1",
                                                        &input
                                                    ))?)?,
                                            "backup_held_history_intent_binding"
                                        );
                                        let name = write["writes"][0]["update"]["name"]
                                            .as_str()
                                            .ok_or_else(|| {
                                                anyhow::anyhow!("backup_held_history_name")
                                            })?;
                                        if event.cut != Cut::UnappliedUnknown {
                                            ensure!(
                                                actual_remote.insert(name.to_owned()),
                                                "backup_held_history_remote_collision"
                                            );
                                        }
                                        match event.cut {
                                            Cut::Known | Cut::AfterAckPost => {
                                                actual.ack = turn
                                                    .observe_commit_data(
                                                        200,
                                                        &remote_fixtures::ack(),
                                                    )
                                                    .is_ok();
                                                if event.cut == Cut::AfterAckPost {
                                                    held.refuse();
                                                }
                                            }
                                            Cut::WrongStatus => {
                                                ensure!(
                                                    turn.observe_commit_data(
                                                        201,
                                                        &remote_fixtures::ack()
                                                    )
                                                    .is_err(),
                                                    "backup_held_history_status"
                                                );
                                                held.refuse();
                                            }
                                            _ => {
                                                turn.lose_result_data();
                                                ensure!(
                                                    turn.submit_data().is_err()
                                                        && turn
                                                            .observe_commit_data(
                                                                200,
                                                                &remote_fixtures::ack()
                                                            )
                                                            .is_err(),
                                                    "backup_held_history_unknown_reopened"
                                                );
                                                held.refuse();
                                            }
                                        }
                                    }
                                }
                            }
                            actual.open = held.check_pending().is_ok();
                        }
                        let bytes = std::fs::read(&path)?;
                        let image = super::super::super::ImageData::decode_data(&bytes, &binding());
                        actual.disk_valid = image.is_ok();
                        actual.spent = image.ok().map(|image| image.slots.len());
                        if actual.disk_valid {
                            let mut commitments = Vec::new();
                            for line in bytes
                                .split(|byte| *byte == b'\n')
                                .skip(1)
                                .filter(|line| !line.is_empty())
                            {
                                let record: super::super::super::RecordData =
                                    crate::json::decode(line)?;
                                commitments.push(record.intent);
                            }
                            actual.intents = Some(commitments);
                        }
                        actual.remote = actual_remote.len();
                        Ok(())
                    }));
                let failure = match attempted {
                    Err(_) => Some(FailureKind::Panic),
                    Ok(Err(_)) => Some(FailureKind::Step),
                    Ok(Ok(())) if actual != expected => Some(FailureKind::Mismatch),
                    _ => None,
                };
                // Retain the attempted failing event in both replay prefixes.
                run.observations.push(actual);
                if let Some(kind) = failure {
                    run.failure = Some(Failure {
                        step: Some(step),
                        kind,
                    });
                    break;
                }
            }
            run
        }

        const MAX_BUNDLE: usize = 262_144;
        struct Saved(PathBuf);
        impl std::fmt::Display for Saved {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("backup_held_history_saved")
            }
        }
        impl std::fmt::Debug for Saved {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(self, f)
            }
        }
        impl std::error::Error for Saved {}

        fn complete(program: &Program, run: &Run) -> bool {
            run.failure.is_none() && run.observations.len() == program.events.len()
        }

        fn retained_prefix(program: &Program, run: &Run) -> bool {
            match &run.failure {
                Some(Failure {
                    step: None,
                    kind: FailureKind::Setup,
                }) => run.observations.is_empty(),
                Some(Failure {
                    step: Some(step),
                    kind,
                }) => {
                    *kind != FailureKind::Setup
                        && *step < program.events.len()
                        && run.observations.len() == step + 1
                }
                Some(_) => false,
                None => complete(program, run),
            }
        }

        fn check(program: Program) -> Result<()> {
            validate(&program)?;
            let first = run(&program);
            let second = run(&program);
            if first == second && complete(&program, &first) && complete(&program, &second) {
                return Ok(());
            }
            let bytes = serde_json::to_vec(&Bundle {
                program,
                first,
                second,
            })?;
            ensure!(
                bytes.len() <= MAX_BUNDLE,
                "backup_held_history_bundle_bound"
            );
            let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/control-slot-replays");
            std::fs::create_dir_all(&parent)?;
            let dir = tempfile::Builder::new()
                .prefix("backup-held-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in(parent)?
                .keep();
            let path = dir.join("replay.json.gz");
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            let mut encoded = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
            encoded.write_all(&bytes)?;
            encoded.finish()?.sync_all()?;
            Err(Saved(path).into())
        }

        #[test]
        fn generated_durable_and_remote_cuts_replay_twice_without_rearming_or_reconstructing_owners()
        -> Result<()> {
            let cuts = [
                Cut::Known,
                Cut::BeforeMayPost,
                Cut::LostAck,
                Cut::UnappliedUnknown,
                Cut::AfterAckPost,
                Cut::WrongStatus,
                Cut::PartialTail,
                Cut::Crash,
            ];
            for seed in 0..16u64 {
                let mut state = seed;
                let mut events = vec![
                    Event {
                        minute: 0,
                        revision: 0,
                        cut: Cut::Known,
                    },
                    Event {
                        minute: 1,
                        revision: 1,
                        cut: Cut::Known,
                    },
                    Event {
                        minute: 2,
                        revision: 2,
                        cut: cuts[seed as usize % cuts.len()],
                    },
                ];
                for _ in 0..29 {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    events.push(Event {
                        minute: ((state >> 9) % 8) as u8,
                        revision: ((state >> 17) % 12) as u8,
                        cut: cuts[(state >> 25) as usize % cuts.len()],
                    });
                }
                check(Program {
                    version: 1,
                    source: fixtures::source()?,
                    events,
                    wrong: None,
                })?;
            }
            Ok(())
        }

        #[test]
        fn failed_history_bundle_is_private_strict_source_bound_and_keeps_both_attempted_prefixes()
        -> Result<()> {
            let program = Program {
                version: 1,
                source: fixtures::source()?,
                events: (0..3)
                    .map(|minute| Event {
                        minute,
                        revision: minute,
                        cut: Cut::Known,
                    })
                    .collect(),
                wrong: Some(2),
            };
            let error = check(program).unwrap_err();
            let path = &error.downcast_ref::<Saved>().unwrap().0;
            assert_eq!(error.to_string(), "backup_held_history_saved");
            assert_eq!(
                std::fs::metadata(path)?.permissions().mode() & 0o7777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())?
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
            let mut bytes = Vec::new();
            let mut encoded = Vec::new();
            File::open(path)?
                .take((MAX_BUNDLE + 1_025) as u64)
                .read_to_end(&mut encoded)?;
            ensure!(
                encoded.len() <= MAX_BUNDLE + 1_024,
                "backup_held_history_encoded_bound"
            );
            let mut decoder = flate2::bufread::GzDecoder::new(&encoded[..]);
            decoder
                .by_ref()
                .take((MAX_BUNDLE + 1) as u64)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= MAX_BUNDLE && decoder.into_inner().is_empty(),
                "backup_held_history_bundle_bound"
            );
            let bundle: Bundle = crate::json::decode(&bytes)?;
            validate(&bundle.program)?;
            assert_eq!(bundle.first, run(&bundle.program));
            assert_eq!(bundle.second, run(&bundle.program));
            assert_eq!(bundle.first.observations.len(), 3);
            assert_eq!(bundle.second.observations.len(), 3);
            assert!(retained_prefix(&bundle.program, &bundle.first));
            assert!(retained_prefix(&bundle.program, &bundle.second));
            assert!(
                bundle.first.observations[..2]
                    .iter()
                    .all(|o| o.append && o.may && o.ack)
            );
            assert!(matches!(
                bundle.first.failure,
                Some(Failure {
                    step: Some(2),
                    kind: FailureKind::Mismatch
                })
            ));
            let mut stale = bundle.program;
            stale.source = Digest::new(b"different source");
            assert!(validate(&stale).is_err());
            let wrong = bytes.iter().position(|b| *b == b'{').unwrap();
            let mut duplicate = bytes.clone();
            duplicate.splice(wrong + 1..wrong + 1, b"\"program\":null,".iter().copied());
            assert!(crate::json::decode::<Bundle>(&duplicate).is_err());
            let empty = Program {
                version: 1,
                source: fixtures::source()?,
                events: Vec::new(),
                wrong: None,
            };
            assert!(validate(&empty).is_err());
            let normal = Program {
                version: 1,
                source: fixtures::source()?,
                events: (0..3)
                    .map(|minute| Event {
                        minute,
                        revision: minute,
                        cut: Cut::Known,
                    })
                    .collect(),
                wrong: None,
            };
            let mut truncated = run(&normal);
            assert!(complete(&normal, &truncated));
            truncated.observations.pop();
            assert!(!complete(&normal, &truncated));
            assert!(!retained_prefix(&normal, &truncated));
            Ok(())
        }
    }
}
