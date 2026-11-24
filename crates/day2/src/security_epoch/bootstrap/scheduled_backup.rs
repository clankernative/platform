// Fixed native root preparation retains the genuine whole parent through
// immutable external birth and all final posts. Drop before Known is refusal.
use super::{
    ActiveControllerStorageContinuity, ActiveLineage, ActiveObservation, CounterRequest,
    EnrolledRoleStage, EpochStore, NativeRole,
};
use crate::security_epoch::{CurrentControllerStoragePhase, storage_authority::PendingBackupRoot};
use anyhow::{Result, ensure};

/// Owns the actual same-stage, same-owner interval. This is deliberately not
/// a prepared/active backup root and exposes no SQL, stage, FD or callback.
/// Its sole Known path requires immutable birth and all actual final posts.
pub(in crate::security_epoch) struct PendingScheduledRootBirth<'storage, 'role> {
    physical: Option<CurrentControllerStoragePhase<'storage, 'role>>,
    reads: CounterRequest<'storage>,
    observed: ActiveObservation,
    lineage: &'storage ActiveLineage,
    selection: &'storage EpochStore,
    continuation: &'storage mut bool,
    pending: Option<PendingBackupRoot>,
    known: bool,
    write_identity: RootBirthWriteIdentity,
}

impl ActiveControllerStorageContinuity {
    pub(in crate::security_epoch) fn begin_scheduled_root_birth<'storage, 'role>(
        &'storage mut self,
        mut stage: EnrolledRoleStage<'role>,
    ) -> Result<PendingScheduledRootBirth<'storage, 'role>> {
        ensure!(self.valid, "active_controller_storage_refused");
        // Close the actual continuation BEFORE any authentication, path or IO.
        // Every early failure leaves it closed; no reconstructed owner/retry.
        self.valid = false;
        stage.storage()?.scheduled_backup_root_selection()?;
        let mut reads = self.counter.request(
            &mut stage,
            &self.policy,
            &self.store,
            NativeRole::EpochController,
        )?;
        let mut physical = self
            .storage
            .begin_pending_current_controller()?
            .acquire(stage)?;
        let observed = self
            .lineage
            .read(&self.store, &mut reads, physical.controller_stage()?)?;
        let mut birth = PendingScheduledRootBirth {
            physical: Some(physical),
            reads,
            observed,
            lineage: &self.lineage,
            selection: &self.store,
            continuation: &mut self.valid,
            pending: None,
            known: false,
            write_identity: RootBirthWriteIdentity,
        };
        birth.check()?;
        let requested = birth
            .physical
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("backup_root_phase_missing"))?
            .prepare_scheduled_backup_root();
        // Mandatory independent post even if creation failed; first error wins.
        let checked = birth.check();
        if requested.is_err() || checked.is_err() {
            birth.refuse();
        }
        let pending = requested?;
        checked?;
        birth.pending = Some(pending);
        birth.check()?;
        Ok(birth)
    }
}

impl PendingScheduledRootBirth<'_, '_> {
    pub(in crate::security_epoch) fn create_known(mut self) -> Result<KnownScheduledBackupRoot> {
        self.check()?;
        let physical = self
            .physical
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("backup_root_phase_missing"))?;
        let pending = self
            .pending
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("backup_root_files_missing"))?;
        let stage = physical.controller_stage()?;
        // Private lexical seal from THIS retained whole parent. Pointer values
        // only compare the actual inputs; possession/knowledge of an address
        // cannot construct this borrowed material or grant dispatch authority.
        let permit = RootBirthWritePermit {
            _identity: &self.write_identity,
            reads: std::ptr::from_ref(&self.reads),
            stage: std::ptr::from_ref(stage),
            pending: std::ptr::from_ref(pending),
        };
        let requested = self
            .reads
            .create_scheduled_backup_root(stage, pending, permit);
        let checked = self.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        self.confirm_birth()?;
        // Check the OLD observation before the fresh strong read; no refreshed
        // read can repair expired/refused native/observation state.
        let physical = self
            .physical
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("backup_root_phase_missing"))?;
        self.observed = self.lineage.read(
            self.selection,
            &mut self.reads,
            physical.controller_stage()?,
        )?;
        self.check()?;
        self.pending
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("backup_root_files_missing"))?
            .require_confirmed_data()?;
        let pending = self
            .pending
            .take()
            .ok_or_else(|| anyhow::anyhow!("backup_root_files_missing"))?;
        let mut physical = self
            .physical
            .take()
            .ok_or_else(|| anyhow::anyhow!("backup_root_phase_missing"))?;
        self.reads.finish(physical.controller_stage()?)?;
        physical.finish_controller_known()?;
        // Infallible moves only after the consuming actual final native post.
        *self.continuation = true;
        self.known = true;
        Ok(KnownScheduledBackupRoot { pending })
    }

    fn confirm_birth(&mut self) -> Result<()> {
        let confirmation =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                self.check()?;
                let physical = self
                    .physical
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("backup_root_phase_missing"))?;
                let pending = self
                    .pending
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("backup_root_files_missing"))?;
                let stage = physical.controller_stage()?;
                // A second one-use lexical permit from the SAME actual creator,
                // never a returned/public token or a reconstructed native parent.
                let permit = RootBirthWritePermit {
                    _identity: &self.write_identity,
                    reads: std::ptr::from_ref(&self.reads),
                    stage: std::ptr::from_ref(stage),
                    pending: std::ptr::from_ref(pending),
                };
                self.reads
                    .confirm_scheduled_backup_root_creation(stage, pending, permit)
            }));
        let confirmation_post =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check()));
        if !matches!(&confirmation, Ok(Ok(()))) || !matches!(&confirmation_post, Ok(Ok(()))) {
            self.refuse();
        }
        match confirmation {
            Err(panic) => std::panic::resume_unwind(panic),
            Ok(Err(error)) => Err(error),
            Ok(Ok(())) => match confirmation_post {
                Err(panic) => std::panic::resume_unwind(panic),
                Ok(result) => result,
            },
        }
    }

    fn check(&mut self) -> Result<()> {
        let requested = (|| {
            ensure!(!*self.continuation, "backup_root_parent_released");
            let physical = self
                .physical
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("backup_root_phase_missing"))?;
            physical.check()?;
            self.lineage.check(
                self.selection,
                &mut self.reads,
                physical.controller_stage()?,
                &mut self.observed,
            )?;
            if let Some(pending) = &mut self.pending {
                physical.check_scheduled_backup_root(pending)?;
            }
            physical.check()
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    fn refuse(&mut self) {
        *self.continuation = false;
        self.observed.refuse();
        self.reads.refuse();
        if let Some(physical) = &mut self.physical {
            physical.refuse();
        }
        if let Some(pending) = &mut self.pending {
            pending.refuse();
        }
    }
}

impl Drop for PendingScheduledRootBirth<'_, '_> {
    fn drop(&mut self) {
        // No IO/check/clock/signing in Drop; an unfinished parent is negative.
        // A later row or file cannot reconstitute this actual borrowed parent.
        if !self.known {
            self.refuse();
        }
    }
}

/// Continuity of this successful actual creator only, not a source/capture
/// grant. No constructor from rows/files/markers, positive reboot or getter.
pub(in crate::security_epoch) struct KnownScheduledBackupRoot {
    pending: PendingBackupRoot,
}

// The only initializer is the genuine whole-parent factory above. No Clone,
// serialization, independent factory or value/boolean can supply this borrow.
struct RootBirthWriteIdentity;

pub(in crate::security_epoch) struct RootBirthWritePermit<'parent, 'connection, 'role> {
    _identity: &'parent RootBirthWriteIdentity,
    reads: *const CounterRequest<'connection>,
    stage: *const EnrolledRoleStage<'role>,
    pending: *const PendingBackupRoot,
}

impl RootBirthWritePermit<'_, '_, '_> {
    pub(in crate::security_epoch) fn require_actual(
        &self,
        reads: &CounterRequest<'_>,
        stage: &EnrolledRoleStage<'_>,
        pending: &PendingBackupRoot,
    ) -> Result<()> {
        ensure!(
            std::ptr::addr_eq(self.reads, std::ptr::from_ref(reads))
                && std::ptr::addr_eq(self.stage, std::ptr::from_ref(stage))
                && std::ptr::addr_eq(self.pending, std::ptr::from_ref(pending)),
            "backup_root_creator_inputs_changed"
        );
        Ok(())
    }
}

// Concrete owner compiler controls, in this isolated owning child.
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
    assert_not_impl!(PendingScheduledRootBirth<'static, 'static>, Clone);
    assert_not_impl!(PendingScheduledRootBirth<'static, 'static>, Copy);
    assert_not_impl!(PendingScheduledRootBirth<'static, 'static>, Default);
    assert_not_impl!(PendingScheduledRootBirth<'static, 'static>, std::fmt::Debug);
    assert_not_impl!(PendingScheduledRootBirth<'static, 'static>, Send);
    assert_not_impl!(PendingScheduledRootBirth<'static, 'static>, Sync);
    assert_not_impl!(
        PendingScheduledRootBirth<'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        PendingScheduledRootBirth<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(
        PendingScheduledRootBirth<'static, 'static>,
        std::os::fd::AsFd
    );
    assert_not_impl!(
        PendingScheduledRootBirth<'static, 'static>,
        std::os::fd::AsRawFd
    );
    assert_not_impl!(
        PendingScheduledRootBirth<'static, 'static>,
        std::os::fd::IntoRawFd
    );
    assert_not_impl!(PendingScheduledRootBirth<'static, 'static>, std::ops::Deref);
    assert_not_impl!(
        PendingScheduledRootBirth<'static, 'static>,
        AsRef<std::fs::File>
    );
    assert_not_impl!(
        PendingScheduledRootBirth<'static, 'static>,
        std::borrow::Borrow<std::fs::File>
    );
    assert_not_impl!(RootBirthWritePermit<'static, 'static, 'static>, Clone);
    assert_not_impl!(RootBirthWritePermit<'static, 'static, 'static>, Copy);
    assert_not_impl!(RootBirthWritePermit<'static, 'static, 'static>, Default);
    assert_not_impl!(
        RootBirthWritePermit<'static, 'static, 'static>,
        std::fmt::Debug
    );
    assert_not_impl!(RootBirthWritePermit<'static, 'static, 'static>, Send);
    assert_not_impl!(RootBirthWritePermit<'static, 'static, 'static>, Sync);
    assert_not_impl!(
        RootBirthWritePermit<'static, 'static, 'static>,
        serde::Serialize
    );
    assert_not_impl!(
        RootBirthWritePermit<'static, 'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(KnownScheduledBackupRoot, Clone);
    assert_not_impl!(KnownScheduledBackupRoot, Copy);
    assert_not_impl!(KnownScheduledBackupRoot, Default);
    assert_not_impl!(KnownScheduledBackupRoot, std::fmt::Debug);
    assert_not_impl!(KnownScheduledBackupRoot, Send);
    assert_not_impl!(KnownScheduledBackupRoot, Sync);
    assert_not_impl!(KnownScheduledBackupRoot, serde::Serialize);
    assert_not_impl!(KnownScheduledBackupRoot, serde::Deserialize<'static>);
    assert_not_impl!(KnownScheduledBackupRoot, std::os::fd::AsFd);
    assert_not_impl!(KnownScheduledBackupRoot, std::os::fd::AsRawFd);
    assert_not_impl!(KnownScheduledBackupRoot, std::os::fd::IntoRawFd);
    assert_not_impl!(KnownScheduledBackupRoot, std::ops::Deref);
    assert_not_impl!(KnownScheduledBackupRoot, AsRef<std::fs::File>);
    assert_not_impl!(KnownScheduledBackupRoot, std::borrow::Borrow<std::fs::File>);
};

#[cfg(test)]
mod tests {
    use quote::ToTokens;

    fn method(source: &str, name: &str) -> String {
        let parsed = syn::parse_file(source).unwrap();
        let mut found = Vec::new();
        for item in parsed.items {
            if let syn::Item::Impl(item) = item {
                if name == "check_durability_profile"
                    && !item
                        .self_ty
                        .to_token_stream()
                        .to_string()
                        .starts_with("CurrentVolumePhase")
                {
                    continue;
                }
                for member in item.items {
                    if let syn::ImplItem::Fn(f) = member
                        && f.sig.ident == name
                    {
                        found.push(f.block.to_token_stream().to_string());
                    }
                }
            }
        }
        assert_eq!(found.len(), 1, "actual method {name}");
        found.pop().unwrap()
    }
    fn ordered(code: &str, sequence: &[&str]) -> bool {
        let mut tail = code;
        for target in sequence {
            let Some((_, rest)) = tail.split_once(target) else {
                return false;
            };
            tail = rest;
        }
        true
    }
    fn creator_guard(source: &str) -> bool {
        let begin = method(source, "begin_scheduled_root_birth");
        let finish = method(source, "create_known");
        ordered(
            &begin,
            &[
                "self . valid = false",
                "scheduled_backup_root_selection",
                "counter . request",
                "begin_pending_current_controller",
                "lineage . read",
                "birth . check",
                "prepare_scheduled_backup_root",
                "let checked = birth . check",
                "requested ?",
                "checked ?",
                "birth . pending = Some",
                "birth . check",
            ],
        ) && !begin.contains("finish_controller_known")
            && ordered(
                &finish,
                &[
                    "self . check",
                    "create_scheduled_backup_root",
                    "let checked = self . check",
                    "requested ?",
                    "checked ?",
                    "self . confirm_birth () ?",
                    "self . lineage . read",
                    "self . check",
                    "require_confirmed_data",
                    "self . pending . take",
                    "self . reads . finish",
                    "physical . finish_controller_known",
                    "self . continuation = true",
                    "self . known = true",
                    "KnownScheduledBackupRoot",
                ],
            )
            && !finish.contains("NativeAcquisition")
            && !finish.contains("begin_current_stage")
            && method(source, "drop").contains("if ! self . known { self . refuse")
    }
    #[test]
    fn actual_creator_keeps_whole_parent_until_external_known_and_all_final_posts() {
        let source = include_str!("scheduled_backup.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(creator_guard(source));
        for (old, new) in [
            ("self.valid = false;", "self.valid = true;"),
            (
                "stage.storage()?.scheduled_backup_root_selection()?;",
                "stage.require_current_role()?;",
            ),
            ("let checked = self.check();", "let checked = Ok(());"),
            (
                "self.reads.finish(physical.controller_stage()?)?;",
                "Ok::<(), anyhow::Error>(())?;",
            ),
            (
                "physical.finish_controller_known()?;",
                "Ok::<(), anyhow::Error>(())?;",
            ),
            ("if !self.known", "if self.known"),
        ] {
            assert_eq!(
                source.matches(old).count(),
                1,
                "actual mutation target {old}"
            );
            assert!(
                !creator_guard(&source.replacen(old, new, 1)),
                "removed {old}"
            );
        }
    }

    fn native_guard(source: &str) -> bool {
        let prepare = method(source, "prepare_scheduled_backup_root");
        ordered(
            &prepare,
            &[
                "VolumeAdmission :: Admitted",
                "ProviderAuthentication :: ConnectionRequest",
                "check_directory",
                "scheduled_backup_root_selection",
                "capture_same_owner",
                "profile . digest",
                "getrandom :: fill",
                "check_directory",
                "PendingRootFiles :: create_pending",
                "check_directory",
                "let checked = self . resources . check_current",
                "requested ?",
                "checked ?",
            ],
        ) && !prepare.contains("check_durability_profile")
            && !prepare.contains("acquire_material")
            && !prepare.contains("StorageBootstrap")
            && !prepare.contains("restore")
    }
    #[test]
    fn actual_native_creator_requires_admitted_volume_and_does_not_relabel_warm_durability() {
        let source = include_str!("../storage_authority/native_volume/scheduled_backup.rs");
        assert!(native_guard(source));
        for (old, new) in [
            ("VolumeAdmission::Admitted", "VolumeAdmission::Observed"),
            (
                "ProviderAuthentication::ConnectionRequest",
                "ProviderAuthentication::StorageBootstrap",
            ),
            (
                "scheduled_backup_root_selection()?",
                "capture_same_owner()?",
            ),
            (
                "self.check_directory(directory, anchor)?;",
                "self.check_durability_profile()?;",
            ),
        ] {
            assert!(source.contains(old));
            assert!(
                !native_guard(&source.replacen(old, new, 1)),
                "actual native mutant {old}"
            );
        }
        let volume = include_str!("../storage_authority/native_volume.rs");
        let warm = method(volume, "check_durability_profile");
        assert!(ordered(
            &warm,
            &[
                "ProviderAuthentication :: ConnectionRequest",
                "VolumeAdmission :: Refused",
                "acquisition . refuse",
                "storage_durability_requires_initial_admission"
            ]
        ));
    }

    fn caught_post(body: &str, name: &str, expected: &syn::Expr) -> bool {
        let body: syn::Block = syn::parse_str(body).unwrap();
        let Some(init) = body.stmts.iter().find_map(|stmt| match stmt {
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(p) if p.ident == name) => local.init.as_ref(),
            _ => None,
        }) else { return false; };
        let syn::Expr::Call(catch) = init.expr.as_ref() else {
            return false;
        };
        if catch.func.to_token_stream().to_string() != "std :: panic :: catch_unwind"
            || catch.args.len() != 1
        {
            return false;
        }
        let Some(syn::Expr::Call(safe)) = catch.args.first() else {
            return false;
        };
        if safe.func.to_token_stream().to_string() != "std :: panic :: AssertUnwindSafe"
            || safe.args.len() != 1
        {
            return false;
        }
        let Some(syn::Expr::Closure(closure)) = safe.args.first() else {
            return false;
        };
        if !closure.inputs.is_empty() {
            return false;
        }
        let mut actual = closure.body.as_ref();
        while let syn::Expr::Block(block) = actual {
            if !block.attrs.is_empty() || block.label.is_some() {
                return false;
            }
            let [syn::Stmt::Expr(inner, None)] = block.block.stmts.as_slice() else {
                return false;
            };
            actual = inner;
        }
        actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    fn confirmation_guard(creator: &str, counter: &str) -> bool {
        let confirm = method(creator, "confirm_birth");
        let read = method(counter, "confirm_scheduled_backup_root_creation");
        ordered(
            &confirm,
            &[
                "self . check",
                "physical . controller_stage",
                "RootBirthWritePermit",
                "self . reads . confirm_scheduled_backup_root_creation",
                "let confirmation_post",
                "self . refuse",
                "match confirmation",
                "match confirmation_post",
            ],
        ) && caught_post(
            &confirm,
            "confirmation_post",
            &syn::parse_quote!(self.check()),
        ) && ordered(
            &read,
            &[
                "permit . require_actual (self , stage , pending)",
                "self . connection . purpose == NativeRole :: EpochController",
                "self . check",
                "scheduled_backup_root_selection",
                "pending . begin_confirmation_data (& self . connection . store)",
                "self . check",
                "self . connection . credential . authorization",
                "acquisition . remaining",
                "http . request_with_ceiling",
                "Route :: ScheduledBackupRootRead",
                "pending . observe_confirmation_data",
                "let checked",
                "pending . refuse",
                "self . refuse",
                "stage . refuse_serving",
                "match requested",
                "match checked",
            ],
        ) && caught_post(&read, "checked", &syn::parse_quote!(self.check(stage)))
            && !confirm.contains("finish_controller_known")
            && !confirm.contains("NativeAcquisition :: begin")
            && !read.contains("finish_controller_known")
            && !read.contains("NativeAcquisition :: begin")
    }

    #[test]
    fn actual_confirmation_keeps_creator_inputs_and_real_counter_and_parent_posts_on_error_and_panic()
     {
        let creator = include_str!("scheduled_backup.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let counter = include_str!("../authenticated_reads/connection.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(creator_guard(creator));
        assert!(confirmation_guard(creator, counter));
        // Replace the ACTUAL named local initializer through the AST. Native
        // formatting may use a transparent closure block, not a second call.
        for (source, name, post, is_creator) in [
            (creator, "confirm_birth", "confirmation_post", true),
            (
                counter,
                "confirm_scheduled_backup_root_creation",
                "checked",
                false,
            ),
        ] {
            let mut parsed = syn::parse_file(source).unwrap();
            let mut changed = 0;
            for item in &mut parsed.items {
                if let syn::Item::Impl(item) = item {
                    for member in &mut item.items {
                        if let syn::ImplItem::Fn(f) = member
                            && f.sig.ident == name
                        {
                            for stmt in &mut f.block.stmts {
                                if let syn::Stmt::Local(local) = stmt
                                    && matches!(&local.pat, syn::Pat::Ident(p) if p.ident == post)
                                {
                                    local.init.as_mut().unwrap().expr =
                                        Box::new(syn::parse_quote!(Ok(Ok(()))));
                                    changed += 1;
                                }
                            }
                        }
                    }
                }
            }
            assert_eq!(changed, 1);
            let mutated = parsed.to_token_stream().to_string();
            assert!(!if is_creator {
                confirmation_guard(&mutated, counter)
            } else {
                confirmation_guard(creator, &mutated)
            });
        }
        for (old, replacement) in [
            ("self.confirm_birth()?;", "Ok::<(), anyhow::Error>(())?;"),
            (".require_confirmed_data()?;", ";"),
        ] {
            assert_eq!(creator.matches(old).count(), 1);
            assert!(!creator_guard(&creator.replacen(old, replacement, 1)));
        }
    }
}

#[cfg(test)]
mod writer_tests {
    use quote::ToTokens;
    fn guarded(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let mut methods = Vec::new();
        for item in file.items {
            if let syn::Item::Impl(item) = item {
                for member in item.items {
                    if let syn::ImplItem::Fn(f) = member
                        && f.sig.ident == "create_scheduled_backup_root"
                    {
                        methods.push(f);
                    }
                }
            }
        }
        if methods.len() != 1 {
            return false;
        }
        let method = &methods[0];
        let signature = method.sig.to_token_stream().to_string();
        let body = method.block.to_token_stream().to_string();
        let Some((before, after)) = body.split_once("http . request_with_ceiling") else {
            return false;
        };
        signature.contains("RootBirthWritePermit")
            && before.contains("permit . require_actual (self , stage , pending)")
            && before.contains("self . connection . purpose == NativeRole :: EpochController")
            && before.contains("pending . submit_birth_data (& self . connection . store)")
            && after.contains("Route :: ScheduledBackupRootCommit")
            && after.contains("pending . observe_birth_data")
            && after.contains("let checked = self . check (stage)")
            && after.contains("pending . refuse")
            && after.contains("requested ? ; checked")
    }
    #[test]
    fn actual_fixed_write_requires_whole_parent_seal_and_keeps_generic_reads_write_refusing() {
        let source = include_str!("../authenticated_reads/connection.rs");
        assert!(guarded(source));
        let parsed = syn::parse_file(source).unwrap();
        let mut selected = None;
        for item in &parsed.items {
            if let syn::Item::Impl(item) = item {
                for member in &item.items {
                    if let syn::ImplItem::Fn(f) = member
                        && f.sig.ident == "create_scheduled_backup_root"
                    {
                        assert!(selected.is_none());
                        selected = Some(f.to_token_stream().to_string());
                    }
                }
            }
        }
        let selected = format!("impl CounterRequest<'_> {{ {} }}", selected.unwrap());
        for (old, new) in [
            (
                "permit . require_actual (self , stage , pending) ? ;",
                "Ok (()) ? ;",
            ),
            (
                "self . connection . purpose == NativeRole :: EpochController",
                "self . connection . purpose == NativeRole :: AppHost",
            ),
            ("pending . observe_birth_data (& bytes)", "Ok (())"),
            ("Route :: ScheduledBackupRootCommit", "Route :: EpochCommit"),
        ] {
            assert_eq!(
                selected.matches(old).count(),
                1,
                "actual write target {old}"
            );
            assert!(
                !guarded(&selected.replacen(old, new, 1)),
                "write guard mutant {old}"
            );
        }
        let source = parsed;
        let route = source
            .items
            .iter()
            .find_map(|i| match i {
                syn::Item::Fn(f) if f.sig.ident == "counter_read_route" => {
                    Some(f.block.to_token_stream().to_string())
                }
                _ => None,
            })
            .unwrap();
        assert!(!route.contains("EpochCommit"));
        assert!(route.contains("epoch_counter_request_write_or_route_refused"));
    }
}

#[cfg(test)]
mod seal_tests {
    use quote::ToTokens;
    use syn::visit::Visit;
    fn guarded(source: &str) -> bool {
        let parsed = syn::parse_file(source).unwrap();
        struct Constructions {
            owner: Option<String>,
            method: Option<String>,
            all: Vec<(Option<String>, Option<String>, String)>,
        }
        impl<'a> Visit<'a> for Constructions {
            fn visit_item_impl(&mut self, item: &'a syn::ItemImpl) {
                let before = self.owner.take();
                self.owner = match item.self_ty.as_ref() {
                    syn::Type::Path(t) => t.path.segments.last().map(|s| s.ident.to_string()),
                    _ => None,
                };
                syn::visit::visit_item_impl(self, item);
                self.owner = before;
            }
            fn visit_impl_item_fn(&mut self, item: &'a syn::ImplItemFn) {
                let before = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = before;
            }
            fn visit_expr_struct(&mut self, value: &'a syn::ExprStruct) {
                if value
                    .path
                    .segments
                    .last()
                    .is_some_and(|p| p.ident == "RootBirthWritePermit")
                {
                    self.all.push((
                        self.owner.clone(),
                        self.method.clone(),
                        value.to_token_stream().to_string(),
                    ));
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let mut found = Constructions {
            owner: None,
            method: None,
            all: Vec::new(),
        };
        found.visit_file(&parsed);
        let expected: syn::Expr = syn::parse_quote!(RootBirthWritePermit {
            _identity: &self.write_identity,
            reads: std::ptr::from_ref(&self.reads),
            stage: std::ptr::from_ref(stage),
            pending: std::ptr::from_ref(pending),
        });
        let expected = expected.to_token_stream().to_string();
        if found.all.len() != 2
            || found.all.iter().any(|(owner, _, value)| {
                owner.as_deref() != Some("PendingScheduledRootBirth") || *value != expected
            })
        {
            return false;
        }
        let names = found
            .all
            .iter()
            .map(|(_, name, _)| name.as_deref())
            .collect::<std::collections::BTreeSet<_>>();
        if names
            != [Some("create_known"), Some("confirm_birth")]
                .into_iter()
                .collect()
        {
            return false;
        }
        let mut create = None;
        let mut confirm = None;
        let mut binding = None;
        for item in parsed.items {
            if let syn::Item::Impl(item) = item {
                for item in item.items {
                    if let syn::ImplItem::Fn(f) = item {
                        let text = f.block.to_token_stream().to_string();
                        match f.sig.ident.to_string().as_str() {
                            "create_known" => create = Some(text),
                            "confirm_birth" => confirm = Some(text),
                            "require_actual" => binding = Some(text),
                            _ => (),
                        }
                    }
                }
            }
        }
        let (Some(create), Some(confirm), Some(bound)) = (create, confirm, binding) else {
            return false;
        };
        let expected_binding: syn::Block = syn::parse_quote!({
            ensure!(
                std::ptr::addr_eq(self.reads, std::ptr::from_ref(reads))
                    && std::ptr::addr_eq(self.stage, std::ptr::from_ref(stage))
                    && std::ptr::addr_eq(self.pending, std::ptr::from_ref(pending)),
                "backup_root_creator_inputs_changed"
            );
            Ok(())
        });
        bound == expected_binding.to_token_stream().to_string()
            && create.contains(&expected)
            && confirm.contains(&expected)
            && create.contains("create_scheduled_backup_root (stage , pending , permit)")
            && confirm.contains("confirm_scheduled_backup_root_creation (stage , pending , permit)")
    }
    #[test]
    fn actual_lexical_seal_has_only_write_and_confirmation_in_the_same_whole_parent() {
        let source = include_str!("scheduled_backup.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(guarded(source));
        for (old, new) in [
            (
                "reads: std::ptr::from_ref(&self.reads)",
                "reads: std::ptr::from_ref(&other.reads)",
            ),
            (
                "stage: std::ptr::from_ref(stage)",
                "stage: std::ptr::from_ref(other_stage)",
            ),
            (
                "pending: std::ptr::from_ref(pending)",
                "pending: std::ptr::from_ref(other_pending)",
            ),
            (
                "std::ptr::addr_eq(self.reads, std::ptr::from_ref(reads))",
                "true",
            ),
            (
                "std::ptr::addr_eq(self.stage, std::ptr::from_ref(stage))",
                "true",
            ),
            (
                "std::ptr::addr_eq(self.pending, std::ptr::from_ref(pending))",
                "true",
            ),
        ] {
            let expected_count = if old.starts_with("std::ptr::addr_eq") {
                1
            } else {
                2
            };
            assert_eq!(
                source.matches(old).count(),
                expected_count,
                "seal mutation {old}"
            );
            for (at, _) in source.match_indices(old) {
                let changed = format!("{}{}{}", &source[..at], new, &source[at + old.len()..]);
                assert!(!guarded(&changed), "seal mutation {old} at {at}");
            }
        }
        let duplicate = format!(
            "{source} fn other() {{ let x=RootBirthWritePermit {{_identity:&identity, reads:std::ptr::null(),stage:std::ptr::null(),pending:std::ptr::null()}}; }}"
        );
        assert!(!guarded(&duplicate));
    }
}
