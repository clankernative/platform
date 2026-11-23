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
                    if let syn::ImplItem::Fn(f) = member {
                        if f.sig.ident == name {
                            found.push(f.block.to_token_stream().to_string());
                        }
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
                    "self . lineage . read",
                    "self . check",
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
                    if let syn::ImplItem::Fn(f) = member {
                        if f.sig.ident == "create_scheduled_backup_root" {
                            methods.push(f);
                        }
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
                    if let syn::ImplItem::Fn(f) = member {
                        if f.sig.ident == "create_scheduled_backup_root" {
                            assert!(selected.is_none());
                            selected = Some(f.to_token_stream().to_string());
                        }
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
        struct Constructions(Vec<String>);
        impl<'a> Visit<'a> for Constructions {
            fn visit_expr_struct(&mut self, s: &'a syn::ExprStruct) {
                if s.path
                    .segments
                    .last()
                    .is_some_and(|p| p.ident == "RootBirthWritePermit")
                {
                    self.0.push(s.to_token_stream().to_string());
                }
                syn::visit::visit_expr_struct(self, s);
            }
        }
        let mut all = Constructions(Vec::new());
        all.visit_file(&parsed);
        if all.0.len() != 1 {
            return false;
        }
        let expected: syn::Expr = syn::parse_quote!(RootBirthWritePermit {
            _identity: &self.write_identity,
            reads: std::ptr::from_ref(&self.reads),
            stage: std::ptr::from_ref(stage),
            pending: std::ptr::from_ref(pending),
        });
        if all.0[0] != expected.to_token_stream().to_string() {
            return false;
        }
        let mut constructor = None;
        let mut binding = None;
        for item in parsed.items {
            if let syn::Item::Impl(item) = item {
                for item in item.items {
                    if let syn::ImplItem::Fn(f) = item {
                        if f.sig.ident == "create_known" {
                            constructor = Some(f.block.to_token_stream().to_string());
                        } else if f.sig.ident == "require_actual" {
                            binding = Some(f.block.to_token_stream().to_string());
                        }
                    }
                }
            }
        }
        let Some(body) = constructor else {
            return false;
        };
        let Some(bound) = binding else { return false };
        let expected: syn::Block = syn::parse_quote!({
            ensure!(
                std::ptr::addr_eq(self.reads, std::ptr::from_ref(reads))
                    && std::ptr::addr_eq(self.stage, std::ptr::from_ref(stage))
                    && std::ptr::addr_eq(self.pending, std::ptr::from_ref(pending)),
                "backup_root_creator_inputs_changed"
            );
            Ok(())
        });
        bound == expected.to_token_stream().to_string()
            && body.contains(&all.0[0])
            && body.contains("create_scheduled_backup_root (stage , pending , permit)")
    }
    #[test]
    fn actual_lexical_seal_has_one_whole_parent_constructor_and_binds_every_actual_input() {
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
            assert_eq!(source.matches(old).count(), 1, "seal mutation {old}");
            assert!(
                !guarded(&source.replacen(old, new, 1)),
                "seal mutation {old}"
            );
        }
        let duplicate = format!(
            "{source} fn other() {{ let x=RootBirthWritePermit {{_identity:&identity, reads:std::ptr::null(),stage:std::ptr::null(),pending:std::ptr::null()}}; }}"
        );
        assert!(!guarded(&duplicate));
    }
}
