//! Retain the actual successfully prepared file across later bounded phases.
//! This owns continuity, not P3, activation, an app holder or writer authority.

use super::{
    FileIdentity, OriginalCreatorFd, PreparedFileProjection, PreparedInitialFile,
    ReviewedFileLayout,
};
#[cfg(target_os = "linux")]
use super::{observe_anchored_file, observe_current_anchored_file};
use crate::security_epoch::storage_authority::native_volume::CurrentVolumePhase;
use crate::security_epoch::{
    authenticated_reads::{ControllerEpochReads, ProviderEpochReads},
    controller::bootstrap_timing::BootstrapTiming,
    controller::evidence::{PreparationFailure, PreparationProgress, PreparationStep},
    native_enrollment::{EnrolledRoleStage, SameEnrolledOwner, StagePurpose},
    storage_authority::{
        DirectoryIdentity, ReviewedStorageSelection, native_volume::NativeVolumeContinuity,
    },
};
use anyhow::{Result, ensure};
use std::{fs::File, thread::ThreadId};

#[cfg(test)]
pub(in crate::security_epoch) mod lifecycle_fixture;

pub(crate) enum PreparedRetentionOutcome<'role> {
    Retained(Box<PreparedFileContinuity>),
    Refused {
        original: Box<PreparedInitialFile<'role>>,
        error: anyhow::Error,
    },
}

pub(crate) struct PreparedFileContinuity {
    selection: ReviewedStorageSelection,
    directory: File,
    anchor: DirectoryIdentity,
    file: File,
    identity: FileIdentity,
    layout: ReviewedFileLayout,
    volume: NativeVolumeContinuity,
    process: u32,
    thread: ThreadId,
    valid: bool,
}

/// Borrows the SAME retained file/device owners and owns one fresh actual
/// controller stage. It is neither a first-holder proof nor a writer permit.
/// An unfinished phase leaves its parent refused without relying on Drop.
pub(crate) struct CurrentPreparedFilePhase<'file, 'role> {
    phase: CurrentVolumePhase<'file, 'role>,
    selection: &'file ReviewedStorageSelection,
    directory: &'file File,
    anchor: &'file DirectoryIdentity,
    file: &'file File,
    identity: &'file FileIdentity,
    layout: &'file ReviewedFileLayout,
    process: u32,
    thread: ThreadId,
    disposition: FilePhaseDisposition<'file>,
}

/// Irreversibly closes this file's continuation before rendezvous I/O. It owns
/// no role, provider acquisition or permission. Dropping it leaves the original
/// file refused; only the eventual current phase's known completion settles it.
pub(in crate::security_epoch::storage_authority) struct PendingPreparedFilePhase<'file> {
    volume: &'file mut NativeVolumeContinuity,
    selection: &'file ReviewedStorageSelection,
    directory: &'file File,
    anchor: &'file DirectoryIdentity,
    file: &'file File,
    identity: &'file FileIdentity,
    layout: &'file ReviewedFileLayout,
    process: u32,
    thread: ThreadId,
    disposition: FilePhaseDisposition<'file>,
}

/// The physical counterpart has a distinct acquisition method: legitimate
/// later writes must never be accepted as an unchanged initial image. Its
/// private inputs are still only closed continuity, not native permission.
pub(in crate::security_epoch::storage_authority) struct PendingPhysicalFilePhase<'file> {
    inputs: PendingPreparedFilePhase<'file>,
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
    assert_not_impl!(PendingPreparedFilePhase<'static>, Clone);
    assert_not_impl!(PendingPreparedFilePhase<'static>, Copy);
    assert_not_impl!(PendingPreparedFilePhase<'static>, Default);
    assert_not_impl!(PendingPreparedFilePhase<'static>, Send);
    assert_not_impl!(PendingPreparedFilePhase<'static>, Sync);
    assert_not_impl!(PendingPreparedFilePhase<'static>, serde::Serialize);
    assert_not_impl!(
        PendingPreparedFilePhase<'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(PendingPhysicalFilePhase<'static>, Clone);
    assert_not_impl!(PendingPhysicalFilePhase<'static>, Copy);
    assert_not_impl!(PendingPhysicalFilePhase<'static>, Default);
    assert_not_impl!(PendingPhysicalFilePhase<'static>, Send);
    assert_not_impl!(PendingPhysicalFilePhase<'static>, Sync);
    assert_not_impl!(PendingPhysicalFilePhase<'static>, serde::Serialize);
    assert_not_impl!(
        PendingPhysicalFilePhase<'static>,
        serde::Deserialize<'static>
    );
};

/// A current physical-file phase after legitimate application writes. It is
/// deliberately distinct from CurrentPreparedFilePhase: the initial exchange
/// cannot accept it or reinterpret modified bytes as a prepared initial image.
/// It supplies no provider P3, activation, counter or current writer authority.
pub(crate) struct CurrentPhysicalFilePhase<'file, 'role> {
    inner: CurrentPreparedFilePhase<'file, 'role>,
}

/// Pessimistically close continuity before any fallible phase work. Only the
/// fixed operation's known successful final check may restore it. This helper
/// has no native constructor, clock, descriptor or authority of its own.
struct FilePhaseDisposition<'file> {
    continuation: &'file mut bool,
    active: bool,
}

impl<'file> FilePhaseDisposition<'file> {
    fn begin(continuation: &'file mut bool) -> Result<Self> {
        ensure!(*continuation, "retained_preparation_refused");
        *continuation = false;
        Ok(Self {
            continuation,
            active: true,
        })
    }

    fn check(&self) -> Result<()> {
        ensure!(
            self.active && !*self.continuation,
            "retained_file_phase_refused"
        );
        Ok(())
    }

    fn refuse(&mut self) {
        self.active = false;
    }

    fn complete(self) -> Result<()> {
        self.check()?;
        *self.continuation = true;
        Ok(())
    }
}

impl<'role> PreparedInitialFile<'role> {
    /// Consume only a SUCCESSFULLY checked preparation. On any failure the
    /// original file/anchor/stage remain owned by the refused outcome. A later
    /// acquisition cannot restart an expired or failed preparation.
    pub(crate) fn retain_for_current_phases(mut self) -> PreparedRetentionOutcome<'role> {
        let timings = self.creator.authority.timings();
        let binding = (|| {
            timings.measure(crate::security_epoch::controller::preparation_timing::Operation::RetentionBefore, || self.check_original()).map_err(|error| {
                PreparationFailure::with_progress(
                    PreparationStep::OriginalRetentionBefore,
                    error,
                    PreparationProgress {
                        last_checked_us: self.acquisition.last_checked_elapsed_micros(),
                        ..PreparationProgress::default()
                    },
                )
            })?;
            let binding = match &mut self.creator.authority.issuer {
                crate::security_epoch::storage_authority::StorageIssuerOwner::Native(volume) => timings.measure(crate::security_epoch::controller::preparation_timing::Operation::RetentionOwner, || volume.capture_same_owner()).map_err(|error| {
                    PreparationFailure::with_progress(
                        PreparationStep::OriginalRetentionOwner,
                        error,
                        PreparationProgress {
                            last_checked_us: self.acquisition.last_checked_elapsed_micros(),
                            ..PreparationProgress::default()
                        },
                    )
                })?,
                #[cfg(test)]
                crate::security_epoch::storage_authority::StorageIssuerOwner::UnqualifiedFilesystemFixture { .. } => {
                    anyhow::bail!("storage_native_retention_requires_enrolled_controller")
                }
            };
            // The final genuine guard must remain the final I/O before the
            // infallible owner move. Do not wrap it in a diagnostic clock read.
            self.check_original().map_err(|error| {
                PreparationFailure::with_progress(
                    PreparationStep::OriginalRetentionAfter,
                    error,
                    PreparationProgress {
                        last_checked_us: self.acquisition.last_checked_elapsed_micros(),
                        ..PreparationProgress::default()
                    },
                )
            })?;
            Ok(binding)
        })();
        match binding {
            Ok(binding) => PreparedRetentionOutcome::Retained(Box::new(
                PreparedFileContinuity::retain(self, binding),
            )),
            Err(error) => {
                self.creator
                    .authority
                    .refuse_preparation(&mut self.acquisition);
                PreparedRetentionOutcome::Refused {
                    original: Box::new(self),
                    error,
                }
            }
        }
    }
}

impl PreparedFileContinuity {
    // Only retain_for_current_phases calls this, after the final original-clock
    // file check and genuine same-enrolled-owner capture. No fallible I/O or
    // descriptor reopen occurs between that check and retaining these owners.
    fn retain(original: PreparedInitialFile<'_>, binding: SameEnrolledOwner) -> Self {
        let OriginalCreatorFd {
            authority,
            file,
            identity,
            ..
        } = original.creator;
        let volume = match authority.issuer {
            crate::security_epoch::storage_authority::StorageIssuerOwner::Native(volume) =>
                volume.retain_resources(binding),
            #[cfg(test)]
            crate::security_epoch::storage_authority::StorageIssuerOwner::UnqualifiedFilesystemFixture { .. } =>
                unreachable!("fixture retention is refused before consuming the original"),
        };
        Self {
            selection: authority.selection,
            directory: authority.directory,
            anchor: authority.identity,
            file,
            identity,
            layout: original.layout,
            volume,
            process: authority.process,
            thread: authority.thread,
            valid: true,
        }
    }

    /// Completed preparation is not renewed. All provider reads, file checks
    /// and later peer work spend THIS stage's original interval. An abandoned,
    /// failed or unknown operation cannot start another phase on this file.
    pub(crate) fn begin_initial_phase<'file, 'role>(
        &'file mut self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentPreparedFilePhase<'file, 'role>> {
        self.begin_pending_initial_phase()?.acquire(stage)
    }

    /// Close before a first-holder readiness exchange, without starting file
    /// or provider I/O. The caller must still supply the actual original stage.
    pub(in crate::security_epoch::storage_authority) fn begin_pending_initial_phase(
        &mut self,
    ) -> Result<PendingPreparedFilePhase<'_>> {
        let disposition = FilePhaseDisposition::begin(&mut self.valid)?;
        Ok(PendingPreparedFilePhase {
            volume: &mut self.volume,
            selection: &self.selection,
            directory: &self.directory,
            anchor: &self.anchor,
            file: &self.file,
            identity: &self.identity,
            layout: &self.layout,
            process: self.process,
            thread: self.thread,
            disposition,
        })
    }

    /// Close the SAME original file before readiness I/O. The pending input
    /// owns no provider or role permission; acquire still needs its actual
    /// original stage and all current physical guards.
    pub(in crate::security_epoch::storage_authority) fn begin_pending_physical_phase(
        &mut self,
    ) -> Result<PendingPhysicalFilePhase<'_>> {
        Ok(PendingPhysicalFilePhase {
            inputs: self.begin_pending_initial_phase()?,
        })
    }

    /// Read-only continuity observation; it grants no peer, P3 or writer
    /// authority. Legitimate later writes need the serving transition.
    pub(crate) fn check_initial(&mut self, stage: EnrolledRoleStage<'_>) -> Result<()> {
        self.begin_initial_phase(stage)?.finish_checked()
    }
}

impl<'file> PendingPhysicalFilePhase<'file> {
    pub(in crate::security_epoch::storage_authority) fn acquire<'role>(
        self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentPhysicalFilePhase<'file, 'role>> {
        let inputs = self.inputs;
        inputs.disposition.check()?;
        let phase = inputs.volume.begin_current(stage)?;
        let mut current = CurrentPhysicalFilePhase {
            inner: CurrentPreparedFilePhase {
                phase,
                selection: inputs.selection,
                directory: inputs.directory,
                anchor: inputs.anchor,
                file: inputs.file,
                identity: inputs.identity,
                layout: inputs.layout,
                process: inputs.process,
                thread: inputs.thread,
                disposition: inputs.disposition,
            },
        };
        current.check()?;
        Ok(current)
    }
}

impl<'file> PendingPreparedFilePhase<'file> {
    pub(in crate::security_epoch::storage_authority) fn acquire_authenticated<'role>(
        self,
        stage: EnrolledRoleStage<'role>,
        authentication: ProviderEpochReads,
        trace: &BootstrapTiming,
    ) -> Result<CurrentPreparedFilePhase<'file, 'role>> {
        let guard = authentication.arm_refusal()?;
        self.disposition.check()?;
        let phase = self
            .volume
            .begin_authenticated(stage, authentication, trace)?;
        let mut current = CurrentPreparedFilePhase {
            phase,
            selection: self.selection,
            directory: self.directory,
            anchor: self.anchor,
            file: self.file,
            identity: self.identity,
            layout: self.layout,
            process: self.process,
            thread: self.thread,
            disposition: self.disposition,
        };
        current.check()?;
        guard.complete()?;
        Ok(current)
    }

    pub(in crate::security_epoch::storage_authority) fn acquire<'role>(
        self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentPreparedFilePhase<'file, 'role>> {
        self.acquire_phase(stage, false)
    }

    pub(in crate::security_epoch::storage_authority) fn acquire_first_holder<'role>(
        self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentPreparedFilePhase<'file, 'role>> {
        self.acquire_phase(stage, true)
    }

    fn acquire_phase<'role>(
        self,
        stage: EnrolledRoleStage<'role>,
        initial: bool,
    ) -> Result<CurrentPreparedFilePhase<'file, 'role>> {
        self.disposition.check()?;
        let phase = if initial {
            self.volume.begin_first_holder(stage)?
        } else {
            self.volume.begin_initial(stage)?
        };
        let mut current = CurrentPreparedFilePhase {
            phase,
            selection: self.selection,
            directory: self.directory,
            anchor: self.anchor,
            file: self.file,
            identity: self.identity,
            layout: self.layout,
            process: self.process,
            thread: self.thread,
            disposition: self.disposition,
        };
        current.check()?;
        Ok(current)
    }
}

impl<'file, 'role> CurrentPreparedFilePhase<'file, 'role> {
    /// Only authentication DATA, using the actual volume's hidden owning
    /// stage. Full file validation is a separate mandatory caller obligation.
    pub(in crate::security_epoch::storage_authority) fn check_authentication(
        &mut self,
        reads: &mut ControllerEpochReads,
    ) -> Result<()> {
        let result = (|| {
            self.check_budget_liveness()?;
            self.phase.check_authentication(reads)
        })();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// Local refusal/owner liveness only, for pure decoding's clock budget.
    /// This does not inspect the file or grant physical/current authority.
    pub(in crate::security_epoch::storage_authority) fn check_budget_liveness(&self) -> Result<()> {
        self.disposition.check()?;
        ensure!(
            self.process == std::process::id() && self.thread == std::thread::current().id(),
            "retained_preparation_owner_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch::storage_authority) fn check_authenticated_reads(
        &mut self,
        reads: &ControllerEpochReads,
    ) -> Result<()> {
        self.check()?;
        self.phase.check_authenticated_reads(reads)
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.check_budget_liveness()?;
            ensure!(
                self.layout.proposal.selection == *self.selection.digest()
                    && self.layout.proposal.core == *self.selection.seed()
                    && self.layout.proposal.length == self.layout.image.bytes().len(),
                "retained_preparation_layout_changed"
            );
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("original_file_platform_unsupported")
            }
            #[cfg(target_os = "linux")]
            {
                check_retained_initial_bytes(self.file, self.layout.image.bytes(), || {
                    check_identity(
                        &mut self.phase,
                        self.directory,
                        self.anchor,
                        self.file,
                        self.identity,
                        Some(self.layout.proposal.length),
                    )
                })
            }
        })();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// Only the authenticated initial-holder composition may interpret this
    /// fixed operation as P3. All real resources remain owned by THIS phase;
    /// a local filesystem fixture cannot construct its native volume owner.
    pub(crate) fn check_initial_durability(&mut self) -> Result<()> {
        let result = (|| {
            self.check()?;
            self.phase.check_durability_profile()?;
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("original_file_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                rustix::fs::fsync(self.file)?;
                self.check()?;
                rustix::fs::fsync(self.directory)?;
                self.check()?;
                self.phase.check_durability_profile()?;
                self.check()
            }
        })();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// The fixed, successfully observed activation performs its LAST initial
    /// byte check before notifying the App that legitimate writes may begin.
    /// The SAME descriptors/provider phase remain live for physical postchecks.
    pub(in crate::security_epoch) fn into_bootstrap_physical_checked(
        mut self,
    ) -> Result<CurrentPhysicalFilePhase<'file, 'role>> {
        // An initial-handshake interval cannot mint a current physical phase,
        // even if a future internal caller reaches this conversion directly.
        self.phase
            .controller_stage()?
            .require_purpose(StagePurpose::StorageBootstrap)?;
        self.check()?;
        let mut physical = CurrentPhysicalFilePhase { inner: self };
        physical.check()?;
        Ok(physical)
    }

    /// A statement only, after current file/provider checks. The closed S1
    /// exchange must authenticate it before the App parses any SQLite bytes.
    pub(crate) fn projection(&mut self) -> Result<PreparedFileProjection> {
        let result = (|| {
            self.check()?;
            let value = PreparedFileProjection {
                core: self.layout.proposal.core.clone(),
                marker: self.layout.proposal.marker.clone(),
                image: self.layout.proposal.image.clone(),
                length: self.layout.proposal.length.try_into()?,
                identity: self.identity.clone(),
            };
            self.check()?;
            Ok(value)
        })();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// Lend the SAME phase's controller stage, never a replacement acquisition.
    /// The fixed peer releases this borrow and checks the file again after I/O.
    pub(crate) fn controller_stage(&mut self) -> Result<&mut EnrolledRoleStage<'role>> {
        self.check()?;
        let result = self.phase.controller_stage();
        if result.is_err() {
            self.disposition.refuse();
        }
        result
    }

    /// The fixed consumer calls this only after a known successful operation
    /// and final message/result checks. An unknown or failed handshake must
    /// retain/refuse this phase, never complete it. This creates no peer proof.
    pub(crate) fn finish_checked(mut self) -> Result<()> {
        self.check()?;
        self.disposition.complete()
    }

    pub(crate) fn refuse(&mut self) {
        self.disposition.refuse();
    }
}

impl<'role> CurrentPhysicalFilePhase<'_, 'role> {
    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.inner.disposition.check()?;
            ensure!(
                self.inner.process == std::process::id()
                    && self.inner.thread == std::thread::current().id(),
                "retained_storage_executor_changed"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("original_file_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                // Active length/content may change under legitimate writes.
                // Identity/modes/nlink/mount and fixed named leaf remain exact;
                // this does not validate or grant the active contents.
                check_identity(
                    &mut self.inner.phase,
                    self.inner.directory,
                    self.inner.anchor,
                    self.inner.file,
                    self.inner.identity,
                    None,
                )
            }
        })();
        if result.is_err() {
            self.inner.disposition.refuse();
        }
        result
    }

    pub(crate) fn controller_stage(&mut self) -> Result<&mut EnrolledRoleStage<'role>> {
        self.check()?;
        self.controller_stage_after_check()
    }

    /// Fixed current-phase composition only: the caller has just completed
    /// this file's full check, with no intervening I/O. Every actual peer I/O
    /// still validates the borrowed stage and is followed by a fresh file
    /// check. No checked flag, transferable token or lifetime is introduced.
    pub(in crate::security_epoch::storage_authority) fn controller_stage_after_check(
        &mut self,
    ) -> Result<&mut EnrolledRoleStage<'role>> {
        self.inner.disposition.check()?;
        let result = self.inner.phase.controller_stage_after_file_check();
        if result.is_err() {
            self.inner.disposition.refuse();
        }
        result
    }

    pub(crate) fn finish_checked(mut self) -> Result<()> {
        self.check()?;
        self.inner.disposition.complete()
    }

    pub(crate) fn refuse(&mut self) {
        self.inner.disposition.refuse();
    }
}

#[cfg(test)]
mod cold_durability_tests {
    // These are restoration controls over the actual cold admission body,
    // not a fake native owner or a new provider/durability implementation.
    fn path(value: &syn::Expr) -> Option<String> {
        match value {
            syn::Expr::Path(value) => Some(
                value
                    .path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            ),
            syn::Expr::Field(value) => {
                let syn::Member::Named(field) = &value.member else {
                    return None;
                };
                Some(format!("{}.{}", path(&value.base)?, field))
            }
            _ => None,
        }
    }

    fn call(value: &syn::Expr, name: &str, arguments: &[&str]) -> bool {
        let (actual, args) = match value {
            syn::Expr::MethodCall(value) => (
                path(&value.receiver).map(|receiver| format!("{receiver}.{}", value.method)),
                &value.args,
            ),
            syn::Expr::Call(value) => (path(&value.func), &value.args),
            _ => return false,
        };
        actual.as_deref() == Some(name)
            && args.len() == arguments.len()
            && args
                .iter()
                .zip(arguments)
                .all(|(value, expected)| path(value).as_deref() == Some(*expected))
    }

    fn propagated(statement: &syn::Stmt, name: &str, arguments: &[&str]) -> bool {
        matches!(statement, syn::Stmt::Expr(syn::Expr::Try(value), Some(_)) if call(&value.expr, name, arguments))
    }

    fn actual_cold_sequence(source: &str) -> bool {
        let file = syn::parse_file(source).unwrap();
        let Some(body) = file.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty, syn::Type::Path(value)
                if value.path.segments.len() == 1 && value.path.segments[0].ident == "CurrentPreparedFilePhase") { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == "check_initial_durability" => Some(&function.block),
                _ => None,
            })
        }) else { return false; };
        if body.stmts.len() != 3 {
            return false;
        }
        let syn::Stmt::Local(result) = &body.stmts[0] else {
            return false;
        };
        if !matches!(&result.pat, syn::Pat::Ident(value) if value.ident == "result") {
            return false;
        }
        let Some(initializer) = &result.init else {
            return false;
        };
        let syn::Expr::Call(invoked) = &*initializer.expr else {
            return false;
        };
        if !invoked.args.is_empty() {
            return false;
        }
        let syn::Expr::Paren(parenthesized) = &*invoked.func else {
            return false;
        };
        let syn::Expr::Closure(closure) = &*parenthesized.expr else {
            return false;
        };
        let syn::Expr::Block(cold) = &*closure.body else {
            return false;
        };
        if cold.block.stmts.len() != 5
            || !propagated(&cold.block.stmts[0], "self.check", &[])
            || !propagated(
                &cold.block.stmts[1],
                "self.phase.check_durability_profile",
                &[],
            )
            || !propagated(&cold.block.stmts[2], "self.check", &[])
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::Block(linux), _) = &cold.block.stmts[4] else {
            return false;
        };
        if linux.attrs.len() != 1
            || !matches!(&linux.attrs[0].meta, syn::Meta::List(value)
            if value.path.is_ident("cfg") && value.tokens.to_string() == "target_os = \"linux\"")
        {
            return false;
        }
        let steps = &linux.block.stmts;
        if steps.len() != 6
            || !propagated(&steps[0], "rustix::fs::fsync", &["self.file"])
            || !propagated(&steps[1], "self.check", &[])
            || !propagated(&steps[2], "rustix::fs::fsync", &["self.directory"])
            || !propagated(&steps[3], "self.check", &[])
            || !propagated(&steps[4], "self.phase.check_durability_profile", &[])
            || !matches!(&steps[5], syn::Stmt::Expr(value, None) if call(value, "self.check", &[]))
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::If(refused), _) = &body.stmts[1] else {
            return false;
        };
        call(&refused.cond, "result.is_err", &[])
            && refused.else_branch.is_none()
            && refused.then_branch.stmts.len() == 1
            && matches!(&refused.then_branch.stmts[0], syn::Stmt::Expr(value, Some(_)) if call(value, "self.disposition.refuse", &[]))
            && matches!(&body.stmts[2], syn::Stmt::Expr(value, None) if path(value).as_deref() == Some("result"))
    }

    #[test]
    fn cold_durability_keeps_full_observations_fsyncs_and_original_error() {
        assert!(actual_cold_sequence(include_str!("continuity.rs")));
    }

    #[test]
    fn cold_durability_rejects_removed_conditional_ignored_and_foreign_checks() {
        let source = include_str!("continuity.rs");
        for (before, after) in [
            ("            self.phase.check_durability_profile()?;", ""),
            (
                "            self.phase.check_durability_profile()?;",
                "            if false { self.phase.check_durability_profile()?; }",
            ),
            (
                "            self.phase.check_durability_profile()?;",
                "            let _ = self.phase.check_durability_profile();",
            ),
            (
                "rustix::fs::fsync(self.file)?;",
                "rustix::fs::fsync(self.directory)?;",
            ),
            (
                "rustix::fs::fsync(self.directory)?;",
                "let _ = rustix::fs::fsync(self.directory);",
            ),
            (
                "                self.check()\n            }\n        })();\n        if result.is_err()",
                "                Ok(())\n            }\n        })();\n        if result.is_err()",
            ),
            (
                "        if result.is_err() {\n            self.disposition.refuse();\n        }\n        result\n    }\n\n    /// The fixed, successfully observed activation",
                "        if result.is_ok() {\n            self.disposition.refuse();\n        }\n        result\n    }\n\n    /// The fixed, successfully observed activation",
            ),
        ] {
            let changed = source.replacen(before, after, 1);
            assert_ne!(source, changed);
            assert!(!actual_cold_sequence(&changed));
        }
    }
}

/// Reread the complete retained INITIAL image on every call. This private
/// atomic operation grants no native owner; production supplies the same
/// identity/original-clock check before and after each actual pread and last.
/// Later physical serving checks do not use this initial-image operation.
#[cfg(any(target_os = "linux", test))]
fn check_retained_initial_bytes(
    file: &File,
    expected: &[u8],
    mut check_identity: impl FnMut() -> Result<()>,
) -> Result<()> {
    let _profile = crate::security_epoch::self_check_profile::enter(
        crate::security_epoch::self_check_profile::Category::OriginalFile,
    );
    ensure!(
        !expected.is_empty() && expected.len() <= super::MAX_IMAGE_BYTES,
        "retained_initial_image_bound"
    );
    let mut bytes = vec![0_u8; expected.len()];
    let mut offset = 0;
    while offset < bytes.len() {
        check_identity()?;
        let end = (offset + super::INITIAL_IO_CHUNK_BYTES).min(bytes.len());
        let read = rustix::io::pread(file, &mut bytes[offset..end], offset as u64)?;
        ensure!(
            read > 0 && read <= end - offset,
            "retained_initial_read_progress"
        );
        offset += read;
        check_identity()?;
    }
    ensure!(bytes == expected, "retained_initial_bytes_changed");
    check_identity()
}

#[cfg(target_os = "linux")]
fn check_identity(
    phase: &mut CurrentVolumePhase<'_, '_>,
    directory: &File,
    anchor: &DirectoryIdentity,
    file: &File,
    identity: &FileIdentity,
    length: Option<usize>,
) -> Result<()> {
    use rustix::fs::{AtFlags, StatxFlags};
    phase.check_directory(directory, anchor)?;
    phase.acquisition().remaining()?;
    let observed = match length {
        Some(length) => observe_anchored_file(directory, anchor, file, length)?,
        None => observe_current_anchored_file(directory, anchor, file)?,
    };
    ensure!(observed == *identity, "retained_initial_file_changed");
    let flags = StatxFlags::INO | StatxFlags::MNT_ID;
    let named = rustix::fs::statx(
        directory,
        super::INITIAL_FILE,
        AtFlags::SYMLINK_NOFOLLOW,
        flags,
    )?;
    ensure!(
        named.stx_mask & flags.bits() == flags.bits()
            && named.stx_ino == identity.inode
            && named.stx_mnt_id == identity.mount
            && named.stx_dev_major == identity.device_major
            && named.stx_dev_minor == identity.device_minor,
        "retained_initial_leaf_changed"
    );
    phase.acquisition().remaining()?;
    phase.check_directory(directory, anchor)
}

#[cfg(test)]
mod retained_initial_read_tests {
    use super::check_retained_initial_bytes;
    use anyhow::{Result, bail};
    use std::{cell::Cell, fs::File, io::Write};

    fn image_file(bytes: &[u8]) -> Result<File> {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        Ok(file)
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "synthetic Linux byte-loop cost only; excludes native volume/provider/role checks"]
    fn profile_synthetic_retained_initial_byte_loop() -> Result<()> {
        use crate::security_epoch::native_clock::{NativeAcquisition, boottime};
        use std::os::unix::fs::MetadataExt;

        let chunk = super::super::INITIAL_IO_CHUNK_BYTES;
        for length in [chunk - 17, chunk + 17, super::super::MAX_IMAGE_BYTES] {
            let bytes: Vec<u8> = (0..length).map(|n| (n % 251) as u8).collect();
            let file = image_file(&bytes)?;
            let identity = file.metadata()?;
            let stamp = |metadata: &std::fs::Metadata| {
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.len(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            };
            let expected = stamp(&identity);
            let mut acquisition = NativeAcquisition::begin(5)?;
            let mut total_ns = Some(0_u64);
            let mut checks = 0;
            for _ in 0..8 {
                let before = boottime().ok();
                let result = check_retained_initial_bytes(&file, &bytes, || {
                    acquisition.remaining()?;
                    anyhow::ensure!(stamp(&file.metadata()?) == expected, "profile_file_changed");
                    checks += 1;
                    Ok(())
                });
                let after = boottime().ok();
                result?;
                let elapsed = before
                    .zip(after)
                    .and_then(|(a, b)| b.checked_sub(a))
                    .and_then(|duration| u64::try_from(duration.as_nanos()).ok());
                total_ns = total_ns.zip(elapsed).and_then(|(a, b)| a.checked_add(b));
                acquisition.remaining()?;
            }
            let chunks = length.div_ceil(chunk);
            assert_eq!(checks, 8 * (2 * chunks + 1));
            acquisition.remaining()?;
            eprintln!(
                "day2-native-original-byte-profile-fixture {}",
                serde_json::json!({
                    "scope": "synthetic_retained_byte_loop_only",
                    "image_bytes": length,
                    "chunk_bytes": chunk,
                    "calls": 8,
                    "fd_identity_checks": checks,
                    "total_ns": total_ns,
                    "excluded": ["volume", "directory", "path", "process", "namespace", "role", "provider"],
                })
            );
        }
        Ok(())
    }

    #[test]
    fn multi_batch_complete_reread_keeps_every_syscall_guard_and_last_check() -> Result<()> {
        let bytes: Vec<u8> = (0..super::super::INITIAL_IO_CHUNK_BYTES + 17)
            .map(|n| (n % 251) as u8)
            .collect();
        let file = image_file(&bytes)?;
        let mut checks = 0;
        check_retained_initial_bytes(&file, &bytes, || {
            checks += 1;
            Ok(())
        })?;
        assert_eq!(checks, 5);
        Ok(())
    }

    #[test]
    fn same_length_changed_bytes_are_reread_without_a_cached_positive() -> Result<()> {
        let bytes = vec![7; super::super::INITIAL_IO_CHUNK_BYTES + 17];
        let file = image_file(&bytes)?;
        check_retained_initial_bytes(&file, &bytes, || Ok(()))?;
        // Change the second batch, with the original file length retained.
        rustix::io::pwrite(&file, &[8], super::super::INITIAL_IO_CHUNK_BYTES as u64)?;
        let error = check_retained_initial_bytes(&file, &bytes, || Ok(())).unwrap_err();
        assert_eq!(error.to_string(), "retained_initial_bytes_changed");
        Ok(())
    }

    #[test]
    fn zero_progress_after_truncation_is_refused() -> Result<()> {
        let file = image_file(&[7; 17])?;
        let error = check_retained_initial_bytes(&file, &[7; 17], || {
            file.set_len(0)?;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "retained_initial_read_progress");
        Ok(())
    }

    #[test]
    fn pre_read_refusal_prevents_the_syscall_and_preserves_its_cause() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let file = File::open(directory.path())?;
        let error =
            check_retained_initial_bytes(&file, &[7], || bail!("pre_read_refused")).unwrap_err();
        assert_eq!(error.to_string(), "pre_read_refused");
        Ok(())
    }

    #[test]
    fn post_read_and_final_refusals_cannot_become_success() -> Result<()> {
        let file = image_file(&[7; 17])?;
        for refused_check in [2, 3] {
            let checks = Cell::new(0);
            let error = check_retained_initial_bytes(&file, &[7; 17], || {
                checks.set(checks.get() + 1);
                if checks.get() == refused_check {
                    bail!("original_guard_refused");
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "original_guard_refused");
            assert_eq!(checks.get(), refused_check);
        }
        Ok(())
    }

    #[test]
    fn unsupported_image_lengths_refuse_before_read_or_guard() -> Result<()> {
        let file = image_file(&[7])?;
        for bytes in [vec![], vec![7; super::super::MAX_IMAGE_BYTES + 1]] {
            let error = check_retained_initial_bytes(&file, &bytes, || {
                panic!("unbounded image must not reach a native guard")
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "retained_initial_image_bound");
        }
        Ok(())
    }
}

#[cfg(test)]
mod phase_disposition_tests {
    use super::FilePhaseDisposition;

    #[test]
    fn abandoning_an_unsettled_phase_cannot_rearm_continuity() {
        let mut continuation = true;
        {
            let phase = FilePhaseDisposition::begin(&mut continuation).unwrap();
            phase.check().unwrap();
        }
        assert!(!continuation);
        assert!(FilePhaseDisposition::begin(&mut continuation).is_err());
    }

    #[test]
    fn a_refused_phase_cannot_complete_or_start_another_phase() {
        let mut continuation = true;
        let mut phase = FilePhaseDisposition::begin(&mut continuation).unwrap();
        phase.check().unwrap();
        phase.refuse();
        assert!(phase.check().is_err());
        assert!(phase.complete().is_err());
        assert!(!continuation);
        assert!(FilePhaseDisposition::begin(&mut continuation).is_err());
    }

    #[test]
    fn only_known_completion_restores_the_continuation_gate() {
        let mut continuation = true;
        FilePhaseDisposition::begin(&mut continuation)
            .unwrap()
            .complete()
            .unwrap();
        assert!(continuation);
        let next = FilePhaseDisposition::begin(&mut continuation).unwrap();
        next.check().unwrap();
        next.complete().unwrap();
        assert!(continuation);
    }

    #[test]
    fn a_previously_refused_file_stays_refused() {
        let mut continuation = false;
        assert!(FilePhaseDisposition::begin(&mut continuation).is_err());
        assert!(!continuation);
    }
}
