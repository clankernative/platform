//! Native identity join of the WHOLE genuine post-installed carrier.
//! Every borrowed counter/physical/target owner stays in that carrier. This is
//! not an owned Controller, ordinary Current or a successful restore result.
use super::{ControllerCurrentInstallationLoan, LostRestoreWriterConfirmation};
use crate::security_epoch::native_enrollment::{
    CurrentStoragePeerPhase, EnrolledRoleStage, NativeRole, RetainedControllerNative,
    SameEnrolledOwner,
};
use anyhow::{Context, Result, ensure};

/// Fixed storage flow for the native Controller adapter. The sole whole-carrier
/// driver supplies these actual disjoint borrows and retains their owners through
/// native completion and consuming disposal. Comparison DATA cannot create a
/// target, native stage, Current, peer or reader.
pub(in crate::security_epoch) struct RestoredControllerCurrentReadLoan<'borrow, 'target, 'selection>
{
    target: &'borrow mut crate::security_epoch::restore_staging::NativeStagedTarget<
        'target,
        'selection,
    >,
    counter: &'borrow mut crate::security_epoch::authenticated_reads::CounterConnectionSlot,
    cohort: &'borrow mut crate::security_epoch::restore_staging::RestoreControllerCohort,
    creator: &'borrow crate::security_epoch::native_enrollment::RestoreCreatorData,
    report: &'borrow crate::security_epoch::kernel::restore::completion::TargetReport,
    policy: &'borrow day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
    selected: &'borrow day2_capabilities::security_epoch::EpochStore,
    completed: Option<crate::security_epoch::authenticated_reads::CompletedRestoredCounterRead>,
    disposition: RestoredReadDisposition,
}

// Private terminal disposition of this actual loan, never caller input or a
// serialized completion witness. Only the sole consuming disposal may settle.
#[derive(PartialEq, Eq)]
enum RestoredReadDisposition {
    Armed,
    Settled,
    Refused,
}

/// The actual saved stage and phase are armed before even inspecting cold
/// counter state. No early error or unwind can leave native input unrefused.
struct RestoredCurrentReadAttempt<'call, 'loan, 'target, 'selection, 'role, 'peer> {
    loan: &'call mut RestoredControllerCurrentReadLoan<'loan, 'target, 'selection>,
    stage: &'call mut EnrolledRoleStage<'role>,
    phase: Option<&'call mut CurrentStoragePeerPhase<'peer>>,
    completed: bool,
}

impl Drop for RestoredCurrentReadAttempt<'_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.stage.refuse_serving();
            if let Some(phase) = &mut self.phase {
                phase.refuse();
            }
            self.loan.refuse();
        }
    }
}

impl RestoredControllerCurrentReadLoan<'_, '_, '_> {
    pub(in crate::security_epoch) fn observe(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        phase: &mut CurrentStoragePeerPhase<'_>,
        reader: &crate::security_epoch::firestore::RestoreWriterPeerRead,
    ) -> Result<day2_capabilities::Digest> {
        let mut attempt = RestoredCurrentReadAttempt {
            loan: self,
            stage,
            phase: Some(phase),
            completed: false,
        };
        let requested = attempt.loan.observe_in(
            attempt.stage,
            attempt
                .phase
                .as_deref_mut()
                .context("restore_current_phase_missing")?,
            reader,
        );
        // These real posts run independently even when the fixed flow failed.
        let physical_post = attempt.loan.check_physical(attempt.stage);
        let peer_post = attempt
            .phase
            .as_deref_mut()
            .context("restore_current_phase_missing")?
            .check(attempt.stage);
        let native_post = attempt.stage.check();
        let snapshot = requested?;
        physical_post?;
        peer_post?;
        native_post?;
        attempt.completed = true;
        Ok(snapshot)
    }

    /// Mandatory after the native phase returns its real peer and before
    /// saved-request completion. Check actual files/cohort and the OLD completed
    /// counter's bound observation without any reauthentication or fresh read.
    pub(in crate::security_epoch) fn final_check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let mut attempt = RestoredCurrentReadAttempt {
            loan: self,
            stage,
            phase: None,
            completed: false,
        };
        let physical = attempt.loan.check_physical(attempt.stage);
        let counter_post = (|| {
            let completed = attempt
                .loan
                .completed
                .as_mut()
                .context("restore_current_counter_completion_missing")?;
            attempt
                .loan
                .counter
                .check_completed_restored(attempt.stage, completed)
        })();
        let physical_post = attempt.loan.check_physical(attempt.stage);
        let native_post = attempt.stage.check();
        physical?;
        counter_post?;
        physical_post?;
        native_post?;
        attempt.completed = true;
        Ok(())
    }

    fn check_physical(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.cohort
            .check_current(self.target, stage, self.creator, self.report)
            .map(|_| ())
    }

    /// One closed sequence. The request and both observations remain lexical
    /// locals while the real slot is borrowed; no self-reference or cached
    /// snapshot can supply a request or repair an already spent original.
    fn observe_in(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        phase: &mut CurrentStoragePeerPhase<'_>,
        reader: &crate::security_epoch::firestore::RestoreWriterPeerRead,
    ) -> Result<day2_capabilities::Digest> {
        let Self {
            target,
            counter,
            cohort,
            creator,
            report,
            policy,
            selected,
            completed,
            disposition: _,
        } = self;
        ensure!(
            completed.is_none(),
            "restore_current_read_already_completed"
        );
        stage.check_current_selection(policy, selected, NativeRole::EpochController)?;
        current_read_resources(target, cohort, creator, report, stage, phase)?;
        let mut reads = counter.restored_controller_request(stage, policy, selected)?;
        let requested = reads.read_restored(stage, selected, reader);
        let post = current_read_resources(target, cohort, creator, report, stage, phase);
        let mut before = requested?;
        post?;
        reads.check_restored_observation(stage, reader, &mut before)?;
        current_read_resources(target, cohort, creator, report, stage, phase)?;
        let announced = phase.announce_known(stage);
        let post = current_read_resources(target, cohort, creator, report, stage, phase);
        announced?;
        post?;
        let acknowledged = phase.await_acknowledgement(stage);
        let post = current_read_resources(target, cohort, creator, report, stage, phase);
        acknowledged?;
        post?;
        // The wait spent THIS original. Its old budget must pass before the
        // new reply is requested, and that old observation stays live through
        // the fresh read and its independent posts, including error paths.
        reads.check_restored_observation(stage, reader, &mut before)?;
        current_read_resources(target, cohort, creator, report, stage, phase)?;
        let requested = reads.read_restored(stage, selected, reader);
        let post = current_read_resources(target, cohort, creator, report, stage, phase);
        let old_post = reads.check_restored_observation(stage, reader, &mut before);
        let mut after = requested?;
        post?;
        old_post?;
        reads.check_restored_observation(stage, reader, &mut after)?;
        ensure!(
            before.snapshot_data() == after.snapshot_data(),
            "restore_current_known_snapshot_changed"
        );
        current_read_resources(target, cohort, creator, report, stage, phase)?;
        let snapshot = after.snapshot_data().clone();
        // The same actual completed guard is stored BEFORE any release I/O.
        // It stays armed through native phase and saved-request settlement.
        *completed = Some(reads.finish_restored(stage, reader, after)?);
        let released = phase.release_known(stage);
        let post = current_read_resources(target, cohort, creator, report, stage, phase);
        released?;
        post?;
        Ok(snapshot)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.disposition = RestoredReadDisposition::Refused;
        if let Some(completed) = &mut self.completed {
            completed.refuse();
        }
        self.target.refuse();
        self.counter.refuse();
    }

    /// Pure consuming negative-duty disposal, called only by the whole-parent
    /// lexical driver after actual native completion returned this snapshot.
    /// FinalChecked alone never proves native completion. This private method
    /// returns no owner, stage, request, budget or reusable permission.
    fn finish_after_native(mut self, snapshot: &day2_capabilities::Digest) -> Result<()> {
        ensure!(
            self.disposition == RestoredReadDisposition::Armed,
            "restore_current_loan_refused"
        );
        let completed = self
            .completed
            .take()
            .context("restore_current_counter_completion_missing")?;
        self.counter
            .release_completed_restored(completed, snapshot)?;
        self.disposition = RestoredReadDisposition::Settled;
        Ok(())
    }
}

fn current_read_resources(
    target: &mut crate::security_epoch::restore_staging::NativeStagedTarget<'_, '_>,
    cohort: &mut crate::security_epoch::restore_staging::RestoreControllerCohort,
    creator: &crate::security_epoch::native_enrollment::RestoreCreatorData,
    report: &crate::security_epoch::kernel::restore::completion::TargetReport,
    stage: &mut EnrolledRoleStage<'_>,
    phase: &mut CurrentStoragePeerPhase<'_>,
) -> Result<()> {
    let physical = cohort.check_current(target, stage, creator, report);
    let peer_post = phase.check(stage);
    let native_post = stage.check();
    physical?;
    peer_post?;
    native_post
}

impl Drop for RestoredControllerCurrentReadLoan<'_, '_, '_> {
    fn drop(&mut self) {
        if self.disposition != RestoredReadDisposition::Settled {
            self.refuse();
        }
    }
}

/// Nonescaping physical/original borrow for the single installed operator
/// packet. Only the whole post-App-acceptance driver constructs this. DATA
/// returned by check is not a completed restore or a reusable permission.
pub(in crate::security_epoch) struct RestoreInstalledOutputLoan<'borrow, 'target, 'selection> {
    original: &'borrow mut crate::security_epoch::restore_original::RestoreOriginalGuard,
    approval: &'borrow crate::security_epoch::restore_approval::ApprovalRequest,
    operation: &'borrow day2_capabilities::Digest,
    creator: &'borrow crate::security_epoch::native_enrollment::RestoreCreatorData,
    report: &'borrow crate::security_epoch::kernel::restore::completion::TargetReport,
    target: &'borrow mut crate::security_epoch::restore_staging::NativeStagedTarget<
        'target,
        'selection,
    >,
    cohort: &'borrow mut crate::security_epoch::restore_staging::RestoreControllerCohort,
    refused: &'borrow std::rc::Rc<std::cell::Cell<bool>>,
    _lost: LostRestoreWriterConfirmation,
}

impl RestoreInstalledOutputLoan<'_, '_, '_> {
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut crate::security_epoch::native_enrollment::EnrolledStorageStage<'_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::RestoreInstalledOutputData> {
        let requested = (|| {
            ensure!(
                self.refused.get(),
                "restore_output_outside_installed_carrier"
            );
            storage.check_restore_original(self.original, self.approval, self.operation)?;
            let cohort = self.cohort.check(self.target, self.creator, self.report)?;
            ensure!(
                self.report.target_incarnation == self.approval.target.incarnation
                    && self.report.target_epoch == self.approval.target.security_epoch
                    && self.report.artifact == self.approval.target.artifact
                    && self.report.schema == self.approval.target.schema,
                "restore_output_installed_target_changed"
            );
            Ok(
                crate::security_epoch::native_enrollment::RestoreInstalledOutputData {
                    approval: self.approval.commitment()?,
                    operation: self.operation.clone(),
                    full_archive: self.approval.full_archive_digest.clone(),
                    target: self.approval.target.clone(),
                    executor: self.approval.executor.clone(),
                    installed: day2_capabilities::Digest::of(&(
                        "day2-protected-restore-installed-output-v1",
                        self.report,
                        &cohort,
                    ))?,
                },
            )
        })();
        // Actual original post is independent of all DATA and physical failures.
        let post = storage.check_restore_original(self.original, self.approval, self.operation);
        if requested.is_err() || post.is_err() {
            self.refuse();
        }
        let data = requested?;
        post?;
        Ok(data)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused.set(true);
        self.original.refuse();
        self.target.refuse();
    }
}

/// Own the complete installation before any terminal precheck. Even a panic
/// before the first native packet step refuses both actual retained roots.
struct ProtectedInstalledAttempt<
    'call,
    'peer,
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    installation: Option<
        PendingControllerCurrentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    >,
    turn: &'call mut crate::security_epoch::native_enrollment::ProtectedRestoreTurn<'peer>,
    completed: bool,
}

impl Drop for ProtectedInstalledAttempt<'_, '_, '_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.turn.refuse();
            if let Some(installation) = &mut self.installation {
                installation.refuse();
            }
        }
    }
}

// Pure precedence for two already-observed outcomes; this owns no authority.
fn installed_observed<T>(
    requested: std::thread::Result<Result<T>>,
    post: std::thread::Result<Result<()>>,
) -> Result<T> {
    match requested {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(Err(error)) => Err(error),
        Ok(Ok(value)) => match post {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(post) => {
                post?;
                Ok(value)
            }
        },
    }
}

pub(in crate::security_epoch) struct PendingControllerCurrentInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    loan: ControllerCurrentInstallationLoan<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
    same: SameEnrolledOwner,
}

/// The old administrative Current is terminal, but ALL of its actual installed
/// resources and lexical borrows remain retained. The native field is only the
/// SAME admitted Controller role borrow. This is neither a fresh App peer nor
/// an ordinary Controller/storage owner or a completed restore result.
///
/// In particular, the old SQL/file/source/original negative guards are not
/// disarmed here. No old parent check can run after its counter is finished or
/// its original retired. The subsequent fixed fresh-peer/file handoff must
/// still consume this whole carrier; dropping it refuses both real owners.
pub(in crate::security_epoch) struct RetiredControllerCurrentInstallation<
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    native: RetainedControllerNative<'role>,
    // A new connection slot belongs to this whole retained carrier, never to
    // an individual warm capture or the retired administrative reader.
    counter: crate::security_epoch::authenticated_reads::CounterConnectionSlot,
    pending: PendingControllerCurrentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
}

impl RetiredControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    /// Keep the WHOLE genuine seven-lifetime installation alive through every
    /// App request. The returned peer stays a lexical local; storing it inside
    /// this same carrier would be self-reference. All errors propagate out of
    /// this consuming scope, whose existing Drop refuses every actual owner.
    /// No operator completion or ordinary Current object is returned here.
    pub(in crate::security_epoch) fn serve_app_currents(mut self) -> Result<()> {
        let native = &mut self.native;
        let counter = &mut self.counter;
        let installation = &mut self.pending.loan.installation;
        let installed = &mut installation.installed;
        let frame = &mut installation
            .installation
            .installation
            .installation
            .installation
            .installation
            .installation
            .frame;
        let reader = &frame.confirmation.owner.auth.action.reader.loan;
        let policy = &reader.policy;
        let selected = &reader.selection;
        let creator = &frame.creator;
        let report = &frame.confirmation.target;
        let target = &mut *frame.target;
        let cohort = frame
            .cohort
            .as_mut()
            .context("restore_current_cohort_missing")?;
        let mut first = Some((&mut *frame.peer, installed));
        let mut returned: Option<
            crate::security_epoch::native_enrollment::RestoredPeerConnection<'_>,
        > = None;
        loop {
            ensure!(
                first.is_some() != returned.is_some(),
                "restore_current_peer_source_changed"
            );
            let pending = match returned.as_mut() {
                Some(peer) => peer.pending(),
                None => {
                    let (peer, installed) = first
                        .as_mut()
                        .context("restore_current_first_peer_missing")?;
                    installed.first_current_pending(peer)
                }
            }?;
            if !pending {
                // Idle pacing only: no request, original, stage, provider
                // permission or retired clock is acquired or sampled here.
                std::thread::park_timeout(std::time::Duration::from_millis(5));
                continue;
            }
            let mut captured = native.capture_current_request()?;
            let rendezvous = match returned.take() {
                Some(peer) => captured.prepare_retained_current_peer(native, peer)?,
                None => {
                    let (peer, installed) =
                        first.take().context("restore_current_first_peer_missing")?;
                    captured.prepare_current_peer(native, peer, installed)?
                }
            };
            let phase = captured.accept_current_peer(native, rendezvous, None)?;
            let mut loan = RestoredControllerCurrentReadLoan {
                target: &mut *target,
                counter: &mut *counter,
                cohort: &mut *cohort,
                creator,
                report,
                policy,
                selected,
                completed: None,
                disposition: RestoredReadDisposition::Armed,
            };
            // The ACTUAL peer is immediately held in this owning local after
            // native Result::Ok. Its existing negative Drop stays armed across
            // disposal; the whole self is also retained until this scope ends.
            let (peer, snapshot) =
                captured.serve_current_peer(native, phase, selected, &mut loan)?;
            loan.finish_after_native(&snapshot)?;
            // No fallible work, clock, callback, wait or I/O follows disposal
            // before retaining that SAME real peer for the next fresh capture.
            returned = Some(peer);
        }
    }
}

impl Drop for RetiredControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        self.counter.refuse();
        self.native.refuse();
        self.pending.refuse();
    }
}

struct NativeControllerPreparing<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
{
    loan: Option<
        ControllerCurrentInstallationLoan<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    >,
    completed: bool,
}

impl Drop for NativeControllerPreparing<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed
            && let Some(loan) = &mut self.loan
        {
            loan.refuse();
        }
    }
}

struct NativeControllerChecking<
    'borrow,
    'frame,
    'confirm,
    'metadata,
    'storage,
    'role,
    'target,
    'selection,
> {
    owner: &'borrow mut PendingControllerCurrentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >,
    completed: bool,
}

impl Drop for NativeControllerChecking<'_, '_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.refuse();
        }
    }
}

impl Drop for PendingControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        self.loan.refuse();
    }
}

impl<'frame, 'confirm, 'metadata, 'storage, 'role, 'target, 'selection>
    PendingControllerCurrentInstallation<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >
{
    /// Consume the genuine installed carrier before any checks or native work.
    /// The same old original remains live through the independent full post.
    pub(super) fn prepare(
        loan: ControllerCurrentInstallationLoan<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    ) -> Result<Self> {
        let mut attempt = NativeControllerPreparing {
            loan: Some(loan),
            completed: false,
        };
        let requested = (|| {
            let loan = attempt
                .loan
                .as_mut()
                .context("restore_native_controller_loan_missing")?;
            loan.check()?;
            capture_controller(loan)
        })();
        let checked = (|| {
            attempt
                .loan
                .as_mut()
                .context("restore_native_controller_loan_missing")?
                .check()
        })();
        if (requested.is_err() || checked.is_err())
            && let Some(loan) = &mut attempt.loan
        {
            loan.refuse();
        }
        let same = requested?;
        checked?;
        let loan = attempt
            .loan
            .take()
            .context("restore_native_controller_loan_missing")?;
        // No I/O, effect, wait or callback follows the full post before this
        // owning move. The future holder still retains ALL seven lifetimes.
        let pending = Self { loan, same };
        attempt.completed = true;
        Ok(pending)
    }

    /// The sole terminal restore driver: actual App installed acceptance and
    /// its full post FIRST, then one fixed operator packet under independent
    /// complete pre/posts at every native step. Old counter/release/retirement
    /// is LAST. No old original may be sampled after that consuming retirement.
    pub(in crate::security_epoch) fn finish_protected_restore(
        self,
        turn: &mut crate::security_epoch::native_enrollment::ProtectedRestoreTurn<'_>,
    ) -> Result<
        RetiredControllerCurrentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let mut attempt = ProtectedInstalledAttempt {
            installation: Some(self),
            turn,
            completed: false,
        };
        {
            let installation = attempt
                .installation
                .as_mut()
                .context("restore_output_installation_missing")?;
            installation.check()?;
            let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                installation.loan.send_installed_acceptance()
            }));
            let post =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| installation.check()));
            installed_observed(requested, post)?;
        }
        let mut state = super::RoleHandoffProgress::Prepare;
        while state != super::RoleHandoffProgress::Delivered {
            let operation = state.operation()?;
            let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                attempt
                    .installation
                    .as_mut()
                    .context("restore_output_installation_missing")?
                    .installed_output_step(attempt.turn, operation)
            }));
            // This runs even after a native error/unwind; the short stage and
            // loan have ended, so it is the WHOLE actual parent/native post.
            let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                attempt
                    .installation
                    .as_mut()
                    .context("restore_output_installation_missing")?
                    .check()
            }));
            let progress = installed_observed(requested, post)?;
            state = state.after(operation, progress)?;
        }
        let mut installation = attempt
            .installation
            .take()
            .context("restore_output_installation_missing")?;
        installation.check()?;
        let native = retire_controller(&mut installation.loan)?;
        // No I/O, callback, positive parent/clock check or wait follows retirement.
        let retired = RetiredControllerCurrentInstallation {
            native,
            counter: crate::security_epoch::authenticated_reads::CounterConnectionSlot::new(),
            pending: installation,
        };
        attempt.completed = true;
        Ok(retired)
    }

    fn installed_output_step(
        &mut self,
        turn: &mut crate::security_epoch::native_enrollment::ProtectedRestoreTurn<'_>,
        operation: super::RoleHandoffIo,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        self.check()?;
        let frame = &mut self
            .loan
            .installation
            .installation
            .installation
            .installation
            .installation
            .installation
            .installation
            .frame;
        let owner = &mut *frame.confirmation.owner;
        // The actual pessimistic mark spans the native short loan and is
        // cleared only by the caller's existing full independent parent post.
        owner.refused.set(true);
        let physical = owner
            .auth
            .action
            .reader
            .loan
            .physical
            .as_mut()
            .context("native_restore_physical_closed")?;
        let stage = physical.controller_stage()?;
        let mut loan = RestoreInstalledOutputLoan {
            original: &mut owner.auth.original,
            approval: &owner.auth.record.statement.request,
            operation: &owner.auth.operation,
            creator: &frame.creator,
            report: &frame.confirmation.target,
            target: frame.target,
            cohort: frame
                .cohort
                .as_mut()
                .context("restore_current_cohort_missing")?,
            refused: &owner.refused,
            _lost: LostRestoreWriterConfirmation {
                refused: std::rc::Rc::clone(&owner.refused),
            },
        };
        use crate::security_epoch::native_enrollment::ProtectedRestoreInstalledIo as Io;
        let operation = match operation {
            super::RoleHandoffIo::Prepare => Io::Prepare,
            super::RoleHandoffIo::Sign => Io::Sign,
            super::RoleHandoffIo::Send => Io::Send,
            super::RoleHandoffIo::Poll => Io::Poll,
        };
        turn.installed_output(stage, &mut loan, operation)
    }
}

impl PendingControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {
    /// Fixed installation check only, never a request or stage getter. A
    /// caught unwind permanently refuses the actual carrier before reuse.
    pub(super) fn check(&mut self) -> Result<()> {
        let mut attempt = NativeControllerChecking {
            owner: self,
            completed: false,
        };
        let requested = (|| {
            attempt.owner.loan.check()?;
            check_controller(&mut attempt.owner.loan, &mut attempt.owner.same)
        })();
        let checked = attempt.owner.loan.check();
        if requested.is_err() || checked.is_err() {
            attempt.owner.refuse();
        }
        requested?;
        checked?;
        attempt.completed = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.loan.refuse();
    }
}

/// Native field partition is private to this fixed post-ACK implementation.
/// A stage borrow ends here, before the caller's independent whole-carrier
/// post. No original, key, file, stage or callback is supplied by a caller.
fn capture_controller(
    loan: &mut ControllerCurrentInstallationLoan<'_, '_, '_, '_, '_, '_, '_>,
) -> Result<SameEnrolledOwner> {
    let frame = &mut loan
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .frame;
    let reader = &mut frame.confirmation.owner.auth.action.reader.loan;
    let physical = reader
        .physical
        .as_mut()
        .context("native_restore_physical_closed")?;
    let stage = physical.controller_stage()?;
    stage.require_current_role()?;
    stage.check_selection(
        &reader.policy,
        &reader.selection,
        NativeRole::EpochController,
    )?;
    stage.capture_same_owner()
}

fn check_controller(
    loan: &mut ControllerCurrentInstallationLoan<'_, '_, '_, '_, '_, '_, '_>,
    same: &mut SameEnrolledOwner,
) -> Result<()> {
    let frame = &mut loan
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .frame;
    let reader = &mut frame.confirmation.owner.auth.action.reader.loan;
    let physical = reader
        .physical
        .as_mut()
        .context("native_restore_physical_closed")?;
    let stage = physical.controller_stage()?;
    stage.require_current_role()?;
    stage.check_selection(
        &reader.policy,
        &reader.selection,
        NativeRole::EpochController,
    )?;
    same.check(stage)
}

/// This fixed field partition exists only under the genuine post-ACK carrier.
/// Stop data comes from the SAME retained accepting owner, never a caller.
/// The actual counter completion must precede the old release, while the
/// complete parent/ten-record checks must precede that counter completion.
fn retire_controller<'role>(
    loan: &mut ControllerCurrentInstallationLoan<'_, '_, '_, '_, 'role, '_, '_>,
) -> Result<RetainedControllerNative<'role>> {
    let frame = &mut loan
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .installation
        .frame;
    let owner = &mut *frame.confirmation.owner;
    let reader = &mut owner.auth.action.reader.loan;
    reader.disposition.require_closed()?;
    reader.reads.finish(
        reader
            .physical
            .as_mut()
            .context("native_restore_physical_closed")?
            .controller_stage()?,
    )?;
    reader
        .physical
        .as_mut()
        .context("native_restore_physical_closed")?
        .release_restore_stop(&owner.stopped)?;
    reader
        .physical
        .take()
        .context("native_restore_physical_closed")?
        .retire_restore_native()
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <RestoreInstalledOutputLoan<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ProtectedInstalledAttempt<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <PendingControllerCurrentInstallation<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <RestoredControllerCurrentReadLoan<'static, 'static, 'static> as Ambiguous<
                _,
            >>::check;
            let _ = <RestoredCurrentReadAttempt<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <RetiredControllerCurrentInstallation<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <NativeControllerPreparing<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
            let _ = <NativeControllerChecking<
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
                'static,
            > as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
};

#[cfg(test)]
mod source_tests {
    use quote::ToTokens;

    fn canonical(stream: proc_macro2::TokenStream) -> String {
        stream
            .into_iter()
            .filter_map(|token| match token {
                proc_macro2::TokenTree::Punct(punctuation) if punctuation.as_char() == ',' => None,
                proc_macro2::TokenTree::Group(group) => {
                    Some(proc_macro2::TokenTree::Group(proc_macro2::Group::new(
                        group.delimiter(),
                        canonical(group.stream()).parse().unwrap(),
                    )))
                }
                other => Some(other),
            })
            .collect::<proc_macro2::TokenStream>()
            .to_string()
    }

    fn method(owner: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        let mut found=file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(item)=item else{return None;};
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident==owner)) {return None;}
            item.items.into_iter().find_map(|item|match item {syn::ImplItem::Fn(item) if item.sig.ident==name=>Some(item),_=>None})
        });
        let result = found.next().unwrap();
        assert!(found.next().is_none());
        result
    }

    // Finite comparison of these closed bodies. Keep tuple commas/arity;
    // normalize punctuation spacing and only formatter-optional list commas.
    fn loan_tokens(stream: proc_macro2::TokenStream) -> String {
        fn normalize_punctuation(tokens: Vec<proc_macro2::TokenTree>) -> proc_macro2::TokenStream {
            use proc_macro2::{Punct, Spacing, TokenTree};
            // Preserve actual compound operators. Only an operator's boundary
            // spacing may differ between source macro tokens and typed syn:
            // `==&value` is `==` then `&`, but `&&` is NEVER two references.
            const OPERATORS: &[&str] = &[
                "<<=", ">>=", "...", "..=", "::", "->", "=>", "==", "!=", ">=", "<=", "&&", "||",
                "<<", ">>", "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "..",
            ];
            let mut output = Vec::new();
            let mut index = 0;
            while index < tokens.len() {
                let TokenTree::Punct(first) = &tokens[index] else {
                    output.push(tokens[index].clone());
                    index += 1;
                    continue;
                };
                let mut end = index + 1;
                let mut previous = first;
                while previous.spacing() == Spacing::Joint {
                    let Some(TokenTree::Punct(next)) = tokens.get(end) else {
                        break;
                    };
                    previous = next;
                    end += 1;
                }
                let mut at = index;
                while at < end {
                    let available: String = tokens[at..end]
                        .iter()
                        .map(|token| {
                            let TokenTree::Punct(p) = token else {
                                unreachable!();
                            };
                            p.as_char()
                        })
                        .collect();
                    let length = OPERATORS
                        .iter()
                        .find(|op| available.starts_with(**op))
                        .map_or(1, |op| op.len());
                    for offset in 0..length {
                        let TokenTree::Punct(p) = &tokens[at + offset] else {
                            unreachable!();
                        };
                        let spacing = if offset + 1 < length {
                            Spacing::Joint
                        } else if at + offset + 1 == end {
                            p.spacing()
                        } else {
                            Spacing::Alone
                        };
                        output.push(TokenTree::Punct(Punct::new(p.as_char(), spacing)));
                    }
                    at += length;
                }
                index = end;
            }
            output.into_iter().collect()
        }

        fn normalize(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            use proc_macro2::{Delimiter, Group, TokenTree};
            let mut output = Vec::new();
            for token in stream {
                match token {
                    TokenTree::Group(group) => {
                        let optional = matches!(output.last(),Some(TokenTree::Ident(name))
                            if !["let","return","if","else","while","for","match"].contains(&name.to_string().as_str()))
                            || matches!(output.last(),Some(TokenTree::Punct(p)) if matches!(p.as_char(),'!'|'>'));
                        let mut inner: Vec<_> = normalize(group.stream()).into_iter().collect();
                        if optional
                            && matches!(
                                group.delimiter(),
                                Delimiter::Parenthesis | Delimiter::Brace
                            )
                            && matches!(inner.last(),Some(TokenTree::Punct(p)) if p.as_char()==',')
                        {
                            inner.pop();
                        }
                        output.push(TokenTree::Group(Group::new(
                            group.delimiter(),
                            inner.into_iter().collect(),
                        )));
                    }
                    other => output.push(other),
                }
            }
            normalize_punctuation(output)
        }
        normalize(stream).to_string()
    }

    fn same_loan_body(actual: &syn::Block, expected: &syn::Block) -> bool {
        loan_tokens(actual.to_token_stream()) == loan_tokens(expected.to_token_stream())
    }

    #[test]
    fn loan_source_comparison_preserves_tuple_arity_and_actual_arguments() {
        let normal = |s: &str| loan_tokens(s.parse().unwrap());
        assert_eq!(normal("call(stage,)"), normal("call(stage)"));
        assert_ne!(normal("(stage,)"), normal("(stage)"));
        assert_ne!(normal("let (stage,)=value;"), normal("let (stage)=value;"));
        assert_ne!(normal("return (stage,);"), normal("return (stage);"));
        assert_ne!(normal("call(stage,reader)"), normal("call((stage,reader))"));
        assert_ne!(normal("call(actual)"), normal("call(foreign)"));
        assert_ne!(normal("a && b"), normal("a & &b"));
        assert_ne!(normal("a || b"), normal("a | |x| b"));
        assert_eq!(
            normal("ensure!(actual==&value)"),
            normal("ensure!(actual == &value)")
        );
    }

    #[test]
    fn actual_read_loan_arms_native_inputs_before_cold_work_and_keeps_independent_posts() {
        let actual = method("RestoredControllerCurrentReadLoan", "observe");
        let expected: syn::Block = syn::parse_quote!({
            let mut attempt = RestoredCurrentReadAttempt {
                loan: self,
                stage,
                phase: Some(phase),
                completed: false,
            };
            let requested = attempt.loan.observe_in(
                attempt.stage,
                attempt
                    .phase
                    .as_deref_mut()
                    .context("restore_current_phase_missing")?,
                reader,
            );
            let physical_post = attempt.loan.check_physical(attempt.stage);
            let peer_post = attempt
                .phase
                .as_deref_mut()
                .context("restore_current_phase_missing")?
                .check(attempt.stage);
            let native_post = attempt.stage.check();
            let snapshot = requested?;
            physical_post?;
            peer_post?;
            native_post?;
            attempt.completed = true;
            Ok(snapshot)
        });
        assert!(same_loan_body(&actual.block, &expected));
        for cut in 0..actual.block.stmts.len() - 1 {
            let mut omitted = actual.block.clone();
            omitted.stmts.remove(cut);
            assert!(!same_loan_body(&omitted, &expected), "observe cut {cut}");
        }
        let mut conditional = actual.block.clone();
        conditional.stmts[2] = syn::parse_quote!(let physical_post=if requested.is_ok() {attempt.loan.check_physical(attempt.stage)} else {Ok(())};);
        assert!(!same_loan_body(&conditional, &expected));
        let mut priority = actual.block.clone();
        priority.stmts.swap(5, 6);
        assert!(!same_loan_body(&priority, &expected));
    }

    #[test]
    fn actual_read_flow_keeps_old_observation_through_ack_fresh_read_and_finishes_before_release() {
        let actual = method("RestoredControllerCurrentReadLoan", "observe_in");
        let expected: syn::Block = syn::parse_quote!({
            let Self {
                target,
                counter,
                cohort,
                creator,
                report,
                policy,
                selected,
                completed,
                disposition: _,
            } = self;
            ensure!(
                completed.is_none(),
                "restore_current_read_already_completed"
            );
            stage.check_current_selection(policy, selected, NativeRole::EpochController)?;
            current_read_resources(target, cohort, creator, report, stage, phase)?;
            let mut reads = counter.restored_controller_request(stage, policy, selected)?;
            let requested = reads.read_restored(stage, selected, reader);
            let post = current_read_resources(target, cohort, creator, report, stage, phase);
            let mut before = requested?;
            post?;
            reads.check_restored_observation(stage, reader, &mut before)?;
            current_read_resources(target, cohort, creator, report, stage, phase)?;
            let announced = phase.announce_known(stage);
            let post = current_read_resources(target, cohort, creator, report, stage, phase);
            announced?;
            post?;
            let acknowledged = phase.await_acknowledgement(stage);
            let post = current_read_resources(target, cohort, creator, report, stage, phase);
            acknowledged?;
            post?;
            reads.check_restored_observation(stage, reader, &mut before)?;
            current_read_resources(target, cohort, creator, report, stage, phase)?;
            let requested = reads.read_restored(stage, selected, reader);
            let post = current_read_resources(target, cohort, creator, report, stage, phase);
            let old_post = reads.check_restored_observation(stage, reader, &mut before);
            let mut after = requested?;
            post?;
            old_post?;
            reads.check_restored_observation(stage, reader, &mut after)?;
            ensure!(
                before.snapshot_data() == after.snapshot_data(),
                "restore_current_known_snapshot_changed"
            );
            current_read_resources(target, cohort, creator, report, stage, phase)?;
            let snapshot = after.snapshot_data().clone();
            *completed = Some(reads.finish_restored(stage, reader, after)?);
            let released = phase.release_known(stage);
            let post = current_read_resources(target, cohort, creator, report, stage, phase);
            released?;
            post?;
            Ok(snapshot)
        });
        assert!(same_loan_body(&actual.block, &expected));
        for cut in 0..actual.block.stmts.len() - 1 {
            let mut omitted = actual.block.clone();
            omitted.stmts.remove(cut);
            assert!(!same_loan_body(&omitted, &expected), "fixed flow cut {cut}");
        }
        let mut release_first = actual.block.clone();
        release_first.stmts.swap(31, 32);
        assert!(!same_loan_body(&release_first, &expected));
        let mut replaced_old = actual.block.clone();
        replaced_old.stmts[19] =
            syn::parse_quote!(let before=reads.read_restored(stage,selected,reader)?;);
        assert!(!same_loan_body(&replaced_old, &expected));
        let old_post_index = actual.block.stmts.iter().position(|statement| {
            matches!(statement,syn::Stmt::Local(local) if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="old_post"))
        }).expect("actual independent old-observation post");
        let mut conditional_old_post = actual.block.clone();
        conditional_old_post.stmts[old_post_index] = syn::parse_quote!(
            let old_post = if requested.is_ok() {reads.check_restored_observation(stage,reader,&mut before)} else {Ok(())};
        );
        assert!(!same_loan_body(&conditional_old_post, &expected));
        let rendered = actual.block.to_token_stream().to_string();
        let foreign = rendered.replace("stage , selected , reader", "stage , foreign , reader");
        assert_ne!(foreign, rendered);
        let changed: syn::Block = syn::parse_str(&foreign).unwrap();
        assert!(!same_loan_body(&changed, &expected));
    }

    #[test]
    fn actual_final_loan_checks_old_counter_and_physical_posts_before_native_completion() {
        let actual = method("RestoredControllerCurrentReadLoan", "final_check");
        let expected: syn::Block = syn::parse_quote!({
            let mut attempt = RestoredCurrentReadAttempt {
                loan: self,
                stage,
                phase: None,
                completed: false,
            };
            let physical = attempt.loan.check_physical(attempt.stage);
            let counter_post = (|| {
                let completed = attempt
                    .loan
                    .completed
                    .as_mut()
                    .context("restore_current_counter_completion_missing")?;
                attempt
                    .loan
                    .counter
                    .check_completed_restored(attempt.stage, completed)
            })();
            let physical_post = attempt.loan.check_physical(attempt.stage);
            let native_post = attempt.stage.check();
            physical?;
            counter_post?;
            physical_post?;
            native_post?;
            attempt.completed = true;
            Ok(())
        });
        assert!(same_loan_body(&actual.block, &expected));
        for cut in 0..actual.block.stmts.len() - 1 {
            let mut omitted = actual.block.clone();
            omitted.stmts.remove(cut);
            assert!(!same_loan_body(&omitted, &expected), "final cut {cut}");
        }
        let mut conditional = actual.block.clone();
        conditional.stmts[2] = syn::parse_quote!(let counter_post=if physical.is_ok() {Ok(())} else {Err(anyhow::anyhow!("unrelated"))};);
        assert!(!same_loan_body(&conditional, &expected));
        let mut premature = actual.block.clone();
        premature.stmts.swap(9, 5);
        assert!(!same_loan_body(&premature, &expected));
    }

    #[test]
    fn actual_read_failure_and_drop_burn_the_passed_stage_peer_tail_and_resources() {
        let actual = method("RestoredControllerCurrentReadLoan", "refuse");
        let expected: syn::Block = syn::parse_quote!({
            self.disposition = RestoredReadDisposition::Refused;
            if let Some(completed) = &mut self.completed {
                completed.refuse();
            }
            self.target.refuse();
            self.counter.refuse();
        });
        assert!(same_loan_body(&actual.block, &expected));
        let actual = method("RestoredControllerCurrentReadLoan", "drop");
        let expected: syn::Block = syn::parse_quote!({
            if self.disposition != RestoredReadDisposition::Settled {
                self.refuse();
            }
        });
        assert!(same_loan_body(&actual.block, &expected));
        let inverted: syn::Block = syn::parse_quote!({
            if self.disposition == RestoredReadDisposition::Settled {
                self.refuse();
            }
        });
        assert!(!same_loan_body(&inverted, &expected));
        let omitted: syn::Block = syn::parse_quote!({
            if self.disposition != RestoredReadDisposition::Settled {
                unrelated();
            }
        });
        assert!(!same_loan_body(&omitted, &expected));
        let actual = method("RestoredCurrentReadAttempt", "drop");
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed {
                self.stage.refuse_serving();
                if let Some(phase) = &mut self.phase {
                    phase.refuse();
                }
                self.loan.refuse();
            }
        });
        assert!(same_loan_body(&actual.block, &expected));
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = &actual.block.stmts[0] else {
            panic!("actual armed drop");
        };
        assert_eq!(branch.then_branch.stmts.len(), 3);
        for cut in 0..3 {
            let mut changed = actual.block.clone();
            let syn::Stmt::Expr(syn::Expr::If(branch), _) = &mut changed.stmts[0] else {
                unreachable!();
            };
            branch.then_branch.stmts.remove(cut);
            assert!(!same_loan_body(&changed, &expected));
        }
    }

    fn loan_constructors(source: &str) -> Vec<(Option<String>, Option<String>)> {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Constructors {
            owner: Option<String>,
            method: Option<String>,
            found: Vec<(Option<String>, Option<String>)>,
        }
        impl<'ast> Visit<'ast> for Constructors {
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                if item.attrs.iter().any(|a|matches!(&a.meta,syn::Meta::List(m) if m.path.is_ident("cfg") && m.tokens.to_string()=="test")) {return;}
                syn::visit::visit_item_mod(self, item);
            }
            fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
                let old = self.owner.clone();
                self.owner = match &*item.self_ty {
                    syn::Type::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()),
                    _ => None,
                };
                syn::visit::visit_item_impl(self, item);
                self.owner = old;
            }
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let old = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = old;
            }
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item.path.segments.last().is_some_and(|s| {
                    s.ident == "RestoredControllerCurrentReadLoan"
                        || self.owner.as_deref() == Some("RestoredControllerCurrentReadLoan")
                            && s.ident == "Self"
                }) {
                    self.found.push((self.owner.clone(), self.method.clone()));
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let mut visitor = Constructors::default();
        visitor.visit_file(&syn::parse_file(source).unwrap());
        visitor.found
    }

    #[test]
    fn actual_current_loan_has_only_the_whole_carrier_lexical_factory_not_part_adoption() {
        let source = include_str!("native_current.rs");
        let expected = vec![(
            Some("RetiredControllerCurrentInstallation".to_owned()),
            Some("serve_app_currents".to_owned()),
        )];
        assert_eq!(loan_constructors(source), expected);
        for counterfeit in [
            "impl RestoredControllerCurrentReadLoan<'_, '_, '_> {fn counterfeit(target:Untrusted,counter:Untrusted)->Self {Self {target,counter}}}",
            "fn counterfeit(target:Untrusted,counter:Untrusted)->Untrusted {RestoredControllerCurrentReadLoan {target,counter}}",
            "impl RetiredControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {fn parts(target:Untrusted,counter:Untrusted)->Untrusted {RestoredControllerCurrentReadLoan {target,counter}}}",
        ] {
            assert_ne!(
                loan_constructors(&format!("{source}\n{counterfeit}")),
                expected
            );
        }
    }

    fn whole_current_scope(body: &syn::Block) -> bool {
        let expected: syn::Block = syn::parse_quote!({
            let native = &mut self.native;
            let counter = &mut self.counter;
            let installation = &mut self.pending.loan.installation;
            let installed = &mut installation.installed;
            let frame = &mut installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .frame;
            let reader = &frame.confirmation.owner.auth.action.reader.loan;
            let policy = &reader.policy;
            let selected = &reader.selection;
            let creator = &frame.creator;
            let report = &frame.confirmation.target;
            let target = &mut *frame.target;
            let cohort = frame
                .cohort
                .as_mut()
                .context("restore_current_cohort_missing")?;
            let mut first = Some((&mut *frame.peer, installed));
            let mut returned: Option<
                crate::security_epoch::native_enrollment::RestoredPeerConnection<'_>,
            > = None;
            loop {
                ensure!(
                    first.is_some() != returned.is_some(),
                    "restore_current_peer_source_changed"
                );
                let pending = match returned.as_mut() {
                    Some(peer) => peer.pending(),
                    None => {
                        let (peer, installed) = first
                            .as_mut()
                            .context("restore_current_first_peer_missing")?;
                        installed.first_current_pending(peer)
                    }
                }?;
                if !pending {
                    std::thread::park_timeout(std::time::Duration::from_millis(5));
                    continue;
                }
                let mut captured = native.capture_current_request()?;
                let rendezvous = match returned.take() {
                    Some(peer) => captured.prepare_retained_current_peer(native, peer)?,
                    None => {
                        let (peer, installed) =
                            first.take().context("restore_current_first_peer_missing")?;
                        captured.prepare_current_peer(native, peer, installed)?
                    }
                };
                let phase = captured.accept_current_peer(native, rendezvous, None)?;
                let mut loan = RestoredControllerCurrentReadLoan {
                    target: &mut *target,
                    counter: &mut *counter,
                    cohort: &mut *cohort,
                    creator,
                    report,
                    policy,
                    selected,
                    completed: None,
                    disposition: RestoredReadDisposition::Armed,
                };
                let (peer, snapshot) =
                    captured.serve_current_peer(native, phase, selected, &mut loan)?;
                loan.finish_after_native(&snapshot)?;
                returned = Some(peer);
            }
        });
        same_loan_body(body, &expected)
    }

    #[test]
    fn actual_whole_scope_captures_after_wakeup_and_keeps_native_peer_before_pure_disposal() {
        let actual = method("RetiredControllerCurrentInstallation", "serve_app_currents");
        assert!(whole_current_scope(&actual.block));
        let syn::Stmt::Expr(syn::Expr::Loop(loop_), _) = actual.block.stmts.last().unwrap() else {
            panic!("actual lexical loop");
        };
        assert_eq!(loop_.body.stmts.len(), 10);
        for cut in 0..actual.block.stmts.len() - 1 {
            let mut omitted = actual.block.clone();
            omitted.stmts.remove(cut);
            assert!(!whole_current_scope(&omitted), "whole-field cut {cut}");
        }
        for cut in 0..loop_.body.stmts.len() {
            let mut omitted = actual.block.clone();
            let syn::Stmt::Expr(syn::Expr::Loop(loop_), _) = omitted.stmts.last_mut().unwrap()
            else {
                unreachable!();
            };
            loop_.body.stmts.remove(cut);
            assert!(!whole_current_scope(&omitted), "loop boundary cut {cut}");
        }
        for (left, right) in [(1, 3), (7, 8), (8, 9)] {
            let mut reordered = actual.block.clone();
            let syn::Stmt::Expr(syn::Expr::Loop(loop_), _) = reordered.stmts.last_mut().unwrap()
            else {
                unreachable!();
            };
            loop_.body.stmts.swap(left, right);
            assert!(!whole_current_scope(&reordered), "order cut {left}/{right}");
        }
        let mut repair = actual.block.clone();
        let syn::Stmt::Expr(syn::Expr::Loop(loop_), _) = repair.stmts.last_mut().unwrap() else {
            unreachable!();
        };
        loop_
            .body
            .stmts
            .insert(0, syn::parse_quote!(self.pending.check()?;));
        assert!(!whole_current_scope(&repair), "no retired parent check");
        let signature: syn::Signature =
            syn::parse_str("fn serve_app_currents(mut self)->Result<()>").unwrap();
        assert_eq!(
            loan_tokens(actual.sig.to_token_stream()),
            loan_tokens(signature.to_token_stream())
        );
    }

    #[test]
    fn actual_consuming_disposal_is_private_after_native_success_and_never_an_early_rearm() {
        let actual = method("RestoredControllerCurrentReadLoan", "finish_after_native");
        assert!(matches!(actual.vis, syn::Visibility::Inherited));
        let expected_signature: syn::Signature = syn::parse_quote!(fn finish_after_native(mut self,snapshot:&day2_capabilities::Digest)->Result<()>);
        let consumes_actual_loan = |signature: &syn::Signature| {
            loan_tokens(signature.to_token_stream())
                == loan_tokens(expected_signature.to_token_stream())
        };
        assert!(consumes_actual_loan(&actual.sig));
        let mut borrowed = actual.sig.clone();
        borrowed.inputs[0] = syn::parse_quote!(&mut self);
        assert!(!consumes_actual_loan(&borrowed));
        let expected: syn::Block = syn::parse_quote!({
            ensure!(
                self.disposition == RestoredReadDisposition::Armed,
                "restore_current_loan_refused"
            );
            let completed = self
                .completed
                .take()
                .context("restore_current_counter_completion_missing")?;
            self.counter
                .release_completed_restored(completed, snapshot)?;
            self.disposition = RestoredReadDisposition::Settled;
            Ok(())
        });
        assert!(same_loan_body(&actual.block, &expected));
        for cut in 0..actual.block.stmts.len() - 1 {
            let mut omitted = actual.block.clone();
            omitted.stmts.remove(cut);
            assert!(!same_loan_body(&omitted, &expected));
        }
        let mut early = actual.block.clone();
        early.stmts.swap(2, 3);
        assert!(!same_loan_body(&early, &expected));
        let mut conditional = actual.block.clone();
        conditional.stmts[2] = syn::parse_quote!(if snapshot == &caller {
            self.counter
                .release_completed_restored(completed, snapshot)?;
        });
        assert!(!same_loan_body(&conditional, &expected));
        use syn::visit::Visit;
        #[derive(Default)]
        struct Calls {
            owner: Option<String>,
            method: Option<String>,
            found: Vec<(Option<String>, Option<String>)>,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                if item.attrs.iter().any(|a|matches!(&a.meta,syn::Meta::List(m) if m.path.is_ident("cfg")&&m.tokens.to_string()=="test")){return;}
                syn::visit::visit_item_mod(self, item);
            }
            fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
                let old = self.owner.clone();
                self.owner = match &*item.self_ty {
                    syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
                    _ => None,
                };
                syn::visit::visit_item_impl(self, item);
                self.owner = old;
            }
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let old = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = old;
            }
            fn visit_expr_method_call(&mut self, item: &'ast syn::ExprMethodCall) {
                if item.method == "finish_after_native" {
                    self.found.push((self.owner.clone(), self.method.clone()));
                }
                syn::visit::visit_expr_method_call(self, item);
            }
            fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
                if matches!(&*item.func,syn::Expr::Path(path) if path.path.segments.last().is_some_and(|segment|segment.ident=="finish_after_native"))
                {
                    self.found.push((self.owner.clone(), self.method.clone()));
                }
                syn::visit::visit_expr_call(self, item);
            }
        }
        let finish_calls = |source: &str| {
            let mut calls = Calls::default();
            calls.visit_file(&syn::parse_file(source).unwrap());
            calls.found
        };
        let source = include_str!("native_current.rs");
        let expected_calls = vec![(
            Some("RetiredControllerCurrentInstallation".to_owned()),
            Some("serve_app_currents".to_owned()),
        )];
        assert_eq!(finish_calls(source), expected_calls);
        for counterfeit in [
            "fn counterfeit(loan:Untrusted,snapshot:Untrusted){RestoredControllerCurrentReadLoan::finish_after_native(loan,snapshot);}",
            "impl RestoredControllerCurrentReadLoan<'_, '_, '_> {fn counterfeit(loan:Untrusted,snapshot:Untrusted){Self::finish_after_native(loan,snapshot);}}",
            "fn counterfeit(loan:Untrusted,snapshot:Untrusted){loan.finish_after_native(snapshot);}",
        ] {
            let calls = finish_calls(&format!("{source}\n{counterfeit}"));
            assert_eq!(calls.len(), expected_calls.len() + 1);
            assert_ne!(calls, expected_calls);
        }
    }

    fn root_native_flow(body: &syn::Block, final_call: &str) -> bool {
        let expected: syn::Block = syn::parse_quote!({
            let frame = &mut loan
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .frame;
            let reader = &mut frame.confirmation.owner.auth.action.reader.loan;
            let physical = reader
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let stage = physical.controller_stage()?;
            stage.require_current_role()?;
        });
        if body.stmts.len() != 7
            || body.stmts[..5]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                != expected
                    .stmts
                    .iter()
                    .map(ToTokens::to_token_stream)
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::Try(selection), Some(_)) = &body.stmts[5] else {
            return false;
        };
        let syn::Expr::MethodCall(selection) = &*selection.expr else {
            return false;
        };
        if selection.method != "check_selection"
            || !matches!(&*selection.receiver,syn::Expr::Path(path) if path.path.is_ident("stage"))
        {
            return false;
        }
        let args = selection
            .args
            .iter()
            .map(|x| x.to_token_stream().to_string())
            .collect::<Vec<_>>();
        if args
            != [
                "& reader . policy",
                "& reader . selection",
                "NativeRole :: EpochController",
            ]
        {
            return false;
        }
        let syn::Stmt::Expr(syn::Expr::MethodCall(tail), None) = &body.stmts[6] else {
            return false;
        };
        match final_call {
            "capture" => {
                tail.method == "capture_same_owner"
                    && tail.args.is_empty()
                    && matches!(&*tail.receiver,syn::Expr::Path(path) if path.path.is_ident("stage"))
            }
            "check" => {
                tail.method == "check"
                    && matches!(&*tail.receiver,syn::Expr::Path(path) if path.path.is_ident("same"))
                    && tail.args.len() == 1
                    && matches!(tail.args.first(),Some(syn::Expr::Path(path)) if path.path.is_ident("stage"))
            }
            _ => false,
        }
    }

    #[test]
    fn actual_native_partition_borrows_only_whole_installed_frame_and_current_controller() {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        for (name, tail) in [
            ("capture_controller", "capture"),
            ("check_controller", "check"),
        ] {
            let items = file
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Fn(item) if item.sig.ident == name => Some(item),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(items.len(), 1);
            let actual = &items[0].block;
            assert!(root_native_flow(actual, tail));
            let rendered = actual.to_token_stream().to_string();
            for (from, to) in [
                ("NativeRole :: EpochController", "NativeRole :: AppHost"),
                ("loan . installation", "other . installation"),
                ("reader . physical", "other . physical"),
                ("stage . require_current_role () ? ;", ""),
            ] {
                assert_eq!(rendered.matches(from).count(), 1);
                let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
                assert!(!root_native_flow(&changed, tail));
            }
        }
    }

    fn negative_start(method: &syn::ImplItemFn, guard: &str, field: &str, value: &str) -> bool {
        let Some(syn::Stmt::Local(first)) = method.block.stmts.first() else {
            return false;
        };
        let Some(init) = &first.init else {
            return false;
        };
        let syn::Expr::Struct(init) = &*init.expr else {
            return false;
        };
        init.path.segments.last().is_some_and(|part|part.ident==guard) && init.rest.is_none() && init.fields.len()==2
            && init.fields.iter().any(|item|matches!(&item.member,syn::Member::Named(name) if name==field) && item.expr.to_token_stream().to_string()==value)
            && init.fields.iter().any(|item|matches!(&item.member,syn::Member::Named(name) if name=="completed") && matches!(&item.expr,syn::Expr::Lit(value) if matches!(&value.lit,syn::Lit::Bool(value) if !value.value)))
    }

    fn prepare_flow(method: &syn::ImplItemFn) -> bool {
        if !negative_start(method, "NativeControllerPreparing", "loan", "Some (loan)") {
            return false;
        }
        let expected: syn::Block = syn::parse_quote!({
            let mut attempt = NativeControllerPreparing {
                loan: Some(loan),
                completed: false,
            };
            let requested = (|| {
                let loan = attempt
                    .loan
                    .as_mut()
                    .context("restore_native_controller_loan_missing")?;
                loan.check()?;
                capture_controller(loan)
            })();
            let checked = (|| {
                attempt
                    .loan
                    .as_mut()
                    .context("restore_native_controller_loan_missing")?
                    .check()
            })();
            if (requested.is_err() || checked.is_err())
                && let Some(loan) = &mut attempt.loan
            {
                loan.refuse();
            }
            let same = requested?;
            checked?;
            let loan = attempt
                .loan
                .take()
                .context("restore_native_controller_loan_missing")?;
            let pending = Self { loan, same };
            attempt.completed = true;
            Ok(pending)
        });
        let mut actual = method.block.clone();
        // Only the optional final named-field comma of this actual Self
        // literal is normalized; no tuple/call/struct-update token is dropped.
        if let Some(syn::Stmt::Local(pending)) = actual.stmts.get_mut(7)
            && let Some(init) = &mut pending.init
            && let syn::Expr::Struct(value) = &mut *init.expr
            && value.path.is_ident("Self")
            && value.rest.is_none()
        {
            value.fields.pop_punct();
        }
        actual.stmts.len() == expected.stmts.len()
            && actual.stmts[1..]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                == expected.stmts[1..]
                    .iter()
                    .map(ToTokens::to_token_stream)
                    .map(|x| x.to_string())
                    .collect::<Vec<_>>()
    }

    #[test]
    fn actual_native_checks_arm_before_work_and_keep_independent_post_and_primary() {
        let prepare = method("PendingControllerCurrentInstallation", "prepare");
        let check = method("PendingControllerCurrentInstallation", "check");
        assert!(prepare_flow(&prepare));
        assert!(negative_start(
            &check,
            "NativeControllerChecking",
            "owner",
            "self"
        ));
        let expected_check: syn::Block = syn::parse_quote!({
            let mut attempt = NativeControllerChecking {
                owner: self,
                completed: false,
            };
            let requested = (|| {
                attempt.owner.loan.check()?;
                check_controller(&mut attempt.owner.loan, &mut attempt.owner.same)
            })();
            let checked = attempt.owner.loan.check();
            if requested.is_err() || checked.is_err() {
                attempt.owner.refuse();
            }
            requested?;
            checked?;
            attempt.completed = true;
            Ok(())
        });
        // Optional terminal field separators do not alter the actual struct
        // fields; all other statements stay exact. The first was checked above.
        assert_eq!(
            check.block.stmts[1..]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            expected_check.stmts[1..]
                .iter()
                .map(ToTokens::to_token_stream)
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
        );
        let body = check.block.to_token_stream().to_string();
        for (from, to) in [
            (
                "let checked = attempt . owner . loan . check () ;",
                "let checked = Ok (()) ;",
            ),
            ("requested ? ; checked ? ;", "checked ? ; requested ? ;"),
            ("attempt . owner . refuse () ;", ""),
        ] {
            assert_eq!(body.matches(from).count(), 1);
            assert_ne!(
                syn::parse_str::<syn::Block>(&body.replacen(from, to, 1))
                    .unwrap()
                    .to_token_stream()
                    .to_string(),
                check.block.to_token_stream().to_string()
            );
        }
        let prepare_body = prepare.block.to_token_stream().to_string();
        let actual_posts = prepare_body.matches(". check ()").count();
        assert_eq!(actual_posts, 2);
        let mut conditional_post = prepare.clone();
        conditional_post.block.stmts[1] = syn::parse_quote! {
            let requested=(|| {
                let loan=attempt.loan.as_mut().context("restore_native_controller_loan_missing")?;
                loan.check()?;
                let same=capture_controller(loan)?;
                loan.check()?;
                Ok(same)
            })();
        };
        conditional_post.block.stmts[2] =
            syn::parse_quote! {let checked=Ok::<(),anyhow::Error>(());};
        assert_eq!(
            conditional_post
                .block
                .to_token_stream()
                .to_string()
                .matches(". check ()")
                .count(),
            actual_posts
        );
        assert!(
            !prepare_flow(&conditional_post),
            "two calls do not prove an independent outer post after primary error"
        );
        let requested_at = prepare_body.find("let same = requested ? ;").unwrap();
        let post_at = prepare_body.find("checked ? ;").unwrap();
        let take_at = prepare_body.find("attempt . loan . take ()").unwrap();
        let complete_at = prepare_body.find("attempt . completed = true").unwrap();
        assert!(requested_at < post_at && post_at < take_at && take_at < complete_at);
        for forbidden in [
            "NativeAcquisition :: begin",
            "begin_current",
            "finish_known",
            "store :: open",
            "release",
            "capture_current",
        ] {
            assert!(!prepare_body.contains(forbidden));
            assert!(!body.contains(forbidden));
        }
    }

    #[test]
    fn actual_native_negative_drop_refuses_the_same_carrier_without_io_or_clock() {
        let pending = method("PendingControllerCurrentInstallation", "drop").block;
        let expected: syn::Block = syn::parse_quote!({
            self.loan.refuse();
        });
        assert_eq!(
            pending.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let checking = method("NativeControllerChecking", "drop").block;
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed {
                self.owner.refuse();
            }
        });
        assert_eq!(
            checking.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let preparing = method("NativeControllerPreparing", "drop").block;
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed
                && let Some(loan) = &mut self.loan
            {
                loan.refuse();
            }
        });
        assert_eq!(
            preparing.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    fn retirement_flow(method: &syn::ImplItemFn) -> bool {
        if method.sig.inputs.len() != 2
            || !matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none())
        {
            return false;
        }
        let expected: syn::Block = syn::parse_quote!({
            let mut attempt = ProtectedInstalledAttempt {
                installation: Some(self),
                turn,
                completed: false,
            };
            {
                let installation = attempt
                    .installation
                    .as_mut()
                    .context("restore_output_installation_missing")?;
                installation.check()?;
                let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    installation.loan.send_installed_acceptance()
                }));
                let post =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| installation.check()));
                installed_observed(requested, post)?;
            }
            let mut state = super::RoleHandoffProgress::Prepare;
            while state != super::RoleHandoffProgress::Delivered {
                let operation = state.operation()?;
                let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    attempt
                        .installation
                        .as_mut()
                        .context("restore_output_installation_missing")?
                        .installed_output_step(attempt.turn, operation)
                }));
                let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    attempt
                        .installation
                        .as_mut()
                        .context("restore_output_installation_missing")?
                        .check()
                }));
                let progress = installed_observed(requested, post)?;
                state = state.after(operation, progress)?;
            }
            let mut installation = attempt
                .installation
                .take()
                .context("restore_output_installation_missing")?;
            installation.check()?;
            let native = retire_controller(&mut installation.loan)?;
            let retired = RetiredControllerCurrentInstallation {
                native,
                counter: crate::security_epoch::authenticated_reads::CounterConnectionSlot::new(),
                pending: installation,
            };
            attempt.completed = true;
            Ok(retired)
        });
        same_loan_body(&method.block, &expected)
    }

    fn scoped_arguments(ty: &syn::Type, expected: &str) -> Option<Vec<String>> {
        let syn::Type::Path(path) = ty else {
            return None;
        };
        if path.qself.is_some() || path.path.segments.len() != 1 {
            return None;
        }
        let part = path.path.segments.first()?;
        if part.ident != expected {
            return None;
        }
        let syn::PathArguments::AngleBracketed(args) = &part.arguments else {
            return None;
        };
        args.args
            .iter()
            .map(|arg| match arg {
                syn::GenericArgument::Lifetime(lifetime) => Some(lifetime.ident.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn actual_retirement_consumes_whole_post_ack_carrier_after_final_full_checks() {
        let actual = method(
            "PendingControllerCurrentInstallation",
            "finish_protected_restore",
        );
        assert!(retirement_flow(&actual));
        // Actual whole-method mutants, not duplicate fixtures. Preserve the
        // original no-post/wrong-owner/primary/old-reader/whole-carrier cuts,
        // now also requiring App acceptance BEFORE operator output.
        fn fragment(text: &str) -> String {
            let block: syn::Block = syn::parse_str(&format!("{{{text}}}")).unwrap();
            let statements = &block.stmts;
            loan_tokens(quote::quote!(#(#statements)*))
        }
        let original = loan_tokens(actual.to_token_stream());
        for (before, after) in [
            ("installation.check()?;", "Ok::<(),anyhow::Error>(())?;"),
            (
                "installation.loan.send_installed_acceptance()",
                "other.loan.send_installed_acceptance()",
            ),
            (
                "let post=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| installation.check()));",
                "let post=Ok(Ok(()));",
            ),
            (
                "let progress=installed_observed(requested,post)?;",
                "let progress=installed_observed(post,requested)?;",
            ),
            (
                "let native=retire_controller(&mut installation.loan)?;",
                "let native=retire_controller(&mut other.loan)?;",
            ),
            (
                "let mut state=super::RoleHandoffProgress::Prepare;",
                "let mut state=super::RoleHandoffProgress::Delivered;",
            ),
            (
                "state=state.after(operation,progress)?;",
                "state=super::RoleHandoffProgress::Delivered;",
            ),
            (
                "attempt.completed=true;",
                "installation.check()?;attempt.completed=true;",
            ),
            ("Ok(retired)", "Ok(native)"),
        ] {
            let before = fragment(before);
            // The initial native check and final check are both required.
            assert!(
                original.contains(&before),
                "actual terminal source target: {before}"
            );
            let changed = original.replacen(&before, &fragment(after), 1);
            let changed: syn::ImplItemFn = syn::parse_str(&changed).unwrap();
            assert!(!retirement_flow(&changed));
        }
        let mut old_counter = actual.clone();
        let syn::Stmt::Local(retired) = &mut old_counter.block.stmts[7] else {
            panic!("actual retained carrier");
        };
        let syn::Expr::Struct(carrier) = &mut *retired.init.as_mut().unwrap().expr else {
            panic!("actual retained literal");
        };
        carrier
            .fields
            .iter_mut()
            .find(|field| matches!(&field.member,syn::Member::Named(name) if name=="counter"))
            .unwrap()
            .expr = syn::parse_quote!(reader.reads);
        assert!(
            !retirement_flow(&old_counter),
            "old administrative reader cannot supply the new slot"
        );
        let mut early = actual.clone();
        early
            .block
            .stmts
            .insert(1, syn::parse_quote!(attempt.completed=true;));
        assert!(!retirement_flow(&early));
        let syn::ReturnType::Type(_, returned) = actual.sig.output else {
            panic!("missing owned output");
        };
        let syn::Type::Path(path) = *returned else {
            panic!("unexpected output");
        };
        let part = path.path.segments.first().unwrap();
        assert!(path.qself.is_none() && path.path.segments.len() == 1 && part.ident == "Result");
        let syn::PathArguments::AngleBracketed(args) = &part.arguments else {
            panic!("missing result argument");
        };
        assert_eq!(args.args.len(), 1);
        let Some(syn::GenericArgument::Type(carrier)) = args.args.first() else {
            panic!("unexpected result argument");
        };
        assert_eq!(
            scoped_arguments(carrier, "RetiredControllerCurrentInstallation").unwrap(),
            [
                "frame",
                "confirm",
                "metadata",
                "storage",
                "role",
                "target",
                "selection"
            ]
        );
    }

    #[test]
    fn actual_installed_output_step_prechecks_same_carrier_and_lends_only_actual_native_fields() {
        let actual = method(
            "PendingControllerCurrentInstallation",
            "installed_output_step",
        );
        let expected: syn::Block = syn::parse_quote!({
            self.check()?;
            let frame = &mut self
                .loan
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .frame;
            let owner = &mut *frame.confirmation.owner;
            owner.refused.set(true);
            let physical = owner
                .auth
                .action
                .reader
                .loan
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?;
            let stage = physical.controller_stage()?;
            let mut loan = RestoreInstalledOutputLoan {
                original: &mut owner.auth.original,
                approval: &owner.auth.record.statement.request,
                operation: &owner.auth.operation,
                creator: &frame.creator,
                report: &frame.confirmation.target,
                target: frame.target,
                cohort: frame
                    .cohort
                    .as_mut()
                    .context("restore_current_cohort_missing")?,
                refused: &owner.refused,
                _lost: LostRestoreWriterConfirmation {
                    refused: std::rc::Rc::clone(&owner.refused),
                },
            };
            use crate::security_epoch::native_enrollment::ProtectedRestoreInstalledIo as Io;
            let operation = match operation {
                super::RoleHandoffIo::Prepare => Io::Prepare,
                super::RoleHandoffIo::Sign => Io::Sign,
                super::RoleHandoffIo::Send => Io::Send,
                super::RoleHandoffIo::Poll => Io::Poll,
            };
            turn.installed_output(stage, &mut loan, operation)
        });
        assert!(same_loan_body(&actual.block, &expected));
        let original = loan_tokens(actual.block.to_token_stream());
        // Compare actual AST fragments; no whitespace deletion or test-string
        // matching can erase a production mutation target.
        fn statement(text: &str) -> String {
            let block: syn::Block = syn::parse_str(&format!("{{{text}}}")).unwrap();
            let stmts = &block.stmts;
            loan_tokens(quote::quote!(#(#stmts)*))
        }
        fn expression(text: &str) -> String {
            let expr: syn::Expr = syn::parse_str(text).unwrap();
            loan_tokens(expr.to_token_stream())
        }
        let cuts = [
            (
                statement("self.check()?;"),
                statement("Ok::<(),anyhow::Error>(())?;"),
            ),
            (
                statement("owner.refused.set(true);"),
                statement("owner.refused.set(false);"),
            ),
            (
                statement("let stage=physical.controller_stage()?;"),
                statement("let stage=other.controller_stage()?;"),
            ),
            (
                expression("&mut owner.auth.original"),
                expression("&mut other.auth.original"),
            ),
            (
                expression("&owner.auth.record.statement.request"),
                expression("&other.auth.record.statement.request"),
            ),
            (
                expression("&owner.auth.operation"),
                expression("&other.auth.operation"),
            ),
            (expression("&frame.creator"), expression("&other.creator")),
            (
                expression("&frame.confirmation.target"),
                expression("&other.confirmation.target"),
            ),
            (expression("frame.target"), expression("other.target")),
            (
                expression("frame.cohort.as_mut().context(\"restore_current_cohort_missing\")?"),
                expression("other.cohort.as_mut().context(\"restore_current_cohort_missing\")?"),
            ),
            (
                expression("turn.installed_output(stage,&mut loan,operation)"),
                expression("other.installed_output(stage,&mut loan,operation)"),
            ),
        ];
        for (before, after) in cuts {
            assert_eq!(
                original.matches(&before).count(),
                1,
                "one actual output-step target: {before}"
            );
            let changed: syn::Block =
                syn::parse_str(&original.replacen(&before, &after, 1)).unwrap();
            assert!(!same_loan_body(&changed, &expected));
        }
        let mut late_pre = actual.block.clone();
        late_pre.stmts.swap(0, 4);
        assert!(!same_loan_body(&late_pre, &expected));
        let mut late_mark = actual.block.clone();
        late_mark.stmts.swap(3, 6);
        assert!(!same_loan_body(&late_mark, &expected));
        // The source borrow MUST end before the caller's independent full post.
        let whole = method(
            "PendingControllerCurrentInstallation",
            "finish_protected_restore",
        );
        assert!(retirement_flow(&whole));
    }

    #[test]
    fn actual_installed_output_loan_joins_original_and_exact_held_target_even_on_failure() {
        let actual = method("RestoreInstalledOutputLoan", "check");
        let expected: syn::Block = syn::parse_quote!({
            let requested = (|| {
                ensure!(
                    self.refused.get(),
                    "restore_output_outside_installed_carrier"
                );
                storage.check_restore_original(self.original, self.approval, self.operation)?;
                let cohort = self.cohort.check(self.target, self.creator, self.report)?;
                ensure!(
                    self.report.target_incarnation == self.approval.target.incarnation
                        && self.report.target_epoch == self.approval.target.security_epoch
                        && self.report.artifact == self.approval.target.artifact
                        && self.report.schema == self.approval.target.schema,
                    "restore_output_installed_target_changed"
                );
                Ok(
                    crate::security_epoch::native_enrollment::RestoreInstalledOutputData {
                        approval: self.approval.commitment()?,
                        operation: self.operation.clone(),
                        full_archive: self.approval.full_archive_digest.clone(),
                        target: self.approval.target.clone(),
                        executor: self.approval.executor.clone(),
                        installed: day2_capabilities::Digest::of(&(
                            "day2-protected-restore-installed-output-v1",
                            self.report,
                            &cohort,
                        ))?,
                    },
                )
            })();
            let post = storage.check_restore_original(self.original, self.approval, self.operation);
            if requested.is_err() || post.is_err() {
                self.refuse();
            }
            let data = requested?;
            post?;
            Ok(data)
        });
        assert!(same_loan_body(&actual.block, &expected));
        let original = loan_tokens(actual.block.to_token_stream());
        fn fragment(text: &str) -> String {
            let block: syn::Block = syn::parse_str(&format!("{{{text}}}")).unwrap();
            let stmts = &block.stmts;
            loan_tokens(quote::quote!(#(#stmts)*))
        }
        for (before, after) in [
            (
                "storage.check_restore_original(self.original,self.approval,self.operation)?;",
                "Ok::<(),anyhow::Error>(())?;",
            ),
            (
                "let cohort=self.cohort.check(self.target,self.creator,self.report)?;",
                "let cohort=other.cohort.check(other.target,self.creator,self.report)?;",
            ),
            (
                "let post=storage.check_restore_original(self.original,self.approval,self.operation);",
                "let post=if requested.is_ok(){storage.check_restore_original(self.original,self.approval,self.operation)}else{Ok(())};",
            ),
            ("let data=requested?;post?;", "post?;let data=requested?;"),
            (
                "if requested.is_err()||post.is_err(){self.refuse();}",
                "if requested.is_err()&&post.is_err(){self.refuse();}",
            ),
        ] {
            let before = fragment(before);
            assert_eq!(original.matches(&before).count(), 1);
            let changed: syn::Block =
                syn::parse_str(&original.replacen(&before, &fragment(after), 1)).unwrap();
            assert!(!same_loan_body(&changed, &expected));
        }
    }

    #[test]
    fn actual_installed_output_drop_refuses_turn_and_whole_carrier_before_any_terminal_check() {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        let drops=file.items.iter().filter_map(|item|{
            let syn::Item::Impl(item)=item else{return None};
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|s|s.ident=="ProtectedInstalledAttempt")) || item.trait_.as_ref().is_none_or(|(_,path,_)|!path.is_ident("Drop")){return None;}
            item.items.iter().find_map(|method|match method{syn::ImplItem::Fn(method) if method.sig.ident=="drop"=>Some(method),_=>None})
        }).collect::<Vec<_>>();
        assert_eq!(drops.len(), 1);
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed {
                self.turn.refuse();
                if let Some(installation) = &mut self.installation {
                    installation.refuse();
                }
            }
        });
        assert!(same_loan_body(&drops[0].block, &expected));
        let mut omitted = drops[0].block.clone();
        omitted.stmts.clear();
        assert!(!same_loan_body(&omitted, &expected));
        let mut inverted = drops[0].block.clone();
        let syn::Stmt::Expr(syn::Expr::If(condition), _) = &mut inverted.stmts[0] else {
            panic!("actual negative Drop");
        };
        *condition.cond = syn::parse_quote!(self.completed);
        assert!(!same_loan_body(&inverted, &expected));
    }

    #[test]
    fn installed_output_keeps_primary_type_pointer_and_independent_post_unwind() {
        struct Primary;
        impl std::fmt::Debug for Primary {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("foreign debug");
            }
        }
        impl std::fmt::Display for Primary {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("foreign display");
            }
        }
        impl std::error::Error for Primary {}
        let error = anyhow::Error::new(Primary);
        let pointer = error.downcast_ref::<Primary>().unwrap() as *const Primary;
        let result = super::installed_observed::<()>(Ok(Err(error)), Err(Box::new("post panic")))
            .unwrap_err();
        assert_eq!(
            result.downcast_ref::<Primary>().unwrap() as *const Primary,
            pointer
        );
        assert!(
            super::installed_observed(Ok(Ok(7)), Ok(Err(anyhow::anyhow!("post refused")))).is_err()
        );
        assert_eq!(super::installed_observed(Ok(Ok(7)), Ok(Ok(()))).unwrap(), 7);
        let panic = std::panic::catch_unwind(|| {
            super::installed_observed::<()>(Err(Box::new("first")), Err(Box::new("second")))
        })
        .unwrap_err();
        assert_eq!(*panic.downcast::<&str>().unwrap(), "first");
    }

    #[test]
    fn installed_output_same_packet_order_never_skips_preparation_or_restarts_after_delivery() {
        use super::super::{RoleHandoffIo as I, RoleHandoffProgress as S};
        use crate::security_epoch::native_enrollment::ReceiverProgress as P;
        let mut state = S::Prepare;
        for (operation, progress, next) in [
            (I::Prepare, P::Advanced, S::Sign),
            (I::Sign, P::Advanced, S::Send),
            (I::Send, P::Interrupted, S::Send),
            (I::Send, P::WouldBlock, S::Poll),
            (I::Poll, P::Interrupted, S::Poll),
            (I::Poll, P::Advanced, S::Send),
            (I::Send, P::Delivered, S::Delivered),
        ] {
            assert_eq!(state.operation().unwrap(), operation);
            state = state.after(operation, progress).unwrap();
            assert_eq!(state, next);
        }
        assert!(state.operation().is_err());
        for state in [S::Prepare, S::Sign, S::Send, S::Poll] {
            for operation in [I::Prepare, I::Sign, I::Send, I::Poll] {
                if state.operation().unwrap() != operation {
                    assert!(state.after(operation, P::Delivered).is_err());
                }
            }
        }
        assert!(S::Prepare.after(I::Prepare, P::Delivered).is_err());
        assert!(S::Sign.after(I::Sign, P::Delivered).is_err());
        assert!(S::Refused.operation().is_err());
    }

    fn terminal_flow(body: &syn::Block) -> bool {
        let expected: syn::Block = syn::parse_quote!({
            let frame = &mut loan
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .installation
                .frame;
            let owner = &mut *frame.confirmation.owner;
            let reader = &mut owner.auth.action.reader.loan;
            reader.disposition.require_closed()?;
            reader.reads.finish(
                reader
                    .physical
                    .as_mut()
                    .context("native_restore_physical_closed")?
                    .controller_stage()?,
            )?;
            reader
                .physical
                .as_mut()
                .context("native_restore_physical_closed")?
                .release_restore_stop(&owner.stopped)?;
            reader
                .physical
                .take()
                .context("native_restore_physical_closed")?
                .retire_restore_native()
        });
        body.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    #[test]
    fn actual_terminal_order_finishes_same_counter_then_same_stop_then_owned_physical() {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        let actual = file
            .items
            .into_iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "retire_controller" => Some(item),
                _ => None,
            })
            .unwrap();
        assert!(terminal_flow(&actual.block));
        for index in 0..actual.block.stmts.len() {
            let mut changed = actual.block.clone();
            changed.stmts.remove(index);
            assert!(!terminal_flow(&changed));
        }
        let mut early_release = actual.block.clone();
        early_release.stmts.swap(4, 5);
        assert!(!terminal_flow(&early_release));
        let mut parent_after_counter = actual.block.clone();
        parent_after_counter
            .stmts
            .insert(5, syn::parse_quote! {loan.check()?;});
        assert!(!terminal_flow(&parent_after_counter));
        let rendered = actual.block.to_token_stream().to_string();
        for (from, to) in [
            ("& owner . stopped", "& other.stopped"),
            ("reader . reads . finish", "other.reads.finish"),
            (". take ()", ". as_mut ()"),
            (". retire_restore_native ()", ". finish_app_known ()"),
        ] {
            assert_eq!(rendered.matches(from).count(), 1);
            let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(!terminal_flow(&changed));
        }
    }

    fn retired_has_no_partial_capture(file: &syn::File) -> bool {
        let mut count = 0;
        for item in &file.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().is_some_and(|part|part.ident=="RetiredControllerCurrentInstallation"))
            {
                continue;
            }
            if item
                .trait_
                .as_ref()
                .is_some_and(|(_, path, _)| path.is_ident("Drop"))
            {
                continue;
            }
            if item.trait_.is_some() {
                return false;
            }
            for item in &item.items {
                let syn::ImplItem::Fn(method) = item else {
                    return false;
                };
                if method.sig.ident != "serve_app_currents" || !whole_current_scope(&method.block) {
                    return false;
                }
                count += 1;
            }
        }
        count == 1
    }

    #[test]
    fn retired_carrier_retains_all_scoped_owners_and_negative_drop_without_getters() {
        let file = syn::parse_file(include_str!("native_current.rs")).unwrap();
        let carrier = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RetiredControllerCurrentInstallation" => {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(carrier.generics.lifetimes().count(), 7);
        assert_eq!(carrier.fields.len(), 3);
        for field in &carrier.fields {
            assert!(matches!(field.vis, syn::Visibility::Inherited));
        }
        let pending = carrier
            .fields
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|name| name == "pending"))
            .unwrap();
        assert_eq!(
            scoped_arguments(&pending.ty, "PendingControllerCurrentInstallation").unwrap(),
            [
                "frame",
                "confirm",
                "metadata",
                "storage",
                "role",
                "target",
                "selection"
            ]
        );
        let native = carrier
            .fields
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|name| name == "native"))
            .unwrap();
        assert_eq!(
            scoped_arguments(&native.ty, "RetainedControllerNative").unwrap(),
            ["role"]
        );
        let negative = method("RetiredControllerCurrentInstallation", "drop");
        let expected: syn::Block = syn::parse_quote!({
            self.counter.refuse();
            self.native.refuse();
            self.pending.refuse();
        });
        assert_eq!(
            negative.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let counter = carrier
            .fields
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|name| name == "counter"))
            .unwrap();
        assert_eq!(
            canonical(counter.ty.to_token_stream()),
            canonical(quote::quote!(
                crate::security_epoch::authenticated_reads::CounterConnectionSlot
            ))
        );
        assert!(retired_has_no_partial_capture(&file));
        for addition in [
            "impl RetiredControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {fn capture_current(self)->Untrusted {untrusted}}",
            "impl RetiredControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {fn native(&mut self)->Untrusted {untrusted}}",
            "impl RetiredControllerCurrentInstallation<'_, '_, '_, '_, '_, '_, '_> {fn counter(&mut self)->Untrusted {untrusted}}",
        ] {
            let changed = syn::parse_file(&format!(
                "{}\n{addition}",
                include_str!("native_current.rs")
            ))
            .unwrap();
            assert!(!retired_has_no_partial_capture(&changed));
        }
    }
}
