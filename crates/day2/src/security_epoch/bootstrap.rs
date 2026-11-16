//! Fixed original-file bootstrap operations. Each one owns a fresh real
//! Controller/file/peer phase and authenticated counter port. There is no
//! public mutation callback, replay/warmup or stored-row-to-send conversion.

use super::{
    InitialStorageContinuity,
    authenticated_reads::{ControllerPort, CounterRequest, RestoredEpochObservation},
    control_slot::{AttemptCore, LogicalCore, SettlementCore, SlotState},
    control_slot_io,
    controller::evidence::{PreparationFailure, PreparationStep},
    controller::serving_timing::{ServingStep, ServingTiming},
    controller::{bootstrap_timing::BootstrapTiming, preparation_timing::Operation},
    firestore::{EpochObservation, Names, Port, RestoreWriterPeerRead},
    journal::{CurrentBootstrapExecution, Purpose},
    kernel::{self, Outcome, Request, Snapshot},
    native_enrollment::{EnrolledRoleStage, NativeRole},
    self_check_profile::{self, Category},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use std::{cell::RefCell, rc::Rc};

mod admin_read;
pub(in crate::security_epoch) use admin_read::{
    AuthenticatedRestoreExecution, CompletedCeremony, ExecutionSourceLoan, FencedRegistryLoan,
    FencedRestoreContinuation, ReservationRegistryLoan, ReservationSourceLoan,
    RestoreAuthenticationAction, RestoreFinalInstallationLoan, RestoreTargetCheck,
    RestoreWriteLoan, RestoreWriterActivationLoan, RestoreWriterConfirmation,
    RestoreWriterExchangeContext, RestoreWriterReleaseLoan, TargetSettlementSourceLoan,
    WriterConfirmationSourceLoan, WriterMayRegistryLoan, WriterRegistryLoan, WriterSendSourceLoan,
};
pub(crate) use admin_read::{
    FencedReadUnit, ReservationReadUnit, WriterMayReadUnit, WriterReadUnit,
};
mod app_serving;
#[cfg(test)]
mod lineage;
pub(crate) use admin_read::{
    ControllerAdminReadLoan, ControllerAdminReader, ControllerRegistryData,
};
#[cfg(test)]
mod controller_serving;

// Fixed comparison lineage and genuine observations. Effective helper scope
// remains bootstrap and its descendants; no parts or native owner escape.
pub(in crate::security_epoch) struct ActiveLineage {
    kind: LineageKind,
}

struct InitialLineage {
    completion: Request,
    activation: Digest,
}

enum LineageKind {
    Initial(Box<InitialLineage>),
    // Only the genuine accepting-owner handoff may construct this branch.
    // There is deliberately no public or DATA-only restored constructor.
    Restored(Box<RestoreWriterPeerRead>),
}

pub(in crate::security_epoch) struct ActiveObservation {
    binding: Digest,
    kind: ObservationKind,
}

enum ObservationKind {
    Initial(Box<EpochObservation>),
    Restored(Box<RestoredEpochObservation>),
}

impl ActiveObservation {
    fn refuse(&mut self) {
        match &mut self.kind {
            ObservationKind::Initial(observed) => observed.refuse(),
            ObservationKind::Restored(observed) => observed.refuse(),
        }
    }
}

impl ActiveLineage {
    /// Selection DATA from the existing fixed successful initial bootstrap.
    /// This does not admit a reader or construct active physical continuity.
    fn initial(completion: Request, activation: Digest) -> Self {
        Self {
            kind: LineageKind::Initial(Box::new(InitialLineage {
                completion,
                activation,
            })),
        }
    }

    /// Comparison DATA from the genuine pending App only. The caller must
    /// retain that same owner through physical conversion and real installed
    /// acknowledgement/posts; this metadata neither installs nor serves it.
    /// A fresh observation still comes only from the actual request in read().
    fn from_app_install(
        pending: &mut crate::security_epoch::native_enrollment::PendingRestoredEnrollment,
        selection: &EpochStore,
    ) -> Result<Self> {
        let reader = pending.checked_restored_reader_data(selection)?;
        Ok(Self {
            kind: LineageKind::Restored(Box::new(reader)),
        })
    }

    /// Negative comparison only. The actual pending owner derives the expected
    /// reader under its full checks and refuses itself on any mismatch before
    /// admitting a counter/read. Equality is not a native owner or permission.
    pub(in crate::security_epoch) fn require_restored_reader_data(
        &self,
        expected: &RestoreWriterPeerRead,
    ) -> Result<()> {
        match &self.kind {
            LineageKind::Restored(reader) => {
                ensure!(
                    reader.binding_data()? == expected.binding_data()?,
                    "active_lineage_restored_reader_changed"
                );
                Ok(())
            }
            LineageKind::Initial(_) => anyhow::bail!("active_lineage_restored_required"),
        }
    }

    fn binding_data(&self) -> Result<Digest> {
        match &self.kind {
            LineageKind::Initial(initial) => Digest::of(&(
                "day2-initial-active-lineage-v1",
                initial.completion.digest()?,
                &initial.activation,
            )),
            LineageKind::Restored(reader) => reader.binding_data(),
        }
    }

    fn require_selection_data(&self, selection: &EpochStore) -> Result<()> {
        match &self.kind {
            LineageKind::Initial(initial) => {
                ensure!(
                    matches!(
                        &initial.completion,
                        Request::CompleteInitialFirstActivation { .. }
                    ),
                    "active_lineage_initial_completion_required"
                );
                initial.completion.validate(selection)
            }
            LineageKind::Restored(reader) => {
                ensure!(
                    reader.matches_selection_data(selection),
                    "active_lineage_store_changed"
                );
                Ok(())
            }
        }
    }

    fn require_pair_data(&self, observed: &ActiveObservation) -> Result<()> {
        ensure!(
            matches!(
                (&self.kind, &observed.kind),
                (LineageKind::Initial(_), ObservationKind::Initial(_))
                    | (LineageKind::Restored(_), ObservationKind::Restored(_))
            ) && observed.binding == self.binding_data()?,
            "active_lineage_observation_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn read(
        &self,
        selection: &EpochStore,
        reads: &mut CounterRequest<'_>,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<ActiveObservation> {
        let requested = (|| {
            self.require_selection_data(selection)?;
            let binding = self.binding_data()?;
            let kind = match &self.kind {
                LineageKind::Initial(initial) => {
                    let names = request_names(selection, &initial.completion)?;
                    let mut observed = reads.read(stage, selection, &names)?;
                    if let Err(error) = check_active_snapshot(
                        selection,
                        &initial.completion,
                        &initial.activation,
                        observed.snapshot(),
                    ) {
                        observed.refuse();
                        return Err(error);
                    }
                    ObservationKind::Initial(Box::new(observed))
                }
                LineageKind::Restored(reader) => ObservationKind::Restored(Box::new(
                    reads.read_restored(stage, selection, reader)?,
                )),
            };
            Ok(ActiveObservation { binding, kind })
        })();
        if requested.is_err() {
            reads.refuse();
        }
        requested
    }

    /// Check the OLD actual observation before a subsequent read. A wrong
    /// pairing is refused directly, without a fake selection or new sample.
    pub(in crate::security_epoch) fn check(
        &self,
        selection: &EpochStore,
        reads: &mut CounterRequest<'_>,
        stage: &mut EnrolledRoleStage<'_>,
        observed: &mut ActiveObservation,
    ) -> Result<()> {
        let requested = (|| {
            self.require_selection_data(selection)?;
            self.require_pair_data(observed)?;
            match (&self.kind, &mut observed.kind) {
                (LineageKind::Initial(initial), ObservationKind::Initial(observed)) => {
                    // Preserve the existing local guard's primary-error order:
                    // actual native/observation checks precede pure snapshot DATA.
                    reads.check_observation(stage, observed)?;
                    check_active_snapshot(
                        selection,
                        &initial.completion,
                        &initial.activation,
                        observed.snapshot(),
                    )
                }
                (LineageKind::Restored(reader), ObservationKind::Restored(observed)) => {
                    reads.check_restored_observation(stage, reader, observed)
                }
                _ => anyhow::bail!("active_lineage_observation_changed"),
            }
        })();
        if requested.is_err() {
            observed.refuse();
            reads.refuse();
        }
        requested
    }

    /// Historical commitment only, after the caller's actual check. Any error
    /// remains in that fixed caller's permanent-refusal path.
    pub(in crate::security_epoch) fn snapshot_data(
        &self,
        observed: &ActiveObservation,
    ) -> Result<Digest> {
        self.require_pair_data(observed)?;
        match &observed.kind {
            ObservationKind::Initial(observed) => {
                crate::security_epoch::journal::snapshot_digest(observed.snapshot())
            }
            ObservationKind::Restored(observed) => Ok(observed.snapshot_data().clone()),
        }
    }

    /// The existing first-restore approval kernel accepts only an initial
    /// predecessor. This never casts restored history back to epoch one.
    fn initial_restore_snapshot_data(
        &self,
        observed: &ActiveObservation,
    ) -> Result<crate::security_epoch::kernel::Snapshot> {
        self.require_pair_data(observed)?;
        match &observed.kind {
            ObservationKind::Initial(observed) => Ok(observed.snapshot().clone()),
            ObservationKind::Restored(_) => anyhow::bail!("initial_restore_lineage_required"),
        }
    }

    /// Initial database birth only; the caller still checks its actual
    /// InitialStorage purpose, native keeper and reviewed runtime selection.
    fn initial_runtime_artifact_data(&self) -> Result<&Digest> {
        match &self.kind {
            LineageKind::Initial(initial) => Ok(&initial.completion.bootstrap().manifest.artifact),
            LineageKind::Restored(_) => anyhow::bail!("initial_restore_lineage_required"),
        }
    }

    /// The fixed first-restore read units retain the initial document names
    /// even after fencing. Restored lineage cannot enter those old-history loans.
    fn initial_restore_names_data(
        &self,
        selection: &EpochStore,
    ) -> Result<crate::security_epoch::firestore::Names> {
        self.require_selection_data(selection)?;
        match &self.kind {
            LineageKind::Initial(initial) => request_names(selection, &initial.completion),
            LineageKind::Restored(_) => anyhow::bail!("initial_restore_lineage_required"),
        }
    }

    fn initial_restore_stop_selection_data(
        &self,
        selection: &EpochStore,
        intent: &crate::security_epoch::kernel::restore::Intent,
        before: &crate::security_epoch::kernel::Snapshot,
    ) -> Result<crate::security_epoch::kernel::restore::StopSelection> {
        self.require_selection_data(selection)?;
        match &self.kind {
            LineageKind::Initial(initial) => {
                crate::security_epoch::kernel::restore::StopSelection::new(
                    selection,
                    intent,
                    &initial.completion,
                    before,
                )
            }
            LineageKind::Restored(_) => anyhow::bail!("initial_restore_lineage_required"),
        }
    }

    fn check_initial_restore_stop_data(
        &self,
        selection: &EpochStore,
        operation: &Digest,
        stop: &crate::security_epoch::kernel::restore::StopSelection,
        observed: &crate::security_epoch::kernel::Snapshot,
    ) -> Result<()> {
        self.require_selection_data(selection)?;
        match &self.kind {
            LineageKind::Initial(initial) => {
                stop.check_active_data(selection, operation, &initial.completion, observed)
            }
            LineageKind::Restored(_) => anyhow::bail!("initial_restore_lineage_required"),
        }
    }

    fn initial_restore_confirmation_data(
        &self,
        selection: &EpochStore,
        operation: &Digest,
        stop: &crate::security_epoch::kernel::restore::StopSelection,
        before: &crate::security_epoch::kernel::Snapshot,
        confirmation: &crate::security_epoch::firestore::ReservationConfirmation,
    ) -> Result<crate::security_epoch::firestore::RestoreConfirmationNames> {
        self.require_selection_data(selection)?;
        match &self.kind {
            LineageKind::Initial(initial) => {
                crate::security_epoch::firestore::RestoreConfirmationNames::new(
                    selection,
                    &initial.completion,
                    operation,
                    stop,
                    before,
                    confirmation,
                )
            }
            LineageKind::Restored(_) => anyhow::bail!("initial_restore_lineage_required"),
        }
    }

    pub(in crate::security_epoch) fn serving_binding(&self, binding: &Digest) -> Result<Digest> {
        match &self.kind {
            LineageKind::Initial(initial) => Digest::of(&(
                "day2-current-active-app-storage-v1",
                initial.completion.digest()?,
                binding,
            )),
            LineageKind::Restored(reader) => Digest::of(&(
                "day2-current-restored-app-storage-v1",
                reader.binding_data()?,
                binding,
            )),
        }
    }

    pub(in crate::security_epoch) fn admin_binding(&self, operation: &Digest) -> Result<Digest> {
        match &self.kind {
            LineageKind::Initial(initial) => Digest::of(&(
                "day2-current-admin-read-v1",
                initial.completion.digest()?,
                operation,
            )),
            LineageKind::Restored(reader) => Digest::of(&(
                "day2-current-restored-admin-read-v1",
                reader.binding_data()?,
                operation,
            )),
        }
    }
}

// The actual observation retains all eight negative traits in the root guard below.

// Fixed Controller callers retain their exact former bodies and guards.
impl ActiveControllerStorageContinuity {
    pub(in crate::security_epoch) fn app_pending(&mut self) -> Result<bool> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.storage.app_pending()
    }

    pub(in crate::security_epoch) fn serve_app_current(
        &mut self,
        stage: EnrolledRoleStage<'_>,
        trace: &ServingTiming,
    ) -> Result<ServingObservation> {
        let _profile = self_check_profile::enter(Category::ServingLocal);
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            let (mut physical, mut reads) = trace.measure(ServingStep::PhysicalBegin, || {
                let _profile = self_check_profile::enter(Category::PhysicalLocal);
                self.storage.begin_current_app(
                    stage,
                    &self.policy,
                    &self.store,
                    &mut self.counter,
                    trace,
                )
            })?;
            // Authenticated request selection is DATA. This can only be the
            // actual retained App enrollment and a fresh Current transcript.
            let binding = trace.measure(ServingStep::RequestBinding, || {
                Ok(physical.app_request()?.binding().clone())
            })?;
            let mut observed = trace.measure(ServingStep::CounterBefore, || {
                self.lineage
                    .read(&self.store, &mut reads, physical.controller_stage()?)
            })?;
            // The checked stage getter performs the complete physical
            // post-read check once, immediately before observation use.
            trace.measure(ServingStep::ProviderBefore, || {
                self.lineage.check(
                    &self.store,
                    &mut reads,
                    physical.controller_stage()?,
                    &mut observed,
                )
            })?;
            // Await the actual App consumer and original postchecks, then
            // reobserve the fixed counter through one closed physical join.
            observed = physical.announce_and_read_app_consumed(
                &mut reads,
                &self.store,
                &self.lineage,
                &mut observed,
                trace,
            )?;
            trace.measure(ServingStep::ProviderAfter, || {
                self.lineage.check(
                    &self.store,
                    &mut reads,
                    physical.controller_stage()?,
                    &mut observed,
                )
            })?;
            // Snapshot commitment is bounded DATA work. The closed finisher
            // performs the full post-validation check before release work.
            let snapshot = trace.measure(ServingStep::Snapshot, || {
                self.lineage.snapshot_data(&observed)
            })?;
            reads.finish(physical.controller_stage()?)?;
            // The enclosing active owner remains closed until the actual
            // physical/peer release succeeds too. A later failure refuses its
            // retained connection; no new request can enter during release.
            trace.measure(ServingStep::Release, || physical.finish_app_known())?;
            Ok(ServingObservation { binding, snapshot })
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
            self.counter.refuse();
        }
        result
    }
}

impl ActiveControllerStorageContinuity {
    /// The Shell's actual role channel remains borrowed alongside the SAME
    /// physical file/provider scope. Retained App liveness is retained here;
    /// it is never interpreted as a fresh App role or Shell database identity.
    pub(in crate::security_epoch) fn serve_shell_current(
        &mut self,
        mut stage: EnrolledRoleStage<'_>,
        peer: &mut crate::security_epoch::native_enrollment::ControllerServingPeer,
    ) -> Result<ServingObservation> {
        ensure!(self.valid, "active_controller_storage_refused");
        self.valid = false;
        let result = (|| {
            // Meet the already-admitted token ceiling before the first
            // immutable Shell Current statement is constructed.
            let mut reads = self.counter.request(
                &mut stage,
                &self.policy,
                &self.store,
                NativeRole::EpochController,
            )?;
            let pending = self.storage.begin_pending_current_controller()?;
            let rendezvous = peer.prepare_current(&mut stage)?;
            let mut physical = pending.acquire(stage)?;
            let mut shell = rendezvous.accept_current(physical.controller_stage()?)?;
            let binding = shell.request_binding().clone();
            let mut observed =
                self.lineage
                    .read(&self.store, &mut reads, physical.controller_stage()?)?;
            // The checked stage getter performs the complete physical
            // post-read check once, immediately before observation use.
            self.lineage.check(
                &self.store,
                &mut reads,
                physical.controller_stage()?,
                &mut observed,
            )?;
            shell.check(physical.controller_stage()?)?;
            shell.announce_known(physical.controller_stage()?)?;
            shell.await_consumed(physical.controller_stage()?)?;
            // The wait cannot replace or repair the old observation's budget.
            self.lineage.check(
                &self.store,
                &mut reads,
                physical.controller_stage()?,
                &mut observed,
            )?;
            observed = self
                .lineage
                .read(&self.store, &mut reads, physical.controller_stage()?)?;
            self.lineage.check(
                &self.store,
                &mut reads,
                physical.controller_stage()?,
                &mut observed,
            )?;
            physical.check()?;
            shell.check(physical.controller_stage()?)?;
            shell.release(physical.controller_stage()?)?;
            shell.finish_checked(physical.controller_stage()?)?;
            let snapshot = self.lineage.snapshot_data(&observed)?;
            reads.finish(physical.controller_stage()?)?;
            physical.finish_controller_known()?;
            Ok(ServingObservation { binding, snapshot })
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
            self.counter.refuse();
            peer.refuse();
        }
        result
    }
}

/// Historical result DATA, returned only after the actual consumer ACK,
/// provider reobservation and physical/peer release have all succeeded.
pub(super) struct ServingObservation {
    pub(super) binding: Digest,
    pub(super) snapshot: Digest,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::security_epoch) enum ServingDisposition {
    Unarmed,
    Armed,
    Known,
    Excluded,
    Refused,
}

// Initial creation image DATA belongs only to the fixed initial Runtime birth.
// An ordinary Current request has no initial seed, including after restore.
// This supplies no physical, role, keeper or database permission.
enum AppRuntimeImage {
    Existing,
    Initial(Box<super::seed_core::OriginalSeedCore>),
}

pub(crate) struct CurrentAppServingPhase<'storage> {
    physical: super::CurrentAppStoragePhase<'storage>,
    reads: super::authenticated_reads::CounterRequest<'storage>,
    observed: ActiveObservation,
    selection: EpochStore,
    lineage: &'storage ActiveLineage,
    image: AppRuntimeImage,
    policy: InitialBootstrapPolicy,
    continuation: &'storage mut bool,
    disposition: ServingDisposition,
    purpose: super::serving::ScopePurpose,
    evidence: super::serving::ConsumerScopeEvidence,
}

/// Fixed lifecycle step selection DATA. None is a write permit. An uncertain
/// write stops the lifecycle; this native entrypoint never rearms/resends May.
#[derive(Clone, Copy)]
pub(super) enum Action {
    Reserve,
    Dispatch,
    Settle,
}

pub(super) fn run_phase(
    storage: &mut InitialStorageContinuity,
    stage: EnrolledRoleStage<'_>,
    policy: &InitialBootstrapPolicy,
    selection: &EpochStore,
    request: &Request,
    action: Action,
    trace: &BootstrapTiming,
) -> Result<Snapshot> {
    let core = (|| {
        LogicalCore::new(
            selection,
            policy.clone(),
            storage.bootstrap_core()?,
            request,
        )
    })()
    .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapCore, error))?;
    let (phase, reads) = storage
        .begin_bootstrap(stage, policy, selection, request, trace)
        .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapFilePeer, error))?;
    let owner = Rc::new(RefCell::new(phase));
    let result = (|| {
        let mut transport = trace
            .measure(Operation::BootstrapWriter, || {
                ControllerPort::acquire(
                    Rc::clone(&owner),
                    policy,
                    selection,
                    reads,
                    trace.timings(),
                )
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapTransport, error))?;
        let mut port = transport.borrow();
        let (counter, mut slot) = trace.measure(Operation::BootstrapSnapshot, || {
            let budget = port.budget().map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapSnapshotBefore, error)
            })?;
            control_slot_io::read_for_action(selection, &core, &mut port, budget).map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapSnapshotBefore, error)
            })
        })?;
        let purpose = match action {
            Action::Settle => Purpose::Reconcile,
            _ => Purpose::Dispatch,
        };
        let context = trace
            .measure(Operation::BootstrapExecution, || {
                CurrentBootstrapExecution::native(
                    Rc::clone(&owner),
                    selection,
                    request,
                    counter.snapshot(),
                    purpose,
                    &mut port,
                )
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapExecution, error));
        let context = match context {
            Ok(value) => value,
            Err(primary) => {
                let _ = slot.abort(&mut port);
                port.refuse();
                return Err(primary);
            }
        };
        trace.measure(Operation::BootstrapMutation, || {
            match action {
                Action::Reserve => {
                    control_slot_io::accept(
                        selection,
                        core.clone(),
                        counter,
                        slot,
                        context,
                        &mut port,
                    )
                    .map_err(|error| {
                        PreparationFailure::at(PreparationStep::BootstrapReservePrepare, error)
                    })?
                    .send(selection, &mut port)
                    .map_err(|error| {
                        PreparationFailure::at(PreparationStep::BootstrapReserveSend, error)
                    })?;
                }
                Action::Dispatch => {
                    (|| {
                        let proposal = (|| {
                            // Only the initial Prepared state is accepted. A historical
                            // May/Retryable/Observed slot is not this actual known claim.
                            let before = slot
                                .data()
                                .context("native_bootstrap_reservation_missing")?;
                            let SlotState::Prepared { next } = before.slot.state else {
                                anyhow::bail!("native_bootstrap_dispatch_not_prepared");
                            };
                            let incarnation = owner
                                .try_borrow_mut()?
                                .controller_stage()?
                                .incarnation_data()?;
                            let mut nonce = [0_u8; 32];
                            crate::host_inputs::Entropy::fill(
                                &crate::host_inputs::SecureEntropy,
                                &mut nonce,
                            )?;
                            port.sample()?;
                            Ok::<_, anyhow::Error>(AttemptCore {
                                logical: core.digest()?,
                                request: request.digest()?,
                                ordinal: next,
                                expected: before.version.clone(),
                                controller_incarnation: incarnation,
                                nonce: Digest::new(&nonce),
                            })
                        })();
                        let attempt = match proposal {
                            Ok(value) => value,
                            Err(primary) => {
                                let _ = slot.abort(&mut port);
                                port.refuse();
                                return Err(primary);
                            }
                        };
                        control_slot_io::claim(
                            selection,
                            core.clone(),
                            counter,
                            slot,
                            context,
                            attempt,
                            &mut port,
                        )
                        .map_err(|error| {
                            PreparationFailure::at(PreparationStep::BootstrapDispatchPrepare, error)
                        })?
                        .send(selection, &mut port)
                        .map_err(|error| {
                            PreparationFailure::at(
                                PreparationStep::BootstrapDispatchRecordSend,
                                error,
                            )
                        })?
                        .send(selection, &mut port)
                        .map_err(|error| {
                            PreparationFailure::at(
                                PreparationStep::BootstrapDispatchCounterSend,
                                error,
                            )
                        })?;
                        Ok::<(), anyhow::Error>(())
                    })()
                    .map_err(|error| {
                        PreparationFailure::at(PreparationStep::BootstrapDispatchPrepare, error)
                    })?;
                }
                Action::Settle => {
                    (|| {
                        let proposal = (|| {
                            let before = slot
                                .data()
                                .context("native_bootstrap_reservation_missing")?;
                            let SlotState::MayHaveBeenSent { attempt } = &before.slot.state else {
                                anyhow::bail!("native_bootstrap_settlement_not_pending");
                            };
                            Ok::<_, anyhow::Error>(SettlementCore {
                                logical: core.digest()?,
                                expected: before.version.clone(),
                                control_attempt: attempt.id.clone(),
                                receipt: request.receipt()?.digest()?,
                            })
                        })();
                        let settlement = match proposal {
                            Ok(value) => value,
                            Err(primary) => {
                                let _ = slot.abort(&mut port);
                                port.refuse();
                                return Err(primary);
                            }
                        };
                        control_slot_io::settle(
                            selection,
                            core.clone(),
                            counter,
                            slot,
                            context,
                            settlement,
                            &mut port,
                        )
                        .map_err(|error| {
                            PreparationFailure::at(PreparationStep::BootstrapSettlePrepare, error)
                        })?
                        .send(selection, &mut port)
                        .map_err(|error| {
                            PreparationFailure::at(PreparationStep::BootstrapSettleSend, error)
                        })?;
                        Ok::<(), anyhow::Error>(())
                    })()
                    .map_err(|error| {
                        PreparationFailure::at(PreparationStep::BootstrapSettlePrepare, error)
                    })?;
                }
            }
            Ok(())
        })?;
        let (observed, slot) = trace.measure(Operation::BootstrapSnapshotAfter, || {
            let budget = port.budget().map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapSnapshotAfter, error)
            })?;
            control_slot_io::read_with_counter(selection, &core, &mut port, budget).map_err(
                |error| PreparationFailure::at(PreparationStep::BootstrapSnapshotAfter, error),
            )
        })?;
        trace
            .measure(Operation::BootstrapValidation, || {
                validate_after(
                    action,
                    selection,
                    request,
                    &core,
                    observed.snapshot(),
                    &slot,
                )
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapValidation, error))?;
        port.sample()
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapValidation, error))?;
        trace
            .measure(Operation::BootstrapAnnouncement, || {
                owner.try_borrow_mut()?.announce_known()
            })
            .map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapAnnouncement, error)
            })?;
        Ok(observed.snapshot().clone())
    })();
    match result {
        Ok(snapshot) => {
            // All consuming contexts, responses and the port must be gone.
            // A leaked/held alias cannot release the original continuation.
            match Rc::try_unwrap(owner) {
                Ok(phase) => {
                    let phase = phase.into_inner();
                    if matches!(action, Action::Settle)
                        && matches!(request, Request::CompleteInitialFirstActivation { .. })
                    {
                        trace
                            .measure(Operation::BootstrapRelease, || {
                                phase.finish_activated(&trace.timings())
                            })
                            .map_err(|error| {
                                PreparationFailure::at(PreparationStep::BootstrapRelease, error)
                            })?;
                    } else {
                        trace
                            .measure(Operation::BootstrapRelease, || {
                                phase.finish_checked(&trace.timings())
                            })
                            .map_err(|error| {
                                PreparationFailure::at(PreparationStep::BootstrapRelease, error)
                            })?;
                    }
                    Ok(snapshot)
                }
                Err(owner) => {
                    owner.try_borrow_mut()?.refuse();
                    anyhow::bail!("native_bootstrap_owner_still_borrowed")
                }
            }
        }
        Err(error) => {
            owner.try_borrow_mut()?.refuse();
            Err(error)
        }
    }
}

// Conditional provider DATA checks shared by both actual participants. These
// values cannot create the native phase or the active storage owner.
fn validate_after(
    action: Action,
    selection: &EpochStore,
    request: &Request,
    core: &LogicalCore,
    observed: &Snapshot,
    slot: &control_slot_io::SlotObservation,
) -> Result<()> {
    let stored = slot
        .data()
        .context("native_bootstrap_postcheck_slot_missing")?;
    ensure!(
        stored.slot.logical == *core,
        "native_bootstrap_postcheck_request_changed"
    );
    match action {
        Action::Reserve => {
            ensure!(
                matches!(stored.slot.state, SlotState::Prepared { .. }),
                "native_bootstrap_reserve_not_known"
            );
            ensure!(
                kernel::reconcile(selection, request, observed)? == Outcome::NotApplied,
                "native_bootstrap_counter_changed_during_reserve"
            );
        }
        Action::Dispatch => {
            ensure!(
                matches!(stored.slot.state, SlotState::MayHaveBeenSent { .. }),
                "native_bootstrap_claim_changed"
            );
            ensure!(
                kernel::reconcile(selection, request, observed)?
                    == Outcome::Applied(Box::new(request.receipt()?)),
                "native_bootstrap_dispatch_not_observed"
            );
        }
        Action::Settle => {
            ensure!(
                matches!(&stored.slot.state, SlotState::Observed {receipt, ..} if **receipt == request.receipt()?),
                "native_bootstrap_settlement_not_observed"
            );
            ensure!(
                kernel::reconcile(selection, request, observed)?
                    == Outcome::Applied(Box::new(request.receipt()?)),
                "native_bootstrap_counter_not_observed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::security_epoch) fn validate_after_fixture(
    action: Action,
    selection: &EpochStore,
    request: &Request,
    core: &LogicalCore,
    observed: &Snapshot,
    slot: &control_slot_io::SlotObservation,
) -> Result<()> {
    validate_after(action, selection, request, core, observed, slot)
}

/// The original App file/peer stay owned through ALL six fixed native stages.
/// A failure keeps this owner refused; progress DATA cannot reconstruct it.
pub(crate) struct AppStorageBootstrap {
    storage: super::AppInitialStorageContinuity,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    create: Request,
    completion: Option<Request>,
    activation: Option<Digest>,
    next: u8,
    valid: bool,
}

pub(crate) struct ActiveAppStorageContinuity {
    storage: super::AppInitialStorageContinuity,
    counter: super::authenticated_reads::CounterConnectionSlot,
    lineage: ActiveLineage,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    valid: bool,
}

pub(crate) struct ActiveControllerStorageContinuity {
    storage: InitialStorageContinuity,
    counter: super::authenticated_reads::CounterConnectionSlot,
    lineage: ActiveLineage,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    valid: bool,
}

impl AppStorageBootstrap {
    pub(crate) fn prepare_current(&mut self) -> Result<()> {
        ensure!(
            self.valid && self.next < 6,
            "app_storage_bootstrap_refused_or_complete"
        );
        if let Err(error) = self.storage.prepare_current() {
            self.refuse();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn retain(
        storage: super::AppInitialStorageContinuity,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<Self> {
        let core = storage.bootstrap_core()?;
        core.validate(policy, store)?;
        let create = Request::CreateInitialAuthority {
            bootstrap: core.bootstrap()?,
        };
        Ok(Self {
            storage,
            policy: policy.clone(),
            store: store.clone(),
            create,
            completion: None,
            activation: None,
            next: 0,
            valid: true,
        })
    }

    /// Exactly one native stage on the already owning App executor. No retry,
    /// polling, replacement owner or arbitrary operational callback is exposed.
    pub(crate) fn advance(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        ensure!(
            self.valid && self.next < 6,
            "app_storage_bootstrap_refused_or_complete"
        );
        self.valid = false;
        let result = (|| {
            let request = if self.next < 3 {
                self.create.clone()
            } else {
                self.completion
                    .clone()
                    .context("app_storage_completion_missing")?
            };
            let action = action_at(self.next)?;
            let core = LogicalCore::new(
                &self.store,
                self.policy.clone(),
                self.storage.bootstrap_core()?,
                &request,
            )?;
            let holder = self.storage.first_holder_data()?;
            // Complete provider authentication within this stage's ORIGINAL
            // five seconds, before file/peer work can spend the separate
            // storage-bootstrap interval. Retaining the successful child
            // does not observe the epoch or acknowledge anything; both provider
            // observations still follow the checked peer's actual Known.
            let mut reads = super::AuthenticatedReads::acquire_storage_bootstrap(
                &self.policy,
                &self.store,
                day2_capabilities::security_epoch::bootstrap::NativeRole::AppHost,
                stage,
            )?
            .retain_storage_bootstrap()?;
            let mut phase = self.storage.begin_bootstrap(stage, &self.store, &request)?;
            phase.await_known(stage)?;
            // The Controller's signed result only unblocks a fresh coherent
            // provider read. It is not itself an activation/serving receipt.
            let (observed, slot) = reads.read_bootstrap_snapshot(stage, &self.store, &core)?;
            validate_after(
                action,
                &self.store,
                &request,
                &core,
                observed.snapshot(),
                &slot,
            )?;
            let completion = if self.next == 2 {
                Some(completion_request(
                    &self.store,
                    &self.create,
                    &core.seed,
                    observed.snapshot(),
                    holder,
                )?)
            } else {
                None
            };
            let activation = if self.next == 5 {
                Some(super::journal::snapshot_digest(observed.snapshot())?)
            } else {
                None
            };
            drop(reads);
            phase.check(stage)?;
            if self.next == 5 {
                phase.finish_activated(stage)?;
            } else {
                phase.finish_checked(stage)?;
            }
            if let Some(completion) = completion {
                self.completion = Some(completion);
            }
            if let Some(activation) = activation {
                self.activation = Some(activation);
            }
            self.next += 1;
            Ok(())
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.storage.refuse();
        }
        result
    }

    /// A failed/incomplete conversion returns the SAME owner, never an adopt
    /// or reconstruction route. All meaningful checks happen in advance.
    pub(crate) fn into_active(self) -> std::result::Result<ActiveAppStorageContinuity, Box<Self>> {
        match self {
            Self {
                storage,
                policy,
                store,
                completion: Some(completion),
                activation: Some(activation),
                next: 6,
                valid: true,
                ..
            } => Ok(ActiveAppStorageContinuity {
                storage,
                counter: super::authenticated_reads::CounterConnectionSlot::new(),
                lineage: ActiveLineage::initial(completion, activation),
                policy,
                store,
                valid: true,
            }),
            incomplete => Err(Box::new(incomplete)),
        }
    }

    pub(crate) fn refuse(&mut self) {
        self.valid = false;
        self.storage.refuse();
    }
}

impl ActiveAppStorageContinuity {
    pub(in crate::security_epoch) fn admit_counter(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        ensure!(self.valid, "active_app_storage_refused");
        self.valid = false;
        let result = (|| {
            self.storage.check_counter_admission(stage)?;
            self.counter.admit(
                stage,
                &self.policy,
                &self.store,
                day2_capabilities::security_epoch::bootstrap::NativeRole::AppHost,
            )?;
            self.storage.check_counter_admission(stage)
        })();
        if result.is_ok() {
            self.valid = true;
        } else {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn prepare_current(&mut self) -> Result<()> {
        ensure!(self.valid, "active_app_storage_refused");
        if let Err(error) = self.storage.prepare_current() {
            self.refuse();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        self.valid = false;
        self.storage.refuse();
        self.counter.refuse();
    }
}

impl ActiveControllerStorageContinuity {
    pub(crate) fn refuse(&mut self) {
        self.valid = false;
        self.storage.refuse();
        self.counter.refuse();
    }
}

fn action_at(index: u8) -> Result<Action> {
    match index {
        0 | 3 => Ok(Action::Reserve),
        1 | 4 => Ok(Action::Dispatch),
        2 | 5 => Ok(Action::Settle),
        _ => anyhow::bail!("native_bootstrap_step_out_of_range"),
    }
}

pub(super) fn request_names(selection: &EpochStore, request: &Request) -> Result<Names> {
    Names::new(
        selection,
        request.bootstrap(),
        match request {
            Request::CreateInitialAuthority { .. } => None,
            Request::CompleteInitialFirstActivation { operation, .. } => Some(operation),
        },
    )
}

fn completion_request(
    selection: &EpochStore,
    create: &Request,
    seed: &super::seed_core::OriginalSeedCore,
    pending: &Snapshot,
    holder: super::kernel::Holder,
) -> Result<Request> {
    ensure!(
        kernel::reconcile(selection, create, pending)?
            == Outcome::Applied(Box::new(create.receipt()?)),
        "native_bootstrap_create_not_observed"
    );
    let root = pending
        .root
        .as_ref()
        .context("native_bootstrap_root_missing")?;
    let sentinel = pending
        .sentinel
        .as_ref()
        .context("native_bootstrap_sentinel_missing")?;
    ensure!(
        matches!(root.value.phase, kernel::Phase::PendingFirstHolder),
        "native_bootstrap_not_pending"
    );
    let mut complete = Request::CompleteInitialFirstActivation {
        bootstrap: create.bootstrap().clone(),
        operation: Digest::new(b"unassigned-completion-operation-data"),
        parent_receipt: create.receipt()?.digest()?,
        before: kernel::Versions {
            root: root.version.clone(),
            sentinel: sentinel.version.clone(),
        },
        holder,
    };
    // This deterministic ID excludes its own operation, after-state and clocks.
    let operation_id = super::control_slot::complete_operation(&complete, &seed.digest()?)?;
    if let Request::CompleteInitialFirstActivation { operation, .. } = &mut complete {
        *operation = operation_id;
    }
    complete.validate(selection)?;
    Ok(complete)
}

/// Portable composition DATA only; this calls the same pure production
/// selector and creates no first-holder, file, role or dispatch owner.
#[cfg(test)]
pub(super) fn completion_request_fixture(
    selection: &EpochStore,
    create: &Request,
    seed: &super::seed_core::OriginalSeedCore,
    pending: &Snapshot,
    holder: super::kernel::Holder,
) -> Result<Request> {
    completion_request(selection, create, seed, pending, holder)
}

pub(super) enum ControllerActivationOutcome {
    Active(Box<ActiveControllerStorageContinuity>),
    Refused {
        storage: Box<InitialStorageContinuity>,
        error: anyhow::Error,
    },
}

pub(super) fn activate_controller(
    mut storage: InitialStorageContinuity,
    owner: &mut super::native_enrollment::EnrolledProcessRoleOwner,
    policy: &InitialBootstrapPolicy,
    selection: &EpochStore,
    evidence: &mut super::controller::evidence::Evidence,
) -> ControllerActivationOutcome {
    evidence.enter(super::controller::evidence::FailurePhase::Activation);
    let result = (|| {
        let core = storage.bootstrap_core()?;
        core.validate(policy, selection)?;
        let create = Request::CreateInitialAuthority {
            bootstrap: core.bootstrap()?,
        };
        let holder = storage.first_holder_data()?;
        let mut pending = None;
        for action in [Action::Reserve, Action::Dispatch, Action::Settle] {
            evidence.enter_bootstrap(&create, action);
            wait_app_pending(&mut storage).map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapWaitApp, error)
            })?;
            let trace = BootstrapTiming::new();
            let result = (|| {
                let stage = trace
                    .measure(Operation::RoleStage, || {
                        owner.begin_storage_bootstrap_stage()
                    })
                    .map_err(|error| {
                        PreparationFailure::at(PreparationStep::BootstrapRole, error)
                    })?;
                run_phase(
                    &mut storage,
                    stage,
                    policy,
                    selection,
                    &create,
                    action,
                    &trace,
                )
            })();
            // Native phase resources have returned/unwound before retaining
            // diagnostic DATA or emitting any later refusal record.
            evidence.bootstrap_timing(trace.snapshot());
            let observed = result?;
            evidence.bootstrap(&create, action, &observed)?;
            pending = Some(observed);
        }
        evidence.enter(super::controller::evidence::FailurePhase::Activation);
        let complete = completion_request(
            selection,
            &create,
            &core,
            &pending.context("native_bootstrap_pending_missing")?,
            holder,
        )?;
        let mut activated = None;
        for action in [Action::Reserve, Action::Dispatch, Action::Settle] {
            evidence.enter_bootstrap(&complete, action);
            wait_app_pending(&mut storage).map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapWaitApp, error)
            })?;
            let trace = BootstrapTiming::new();
            let result = (|| {
                let stage = trace
                    .measure(Operation::RoleStage, || {
                        owner.begin_storage_bootstrap_stage()
                    })
                    .map_err(|error| {
                        PreparationFailure::at(PreparationStep::BootstrapRole, error)
                    })?;
                run_phase(
                    &mut storage,
                    stage,
                    policy,
                    selection,
                    &complete,
                    action,
                    &trace,
                )
            })();
            // Native phase resources have returned/unwound before retaining
            // diagnostic DATA or emitting any later refusal record.
            evidence.bootstrap_timing(trace.snapshot());
            let observed = result?;
            evidence.bootstrap(&complete, action, &observed)?;
            activated = Some(observed);
        }
        evidence.enter(super::controller::evidence::FailurePhase::Activation);
        let snapshot = activated.context("native_activation_observation_missing")?;
        let activation = super::journal::snapshot_digest(&snapshot)?;
        evidence.activated(&complete, &activation)?;
        // Cold provider admission is completed before the active Controller
        // escapes into its listener/request loop. It never spends an App or
        // Shell request's packet/physical waiting time or renews that request.
        let mut counter = super::authenticated_reads::CounterConnectionSlot::new();
        let stage = owner.begin_current_stage()?;
        let mut physical = storage.begin_pending_current_controller()?.acquire(stage)?;
        counter.admit(
            physical.controller_stage()?,
            policy,
            selection,
            day2_capabilities::security_epoch::bootstrap::NativeRole::EpochController,
        )?;
        physical.finish_controller_known()?;
        Ok((complete, activation, counter))
    })();
    match result {
        Ok((completion, activation, counter)) => {
            ControllerActivationOutcome::Active(Box::new(ActiveControllerStorageContinuity {
                storage,
                counter,
                lineage: ActiveLineage::initial(completion, activation),
                policy: policy.clone(),
                store: selection.clone(),
                valid: true,
            }))
        }
        Err(error) => {
            storage.refuse();
            ControllerActivationOutcome::Refused {
                storage: Box::new(storage),
                error,
            }
        }
    }
}

fn wait_app_pending(storage: &mut InitialStorageContinuity) -> Result<()> {
    while !storage.app_pending()? {
        // Readiness is DATA only. Do not acquire or renew a role while the
        // actual App is still completing its preceding known operation.
        std::thread::park_timeout(std::time::Duration::from_millis(5));
    }
    Ok(())
}

/// A current coherent snapshot must retain the exact activation, including all
/// provider version tokens. Even an identical-value administrative rewrite is
/// a changed authority observation, not a renewable lease.
pub(super) fn check_active_snapshot(
    selection: &EpochStore,
    completion: &Request,
    activation: &Digest,
    snapshot: &Snapshot,
) -> Result<()> {
    ensure!(
        matches!(completion, Request::CompleteInitialFirstActivation { .. }),
        "native_serving_initial_activation_required"
    );
    ensure!(
        kernel::reconcile(selection, completion, snapshot)?
            == Outcome::Applied(Box::new(completion.receipt()?)),
        "native_serving_activation_changed"
    );
    ensure!(
        super::journal::snapshot_digest(snapshot)? == *activation,
        "native_serving_provider_versions_changed"
    );
    Ok(())
}

// The exported loan boundary must retain the leaf owner's negative traits.
// This verifies the concrete facade used by the fixed native writer, without
// a constructor, permission DTO or a different owner hidden behind an alias.
const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <FencedRestoreContinuation<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoreWriteLoan<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ActiveObservation as Ambiguous<_>>::check;
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
mod tests {
    use super::*;

    #[test]
    fn fixed_original_lifecycle_has_six_steps_and_no_retry_or_adoption_step() {
        for (index, expected) in [
            Action::Reserve,
            Action::Dispatch,
            Action::Settle,
            Action::Reserve,
            Action::Dispatch,
            Action::Settle,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(matches!(
                (action_at(index as u8).unwrap(), expected),
                (Action::Reserve, Action::Reserve)
                    | (Action::Dispatch, Action::Dispatch)
                    | (Action::Settle, Action::Settle)
            ));
        }
        for index in [6, 7, u8::MAX] {
            assert!(action_at(index).is_err());
        }
    }

    #[test]
    fn active_supplier_never_admits_an_initial_create_receipt_or_empty_counter() {
        let store = super::super::tests::selection();
        let create = super::super::tests::create();
        let empty = Snapshot {
            root: None,
            sentinel: None,
            create: None,
            activate: None,
        };
        let copied = super::super::journal::snapshot_digest(&empty).unwrap();
        assert!(check_active_snapshot(&store, &create, &copied, &empty).is_err());
        assert!(matches!(
            kernel::reconcile(&store, &create, &empty).unwrap(),
            Outcome::NotApplied
        ));
    }

    #[test]
    fn active_observation_keeps_all_provider_versions_not_just_copied_values() {
        // Pure conditional DATA control; this creates no native owner/permission.
        let store = super::super::tests::selection();
        let create = super::super::tests::create();
        let version = |n: u32| -> kernel::UpdateTime {
            format!("2026-10-20T00:00:00.{n:06}Z").try_into().unwrap()
        };
        let complete = Request::CompleteInitialFirstActivation {
            bootstrap: create.bootstrap().clone(),
            operation: Digest::new(b"distinct-complete"),
            parent_receipt: create.receipt().unwrap().digest().unwrap(),
            before: kernel::Versions {
                root: version(1),
                sentinel: version(1),
            },
            holder: kernel::Holder {
                principal: Digest::new(b"p"),
                pod_uid: "a6b27e63-16d8-4b99-92f6-2437e5b20f43".into(),
                process_incarnation: Digest::new(b"i"),
                ephemeral_key: Digest::new(b"k"),
            },
        };
        let (root, sentinel) = complete.records().unwrap();
        let current = Snapshot {
            root: Some(kernel::Versioned {
                value: root,
                version: version(3),
            }),
            sentinel: Some(kernel::Versioned {
                value: sentinel,
                version: version(3),
            }),
            create: Some(kernel::Versioned {
                value: create.receipt().unwrap(),
                version: version(1),
            }),
            activate: Some(kernel::Versioned {
                value: complete.receipt().unwrap(),
                version: version(3),
            }),
        };
        let binding = super::super::journal::snapshot_digest(&current).unwrap();
        check_active_snapshot(&store, &complete, &binding, &current).unwrap();
        for index in 0..4 {
            let mut rewritten = current.clone();
            match index {
                0 => rewritten.root.as_mut().unwrap().version = version(4),
                1 => rewritten.sentinel.as_mut().unwrap().version = version(4),
                2 => rewritten.create.as_mut().unwrap().version = version(4),
                _ => rewritten.activate.as_mut().unwrap().version = version(4),
            }
            // Equivalent values/receipt hashes still cannot renew this version.
            assert!(check_active_snapshot(&store, &complete, &binding, &rewritten).is_err());
        }
        let mut missing = current.clone();
        missing.activate = None;
        assert!(check_active_snapshot(&store, &complete, &binding, &missing).is_err());
        let mut foreign = complete.clone();
        if let Request::CompleteInitialFirstActivation { holder, .. } = &mut foreign {
            holder.ephemeral_key = Digest::new(b"other-first-holder-key");
        }
        assert!(check_active_snapshot(&store, &foreign, &binding, &current).is_err());
    }
}
