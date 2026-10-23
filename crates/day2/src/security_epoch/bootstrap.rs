//! Fixed original-file bootstrap operations. Each one owns a fresh real
//! Controller/file/peer phase and authenticated counter port. There is no
//! public mutation callback, replay/warmup or stored-row-to-send conversion.

use super::{
    InitialStorageContinuity,
    authenticated_reads::ControllerPort,
    control_slot::{AttemptCore, LogicalCore, SettlementCore, SlotState},
    control_slot_io,
    controller::evidence::{PreparationFailure, PreparationStep},
    controller::{bootstrap_timing::BootstrapTiming, preparation_timing::Operation},
    firestore::{self, Names, Port},
    journal::{CurrentBootstrapExecution, Purpose},
    kernel::{self, Outcome, Request, Snapshot},
    native_enrollment::EnrolledRoleStage,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use std::{cell::RefCell, rc::Rc};

mod app_serving;
mod controller_serving;

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

pub(crate) struct CurrentAppServingPhase<'storage> {
    physical: super::CurrentAppStoragePhase<'storage>,
    reads: super::RetainedEpochReads,
    observed: super::EpochObservation,
    selection: EpochStore,
    completion: Request,
    activation: Digest,
    seed: super::seed_core::OriginalSeedCore,
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
        let names = Names::new(
            selection,
            request.bootstrap(),
            match request {
                Request::CreateInitialAuthority { .. } => None,
                Request::CompleteInitialFirstActivation { operation, .. } => Some(operation),
            },
        )
        .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapNames, error))?;
        let counter = trace.measure(Operation::BootstrapCounter, || {
            let counter_budget = port.budget().map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapCounterBefore, error)
            })?;
            firestore::read_with_budget(&mut port, &names, counter_budget).map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapCounterBefore, error)
            })
        })?;
        let slot = trace.measure(Operation::BootstrapSlot, || {
            let slot_budget = port.budget().map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapSlotBefore, error)
            })?;
            control_slot_io::read_with_budget(selection, &core, &mut port, slot_budget).map_err(
                |error| PreparationFailure::at(PreparationStep::BootstrapSlotBefore, error),
            )
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
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapExecution, error))?;
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
                        let attempt = AttemptCore {
                            logical: core.digest()?,
                            request: request.digest()?,
                            ordinal: next,
                            expected: before.version.clone(),
                            controller_incarnation: incarnation,
                            nonce: Digest::new(&nonce),
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
                        let before = slot
                            .data()
                            .context("native_bootstrap_reservation_missing")?;
                        let SlotState::MayHaveBeenSent { attempt } = &before.slot.state else {
                            anyhow::bail!("native_bootstrap_settlement_not_pending");
                        };
                        let settlement = SettlementCore {
                            logical: core.digest()?,
                            expected: before.version.clone(),
                            control_attempt: attempt.id.clone(),
                            receipt: request.receipt()?.digest()?,
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
        let observed = trace.measure(Operation::BootstrapCounterAfter, || {
            let counter_budget = port.budget().map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapCounterAfter, error)
            })?;
            firestore::read_with_budget(&mut port, &names, counter_budget).map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapCounterAfter, error)
            })
        })?;
        let slot = trace.measure(Operation::BootstrapSlotAfter, || {
            let slot_budget = port.budget().map_err(|error| {
                PreparationFailure::at(PreparationStep::BootstrapSlotAfter, error)
            })?;
            control_slot_io::read_with_budget(selection, &core, &mut port, slot_budget)
                .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapSlotAfter, error))
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
    completion: Request,
    activation: Digest,
    policy: InitialBootstrapPolicy,
    store: EpochStore,
    valid: bool,
}

pub(crate) struct ActiveControllerStorageContinuity {
    storage: InitialStorageContinuity,
    completion: Request,
    activation: Digest,
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
            let names = request_names(&self.store, &request)?;
            let observed = reads.read(stage, &self.store, &names)?;
            let slot = reads.read_slot(stage, &self.store, &core)?;
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
                completion,
                activation,
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
    }
}

impl ActiveControllerStorageContinuity {
    pub(crate) fn refuse(&mut self) {
        self.valid = false;
        self.storage.refuse();
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
        Ok((complete, activation))
    })();
    match result {
        Ok((completion, activation)) => {
            ControllerActivationOutcome::Active(Box::new(ActiveControllerStorageContinuity {
                storage,
                completion,
                activation,
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
