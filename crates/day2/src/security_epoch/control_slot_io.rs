//! Bounded shared-slot operations under opaque current execution authority.
//! Native execution retains the actual original file/P3, enrolled Controller
//! and App peer through the consuming dispatch; live profile qualification is
//! a separate gate. DATA-only
//! codec proposals and stored MayHaveBeenSent never enter the counter writer.

use super::{
    control_slot::{AttemptCore, LogicalCore, RearmCore, SettlementCore, Slot, SlotState},
    control_slot_firestore::{self as codec, VersionedSlot},
    controller::evidence::FailureBoundary,
    firestore::{ActionTransaction, Budget, EpochObservation, Port, Sample},
    journal::{AuthorizedDispatch, CurrentBootstrapExecution, Purpose, snapshot_digest},
    kernel::{self, Outcome, Request, UpdateTime},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochProvider, EpochStore},
};
use serde::Deserialize;
use serde_json::Value;
use std::{marker::PhantomData, rc::Rc};

fn endpoint(selection: &EpochStore, operation: &str) -> String {
    let EpochProvider::FirestoreNativeV1 {
        project, database, ..
    } = &selection.provider;
    format!(
        "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents:{operation}",
        project.as_str(),
        database.as_str()
    )
}

pub(crate) struct SlotObservation {
    selection: Digest,
    logical: Digest,
    value: Option<VersionedSlot>,
    budget: Budget,
    valid: bool,
    local: PhantomData<Rc<()>>,
    transaction: Option<ActionTransaction>,
}

impl SlotObservation {
    /// Best-effort cleanup under the same remaining authority and budget. No
    /// expired/refused owner may bypass its transport guards to roll back.
    pub(super) fn abort(&mut self, port: &mut impl Port) -> Result<()> {
        let result = match self.transaction.take() {
            Some(pending) => pending.rollback(port, &mut self.budget),
            None => Ok(()),
        };
        if result.is_err() {
            self.valid = false;
            port.refuse();
        }
        result
    }

    fn check_binding(&mut self, selection: &EpochStore, core: &LogicalCore) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "control_slot_observation_refused");
            ensure!(
                self.selection == Digest::of(selection)? && self.logical == core.digest()?,
                "control_slot_observation_binding"
            );
            Ok(())
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    fn constrain_budget(&mut self, budget: &mut Budget, sample: &Sample) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "control_slot_observation_refused");
            budget.constrain_to(&mut self.budget, sample)?;
            Ok(())
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    pub(super) fn data(&self) -> Option<&VersionedSlot> {
        self.value.as_ref()
    }

    pub(super) fn into_data(self) -> Option<VersionedSlot> {
        self.value
    }
}

/// One coherent strong provider read supplies both observations. Each retains
/// the same spent original budget; neither observation is native authority.
pub(super) fn read_with_counter(
    selection: &EpochStore,
    core: &LogicalCore,
    port: &mut impl Port,
    budget: Budget,
) -> Result<(EpochObservation, SlotObservation)> {
    let result = (|| {
        // Charge these binding hashes before the reader's final clock sample.
        let selection_binding = Digest::of(selection)?;
        let logical = core.digest()?;
        let (counter, value, budget) =
            super::firestore::read_with_slot(selection, core, port, budget)?;
        Ok((
            counter,
            SlotObservation {
                selection: selection_binding,
                logical,
                value,
                budget,
                valid: true,
                local: PhantomData,
                transaction: None,
            },
        ))
    })();
    if result.is_err() {
        port.refuse();
    }
    result
}

/// The Controller holds this exact read-write transaction until the consuming
/// slot commit. App and post-commit strong reads never receive one.
pub(super) fn read_for_action(
    selection: &EpochStore,
    core: &LogicalCore,
    port: &mut impl Port,
    budget: Budget,
) -> Result<(EpochObservation, SlotObservation)> {
    let result = (|| {
        let selection_binding = Digest::of(selection)?;
        let logical = core.digest()?;
        let (counter, value, budget, transaction) =
            super::firestore::begin_action(selection, core, port, budget)?;
        Ok((
            counter,
            SlotObservation {
                selection: selection_binding,
                logical,
                value,
                budget,
                valid: true,
                local: PhantomData,
                transaction: Some(transaction),
            },
        ))
    })();
    if result.is_err() {
        port.refuse();
    }
    result
}

pub(crate) struct Mutation<'storage, 'role> {
    core: LogicalCore,
    after: Slot,
    write: Value,
    counter: EpochObservation,
    slot: SlotObservation,
    context: CurrentBootstrapExecution<'storage, 'role>,
    purpose: Purpose,
}

fn refuse_after_cleanup(
    slot: &mut SlotObservation,
    context: &mut CurrentBootstrapExecution<'_, '_>,
    port: &mut impl Port,
    primary: anyhow::Error,
) -> anyhow::Error {
    let _ = slot.abort(port);
    context.refuse();
    port.refuse();
    primary
}

impl<'storage, 'role> Mutation<'storage, 'role> {
    fn check(&mut self, selection: &EpochStore, port: &mut impl Port) -> Result<(Sample, Budget)> {
        let result = (|| {
            self.core.validate(selection)?;
            self.counter.check_binding(selection)?;
            self.slot.check_binding(selection, &self.core)?;
            // One full observation of this SAME context/file/peer/provider
            // owner, after all pure binding work. It is not a reusable proof.
            let (sample, mut budget) = self.context.check(
                selection,
                &self.core.counter,
                self.counter.snapshot(),
                self.purpose,
                port,
            )?;
            self.counter.constrain_budget(&mut budget, &sample)?;
            self.slot.constrain_budget(&mut budget, &sample)?;
            // Charge the full observation and subsequent DATA work with an
            // ACTUAL fresh clock from the same retained original owner.
            let sample = self.context.clock_sample(port)?;
            self.counter.constrain_budget(&mut budget, &sample)?;
            self.slot.constrain_budget(&mut budget, &sample)?;
            Ok((sample, budget))
        })();
        if result.is_err() {
            self.context.refuse();
            port.refuse();
        }
        result
    }

    fn send(mut self, selection: &EpochStore, port: &mut impl Port) -> Result<(Self, UpdateTime)> {
        let prepared = (|| {
            let (_, budget) = self
                .check(selection, port)
                .map_err(|error| FailureBoundary::MutationBefore.at(error))?;
            let body = self
                .slot
                .transaction
                .as_ref()
                .context("control_slot_action_transaction_required")?
                .commit_body(selection, &self.core, &self.write)
                .map_err(|error| FailureBoundary::MutationBody.at(error))?;
            Ok((budget, body))
        })();
        let (mut budget, body) = match prepared {
            Ok(value) => value,
            Err(primary) => {
                return Err(refuse_after_cleanup(
                    &mut self.slot,
                    &mut self.context,
                    port,
                    primary,
                ));
            }
        };
        // Spend before the first possible send. A lost or malformed commit
        // response never retains a token that could authorize a resend.
        self.slot
            .transaction
            .take()
            .context("control_slot_action_transaction_required")?;
        let result = (|| {
            let bytes = budget
                .call(port, &endpoint(selection, "commit"), &body)
                .map_err(|error| FailureBoundary::CommitExchange.at(error))?;
            let version =
                commit_version(&bytes).map_err(|error| FailureBoundary::CommitDecode.at(error))?;
            self.check(selection, port)
                .map_err(|error| FailureBoundary::MutationAfter.at(error))?;
            Ok(version)
        })();
        match result {
            Ok(version) => Ok((self, version)),
            Err(primary) => {
                self.context.refuse();
                port.refuse();
                Err(primary)
            }
        }
    }
}

fn commit_version(bytes: &[u8]) -> Result<UpdateTime> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Reply {
        write_results: Vec<WriteResult>,
        commit_time: UpdateTime,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WriteResult {
        update_time: UpdateTime,
    }
    let mut reply: Reply = crate::json::decode(bytes)?;
    ensure!(
        reply.write_results.len() == 1,
        "control_slot_commit_result_count"
    );
    let version = reply.write_results.remove(0).update_time;
    let updated = time::OffsetDateTime::parse(
        &String::from(version.clone()),
        &time::format_description::well_known::Rfc3339,
    )?;
    let committed = time::OffsetDateTime::parse(
        &String::from(reply.commit_time),
        &time::format_description::well_known::Rfc3339,
    )?;
    ensure!(updated <= committed, "control_slot_commit_time_order");
    Ok(version)
}

pub(crate) struct SlotMaintenanceMutation<'storage, 'role> {
    mutation: Mutation<'storage, 'role>,
}

pub(crate) struct SlotClaimMutation<'storage, 'role> {
    mutation: Mutation<'storage, 'role>,
}

/// Only a known claim commit while all original authority remains valid can
/// construct this. Readback of a matching stored May never does. Consumption
/// permits one local send attempt, not a once-only remote application claim.
pub(crate) struct KnownClaim<'storage, 'role> {
    mutation: Mutation<'storage, 'role>,
}

fn checked<'storage, 'role>(
    mut mutation: Mutation<'storage, 'role>,
    selection: &EpochStore,
    port: &mut impl Port,
    expected: Outcome,
) -> Result<Mutation<'storage, 'role>> {
    let result = (|| {
        ensure!(
            mutation.slot.transaction.is_some(),
            "control_slot_action_transaction_required"
        );
        mutation.check(selection, port)?;
        ensure!(
            kernel::reconcile(
                selection,
                &mutation.core.counter,
                mutation.counter.snapshot()
            )? == expected,
            "control_slot_counter_outcome"
        );
        Ok(())
    })();
    if let Err(primary) = result {
        return Err(refuse_after_cleanup(
            &mut mutation.slot,
            &mut mutation.context,
            port,
            primary,
        ));
    }
    Ok(mutation)
}

pub(super) fn accept<'storage, 'role>(
    selection: &EpochStore,
    core: LogicalCore,
    counter: EpochObservation,
    slot: SlotObservation,
    context: CurrentBootstrapExecution<'storage, 'role>,
    port: &mut impl Port,
) -> Result<SlotMaintenanceMutation<'storage, 'role>> {
    let mut slot = slot;
    let mut context = context;
    let proposal = (|| {
        ensure!(slot.value.is_none(), "control_slot_already_reserved");
        let after = Slot::prepared(core.clone());
        let write = codec::create_data(selection, &after)?;
        Ok((after, write))
    })();
    let (after, write) =
        proposal.map_err(|error| refuse_after_cleanup(&mut slot, &mut context, port, error))?;
    Ok(SlotMaintenanceMutation {
        mutation: checked(
            Mutation {
                core,
                after,
                write,
                counter,
                slot,
                context,
                purpose: Purpose::Dispatch,
            },
            selection,
            port,
            Outcome::NotApplied,
        )?,
    })
}

pub(super) fn claim<'storage, 'role>(
    selection: &EpochStore,
    core: LogicalCore,
    counter: EpochObservation,
    slot: SlotObservation,
    context: CurrentBootstrapExecution<'storage, 'role>,
    attempt: AttemptCore,
    port: &mut impl Port,
) -> Result<SlotClaimMutation<'storage, 'role>> {
    let mut slot = slot;
    let mut context = context;
    let proposal = (|| {
        let before = slot
            .value
            .as_ref()
            .context("control_slot_reservation_missing")?;
        ensure!(
            before.slot.logical == core,
            "control_slot_reservation_replaced"
        );
        let after = before
            .slot
            .claim_data(selection, &before.version, attempt)?;
        let write = codec::cas_data(selection, before, &after)?;
        Ok((after, write))
    })();
    let (after, write) =
        proposal.map_err(|error| refuse_after_cleanup(&mut slot, &mut context, port, error))?;
    Ok(SlotClaimMutation {
        mutation: checked(
            Mutation {
                core,
                after,
                write,
                counter,
                slot,
                context,
                purpose: Purpose::Dispatch,
            },
            selection,
            port,
            Outcome::NotApplied,
        )?,
    })
}

pub(super) fn rearm<'storage, 'role>(
    selection: &EpochStore,
    core: LogicalCore,
    counter: EpochObservation,
    slot: SlotObservation,
    context: CurrentBootstrapExecution<'storage, 'role>,
    rearm: RearmCore,
    port: &mut impl Port,
) -> Result<SlotMaintenanceMutation<'storage, 'role>> {
    let mut slot = slot;
    let mut context = context;
    let proposal = (|| {
        ensure!(
            rearm.not_applied_observation == snapshot_digest(counter.snapshot())?,
            "control_slot_rearm_observation_mismatch"
        );
        let before = slot
            .value
            .as_ref()
            .context("control_slot_reservation_missing")?;
        ensure!(
            before.slot.logical == core,
            "control_slot_reservation_replaced"
        );
        let after = before.slot.rearm_data(selection, &before.version, rearm)?;
        let write = codec::cas_data(selection, before, &after)?;
        Ok((after, write))
    })();
    let (after, write) =
        proposal.map_err(|error| refuse_after_cleanup(&mut slot, &mut context, port, error))?;
    Ok(SlotMaintenanceMutation {
        mutation: checked(
            Mutation {
                core,
                after,
                write,
                counter,
                slot,
                context,
                purpose: Purpose::Reconcile,
            },
            selection,
            port,
            Outcome::NotApplied,
        )?,
    })
}

pub(super) fn settle<'storage, 'role>(
    selection: &EpochStore,
    core: LogicalCore,
    counter: EpochObservation,
    slot: SlotObservation,
    context: CurrentBootstrapExecution<'storage, 'role>,
    settlement: SettlementCore,
    port: &mut impl Port,
) -> Result<SlotMaintenanceMutation<'storage, 'role>> {
    let mut slot = slot;
    let mut context = context;
    let proposal = (|| {
        let before = slot
            .value
            .as_ref()
            .context("control_slot_reservation_missing")?;
        ensure!(
            before.slot.logical == core,
            "control_slot_reservation_replaced"
        );
        let expected = core.counter.receipt()?;
        let after =
            before
                .slot
                .settle_data(selection, &before.version, settlement, expected.clone())?;
        let write = codec::cas_data(selection, before, &after)?;
        Ok((after, write, expected))
    })();
    let (after, write, expected) =
        proposal.map_err(|error| refuse_after_cleanup(&mut slot, &mut context, port, error))?;
    Ok(SlotMaintenanceMutation {
        mutation: checked(
            Mutation {
                core,
                after,
                write,
                counter,
                slot,
                context,
                purpose: Purpose::Reconcile,
            },
            selection,
            port,
            Outcome::Applied(Box::new(expected)),
        )?,
    })
}

impl<'storage, 'role> SlotMaintenanceMutation<'storage, 'role> {
    pub(super) fn send(self, selection: &EpochStore, port: &mut impl Port) -> Result<UpdateTime> {
        let (_, version) = self.mutation.send(selection, port)?;
        // Historical acknowledgement only; never a counter-send permit.
        Ok(version)
    }
}

impl<'storage, 'role> SlotClaimMutation<'storage, 'role> {
    pub(super) fn send(
        self,
        selection: &EpochStore,
        port: &mut impl Port,
    ) -> Result<KnownClaim<'storage, 'role>> {
        let (mutation, _) = self.mutation.send(selection, port)?;
        ensure!(
            matches!(mutation.after.state, SlotState::MayHaveBeenSent { .. }),
            "control_slot_claim_state"
        );
        Ok(KnownClaim { mutation })
    }
}

impl<'storage, 'role> KnownClaim<'storage, 'role> {
    pub(super) fn check(
        &mut self,
        selection: &EpochStore,
        port: &mut impl Port,
    ) -> Result<(Sample, Budget)> {
        self.mutation.check(selection, port)
    }

    pub(super) fn refuse(&mut self) {
        self.mutation.context.refuse();
    }

    pub(super) fn prepare(
        mut self,
        selection: &EpochStore,
        port: &mut impl Port,
    ) -> Result<(Self, Request, Budget)> {
        let (_, budget) = self.mutation.check(selection, port)?;
        let request = self.mutation.core.counter.clone();
        Ok((self, request, budget))
    }

    pub(super) fn send(self, selection: &EpochStore, port: &mut impl Port) -> Result<()> {
        super::firestore::commit(port, selection, AuthorizedDispatch::Shared(Box::new(self)))
    }
}
