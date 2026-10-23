//! Bounded shared-slot operations under opaque current execution authority.
//! Native execution retains the actual original file/P3, enrolled Controller
//! and App peer through the consuming dispatch; live profile qualification is
//! a separate gate. DATA-only
//! codec proposals and stored MayHaveBeenSent never enter the counter writer.

use super::{
    control_slot::{AttemptCore, LogicalCore, RearmCore, SettlementCore, Slot, SlotState},
    control_slot_firestore::{self as codec, VersionedSlot},
    firestore::{Budget, EpochObservation, Port, Sample},
    journal::{AuthorizedDispatch, CurrentBootstrapExecution, Purpose, snapshot_digest},
    kernel::{self, Outcome, Request, UpdateTime},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochProvider, EpochStore},
};
use serde::Deserialize;
use serde_json::{Value, json};
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
}

impl SlotObservation {
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadEntry {
    transaction: Option<String>,
    read_time: Option<String>,
    found: Option<Value>,
    missing: Option<String>,
}

pub(super) fn read_with_budget(
    selection: &EpochStore,
    core: &LogicalCore,
    port: &mut impl Port,
    mut budget: Budget,
) -> Result<SlotObservation> {
    let name = codec::name(selection, core)?;
    let body = serde_json::to_vec(&json!({"documents":[name],"newTransaction":{"readOnly":{}}}))?;
    let bytes = budget.call(port, &endpoint(selection, "batchGet"), &body)?;
    let mut entries: Vec<ReadEntry> = crate::json::decode(&bytes)?;
    ensure!(
        !entries.is_empty() && entries.len() <= 2,
        "control_slot_batch_shape"
    );
    let token = entries[0]
        .transaction
        .take()
        .context("control_slot_transaction_missing")?;
    let decoded = STANDARD.decode(&token)?;
    ensure!(
        !decoded.is_empty() && decoded.len() <= 1024 && STANDARD.encode(decoded) == token,
        "control_slot_transaction_shape"
    );
    let result = (|| {
        if entries[0].found.is_none() && entries[0].missing.is_none() {
            ensure!(entries[0].read_time.is_none(), "control_slot_header_fields");
            entries.remove(0);
        }
        ensure!(entries.len() == 1, "control_slot_batch_shape");
        let entry = entries.pop().unwrap();
        ensure!(
            entry.transaction.is_none(),
            "control_slot_duplicate_transaction"
        );
        let read_time = entry.read_time.context("control_slot_read_time_missing")?;
        time::OffsetDateTime::parse(&read_time, &time::format_description::well_known::Rfc3339)?;
        match (entry.found, entry.missing) {
            (Some(document), None) => Ok(Some(codec::decode(
                selection,
                core,
                &serde_json::to_vec(&document)?,
            )?)),
            (None, Some(missing)) => {
                ensure!(missing == name, "control_slot_unrequested_document");
                Ok(None)
            }
            _ => anyhow::bail!("control_slot_batch_shape"),
        }
    })();
    // Semantic failure still closes the actual provider read transaction.
    let rollback = serde_json::to_vec(&json!({"transaction":token}))?;
    let cleanup = budget.call(port, &endpoint(selection, "rollback"), &rollback)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    let _: Empty = crate::json::decode(&cleanup)?;
    let selection = Digest::of(selection)?;
    let logical = core.digest()?;
    // Both HTTP exchanges retain full pre/post guards. This last step only
    // charges decoding of the already received response to the same clock.
    budget.remaining_decoding(port)?;
    Ok(SlotObservation {
        selection,
        logical,
        value: result?,
        budget,
        valid: true,
        local: PhantomData,
    })
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
        let (_, mut budget) = self.check(selection, port)?;
        let body = serde_json::to_vec(&json!({"writes":[self.write]}))?;
        let bytes = budget.call(port, &endpoint(selection, "commit"), &body)?;
        let version = commit_version(&bytes)?;
        self.check(selection, port)?;
        Ok((self, version))
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
    mutation.check(selection, port)?;
    ensure!(
        kernel::reconcile(
            selection,
            &mutation.core.counter,
            mutation.counter.snapshot()
        )? == expected,
        "control_slot_counter_outcome"
    );
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
    ensure!(slot.value.is_none(), "control_slot_already_reserved");
    let after = Slot::prepared(core.clone());
    let write = codec::create_data(selection, &after)?;
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
