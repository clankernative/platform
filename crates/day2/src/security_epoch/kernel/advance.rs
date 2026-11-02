//! First epoch advance: active initial authority becomes fenced, never active.
//! Requests, conditional plans and reconciled receipts are historical DATA.
//! This module supplies no maintenance permission, native context or send port.
use super::{
    AuthorityRecord, EpochStore, Phase, Receipt as InitialReceipt, Request as InitialRequest,
    SentinelRecord, Snapshot, Versioned, Versions,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, security_epoch::SecurityEpoch};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Fence {
    operation: Digest,
    request: Digest,
    activation_receipt: Digest,
    previous_root: Digest,
    previous_sentinel: Digest,
    #[serde(with = "super::epoch_decimal")]
    previous_epoch: SecurityEpoch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Request {
    selection: Digest,
    operation: Digest,
    activation: InitialReceipt,
    before: Versions,
}

impl Request {
    /// Select the exact active initial state. This does not authorize its write.
    pub(in crate::security_epoch) fn new(
        selection: &EpochStore,
        operation: Digest,
        observed: &Snapshot,
    ) -> Result<Self> {
        selection.validate()?;
        let request = Self {
            selection: Digest::of(selection)?,
            operation,
            activation: observed
                .activate
                .as_ref()
                .context("security_epoch_advance_activation_missing")?
                .value
                .clone(),
            before: Versions {
                root: observed
                    .root
                    .as_ref()
                    .context("security_epoch_advance_root_missing")?
                    .version
                    .clone(),
                sentinel: observed
                    .sentinel
                    .as_ref()
                    .context("security_epoch_advance_sentinel_missing")?
                    .version
                    .clone(),
            },
        };
        request.prepare(selection, observed)?;
        Ok(request)
    }

    fn validate(&self, selection: &EpochStore) -> Result<()> {
        selection.validate()?;
        ensure!(
            self.selection == Digest::of(selection)?,
            "security_epoch_advance_selection_changed"
        );
        self.activation.request.validate(selection)?;
        ensure!(
            matches!(
                self.activation.request,
                InitialRequest::CompleteInitialFirstActivation { .. }
            ) && self.activation == self.activation.request.receipt()?,
            "security_epoch_advance_activation_mismatch"
        );
        ensure!(
            &self.operation != self.activation.request.operation()
                && self.operation != self.activation.request.bootstrap().create_operation,
            "security_epoch_advance_operation_reused"
        );
        Ok(())
    }

    fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-external-epoch-advance-request-v1", self))
    }

    fn records(&self, selection: &EpochStore) -> Result<(AuthorityRecord, SentinelRecord)> {
        self.validate(selection)?;
        let (mut root, mut sentinel) = self.activation.request.records()?;
        let fence = Fence {
            operation: self.operation.clone(),
            request: self.digest()?,
            activation_receipt: self.activation.digest()?,
            previous_root: Digest::of(&root)?,
            previous_sentinel: Digest::of(&sentinel)?,
            previous_epoch: root.epoch,
        };
        root.epoch = root.epoch.successor()?;
        root.phase = Phase::Fenced {
            fence: Box::new(fence.clone()),
        };
        // The bootstrap sentinel keeps its immutable initial epoch. Its new
        // phase and conditional version fence the same observed initial state.
        sentinel.phase = Phase::Fenced {
            fence: Box::new(fence),
        };
        Ok((root, sentinel))
    }

    fn receipt(&self, selection: &EpochStore) -> Result<Receipt> {
        let (root, sentinel) = self.records(selection)?;
        Ok(Receipt {
            format: ReceiptFormat::Day2CredentialEpochAdvanceV1,
            request: self.clone(),
            request_digest: self.digest()?,
            after_root: Digest::of(&root)?,
            after_sentinel: Digest::of(&sentinel)?,
        })
    }

    /// Both exact provider versions must be CAS conditions in one atomic write
    /// with a create-only receipt. A plan is not a dispatch or retry permission.
    pub(in crate::security_epoch) fn prepare(
        &self,
        selection: &EpochStore,
        observed: &Snapshot,
    ) -> Result<Plan> {
        self.validate(selection)?;
        ensure!(
            matches!(
                super::reconcile(selection, &self.activation.request, observed)?,
                super::Outcome::Applied(_)
            ),
            "security_epoch_advance_initial_authority_not_active"
        );
        self.require_history(observed)?;
        ensure!(
            observed
                .root
                .as_ref()
                .context("security_epoch_advance_root_missing")?
                .version
                == self.before.root
                && observed
                    .sentinel
                    .as_ref()
                    .context("security_epoch_advance_sentinel_missing")?
                    .version
                    == self.before.sentinel,
            "security_epoch_advance_conditional_version_changed"
        );
        let (root, sentinel) = self.records(selection)?;
        Ok(Plan {
            before: self.before.clone(),
            root,
            sentinel,
            receipt: self.receipt(selection)?,
        })
    }

    fn require_history(&self, observed: &Snapshot) -> Result<()> {
        let create = InitialRequest::CreateInitialAuthority {
            bootstrap: self.activation.request.bootstrap().clone(),
        };
        ensure!(
            observed
                .create
                .as_ref()
                .context("security_epoch_advance_create_missing")?
                .value
                == create.receipt()?
                && observed
                    .activate
                    .as_ref()
                    .context("security_epoch_advance_activation_missing")?
                    .value
                    == self.activation,
            "security_epoch_advance_history_mismatch"
        );
        Ok(())
    }
}

pub(in crate::security_epoch) struct Plan {
    pub before: Versions,
    pub root: AuthorityRecord,
    pub sentinel: SentinelRecord,
    pub receipt: Receipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptFormat {
    Day2CredentialEpochAdvanceV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Receipt {
    format: ReceiptFormat,
    request: Request,
    request_digest: Digest,
    after_root: Digest,
    after_sentinel: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum Outcome {
    NotApplied,
    Applied(Box<Receipt>),
}

/// Classify only this exact conditional operation against a coherent read.
/// Absence of a receipt alone never proves that a write was not applied.
pub(in crate::security_epoch) fn reconcile(
    selection: &EpochStore,
    request: &Request,
    observed: &Snapshot,
    receipt: Option<&Versioned<Receipt>>,
) -> Result<Outcome> {
    request.validate(selection)?;
    request.require_history(observed)?;
    let Some(receipt) = receipt else {
        request.prepare(selection, observed)?;
        return Ok(Outcome::NotApplied);
    };
    let expected = request.receipt(selection)?;
    let (root, sentinel) = request.records(selection)?;
    let observed_root = observed
        .root
        .as_ref()
        .context("security_epoch_advance_root_missing")?;
    let observed_sentinel = observed
        .sentinel
        .as_ref()
        .context("security_epoch_advance_sentinel_missing")?;
    ensure!(
        receipt.value == expected
            && observed_root.value == root
            && observed_sentinel.value == sentinel
            && observed_root.version != request.before.root
            && observed_sentinel.version != request.before.sentinel,
        "security_epoch_advance_partial_or_foreign_state"
    );
    Ok(Outcome::Applied(Box::new(expected)))
}

#[cfg(test)]
mod tests;
