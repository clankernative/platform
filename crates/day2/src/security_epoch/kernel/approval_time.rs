//! Conditional safe-time-floor DATA outside the app/archive rollback domain.
//! No sampler, initializer, native writer or qualified approval-time owner is
//! constructed here. Missing state refuses; it is never interpreted as zero.
use super::{EpochStore, Phase, Snapshot, UpdateTime, Versioned};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Utc {
    pub seconds: u64,
    pub nanos: u32,
}

impl Utc {
    fn value(&self) -> Result<u128> {
        ensure!(
            self.seconds <= i64::MAX as u64 && self.nanos < 1_000_000_000,
            "restore_time_value"
        );
        Ok(u128::from(self.seconds) * 1_000_000_000 + u128::from(self.nanos))
    }
}

/// Observations remain DATA; only the actual retained host sampler and known
/// external commit can eventually qualify these bounds for a consuming owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Interval {
    pub domain: Digest,
    pub lower: Utc,
    pub upper: Utc,
}

impl Interval {
    fn validate(&self) -> Result<()> {
        let lower = self.lower.value()?;
        let upper = self.upper.value()?;
        ensure!(
            lower <= upper && upper - lower <= 1_000_000_000,
            "restore_time_interval"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    Day2RestoreTimeFloorV1,
    Day2RestoreTimeReceiptV1,
}

/// A stable, non-decreasing upper bound. It is not scoped to a grant, process,
/// boot, future target epoch, signing key or mutable IAM/config revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Floor {
    format: Format,
    authority: Digest,
    upper: Utc,
    operation: Digest,
}

impl Floor {
    fn validate(&self, selected: &EpochStore) -> Result<()> {
        self.upper.value()?;
        ensure!(
            self.format == Format::Day2RestoreTimeFloorV1
                && self.authority == selected.authority_key()?,
            "restore_time_floor_binding"
        );
        Ok(())
    }
}

/// Exact create-only historical evidence, committed atomically with the floor.
/// Reading this after a lost ACK cannot reconstruct a lost native/time owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Receipt {
    format: Format,
    authority: Digest,
    operation: Digest,
    before_version: UpdateTime,
    before_floor: Digest,
    after_floor: Digest,
    interval: Interval,
}

impl Receipt {
    pub(in crate::security_epoch) fn key(&self, selected: &EpochStore) -> Result<Digest> {
        ensure!(
            self.format == Format::Day2RestoreTimeReceiptV1
                && self.authority == selected.authority_key()?,
            "restore_time_receipt_binding"
        );
        Digest::of(&(
            "day2-restore-time-receipt-key-v1",
            &self.authority,
            &self.operation,
        ))
    }
}

pub(in crate::security_epoch) fn key(selected: &EpochStore) -> Result<Digest> {
    Digest::of(&("day2-restore-time-floor-key-v1", selected.authority_key()?))
}

fn current(selected: &EpochStore, observed: &Snapshot) -> Result<()> {
    let active = observed
        .activate
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("restore_time_current_root_missing"))?;
    ensure!(
        observed
            .root
            .as_ref()
            .is_some_and(|root| matches!(root.value.phase, Phase::ActiveFirstHolder { .. })),
        "restore_time_current_root_required"
    );
    ensure!(
        matches!(
            super::reconcile(selected, &active.value.request, observed)?,
            super::Outcome::Applied(_)
        ),
        "restore_time_current_root_changed"
    );
    Ok(())
}

/// Five exact read-version conditions plus create-only operation absence must
/// guard BOTH writes in ONE provider transaction. Native check/send/readback
/// authority and the known May journal remain mandatory, separate work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) struct Plan {
    pub selected: EpochStore,
    pub before: Snapshot,
    pub prior: Versioned<Floor>,
    pub after: Floor,
    pub receipt: Receipt,
}

impl Plan {
    pub(in crate::security_epoch) fn prepare(
        selected: &EpochStore,
        before: &Snapshot,
        floor: Option<&Versioned<Floor>>,
        operation: Digest,
        interval: Interval,
    ) -> Result<Self> {
        current(selected, before)?;
        let prior = floor.ok_or_else(|| anyhow::anyhow!("restore_time_floor_missing"))?;
        prior.value.validate(selected)?;
        interval.validate()?;
        // Overlap is not repaired with max(now,H). Another process's floor is
        // never substituted for this actual original's current time witness.
        ensure!(
            interval.lower >= prior.value.upper && operation != prior.value.operation,
            "restore_time_floor_overlap_rewind_or_operation_reuse"
        );
        let after = Floor {
            format: Format::Day2RestoreTimeFloorV1,
            authority: selected.authority_key()?,
            upper: interval.upper.clone(),
            operation: operation.clone(),
        };
        let receipt = Receipt {
            format: Format::Day2RestoreTimeReceiptV1,
            authority: selected.authority_key()?,
            operation,
            before_version: prior.version.clone(),
            before_floor: Digest::of(&prior.value)?,
            after_floor: Digest::of(&after)?,
            interval,
        };
        Ok(Self {
            selected: selected.clone(),
            before: before.clone(),
            prior: prior.clone(),
            after,
            receipt,
        })
    }

    /// Pure equality checks do not supply the actual provider transaction or
    /// authorize a send. An existing operation receipt always prevents replay.
    pub(in crate::security_epoch) fn revalidate(
        &self,
        selected: &EpochStore,
        observed: &Snapshot,
        floor: Option<&Versioned<Floor>>,
        receipt: Option<&Versioned<Receipt>>,
    ) -> Result<()> {
        ensure!(
            *selected == self.selected
                && *observed == self.before
                && floor == Some(&self.prior)
                && receipt.is_none(),
            "restore_time_conditional_state_changed"
        );
        ensure!(
            *self
                == Self::prepare(
                    selected,
                    observed,
                    floor,
                    self.receipt.operation.clone(),
                    self.receipt.interval.clone(),
                )?,
            "restore_time_plan_changed"
        );
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum Outcome {
    NotApplied,
    Applied,
    Conflict,
}

// Ordering provider document versions does not make them host/approval time.
fn newer(candidate: &UpdateTime, prior: &UpdateTime) -> Result<bool> {
    let format = &time::format_description::well_known::Rfc3339;
    let candidate = time::OffsetDateTime::parse(&candidate.0, format)?;
    let prior = time::OffsetDateTime::parse(&prior.0, format)?;
    Ok(candidate > prior)
}

/// Coherent readback classifies only the exact attempted operation. Even
/// Applied is historical DATA, never a grant, renewed clock or send permission.
pub(in crate::security_epoch) fn reconcile(
    plan: &Plan,
    selected: &EpochStore,
    observed: &Snapshot,
    floor: Option<&Versioned<Floor>>,
    receipt: Option<&Versioned<Receipt>>,
) -> Result<Outcome> {
    plan.revalidate(&plan.selected, &plan.before, Some(&plan.prior), None)?;
    current(selected, observed)?;
    ensure!(
        *selected == plan.selected && *observed == plan.before,
        "restore_time_readback_root_changed"
    );
    Ok(match (floor, receipt) {
        (Some(floor), None) if *floor == plan.prior => Outcome::NotApplied,
        (Some(floor), Some(receipt))
            if floor.value == plan.after
                && floor.version == receipt.version
                && newer(&floor.version, &plan.prior.version)?
                && receipt.value == plan.receipt =>
        {
            Outcome::Applied
        }
        _ => Outcome::Conflict,
    })
}

#[cfg(test)]
mod tests;
