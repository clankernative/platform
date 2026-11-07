//! Settlement of a reserved restore's DATA observation. Neither disposition
//! admits a target, changes the fenced epoch, nor permits copy, key or writer use.
use super::{Current, EpochStore, Phase, Snapshot, Versioned, advance};
use crate::security_epoch::kernel::restore::Policy;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

/// Exact current provider records, including their update tokens. A conditional
/// send must compare every record, even after an equal-value rewrite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) struct State {
    pub snapshot: Snapshot,
    pub advance: Versioned<advance::Receipt>,
    pub reservation: Versioned<super::Receipt>,
}

impl State {
    fn commitment(&self) -> Result<Digest> {
        let s = &self.snapshot;
        Digest::of(&(
            "day2-secure-restore-settlement-state-v1",
            s.root.as_ref().map(|r| (&r.value, &r.version)),
            s.sentinel.as_ref().map(|r| (&r.value, &r.version)),
            s.create.as_ref().map(|r| (&r.value, &r.version)),
            s.activate.as_ref().map(|r| (&r.value, &r.version)),
            (&self.advance.value, &self.advance.version),
            (&self.reservation.value, &self.reservation.version),
        ))
    }
}

/// Bounded observation supplied as DATA by an eventual checked reset producer.
/// These commitments do NOT authenticate that producer or prove sanitization.
/// There is deliberately no preserve-old-authority policy or admission boolean.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct TargetReport {
    pub intent: Digest,
    pub archive: Digest,
    pub target_incarnation: Digest,
    pub target_epoch: u64,
    pub image: Digest,
    pub schema: Digest,
    pub artifact: Digest,
    pub reset_observation: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum Refusal {
    OperatorCancelled,
    TargetObservationRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::security_epoch) enum Disposition {
    Completed { report: TargetReport },
    Refused { reason: Refusal },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Receipt {
    format: Format,
    operation: Digest,
    request: Digest,
    reserved: Digest,
    disposition: Disposition,
    policy: Policy,
    // Preparation time, not a claim about provider commit time or target age.
    prepared_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    Day2SecureRestoreSettlementV1,
}

/// A single original request, never renewed after expiry, replacement or an
/// uncertain send. Reconciliation below classifies history, not permission.
pub(in crate::security_epoch) struct Request {
    original: super::Request,
    source: Snapshot,
    before: State,
    disposition: Disposition,
    authorization: Current,
    prepared_at: i64,
}

impl Request {
    pub(in crate::security_epoch) fn new(
        selected: &EpochStore,
        reservation: &super::Plan,
        before: &State,
        current: &Current,
        at: i64,
        disposition: Disposition,
    ) -> Result<Self> {
        let request = Self {
            original: reservation.receipt.request.clone(),
            source: reservation.before.clone(),
            before: before.clone(),
            disposition,
            authorization: current.clone(),
            prepared_at: at,
        };
        // Validate the actual supplied parent plan as well as the reconstruction.
        ensure!(
            matches!(
                super::reconcile(
                    selected,
                    reservation,
                    &before.snapshot,
                    Some(&before.advance),
                    Some(&before.reservation)
                )?,
                super::Outcome::Applied(_)
            ),
            "restore_settlement_not_reserved"
        );
        request.prepare(selected, current, at, before, None)?;
        Ok(request)
    }

    fn reservation(&self, selected: &EpochStore) -> Result<super::Plan> {
        self.original.prepare(
            selected,
            &self.original.authorization,
            self.original.prepared_at,
            &self.source,
            None,
        )
    }

    /// Fresh current authority authorizes only creation of a terminal DATA
    /// record. Expired/revoked/missing-key evidence produces no write plan, even
    /// for refusal. A genuine owner must separately latch any permanent refusal.
    pub(in crate::security_epoch) fn prepare(
        &self,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        observed: &State,
        terminal: Option<&Versioned<Receipt>>,
    ) -> Result<Plan> {
        ensure!(
            observed == &self.before && terminal.is_none(),
            "restore_settlement_state_or_terminal_changed"
        );
        super::authorize(
            selected,
            &self.original.intent,
            &self.original.authorization.grant,
            current,
            at,
            &self.source,
        )?;
        ensure!(
            at >= self.prepared_at
                && self.prepared_at >= self.original.prepared_at
                && current.observed_at >= self.authorization.observed_at
                && self.authorization.observed_at >= self.original.authorization.observed_at
                && current.grant == self.authorization.grant,
            "restore_settlement_original_clock_or_grant_changed"
        );
        let reserved = self.reservation(selected)?;
        ensure!(
            matches!(
                super::reconcile(
                    selected,
                    &reserved,
                    &observed.snapshot,
                    Some(&observed.advance),
                    Some(&observed.reservation)
                )?,
                super::Outcome::Applied(_)
            ),
            "restore_settlement_reservation_changed"
        );
        let root = observed.snapshot.root.as_ref().unwrap();
        ensure!(
            root.value.epoch.value() == 2 && matches!(&root.value.phase, Phase::Fenced { .. }),
            "restore_settlement_epoch_not_fenced"
        );
        if let Disposition::Completed { report } = &self.disposition {
            let intent = &self.original.intent;
            ensure!(
                report.intent == intent.commitment(selected)?
                    && report.archive == intent.archive.image
                    && report.target_incarnation == intent.target_incarnation
                    && report.target_epoch == 2
                    && report.schema == intent.archive.schema
                    && report.artifact == intent.archive.artifact,
                "restore_settlement_target_report_changed"
            );
        }
        let captured = self.before.commitment()?;
        let request = Digest::of(&(
            "day2-secure-restore-settlement-request-v1",
            self.original.digest()?,
            captured.clone(),
            &self.disposition,
            &self.authorization,
            self.prepared_at,
        ))?;
        Ok(Plan {
            before: self.before.clone(),
            receipt: Receipt {
                format: Format::Day2SecureRestoreSettlementV1,
                operation: self.original.intent.operation.clone(),
                request,
                reserved: captured,
                disposition: self.disposition.clone(),
                policy: Policy::ReissueAndReauthorizeV1,
                prepared_at: self.prepared_at,
            },
        })
    }
}

/// Create-only terminal record under the ORIGINAL restore operation. Complete
/// and refuse compete for that one key; neither changes any authority record.
pub(in crate::security_epoch) struct Plan {
    pub before: State,
    pub receipt: Receipt,
}

impl Plan {
    pub(in crate::security_epoch) fn revalidate(
        &self,
        selected: &EpochStore,
        request: &Request,
        current: &Current,
        at: i64,
        observed: &State,
        terminal: Option<&Versioned<Receipt>>,
    ) -> Result<()> {
        let expected = request.prepare(selected, current, at, observed, terminal)?;
        ensure!(
            self.before == expected.before && self.receipt == expected.receipt,
            "restore_settlement_plan_changed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum Outcome {
    NotApplied,
    Recorded(Box<Receipt>),
    Conflict,
}

/// Historical readback after an uncertain completion, including after expiry.
/// No dispatch or refresh follows any outcome; no terminal record activates a
/// target or re-grants the old authority. Newer/equal-rewritten state conflicts.
pub(in crate::security_epoch) fn reconcile(
    selected: &EpochStore,
    request: &Request,
    plan: &Plan,
    observed: &State,
    terminal: Option<&Versioned<Receipt>>,
) -> Result<Outcome> {
    let expected = request.prepare(
        selected,
        &request.authorization,
        request.prepared_at,
        &request.before,
        None,
    )?;
    ensure!(
        expected.before == plan.before && expected.receipt == plan.receipt,
        "restore_settlement_invalid_historical_plan"
    );
    if observed != &plan.before {
        return Ok(Outcome::Conflict);
    }
    Ok(match terminal {
        None => Outcome::NotApplied,
        Some(record) if record.value == plan.receipt => {
            Outcome::Recorded(Box::new(record.value.clone()))
        }
        Some(_) => Outcome::Conflict,
    })
}

#[cfg(test)]
mod tests;
