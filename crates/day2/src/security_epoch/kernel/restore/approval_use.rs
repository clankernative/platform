//! Five-record conditional reservation DATA. Neither a signed request nor a
//! stored use row creates a consumed native approval owner. The actual consumer
//! must retain the producer and native storage owners before/after the send.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    Day2RestoreApprovalUseV1,
}

/// Historical, immutable single-use record outside the restored backup domain.
/// It is keyed by GRANT, not operation, and cannot be converted to permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct UseRecord {
    format: Format,
    approval: ApprovalRequest,
    operation: Digest,
    request: Digest,
    reservation: Digest,
}

impl UseRecord {
    pub(in crate::security_epoch) fn key(&self, selected: &EpochStore) -> Result<Digest> {
        selected.validate()?;
        self.approval.validate()?;
        ensure!(
            self.approval.target.scope == selected.scope
                && self.approval.target.authority == selected.authority_key()?,
            "restore_use_selection_changed"
        );
        Digest::of(&(
            "day2-restore-approval-use-key-v1",
            selected.authority_key()?,
            &self.approval.grant_id,
        ))
    }
}

/// All five writes and every read-version/absence condition are one provider
/// transaction. The existing four-record plan is revalidated, not reimplemented.
pub(in crate::security_epoch) struct Plan {
    pub reservation: super::Plan,
    pub approval_use: UseRecord,
}

impl Plan {
    pub(in crate::security_epoch) fn new(
        reservation: super::Plan,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        observed: &Snapshot,
        ledger: Option<&Versioned<Receipt>>,
        used: Option<&Versioned<UseRecord>>,
    ) -> Result<Self> {
        reservation.revalidate(selected, current, at, observed, ledger)?;
        ensure!(used.is_none(), "restore_approval_already_consumed");
        let request = &reservation.receipt.request;
        let approval_use = UseRecord {
            format: Format::Day2RestoreApprovalUseV1,
            approval: request.authorization.grant.approval.clone(),
            operation: request.intent.operation.clone(),
            request: request.digest()?,
            reservation: Digest::of(&reservation.receipt)?,
        };
        approval_use.key(selected)?;
        Ok(Self {
            reservation,
            approval_use,
        })
    }

    /// Recheck the actual same original immediately before send. In particular,
    /// an absent use row cannot excuse a changed root or freshen the approval.
    pub(in crate::security_epoch) fn revalidate(
        &self,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        observed: &Snapshot,
        ledger: Option<&Versioned<Receipt>>,
        used: Option<&Versioned<UseRecord>>,
    ) -> Result<()> {
        self.reservation
            .revalidate(selected, current, at, observed, ledger)?;
        ensure!(used.is_none(), "restore_approval_already_consumed");
        let request = &self.reservation.receipt.request;
        ensure!(
            self.approval_use
                == (UseRecord {
                    format: Format::Day2RestoreApprovalUseV1,
                    approval: request.authorization.grant.approval.clone(),
                    operation: request.intent.operation.clone(),
                    request: request.digest()?,
                    reservation: Digest::of(&self.reservation.receipt)?,
                }),
            "restore_approval_use_plan_changed"
        );
        self.approval_use.key(selected)?;
        Ok(())
    }
}

/// Historical outcome only. Even Applied never mints/reconstructs a consumed
/// owner after an unknown reply, expiry, process loss or missing postcheck.
pub(in crate::security_epoch) fn reconcile(
    selected: &EpochStore,
    plan: &Plan,
    observed: &Snapshot,
    advance: Option<&Versioned<advance::Receipt>>,
    ledger: Option<&Versioned<Receipt>>,
    used: Option<&Versioned<UseRecord>>,
) -> Result<Outcome> {
    let request = &plan.reservation.receipt.request;
    plan.revalidate(
        selected,
        &request.authorization,
        request.prepared_at,
        &plan.reservation.before,
        None,
        None,
    )?;
    let reserved = super::reconcile(selected, &plan.reservation, observed, advance, ledger)?;
    Ok(match (reserved, used) {
        (Outcome::NotApplied, None) => Outcome::NotApplied,
        (Outcome::Applied(receipt), Some(row)) if row.value == plan.approval_use => {
            Outcome::Applied(receipt)
        }
        _ => Outcome::Conflict,
    })
}
