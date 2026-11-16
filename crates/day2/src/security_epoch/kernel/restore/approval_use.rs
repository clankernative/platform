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
    /// Pure binding of the receiving read to its signed approval/target and
    /// immutable consumed-use history. This grants no live approval use.
    pub(in crate::security_epoch) fn require_peer_data(
        &self,
        binding: &super::writer::PeerBinding<'_>,
    ) -> Result<()> {
        self.approval.validate()?;
        ensure!(
            self.approval.commitment()? == *binding.approval_request
                && self.approval.full_archive_digest == *binding.full_archive
                && self.approval.target == *binding.target
                && self.operation == *binding.operation,
            "restore_peer_consumed_approval_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn grant_id_data(&self) -> &Digest {
        &self.approval.grant_id
    }

    pub(in crate::security_epoch) fn key(&self, selected: &EpochStore) -> Result<Digest> {
        selected.validate()?;
        self.approval.validate()?;
        ensure!(
            self.approval.target.scope == selected.scope
                && self.approval.target.authority == selected.authority_key()?,
            "restore_use_selection_changed"
        );
        use_key_data(selected, &self.approval.grant_id)
    }
}

/// Exact historical selector DATA, never grant consumption or permission.
pub(in crate::security_epoch) fn use_key_data(
    selected: &EpochStore,
    grant: &Digest,
) -> Result<Digest> {
    selected.validate()?;
    Digest::of(&(
        "day2-restore-approval-use-key-v1",
        selected.authority_key()?,
        grant,
    ))
}

/// All five writes and every read-version/absence condition are one provider
/// transaction. The existing four-record plan is revalidated, not reimplemented.
// Copying preserves exact historical DATA; actual native owners and their
// one-shot dispatch/original/postchecks remain separate and non-cloneable.
#[derive(Clone)]
pub(in crate::security_epoch) struct Plan {
    pub reservation: super::Plan,
    pub approval_use: UseRecord,
}

/// Provider selector DATA derived from the validated original plan. No caller
/// document path, signing key, approval owner or send permission is accepted.
pub(in crate::security_epoch) struct Selectors {
    pub bootstrap: super::super::Bootstrap,
    pub activation: Digest,
    pub advance: Digest,
    pub operation: Digest,
    pub grant: Digest,
}

impl Plan {
    /// Exact input DATA for the retained native writer loan. This does not
    /// authenticate an archive, namespace, approval or current owner. The loan
    /// must separately keep its actual same-original pre/post checks live.
    pub(in crate::security_epoch) fn require_staging_input_data(
        &self,
        selected: &EpochStore,
        intent: &Intent,
        namespace: &day2_capabilities::credentials::Namespace,
    ) -> Result<()> {
        self.selectors(selected)?;
        namespace.validate()?;
        let request = &self.reservation.receipt.request;
        ensure!(
            request.intent == *intent
                && namespace.installation == selected.scope.installation
                && namespace.environment == selected.scope.environment
                && namespace.app == selected.scope.app
                && namespace.binding_generation
                    == request
                        .authorization
                        .grant
                        .approval
                        .target
                        .binding_generation,
            "restore_staging_input_changed"
        );
        Ok(())
    }

    /// Request DATA to join the immutable signed publication to this exact
    /// reservation. Neither side supplies signature verification or authority.
    pub(in crate::security_epoch) fn require_publication_data(
        &self,
        selected: &EpochStore,
        publication: &crate::security_epoch::restore_approval::publication::Publication,
    ) -> Result<()> {
        publication.require_request_data(selected, &self.approval_use.approval)
    }

    pub(in crate::security_epoch) fn selectors(&self, selected: &EpochStore) -> Result<Selectors> {
        let request = &self.reservation.receipt.request;
        self.revalidate(
            selected,
            &request.authorization,
            request.prepared_at,
            &self.reservation.before,
            None,
            None,
        )?;
        let activation = &self
            .reservation
            .before
            .activate
            .as_ref()
            .context("restore_provider_activation_missing")?
            .value
            .request;
        Ok(Selectors {
            bootstrap: activation.bootstrap().clone(),
            activation: activation.operation().clone(),
            advance: request.intent.advance_operation(selected)?,
            operation: request.intent.operation.clone(),
            grant: self.approval_use.key(selected)?,
        })
    }

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
