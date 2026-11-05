//! First prepare-for-restore transition. All inputs and outputs are DATA, not
//! maintenance permission, a copy permit, a native owner or writer readiness.
//! The epoch fence and both create-only receipts must commit atomically.
pub(in crate::security_epoch) mod approval_use;
pub(in crate::security_epoch) mod completion;

use super::{EpochStore, Phase, Snapshot, Versioned, advance};
use crate::security_epoch::restore_approval::{AdminIdentity, ApprovalRequest, TargetBinding};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{BindingRef, Digest, security_epoch::AuthorityScope};
use serde::{Deserialize, Serialize};

/// Exact historical references, never key material or an alias for "latest".
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum KeyPurpose {
    CustodyEncryption,
    CustodyVerifier,
    ShellAttestation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct ExactKey {
    pub binding: BindingRef,
    pub version: String,
    pub purpose: KeyPurpose,
}

fn keys(keys: &[ExactKey]) -> Result<()> {
    ensure!((1..=32).contains(&keys.len()), "restore_key_manifest_bound");
    let mut previous = None;
    for key in keys {
        ensure!(
            (1..=128).contains(&key.version.len())
                && !key.version.eq_ignore_ascii_case("latest")
                && !key.version.eq_ignore_ascii_case("current")
                && key
                    .version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "restore_exact_key_version"
        );
        let identity = (
            &key.purpose,
            key.binding.id.as_str(),
            key.binding.revision.as_str(),
            key.version.as_str(),
        );
        ensure!(
            previous.is_none_or(|before| before < identity),
            "restore_key_manifest_order"
        );
        previous = Some(identity);
    }
    Ok(())
}

/// A preflight's bounded commitment to a complete immutable backup. The caller
/// must validate the actual copy/schema and obtain the exact keys independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Backup {
    pub scope: AuthorityScope,
    pub authority: Digest,
    pub source_incarnation: Digest,
    pub security_epoch: u64,
    pub full_archive_digest: Digest,
    pub image: Digest,
    pub schema: Digest,
    pub artifact: Digest,
    pub key_set: Digest,
    pub required_keys: Vec<ExactKey>,
}

/// No preservation profile exists. An eventual copy step must invalidate old
/// credentials/callbacks/delivery and quarantine OAuth for reauthorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Policy {
    ReissueAndReauthorizeV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Intent {
    pub operation: Digest,
    pub archive: Backup,
    pub target_incarnation: Digest,
}

impl Intent {
    pub(in crate::security_epoch) fn commitment(&self, selected: &EpochStore) -> Result<Digest> {
        selected.validate()?;
        keys(&self.archive.required_keys)?;
        ensure!(
            self.archive.scope == selected.scope
                && self.archive.authority == selected.authority_key()?
                && self.archive.key_set == selected.key_set
                && self.archive.security_epoch == 1
                && self.target_incarnation != self.archive.source_incarnation,
            "restore_backup_scope_epoch_or_incarnation"
        );
        Digest::of(&(
            "day2-secure-restore-intent-v1",
            selected,
            self,
            Policy::ReissueAndReauthorizeV1,
        ))
    }

    fn advance_operation(&self, selected: &EpochStore) -> Result<Digest> {
        // The existing fenced phase must itself name this exact archive and
        // target, rather than an operation reusable for a different restore.
        Digest::of(&(
            "day2-secure-restore-advance-operation-v1",
            self.commitment(selected)?,
        ))
    }
}

/// Statement by a future trusted maintenance/fencing source, not evidence that
/// this kernel fenced a process or waited out leases. Bound to this exact root
/// and incumbent holder; a different source/receipt cannot stand in for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Fence {
    pub root: Digest,
    pub holder: Digest,
    pub receipt: Digest,
}

/// Fixed original authorization interval. Neither fresh observation nor
/// historical reconciliation extends it. Human issuance/reveal permission is
/// not a source for this independent maintenance statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Grant {
    pub intent: Digest,
    pub issuer: Digest,
    pub revision: Digest,
    pub policy: Digest,
    pub clock_domain: Digest,
    pub approval: ApprovalRequest,
    pub fence: Fence,
}

/// Fresh, local, controlled-port DATA. A native supplier must authenticate the
/// source and exact key availability without acquiring another owner in SQL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Current {
    pub grant: Grant,
    pub target: TargetBinding,
    pub custody: BindingRef,
    pub executor: AdminIdentity,
    pub enabled: bool,
    pub observed_at: i64,
    pub ready_until: i64,
    pub available_keys: Vec<ExactKey>,
}

fn authorize(
    selected: &EpochStore,
    intent: &Intent,
    grant: &Grant,
    current: &Current,
    at: i64,
    before: &Snapshot,
) -> Result<()> {
    grant.approval.validate()?;
    let approved = &grant.approval;
    ensure!(
        approved.target == current.target
            && approved.executor == current.executor
            && approved.custody == current.custody
            && approved.full_archive_digest == intent.archive.full_archive_digest
            && approved.target.scope == selected.scope
            && approved.target.authority == selected.authority_key()?
            && approved.target.selection == Digest::of(selected)?
            && approved.target.incarnation == intent.target_incarnation
            && approved.target.security_epoch == 2
            && approved.target.artifact == intent.archive.artifact
            && approved.target.schema == intent.archive.schema,
        "restore_approval_binding_changed"
    );
    ensure!(
        current.enabled
            && &current.grant == grant
            && grant.intent == intent.commitment(selected)?
            && current.available_keys == intent.archive.required_keys,
        "restore_current_authority_or_exact_keys_changed"
    );
    let root = &before.root.as_ref().context("restore_root_missing")?.value;
    let Phase::ActiveFirstHolder { completion } = &root.phase else {
        anyhow::bail!("restore_initial_authority_not_active");
    };
    ensure!(
        root.epoch.value() == 1
            && intent.archive.source_incarnation == root.bootstrap.manifest.database_incarnation
            && intent.operation != root.bootstrap.create_operation
            && &intent.operation
                != before
                    .activate
                    .as_ref()
                    .context("restore_activation_missing")?
                    .value
                    .request
                    .operation()
            && grant.fence.root == Digest::of(root)?
            && grant.fence.holder == Digest::of(&completion.holder)?,
        "restore_incumbent_fence_or_source_changed"
    );
    ensure!(
        approved.approved_at >= 0
            && approved.approved_at <= current.observed_at
            && current.observed_at <= at
            && at < current.ready_until
            && current.ready_until <= approved.expires_at
            && current
                .ready_until
                .checked_sub(current.observed_at)
                .is_some_and(|span| (1..=i64::from(selected.max_lease_seconds)).contains(&span)),
        "restore_expired_or_clock_rewound"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Request {
    intent: Intent,
    advance: advance::Request,
    authorization: Current,
    prepared_at: i64,
}

impl Request {
    pub(in crate::security_epoch) fn new(
        selected: &EpochStore,
        intent: Intent,
        current: &Current,
        at: i64,
        before: &Snapshot,
    ) -> Result<Self> {
        authorize(selected, &intent, &current.grant, current, at, before)?;
        let advance = advance::Request::new(selected, intent.advance_operation(selected)?, before)?;
        let request = Self {
            intent,
            advance,
            authorization: current.clone(),
            prepared_at: at,
        };
        request.prepare(selected, current, at, before, None)?;
        Ok(request)
    }

    pub(in crate::security_epoch) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-secure-restore-request-v1", self))
    }

    /// A conditional plan only. The provider must atomically CAS root/sentinel
    /// and create BOTH the existing advance receipt and this restore ledger.
    pub(in crate::security_epoch) fn prepare(
        &self,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        before: &Snapshot,
        ledger: Option<&Versioned<Receipt>>,
    ) -> Result<Plan> {
        authorize(
            selected,
            &self.intent,
            &self.authorization.grant,
            current,
            at,
            before,
        )?;
        ensure!(
            at >= self.prepared_at
                && current.observed_at >= self.authorization.observed_at
                && ledger.is_none(),
            "restore_stale_or_already_reserved"
        );
        // Reconstruct the exact request, rather than trusting decoded request
        // fields which could bind a different operation/activation/version.
        ensure!(
            self.advance
                == advance::Request::new(
                    selected,
                    self.intent.advance_operation(selected)?,
                    before
                )?,
            "restore_advance_request_changed"
        );
        let advance = self.advance.prepare(selected, before)?;
        ensure!(
            advance.root.epoch.value() == 2
                && self.intent.archive.security_epoch < advance.root.epoch.value(),
            "restore_backup_not_fenced"
        );
        let receipt = Receipt {
            format: ReceiptFormat::Day2SecureRestoreReservationV1,
            request: self.clone(),
            request_digest: self.digest()?,
            advance_receipt: Digest::of(&advance.receipt)?,
            target_epoch: advance.root.epoch.value(),
            policy: Policy::ReissueAndReauthorizeV1,
        };
        Ok(Plan {
            before: before.clone(),
            advance,
            receipt,
        })
    }
}

/// Pure plan DATA: no dispatch/copy/publication methods and no native factory.
pub(in crate::security_epoch) struct Plan {
    pub before: Snapshot,
    pub advance: advance::Plan,
    pub receipt: Receipt,
}

impl Plan {
    /// Fresh evidence must be checked immediately before the conditional send.
    /// Exact versions also reject equal-value rewrites and competing restores.
    pub(in crate::security_epoch) fn revalidate(
        &self,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        observed: &Snapshot,
        ledger: Option<&Versioned<Receipt>>,
    ) -> Result<()> {
        ensure!(observed == &self.before, "restore_before_state_changed");
        let expected = self
            .receipt
            .request
            .prepare(selected, current, at, observed, ledger)?;
        ensure!(
            self.advance.before == expected.advance.before
                && self.advance.root == expected.advance.root
                && self.advance.sentinel == expected.advance.sentinel
                && self.advance.receipt == expected.advance.receipt
                && self.receipt == expected.receipt,
            "restore_conditional_plan_changed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptFormat {
    Day2SecureRestoreReservationV1,
}

/// Historical preparation reservation, not completed restore, copy permission,
/// key readiness, a serving epoch observation or a replacement writer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Receipt {
    format: ReceiptFormat,
    request: Request,
    request_digest: Digest,
    advance_receipt: Digest,
    target_epoch: u64,
    policy: Policy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum Outcome {
    NotApplied,
    Applied(Box<Receipt>),
    Conflict,
}

/// Historical classification only. No fresh authorization is inferred, and no
/// automatic retry follows either an absent receipt or an unknown send result.
pub(in crate::security_epoch) fn reconcile(
    selected: &EpochStore,
    plan: &Plan,
    observed: &Snapshot,
    advance_receipt: Option<&Versioned<advance::Receipt>>,
    ledger: Option<&Versioned<Receipt>>,
) -> Result<Outcome> {
    let request = &plan.receipt.request;
    // Validate the captured original DATA, never manufacture a new observation
    // or recheck current permission to classify an already dispatched effect.
    let expected = request.prepare(
        selected,
        &request.authorization,
        request.prepared_at,
        &plan.before,
        None,
    )?;
    ensure!(
        expected.advance.before == plan.advance.before
            && expected.advance.root == plan.advance.root
            && expected.advance.sentinel == plan.advance.sentinel
            && expected.advance.receipt == plan.advance.receipt
            && expected.receipt == plan.receipt,
        "restore_invalid_historical_plan"
    );
    if ledger.is_none() && advance_receipt.is_none() && observed == &plan.before {
        return Ok(Outcome::NotApplied);
    }
    let Some(ledger) = ledger else {
        return Ok(Outcome::Conflict);
    };
    if ledger.value != plan.receipt {
        return Ok(Outcome::Conflict);
    }
    Ok(
        match advance::reconcile(
            selected,
            &plan.receipt.request.advance,
            observed,
            advance_receipt,
        ) {
            Ok(advance::Outcome::Applied(_)) => Outcome::Applied(Box::new(ledger.value.clone())),
            _ => Outcome::Conflict,
        },
    )
}

#[cfg(test)]
mod tests;
