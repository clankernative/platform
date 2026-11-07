//! The server challenge commits to the restore intent before human interaction.
//! Approval timestamps are added only after genuine completion. This entire
//! module is DATA: it supplies neither a clock nor signing/current authority.
use super::{AdminIdentity, ApprovalRequest, RESTORE_APPROVAL_LIFETIME_SECONDS, TargetBinding};
use anyhow::{Result, ensure};
use day2_capabilities::{BindingRef, Digest};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalIntent {
    pub grant_id: Digest,
    pub full_archive_digest: Digest,
    pub target: TargetBinding,
    pub executor: AdminIdentity,
    pub custody: BindingRef,
}

impl ApprovalIntent {
    pub(crate) fn validate(&self) -> Result<()> {
        self.executor.validate()?;
        self.target.validate()
    }

    /// Every known request field is committed, with a domain distinct from the
    /// finalized signed request. The registry key binding separately commits
    /// the genuine approver selection; this digest authenticates no principal.
    pub(crate) fn commitment(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&("day2-restore-approval-intent-v1", self))
    }

    pub(crate) fn require_exact(&self, expected: &Self) -> Result<()> {
        self.validate()?;
        expected.validate()?;
        ensure!(self == expected, "restore_approval_intent_changed");
        Ok(())
    }

    /// Pure assembly, never a clock/approval constructor. The genuine producer
    /// must obtain this timestamp from its qualified completion clock/floor
    /// and retain all source postchecks before signing or publishing anything.
    pub(crate) fn request_data(&self, approved_at: i64) -> Result<ApprovalRequest> {
        self.validate()?;
        let request = ApprovalRequest {
            grant_id: self.grant_id.clone(),
            full_archive_digest: self.full_archive_digest.clone(),
            target: self.target.clone(),
            executor: self.executor.clone(),
            custody: self.custody.clone(),
            approved_at,
            expires_at: approved_at
                .checked_add(i64::try_from(RESTORE_APPROVAL_LIFETIME_SECONDS)?)
                .ok_or_else(|| anyhow::anyhow!("restore_approval_time_overflow"))?,
        };
        request.validate()?;
        Ok(request)
    }

    /// No caller may replace an intent field while adding the final clock
    /// observation. Comparing this DATA still does not verify that clock.
    pub(crate) fn require_request(&self, request: &ApprovalRequest) -> Result<()> {
        self.validate()?;
        request.validate()?;
        ensure!(
            self.grant_id == request.grant_id
                && self.full_archive_digest == request.full_archive_digest
                && self.target == request.target
                && self.executor == request.executor
                && self.custody == request.custody,
            "restore_approval_intent_changed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
