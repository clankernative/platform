//! Canonical restore-approval DATA shared by the producer and consumer.
//! Parsing, hashing or comparing a request creates no passkey proof, native
//! original, consumed grant, fence, archive readiness or writer permission.

use anyhow::{Result, ensure};
use day2_capabilities::{BindingRef, Digest, security_epoch::AuthorityScope};
use serde::{Deserialize, Serialize};

/// User-approved fixed interval from approval, never from consumption/recovery.
/// The existing request/Current freshness bounds are independent and unchanged.
pub(crate) const RESTORE_APPROVAL_LIFETIME_SECONDS: u64 = 3600;
const MAX_REQUEST_BYTES: usize = 16_384;

mod kms;
pub(crate) mod signed;
mod intent;
pub(crate) use intent::ApprovalIntent;

/// Exact selected target DATA. The consumer must compare every field with its
/// actual current selection, fenced epoch and held target, not just a digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetBinding {
    pub scope: AuthorityScope,
    pub binding_generation: u64,
    pub authority: Digest,
    pub selection: Digest,
    pub incarnation: Digest,
    pub security_epoch: u64,
    pub artifact: Digest,
    pub schema: Digest,
}

impl TargetBinding {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.binding_generation > 0 && self.security_epoch > 0,
            "restore_approval_target_shape"
        );
        Ok(())
    }
}

/// Identity DATA only. An email or this decoded pair cannot authenticate an
/// executor. The actual owner must verify identity, subject binding and current
/// policy.admins membership independently. Approver and executor may be equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdminIdentity {
    pub email: String,
    pub subject: String,
}

impl AdminIdentity {
    fn validate(&self) -> Result<()> {
        crate::authority::valid_actor(&self.email)
            .map_err(|_| anyhow::anyhow!("restore_approval_identity_shape"))?;
        ensure!(
            self.email.len() >= 3
                && self.email == self.email.to_ascii_lowercase()
                && !self.email.chars().any(char::is_whitespace)
                && self.email.split('@').count() == 2
                && self.email.split('@').all(|part| !part.is_empty())
                && (1..=1024).contains(&self.subject.len())
                && !self.subject.chars().any(char::is_control),
            "restore_approval_identity_shape"
        );
        Ok(())
    }
}

/// Complete approval request DATA, including the complete captured archive's
/// bytes/inventory digest (not a metadata, SQLite image or reset digest), fixed
/// times and existing vault binding. The consumer must validate the real archive.
/// There is deliberately no permission/original or scalar approval constructor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalRequest {
    pub grant_id: Digest,
    pub full_archive_digest: Digest,
    pub target: TargetBinding,
    pub executor: AdminIdentity,
    pub custody: BindingRef,
    pub approved_at: i64,
    pub expires_at: i64,
}

impl ApprovalRequest {
    pub(crate) fn intent(&self) -> ApprovalIntent {
        ApprovalIntent {
            grant_id: self.grant_id.clone(),
            full_archive_digest: self.full_archive_digest.clone(),
            target: self.target.clone(),
            executor: self.executor.clone(),
            custody: self.custody.clone(),
        }
    }

    /// Shape checks only. No clock is sampled and no current permission follows.
    pub(crate) fn validate(&self) -> Result<()> {
        self.executor.validate()?;
        self.target.validate()?;
        ensure!(
            self.approved_at >= 0
                && self.expires_at.checked_sub(self.approved_at)
                    == Some(i64::try_from(RESTORE_APPROVAL_LIFETIME_SECONDS)?),
            "restore_approval_fixed_lifetime"
        );
        Ok(())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_REQUEST_BYTES,
            "restore_approval_request_bound"
        );
        let request: Self = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("restore_approval_request_encoding"))?;
        request.validate()?;
        Ok(request)
    }

    /// Domain-separated commitment to every field. This is not a signature or
    /// proof of archive availability, passkey verification or durable use.
    pub(crate) fn commitment(&self) -> Result<Digest> {
        self.validate()?;
        Digest::of(&("day2-restore-approval-request-v1", self))
    }

    /// Complete equality, not hash-only admission. Both operands remain DATA;
    /// authenticating their owners and consuming the grant are separate work.
    pub(crate) fn require_exact(&self, expected: &Self) -> Result<()> {
        self.validate()?;
        expected.validate()?;
        ensure!(self == expected, "restore_approval_request_changed");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
