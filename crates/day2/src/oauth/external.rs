//! Explicit external-account settlement. Provider tokens wait in encrypted
//! quarantine until the security shell confirms the exact displayed identity
//! with a fresh authenticated session and one pending challenge.

use super::account::{self, ProviderAccount, VerifiedExternalAccount};
use super::connect::{self, ConnectIntent};
use super::custody::{self, PreparedExternalQuarantine};
use super::exchange::{ExchangeBinding, PrivateExchangeResponse};
use super::profiles::{
    self, AccountBindingEvidence, OutboundQualification, ValidatedTokenResponse,
};
use crate::managed_credentials::crypto::KeyLease;
use anyhow::{Result, ensure};
use day2_capabilities::oauth::SecurityOriginRef;
use day2_capabilities::{BindingRef, Digest};
use ring::hmac;
use rusqlite::{Connection, OptionalExtension};

pub struct VerifiedExternalExchange {
    verified: VerifiedExternalAccount,
    binding: ExchangeBinding,
    tokens: ValidatedTokenResponse,
}

impl PrivateExchangeResponse {
    pub fn validate_external(
        self,
        input: OutboundQualification<'_>,
        observed: &ProviderAccount,
    ) -> Result<VerifiedExternalExchange> {
        let qualified = profiles::qualify_outbound_connect(
            input.intent,
            input.binding,
            input.requirement,
            input.permission,
            input.reviewed,
            input.instance,
        )?;
        ensure!(
            self.intent == *qualified.intent()
                && self.binding.matches_current(&input)?
                && observed.issuer == self.binding.issuer_url,
            "external response does not match qualified exchange"
        );
        ensure!(
            self.http.status == 200 && self.http.content_type == "application/json",
            "unsupported provider token response status or content type"
        );
        let tokens = input
            .reviewed
            .protocol
            .validate_token_response(&self.http.body, input.permission)?;
        let verified = VerifiedExternalAccount::verify(
            &self.intent,
            input.requirement,
            input.permission,
            input.instance,
            observed,
            &tokens,
        )?;
        Ok(VerifiedExternalExchange {
            verified,
            binding: self.binding,
            tokens,
        })
    }
}

pub struct PreparedExternalSettlement {
    verified: VerifiedExternalAccount,
    binding: ExchangeBinding,
    material: PreparedExternalQuarantine,
}

impl VerifiedExternalExchange {
    pub(crate) fn prepare_quarantine(
        self,
        key: &KeyLease,
        now: i64,
    ) -> Result<PreparedExternalSettlement> {
        let material = custody::prepare_external_quarantine(
            key,
            self.verified.intent(),
            (self.verified.account(), self.verified.scope_evidence()),
            self.verified.observed(),
            &self.binding,
            self.tokens,
            now,
        )?;
        Ok(PreparedExternalSettlement {
            verified: self.verified,
            binding: self.binding,
            material,
        })
    }
}

/// Quarantine and the awaiting-approval state commit together. No token slot
/// becomes active at this boundary.
pub fn quarantine_external(
    db: &mut Connection,
    prepared: PreparedExternalSettlement,
    current: OutboundQualification<'_>,
    now: i64,
) -> Result<bool> {
    let qualified = profiles::qualify_outbound_connect(
        current.intent,
        current.binding,
        current.requirement,
        current.permission,
        current.reviewed,
        current.instance,
    )?;
    if prepared.verified.intent() != qualified.intent()
        || !prepared.binding.matches_current(&current)?
        || prepared.material.quarantined_at() != now
        || prepared.verified.security_origin() != &current.instance.shell.origin
        || !matches!(
            &current.instance.account,
            AccountBindingEvidence::ExplicitExternal { approval, .. }
                if approval == prepared.verified.approval()
        )
    {
        return Ok(false);
    }
    connect::quarantine_external_bound(db, &prepared.verified, &prepared.binding, now, |tx| {
        custody::publish_external_quarantine(tx, prepared.material)
    })
}

/// Host-only presentation. The app receives the redacted connect state. The
/// security shell may show these fields after loading and decrypting custody.
pub struct PendingExternalApproval {
    intent: ConnectIntent,
    binding: ExchangeBinding,
    account: String,
    scope_evidence: String,
    observed: ProviderAccount,
    challenge: Digest,
    quarantined_at: i64,
    approval: BindingRef,
    security_origin: SecurityOriginRef,
    original_session: Digest,
}

impl PendingExternalApproval {
    pub fn attempt(&self) -> &str {
        &self.intent.attempt
    }

    pub fn observed_account(&self) -> &ProviderAccount {
        &self.observed
    }

    pub fn challenge(&self) -> &Digest {
        &self.challenge
    }

    pub fn slot(&self) -> &str {
        &self.intent.slot
    }

    pub fn generation(&self) -> i64 {
        self.intent.proposed_generation
    }

    pub fn human(&self) -> &str {
        &self.intent.owner
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn scope_evidence(&self) -> &str {
        &self.scope_evidence
    }

    pub fn approval_binding(&self) -> &BindingRef {
        &self.approval
    }

    pub fn security_origin(&self) -> &SecurityOriginRef {
        &self.security_origin
    }

    pub(crate) fn quarantined_at(&self) -> i64 {
        self.quarantined_at
    }
}

pub(crate) fn load_pending_external(
    db: &Connection,
    current: OutboundQualification<'_>,
    key: &KeyLease,
    now: i64,
) -> Result<Option<PendingExternalApproval>> {
    let qualified = profiles::qualify_outbound_connect(
        current.intent,
        current.binding,
        current.requirement,
        current.permission,
        current.reviewed,
        current.instance,
    )?;
    let row: Option<(ConnectIntent, String, Option<String>, Option<String>)> = db
        .query_row(
            "SELECT slot, expected_generation, expected_epoch, proposed_generation, owner,
                    profile, registration, callback, consent, expires_at,
                    state, account, scope_evidence
             FROM oauth_connect_attempts WHERE attempt = ?1",
            [&current.intent.attempt],
            |row| {
                Ok((
                    ConnectIntent {
                        attempt: current.intent.attempt.clone(),
                        slot: row.get(0)?,
                        expected_generation: row.get(1)?,
                        expected_epoch: row.get(2)?,
                        proposed_generation: row.get(3)?,
                        owner: row.get(4)?,
                        profile: row.get(5)?,
                        registration: row.get(6)?,
                        callback: row.get(7)?,
                        consent: row.get(8)?,
                        expires_at: row.get(9)?,
                    },
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            },
        )
        .optional()?;
    let Some((intent, state, account, scope_evidence)) = row else {
        return Ok(None);
    };
    let (Some(account), Some(scope_evidence)) = (account, scope_evidence) else {
        return Ok(None);
    };
    if intent != *qualified.intent()
        || state != "awaiting_account_approval"
        || now >= intent.expires_at
    {
        return Ok(None);
    }
    let Some(binding) = super::exchange::load_binding(db, &intent.attempt)? else {
        return Ok(None);
    };
    if !binding.matches_current(&current)? {
        return Ok(None);
    }
    let Some(pending) = custody::load_pending_external_identity(
        db,
        key,
        &intent,
        &binding,
        &account,
        &scope_evidence,
    )?
    else {
        return Ok(None);
    };
    account::validate_pending_external(
        &intent,
        current.requirement,
        current.permission,
        current.instance,
        &pending.observed,
        &account,
        &scope_evidence,
    )?;
    let AccountBindingEvidence::ExplicitExternal { approval, .. } = &current.instance.account
    else {
        anyhow::bail!("external approval binding missing");
    };
    Ok(Some(PendingExternalApproval {
        intent,
        binding,
        account,
        scope_evidence,
        observed: pending.observed,
        challenge: pending.challenge,
        quarantined_at: pending.quarantined_at,
        approval: approval.clone(),
        security_origin: current.instance.shell.origin.clone(),
        original_session: current.binding.session().clone(),
    }))
}

/// Evidence supplied by the trusted security shell after it authenticates the
/// human again and records an explicit confirmation of the pending challenge.
/// Raw session credentials do not enter this kernel or SQLite.
pub struct FreshExternalApproval {
    pub attempt: String,
    pub slot: String,
    pub generation: i64,
    pub human: String,
    pub account: String,
    pub scope_evidence: String,
    pub challenge: Digest,
    pub security_origin: SecurityOriginRef,
    pub approval: BindingRef,
    pub session: Digest,
    pub authenticated_at: i64,
    pub confirmed_at: i64,
    key_version: String,
    signature: [u8; 32],
}

impl FreshExternalApproval {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            "oauth-external-security-shell-approval-v1",
            &self.key_version,
            &self.attempt,
            &self.slot,
            self.generation,
            &self.human,
            &self.account,
            &self.scope_evidence,
            &self.challenge,
            &self.security_origin,
            &self.approval,
            &self.session,
            self.authenticated_at,
            self.confirmed_at,
        ))?)
    }

    fn verify(
        &self,
        pending: &PendingExternalApproval,
        shell: &ShellApprovalKeyLease,
        now: i64,
    ) -> Result<()> {
        shell.verify(self)?;
        ensure!(
            self.attempt == pending.intent.attempt
                && self.slot == pending.intent.slot
                && self.generation == pending.intent.proposed_generation
                && self.human == pending.intent.owner
                && self.account == pending.account
                && self.scope_evidence == pending.scope_evidence
                && self.challenge == pending.challenge
                && self.security_origin == pending.security_origin
                && self.approval == pending.approval
                && self.session != pending.original_session,
            "external approval does not match pending identity"
        );
        ensure!(
            self.authenticated_at > pending.quarantined_at
                && self.confirmed_at >= self.authenticated_at
                && now >= self.confirmed_at
                && now
                    .checked_sub(self.authenticated_at)
                    .is_some_and(|age| age <= 300)
                && now
                    .checked_sub(self.confirmed_at)
                    .is_some_and(|age| age <= 60),
            "external approval requires a fresh security session"
        );
        Ok(())
    }
}

/// A separate, admitted security-shell key. Only the shell may call `attest`
/// after it has checked a fresh human session and an explicit confirmation.
pub(crate) struct ShellApprovalKeyLease {
    key: hmac::Key,
    version: String,
    origin: SecurityOriginRef,
    approval: BindingRef,
}

impl ShellApprovalKeyLease {
    pub(crate) fn new(
        key: &[u8; 32],
        version: String,
        origin: SecurityOriginRef,
        approval: BindingRef,
    ) -> Result<Self> {
        ensure!(
            !version.is_empty()
                && version.len() <= 64
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid security-shell approval key version"
        );
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
            version,
            origin,
            approval,
        })
    }

    pub(crate) fn attest(
        &self,
        pending: &PendingExternalApproval,
        session: Digest,
        authenticated_at: i64,
        confirmed_at: i64,
    ) -> Result<FreshExternalApproval> {
        ensure!(
            pending.security_origin == self.origin && pending.approval == self.approval,
            "security-shell approval key binding mismatch"
        );
        let mut evidence = FreshExternalApproval {
            attempt: pending.intent.attempt.clone(),
            slot: pending.intent.slot.clone(),
            generation: pending.intent.proposed_generation,
            human: pending.intent.owner.clone(),
            account: pending.account.clone(),
            scope_evidence: pending.scope_evidence.clone(),
            challenge: pending.challenge.clone(),
            security_origin: self.origin.clone(),
            approval: self.approval.clone(),
            session,
            authenticated_at,
            confirmed_at,
            key_version: self.version.clone(),
            signature: [0; 32],
        };
        evidence.signature = hmac::sign(&self.key, &evidence.signing_bytes()?)
            .as_ref()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid security-shell approval signature"))?;
        Ok(evidence)
    }

    fn verify(&self, evidence: &FreshExternalApproval) -> Result<()> {
        ensure!(
            evidence.key_version == self.version
                && evidence.security_origin == self.origin
                && evidence.approval == self.approval,
            "security-shell approval key binding mismatch"
        );
        hmac::verify(&self.key, &evidence.signing_bytes()?, &evidence.signature)
            .map_err(|_| anyhow::anyhow!("security-shell approval attestation invalid"))
    }
}

/// The challenge, encrypted token identity, attempt, slot CAS and activation
/// all revalidate within the final SQLite transaction.
pub(crate) fn approve_external(
    db: &mut Connection,
    current: OutboundQualification<'_>,
    key: &KeyLease,
    shell: &ShellApprovalKeyLease,
    approval: FreshExternalApproval,
    now: i64,
) -> Result<bool> {
    let Some(pending) = load_pending_external(db, current, key, now)? else {
        return Ok(false);
    };
    approval.verify(&pending, shell, now)?;
    connect::activate_external_bound(
        db,
        &pending.intent,
        &pending.binding,
        &pending.account,
        &pending.scope_evidence,
        now,
        |tx| {
            custody::commit_external_quarantine(
                tx,
                key,
                &pending.intent,
                &pending.binding,
                &pending.account,
                &pending.scope_evidence,
                &pending.challenge,
            )
        },
    )
}
