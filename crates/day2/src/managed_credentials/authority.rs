//! Host-selected, short-lived readiness and exact-version custody leases.
//! The snapshot is supplied by the installation's admitted readiness adapters;
//! browser fields never select a provider, key, issuer or security epoch.
use super::{
    crypto::KeyLease,
    issuance::{Authority, ReadyKeys},
    store::HumanRevealPermit,
};
use crate::oauth::approval_registry::{ApprovalKeyProvider, ApprovalKeyPurpose, ApprovalKeyRef};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    credentials::{CredentialFamilyBinding, ManagementPolicy, ManagementPredicate},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

#[derive(Clone)]
pub(crate) struct Selection {
    pub binding: CredentialFamilyBinding,
    pub security_origin: String,
    pub management: ManagementPolicy,
    pub verifier: ApprovalKeyRef,
    pub encryption: ApprovalKeyRef,
    pub security_epoch: u64,
    pub observed_at: i64,
    pub ready_until: i64,
    pub grant_until: i64,
    pub max_active_lineages: u32,
    /// Current admitted human accounts, keyed by email with canonical subjects.
    pub issuers: BTreeMap<String, String>,
}

pub(crate) struct SelectedAuthority {
    entries: RwLock<Vec<Selection>>,
    keys: Arc<dyn ApprovalKeyProvider>,
}

impl SelectedAuthority {
    pub(crate) fn new(entries: Vec<Selection>, keys: Arc<dyn ApprovalKeyProvider>) -> Result<Self> {
        let result = Self {
            entries: RwLock::new(Vec::new()),
            keys,
        };
        result.replace(entries)?;
        Ok(result)
    }

    pub(crate) fn replace(&self, entries: Vec<Selection>) -> Result<()> {
        ensure!(entries.len() <= 128, "credential admission budget");
        let mut seen = std::collections::BTreeSet::new();
        for entry in &entries {
            let origin = url::Url::parse(&entry.security_origin)?;
            ensure!(
                origin.scheme() == "https"
                    && origin.origin().ascii_serialization() == entry.security_origin,
                "credential readiness security origin mismatch"
            );
            ensure!(
                seen.insert((
                    entry.binding.namespace.clone(),
                    entry.binding.family.clone()
                )),
                "duplicate credential admission"
            );
            ensure!(
                entry.verifier.binding == entry.binding.verifier
                    && entry.encryption.binding == entry.binding.custody
                    && entry.verifier.binding != entry.encryption.binding,
                "credential key purpose binding mismatch"
            );
            ensure!(
                entry.security_epoch > 0
                    && entry.observed_at >= 0
                    && entry.ready_until > entry.observed_at
                    && entry.ready_until - entry.observed_at <= 300
                    && entry.grant_until >= entry.ready_until
                    && (1..=10_000).contains(&entry.max_active_lineages)
                    && entry.issuers.len() <= 10_000
                    && matches!(entry.management.issue, ManagementPredicate::Creator)
                    && matches!(
                        entry.binding.delivery,
                        day2_capabilities::credentials::DeliveryProfile::AuthenticatedCreatorReveal
                    ),
                "unsupported or unbounded credential readiness"
            );
            for (actor, subject) in &entry.issuers {
                crate::authority::valid_actor(actor)?;
                ensure!(
                    !subject.is_empty() && subject.len() <= 256,
                    "invalid credential subject"
                );
            }
        }
        *self
            .entries
            .write()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))? = entries;
        Ok(())
    }

    fn selected<'a>(
        entries: &'a [Selection],
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<&'a Selection> {
        let entry = entries
            .iter()
            .find(|entry| {
                entry.binding.namespace == binding.namespace
                    && entry.binding.family == binding.family
            })
            .context("credential family readiness unavailable")?;
        ensure!(
            &entry.binding == binding
                && &entry.management == management
                && entry.observed_at <= now
                && now < entry.ready_until
                && entry.issuers.get(actor).map(String::as_str) == Some(subject),
            "credential authority unavailable or changed"
        );
        Ok(entry)
    }

    fn key(&self, reference: &ApprovalKeyRef, purpose: ApprovalKeyPurpose) -> Result<[u8; 32]> {
        let material = self.keys.load(reference, purpose)?;
        ensure!(
            material.binding == reference.binding
                && material.version == reference.version
                && material.purpose == purpose,
            "credential key lease identity mismatch"
        );
        Ok(material.bytes)
    }

    fn lease(&self, selected: &Selection) -> Result<KeyLease> {
        let mut verifier = self.key(&selected.verifier, ApprovalKeyPurpose::CustodyVerifier)?;
        let mut encryption =
            self.key(&selected.encryption, ApprovalKeyPurpose::CustodyEncryption)?;
        let result = KeyLease::new(
            &verifier,
            &encryption,
            selected.verifier.version.clone(),
            selected.encryption.version.clone(),
        );
        verifier.fill(0);
        encryption.fill(0);
        result
    }
}

impl Authority for SelectedAuthority {
    fn check_shell(&self, binding: &CredentialFamilyBinding, origin: &str) -> Result<()> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        ensure!(
            entries
                .iter()
                .any(|entry| &entry.binding == binding && entry.security_origin == origin),
            "credential shell not selected for family"
        );
        Ok(())
    }
    fn prepare(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<ReadyKeys> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        let selected = Self::selected(&entries, binding, management, actor, subject, now)?;
        Ok(ReadyKeys {
            keys: self.lease(selected)?,
            binding: Digest::of(binding)?,
            security_epoch: selected.security_epoch,
            valid_until: selected.grant_until,
            max_active_lineages: selected.max_active_lineages,
        })
    }

    fn validate(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        ready: &ReadyKeys,
        now: i64,
    ) -> Result<()> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        let selected = Self::selected(&entries, binding, management, actor, subject, now)?;
        ensure!(
            ready.binding == Digest::of(binding)?
                && ready.security_epoch == selected.security_epoch
                && ready.keys.verifier_version == selected.verifier.version
                && ready.keys.encryption_version == selected.encryption.version
                && ready.valid_until <= selected.grant_until
                && now < ready.valid_until
                && ready.max_active_lineages <= selected.max_active_lineages,
            "credential readiness changed"
        );
        Ok(())
    }

    fn reveal_epoch(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        now: i64,
    ) -> Result<u64> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        Ok(Self::selected(&entries, binding, management, actor, subject, now)?.security_epoch)
    }

    fn human_keys(
        &self,
        binding: &CredentialFamilyBinding,
        management: &ManagementPolicy,
        actor: &str,
        subject: &str,
        permit: &HumanRevealPermit,
        now: i64,
    ) -> Result<KeyLease> {
        let entries = self
            .entries
            .read()
            .map_err(|_| anyhow::anyhow!("credential admission lock poisoned"))?;
        let selected = Self::selected(&entries, binding, management, actor, subject, now)?;
        ensure!(
            permit.encryption_version() == selected.encryption.version
                && permit.security_epoch() == selected.security_epoch,
            "credential delivery key or epoch retired"
        );
        self.lease(selected)
    }
}
