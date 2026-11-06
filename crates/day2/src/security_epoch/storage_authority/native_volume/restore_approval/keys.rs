//! Exact archive-key acquisition under the actual executor. No manifest,
//! decoded reply or fixture clock constructs native availability.
use super::{NativeAcquisition, NativeApprovalSource};
use crate::{
    artifact::{SecurityKeyPurpose, SecurityKeySelection},
    oauth::approval_keys::{GcpSecretVersion, decode_secret_access_response},
    security_epoch::{
        bootstrap::ExecutionSourceLoan,
        kernel::restore::{ExactKey, Intent, KeyPurpose},
        restore_approval::signed::SignedApprovalRecord,
    },
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, SecretProvider};
use reqwest::{blocking::Client, header::HeaderValue};
use std::{io::Read, time::Duration};
use zeroize::Zeroizing;

const ORIGIN: &str = "https://secretmanager.googleapis.com";
const MAX_REPLY: usize = 4096;

/// Real retained secret material, not a list of desired references. Only the
/// actual native source below can create this owner; no key/header getter or
/// serialization exists. Its clock shares the parent's original refusal.
pub(in crate::security_epoch) struct HistoricalKeyAvailability {
    intent: Intent,
    request: Digest,
    operation: Digest,
    material: Vec<HeldKey>,
    original: NativeAcquisition,
}

struct HeldKey {
    selected: ExactKey,
    material: Zeroizing<Vec<u8>>,
}

struct SelectedKey {
    archive: ExactKey,
    provider: GcpSecretVersion,
}

fn purpose_matches(archive: &KeyPurpose, current: SecurityKeyPurpose) -> bool {
    matches!(
        (archive, current),
        (KeyPurpose::CustodyEncryption, SecurityKeyPurpose::CredentialEncryption
            | SecurityKeyPurpose::OauthCustodyEncryption)
            | (KeyPurpose::CustodyVerifier, SecurityKeyPurpose::CredentialVerifier
                | SecurityKeyPurpose::OauthCustodyVerifier)
            | (KeyPurpose::ShellAttestation, SecurityKeyPurpose::CredentialShellAttestation
                | SecurityKeyPurpose::OauthShellAttestation)
    )
}

// Pure resolution DATA. Archive strings cannot supply a project, secret name
// or alias. Each requirement must resolve to one exact admitted resource.
fn resolve(required: &[ExactKey], admitted: &[SecurityKeySelection]) -> Result<Vec<SelectedKey>> {
    ensure!((1..=32).contains(&required.len()), "restore_keys_manifest_bound");
    let mut result = Vec::new();
    let mut resources = std::collections::BTreeSet::new();
    let mut previous = None;
    for key in required {
        let identity = (&key.purpose, key.binding.id.as_str(), key.binding.revision.as_str(), key.version.as_str());
        ensure!(previous.is_none_or(|before| before < identity), "restore_keys_manifest_order");
        previous = Some(identity);
        let mut found = None;
        for selected in admitted {
            if selected.binding != key.binding || !purpose_matches(&key.purpose, selected.purpose) {
                continue;
            }
            let SecretProvider::GcpVersion { project_number, secret, version } = &selected.provider;
            if key.version != version.to_string() { continue; }
            let candidate = GcpSecretVersion {
                project_number: project_number.get(),
                secret: secret.as_str().to_owned(),
                version: version.get(),
            };
            candidate.validate()?;
            // The same physical key may be selected by several namespaces.
            // Conflicting resources for an archive reference are ambiguous.
            ensure!(found.as_ref().is_none_or(|before| before == &candidate), "restore_keys_ambiguous_resource");
            found = Some(candidate);
        }
        let provider = found.context("restore_keys_version_not_admitted")?;
        ensure!(resources.insert(provider.resource_name()), "restore_keys_resource_reused");
        result.push(SelectedKey { archive: key.clone(), provider });
    }
    Ok(result)
}

impl HistoricalKeyAvailability {
    pub(in crate::security_epoch) fn require(
        &mut self,
        intent: &Intent,
        record: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(&self.intent == intent, "restore_keys_intent_substituted");
            self.check_retained(record, operation)
        })();
        if requested.is_err() { self.original.refuse(); }
        requested
    }

    /// SQL-safe retained-material/original checks only. Actual current registry,
    /// file/peer/fence checks remain the retaining parent's responsibility.
    pub(in crate::security_epoch) fn check_retained(
        &mut self,
        record: &SignedApprovalRecord,
        operation: &Digest,
    ) -> Result<()> {
        let requested = (|| {
            self.original.remaining()?;
            ensure!(self.request == record.statement.request.commitment()?
                && &self.operation == operation
                && self.intent.operation == *operation
                && self.intent.archive.full_archive_digest == record.statement.request.full_archive_digest
                && self.material.len() == self.intent.archive.required_keys.len()
                && !self.material.is_empty()
                && self.material.iter().zip(&self.intent.archive.required_keys)
                    .all(|(held, required)| held.selected == *required && held.material.len() == 32),
                "restore_keys_retained_material_changed");
            self.original.remaining()?;
            Ok(())
        })();
        if requested.is_err() { self.original.refuse(); }
        requested
    }
}

impl Drop for HistoricalKeyAvailability {
    fn drop(&mut self) { self.original.refuse(); }
}

impl NativeApprovalSource {
    pub(in crate::security_epoch) fn retain_historical_keys(
        &mut self,
        owner: &mut ExecutionSourceLoan<'_, '_, '_, '_>,
        intent: &Intent,
    ) -> Result<HistoricalKeyAvailability> {
        let requested = (|| {
            ensure!(!self.historical_keys_attempted, "restore_keys_attempt_spent");
            self.historical_keys_attempted = true;
            owner.check(self)?;
            let selected = owner.historical_key_data(&self.store, &self.policy, intent);
            let checked = owner.check(self);
            let admitted = selected?;
            checked?;
            let selection = resolve(&intent.archive.required_keys, &admitted)?;
            let minted = crate::security_epoch::CredentialMaterial::mint_restore_key_reader(
                &self.material.source,
                &self.policy.controller.google_service_account,
                &self.material.http,
                &mut self.original,
            );
            let checked = owner.check(self);
            let credential = minted?;
            checked?;
            // narrow preserves the original origin/observation and takes the
            // minimum of the existing deadline; MAX cannot extend it.
            let original = self.original.narrow(self.store.max_lease_seconds, Duration::MAX)?;
            let http = KeyHttp::new()?;
            let mut attempt = KeyAttempt {
                context: KeyContext::Native { owner: &mut *owner, source: &mut *self, credential },
                complete: false,
            };
            let material = http.read_all(&selection, &mut attempt.context)?;
            attempt.context.check()?;
            let mut keys = HistoricalKeyAvailability {
                intent: intent.clone(),
                request: attempt.context.request_commitment_data()?,
                operation: intent.operation.clone(),
                material,
                original,
            };
            // One final actual-owner check is required before availability can
            // be installed. Failure drops material and poisons the same clock.
            attempt.context.check()?;
            keys.original.remaining()?;
            attempt.complete = true;
            Ok(keys)
        })();
        if requested.is_err() {
            self.refuse();
            owner.refuse();
        }
        requested
    }
}

enum KeyContext<'borrow, 'fields, 'metadata, 'storage, 'role> {
    Native {
        owner: &'borrow mut ExecutionSourceLoan<'fields, 'metadata, 'storage, 'role>,
        source: &'borrow mut NativeApprovalSource,
        credential: crate::security_epoch::CredentialMaterial,
    },
    #[cfg(test)]
    Fixture { authorization: HeaderValue, fail_at: Option<usize>, checks: usize, original: &'borrow mut NativeAcquisition },
}

impl KeyContext<'_, '_, '_, '_, '_> {
    fn check(&mut self) -> Result<Duration> {
        match self {
            Self::Native { owner, source, .. } => { owner.check(source)?; source.original.remaining() }
            #[cfg(test)]
            Self::Fixture { original, checks, fail_at, .. } => {
                let at = *checks;
                *checks += 1;
                if *fail_at == Some(at) { original.refuse(); }
                original.remaining()
            },
        }
    }

    fn request_commitment_data(&self) -> Result<Digest> {
        match self {
            Self::Native { owner, .. } => owner.request_commitment_data(),
            #[cfg(test)]
            Self::Fixture { .. } => anyhow::bail!("restore_keys_native_owner_required"),
        }
    }

    fn authorization(&self) -> Result<HeaderValue> {
        match self {
            Self::Native { credential, .. } => credential.authorization(),
            #[cfg(test)]
            Self::Fixture { authorization, .. } => Ok(authorization.clone()),
        }
    }

    fn refuse(&mut self) {
        match self {
            Self::Native { owner, source, .. } => { owner.refuse(); source.refuse(); }
            #[cfg(test)]
            Self::Fixture { original, .. } => original.refuse(),
        }
    }
}

struct KeyAttempt<'borrow, 'fields, 'metadata, 'storage, 'role> {
    context: KeyContext<'borrow, 'fields, 'metadata, 'storage, 'role>,
    complete: bool,
}

impl Drop for KeyAttempt<'_, '_, '_, '_, '_> {
    fn drop(&mut self) { if !self.complete { self.context.refuse(); } }
}

struct KeyHttp {
    client: Client,
    #[cfg(test)]
    fixture_origin: Option<String>,
}

impl KeyHttp {
    fn new() -> Result<Self> {
        Ok(Self {
            client: Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never()).build()?,
            #[cfg(test)]
            fixture_origin: None,
        })
    }

    fn read_all(&self, selected: &[SelectedKey], context: &mut KeyContext<'_, '_, '_, '_, '_>) -> Result<Vec<HeldKey>> {
        let requested = (|| {
            ensure!((1..=32).contains(&selected.len()), "restore_keys_manifest_bound");
            let mut result = Vec::new();
            for key in selected {
                let material = self.read(&key.provider, context)?;
                ensure!(material.len() == 32, "restore_keys_material_shape");
                result.push(HeldKey { selected: key.archive.clone(), material });
            }
            context.check()?;
            Ok(result)
        })();
        if requested.is_err() { context.refuse(); }
        requested
    }

    fn read(&self, selected: &GcpSecretVersion, context: &mut KeyContext<'_, '_, '_, '_, '_>) -> Result<Zeroizing<Vec<u8>>> {
        let origin = ORIGIN;
        #[cfg(test)]
        let origin = self.fixture_origin.as_deref().unwrap_or(origin);
        context.check()?;
        let mut authorization = context.authorization()?;
        authorization.set_sensitive(true);
        let request = self.client.get(format!("{origin}/v1/{}:access", selected.resource_name()))
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(context.check()?);
        let sent = request.send().map_err(|_| anyhow::anyhow!("restore_keys_transport"));
        let checked = context.check();
        let response = sent?;
        checked?;
        ensure!(response.status() == reqwest::StatusCode::OK, "restore_keys_unavailable");
        ensure!(response.content_length().is_none_or(|n| n <= MAX_REPLY as u64), "restore_keys_reply_bound");
        let mut bytes = Zeroizing::new(Vec::new());
        let read = response.take((MAX_REPLY + 1) as u64).read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("restore_keys_transport"));
        let checked = context.check();
        read?;
        checked?;
        ensure!(bytes.len() <= MAX_REPLY, "restore_keys_reply_bound");
        decode_secret_access_response(selected, &bytes).map(Zeroizing::new)
    }
}

#[cfg(test)]
mod tests;
