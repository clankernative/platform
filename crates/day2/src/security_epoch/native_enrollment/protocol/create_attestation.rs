//! Fallback CREATE comparison DATA only. No authenticated control-plane tap,
//! journal writer, clock, native owner or ProtectedScheduledCreate is supplied.
//! A valid signature cannot fill in provenance absent from the actual input.
use super::{EnrollmentPolicy, IssuerCertificate, verify};
use crate::security_epoch::scheduled_backup::{ScheduledSlot, WorkloadUid};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

const PURPOSE: &str = "scheduled-backup-create-comparison-v1";
const MAX_DATA_BYTES: usize = 8192;

#[cfg(test)]
mod tests;

/// Reviewed configuration selection, never a packet-selected trust root.
/// Its actual authenticated source/channel and current registry postchecks are
/// obligations of the still-unimplemented, closed native supplier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TapSelectionData {
    pub registry: Digest,
    pub profile: Digest,
    pub tap_code: Digest,
    pub channel_peer_key: Digest,
    pub key_version: Digest,
    pub feed_epoch: Digest,
    pub cluster_incarnation: Digest,
}

/// Exact current requester joins, derived independently by the real issuer.
/// UID and slot codecs reuse the existing canonical scheduled-backup profile.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateBindingData {
    pub namespace_uid: WorkloadUid,
    pub cron_job_uid: WorkloadUid,
    pub service_account_uid: WorkloadUid,
    pub job_uid: WorkloadUid,
    pub pod_uid: WorkloadUid,
    pub slot: ScheduledSlot,
    pub cron_spec: Digest,
    pub job_spec: Digest,
    pub pod_spec: Digest,
    pub admission: Digest,
    pub policy: Digest,
    /// Complete saved intent/request/controller/connection/original/nonces.
    /// This commitment is not permission or a new original.
    pub request: Digest,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CreateStageData {
    RequestReceived,
    ResponseStarted,
    ResponseComplete,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ImpersonationData {
    Absent,
    Present,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CreateResourceData {
    BatchV1Job,
    CoreV1Pod,
}

/// The real tap must check the actual upstream verb before constructing this
/// closed projection. A typed value alone is not proof it observed a CREATE.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CreateVerbData {
    Create,
}

/// These fields must eventually be produced by a qualified API-server tap.
/// The explicit completeness/absence values here are assertions in signed
/// DATA, NOT authenticated origin evidence or a constructor for that source.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateEventData {
    pub verb: CreateVerbData,
    pub resource: CreateResourceData,
    pub audit_id: Digest,
    /// Strict durable arrival order only; not upstream causality/completeness.
    pub journal_sequence: u64,
    pub uid: WorkloadUid,
    pub owner_uid: WorkloadUid,
    pub spec: Digest,
    pub original_subject: Digest,
    pub effective_subject: Digest,
    pub impersonation: ImpersonationData,
    pub identity_complete: bool,
    pub spec_complete: bool,
    pub stage: CreateStageData,
    pub status: u16,
    pub dry_run: bool,
}

impl CreateEventData {
    fn require_data(
        &self,
        resource: CreateResourceData,
        uid: &WorkloadUid,
        owner: &WorkloadUid,
        spec: &Digest,
        subject: &str,
    ) -> Result<()> {
        let subject = Digest::of(&("day2-create-original-subject-v1", subject))?;
        ensure!(
            self.resource == resource
                && self.journal_sequence > 0
                && self.uid == *uid
                && self.owner_uid == *owner
                && self.spec == *spec
                && self.original_subject == subject
                && self.effective_subject == subject
                && self.impersonation == ImpersonationData::Absent
                && self.identity_complete
                && self.spec_complete
                && self.stage == CreateStageData::ResponseComplete
                && self.status == 201
                && !self.dry_run,
            "backup_create_event_data"
        );
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateAttestationData {
    pub tap: TapSelectionData,
    pub issuer: Digest,
    pub challenge: Digest,
    pub binding: CreateBindingData,
    pub job: CreateEventData,
    pub pod: CreateEventData,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedCreateAttestationData {
    pub data: CreateAttestationData,
    pub signature: String,
}

impl SignedCreateAttestationData {
    /// Pure comparison. The caller must independently select these expected
    /// facts from the SAME retained issuer cohort and actual requester/action.
    /// This returns no witness, source owner, clock, admission or upload grant.
    pub(super) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        held_issuer: &IssuerCertificate,
        expected_tap: &TapSelectionData,
        expected_binding: &CreateBindingData,
        expected_challenge: &Digest,
    ) -> Result<()> {
        held_issuer.verify(policy)?;
        let selected = policy
            .scheduled_backup
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("backup_requester_disabled"))?;
        selected.validate_data()?;
        ensure!(
            self.data.tap == *expected_tap
                && self.data.tap.cluster_incarnation == selected.cluster
                && self.data.issuer == held_issuer.digest()?
                && self.data.challenge == *expected_challenge
                && self.data.binding == *expected_binding
                && self.data.binding.policy == policy.digest()?
                && self.data.binding.namespace_uid
                    == WorkloadUid::try_from(selected.namespace.uid.clone())?
                && self.data.binding.cron_job_uid
                    == WorkloadUid::try_from(selected.cron_job.uid.clone())?
                && self.data.binding.service_account_uid
                    == WorkloadUid::try_from(selected.service_account.uid.clone())?
                && self.data.binding.cron_spec == selected.cron_spec
                && self.data.binding.admission == selected.admission_generation_data()?,
            "backup_create_attestation_data_changed"
        );
        self.data.job.require_data(
            CreateResourceData::BatchV1Job,
            &self.data.binding.job_uid,
            &self.data.binding.cron_job_uid,
            &self.data.binding.job_spec,
            &selected.cron_controller,
        )?;
        self.data.pod.require_data(
            CreateResourceData::CoreV1Pod,
            &self.data.binding.pod_uid,
            &self.data.binding.job_uid,
            &self.data.binding.pod_spec,
            &selected.job_controller,
        )?;
        ensure!(
            self.data.job.audit_id != self.data.pod.audit_id
                && self.data.job.journal_sequence < self.data.pod.journal_sequence,
            "backup_create_attestation_pair"
        );
        verify(
            &held_issuer.data.public_key,
            PURPOSE,
            &self.data,
            &self.signature,
        )
    }

    pub(super) fn encode_data(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= MAX_DATA_BYTES, "backup_create_data_bound");
        Ok(bytes)
    }

    pub(super) fn decode_data(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_DATA_BYTES, "backup_create_data_bound");
        let value: Self = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("backup_create_data_encoding"))?;
        // Pin map-only records and canonical bytes; duplicate-preserving decode
        // happens first. No provider field/error string survives a refusal.
        ensure!(value.encode_data()? == bytes, "backup_create_data_encoding");
        Ok(value)
    }
}
