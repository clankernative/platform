//! Scheduled-backup intent and reservation DATA only. No native requester,
//! source permission, provider dispatch or owner constructor is supplied here.
//! The accepting driver must join its actual authenticated requester, original
//! and durable uncertainty gate before using a create-only reservation.
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{AuthorityScope, EpochStore, SecurityEpoch, ServiceAccountUid},
};
use serde::{Deserialize, Serialize};

mod journal;
pub(in crate::security_epoch) mod requester;
mod reservation;

const MAX_PAYLOAD: usize = 16_384;
const SLOT_DOMAIN: &str = "day2-scheduled-backup-slot-v1";
const INTENT_DOMAIN: &str = "day2-scheduled-backup-intent-v1";

/// This fixed GKE profile admits canonical UUID workload identities. It is not
/// a claim that all Kubernetes implementations use UUID-shaped UIDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(in crate::security_epoch) struct WorkloadUid(String);

impl TryFrom<String> for WorkloadUid {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        ensure!(
            value.len() == 36
                && value.bytes().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                }),
            "backup_request_workload_uid"
        );
        Ok(Self(value))
    }
}

impl From<WorkloadUid> for String {
    fn from(value: WorkloadUid) -> Self {
        value.0
    }
}

/// A canonical scheduler-provided slot, not a client clock or native deadline.
/// Its trusted provenance is a separate mandatory issuer/admission obligation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(in crate::security_epoch) struct ScheduledSlot(String);

impl TryFrom<String> for ScheduledSlot {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let format = &time::format_description::well_known::Rfc3339;
        let parsed = time::OffsetDateTime::parse(&value, format)
            .map_err(|_| anyhow::anyhow!("backup_request_scheduled_slot"))?;
        ensure!(
            value.len() == 20
                && value.ends_with('Z')
                && parsed.nanosecond() == 0
                && parsed
                    .format(format)
                    .map_err(|_| anyhow::anyhow!("backup_request_scheduled_slot"))?
                    == value,
            "backup_request_scheduled_slot"
        );
        Ok(Self(value))
    }
}

impl From<ScheduledSlot> for String {
    fn from(value: ScheduledSlot) -> Self {
        value.0
    }
}

/// Stable across policy/admission generation, Job replacement, source/key
/// rotation, operation, transport nonce and destination changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    scope: AuthorityScope,
    cron_job_uid: WorkloadUid,
    scheduled_at: ScheduledSlot,
}

impl Slot {
    fn key_data(&self) -> Result<Digest> {
        Digest::of(&(
            SLOT_DOMAIN,
            self.scope.installation.as_str(),
            self.scope.environment.as_str(),
            self.scope.app.as_str(),
            self.cron_job_uid.0.as_str(),
            self.scheduled_at.0.as_str(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requester {
    cluster: Digest,
    node: Digest,
    namespace_uid: WorkloadUid,
    job_uid: WorkloadUid,
    pod_uid: WorkloadUid,
    ksa_uid: WorkloadUid,
    uploader_uid: ServiceAccountUid,
    image: Digest,
    executable: Digest,
    process: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    store: Digest,
    authority: Digest,
    epoch: SecurityEpoch,
    artifact: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transport {
    controller: Digest,
    connection: Digest,
    requester_nonce: Digest,
    controller_nonce: Digest,
    original: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    bucket: String,
    prefix: String,
    readers: Digest,
}

impl Destination {
    fn validate_data(&self, slot: &Slot) -> Result<()> {
        // A deliberately narrow configured bucket profile, not an endpoint or
        // permission selected by the incoming requester. Actual policy equality
        // and create-only uploader identity are separate accepting obligations.
        ensure!(
            (3..=63).contains(&self.bucket.len())
                && self
                    .bucket
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && self.bucket.as_bytes()[0].is_ascii_alphanumeric()
                && self.bucket.as_bytes()[self.bucket.len() - 1].is_ascii_alphanumeric(),
            "backup_request_bucket"
        );
        ensure!(self.prefix.len() <= 128, "backup_request_prefix_bound");
        let stamp = self
            .prefix
            .strip_prefix(slot.scope.app.as_str())
            .and_then(|p| p.strip_prefix('/'))
            .context("backup_request_prefix")?;
        // Preserve the existing <app>/<UTC run stamp> convention. The exact
        // value must be fixed in, and compared with, the admitted intent; the
        // codec neither chooses a fresh prefix nor changes it after collision.
        ensure!(
            stamp.len() == 16
                && stamp.as_bytes()[8] == b'T'
                && stamp.as_bytes()[15] == b'Z'
                && stamp
                    .bytes()
                    .enumerate()
                    .all(|(i, b)| matches!(i, 8 | 15) || b.is_ascii_digit()),
            "backup_request_prefix"
        );
        let expanded = format!(
            "{}-{}-{}T{}:{}:{}Z",
            &stamp[0..4],
            &stamp[4..6],
            &stamp[6..8],
            &stamp[9..11],
            &stamp[11..13],
            &stamp[13..15]
        );
        let _: ScheduledSlot = expanded.try_into()?;
        Ok(())
    }
}

/// Complete comparison DATA. These digests never replace the live facts they
/// commit to, and decoding this value cannot reconstruct a source/role owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    slot: Slot,
    policy_generation: Digest,
    admission_generation: Digest,
    cron_job_spec: Digest,
    requester: Requester,
    source: Source,
    transport: Transport,
    operation: Digest,
    destination: Destination,
}

impl Intent {
    fn validate_data(&self) -> Result<()> {
        self.destination.validate_data(&self.slot)?;
        ensure!(
            self.transport.requester_nonce != self.transport.controller_nonce,
            "backup_request_reflected_nonce"
        );
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_PAYLOAD,
            "backup_request_payload_bound"
        );
        Ok(())
    }

    fn decode_data(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode_canonical(bytes)?;
        value.validate_data()?;
        Ok(value)
    }

    fn commitment_data(&self) -> Result<Digest> {
        self.validate_data()?;
        Digest::of(&(INTENT_DOMAIN, self))
    }

    fn require_selection_data(&self, selected: &EpochStore) -> Result<()> {
        selected.validate()?;
        self.validate_data()?;
        ensure!(
            self.slot.scope == selected.scope && self.source.store == Digest::of(selected)?,
            "backup_request_store_selection"
        );
        Ok(())
    }
}

fn decode_canonical<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() <= MAX_PAYLOAD, "backup_request_payload_bound");
    let value: T = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("backup_request_payload_encoding"))?;
    ensure!(
        serde_json::to_vec(&value)? == bytes,
        "backup_request_noncanonical_payload"
    );
    Ok(value)
}
