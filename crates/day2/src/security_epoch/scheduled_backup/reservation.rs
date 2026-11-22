//! One fixed create-only attempt document and a non-resumable local turn.
//! All results are DATA. No transport/provider/source owner is created here.
use super::{Intent, MAX_PAYLOAD, Slot, decode_canonical};
use crate::security_epoch::kernel::UpdateTime;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochProvider, EpochStore},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const RECORD_DOMAIN: &str = "day2-scheduled-backup-attempt-record-v1";
const COLLECTION: &str = "day2_scheduled_backup_attempts_v1";
const MAX_REPLY: usize = 4_096;

#[cfg(test)]
mod tests;

/// Immutable spent-attempt record, not a captured archive or grant. There is
/// intentionally no status field, CAS, reset, delete or retry transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptRecord {
    format: u8,
    intent: Intent,
    commitment: Digest,
}

impl AttemptRecord {
    fn new_data(intent: Intent) -> Result<Self> {
        let commitment = intent.commitment_data()?;
        Ok(Self {
            format: 1,
            intent,
            commitment,
        })
    }

    fn decode_data(bytes: &[u8], expected: &Slot) -> Result<Self> {
        let value: Self = decode_canonical(bytes)?;
        ensure!(
            value.format == 1
                && value.intent.slot == *expected
                && value.commitment == value.intent.commitment_data()?,
            "backup_attempt_record_changed"
        );
        Ok(value)
    }
}

fn document_name_data(selected: &EpochStore, slot: &Slot) -> Result<String> {
    selected.validate()?;
    ensure!(slot.scope == selected.scope, "backup_attempt_scope_changed");
    let EpochProvider::FirestoreNativeV1 {
        project, database, ..
    } = &selected.provider;
    let key = slot.key_data()?;
    Ok(format!(
        "projects/{}/databases/{}/documents/{COLLECTION}/{}",
        project.as_str(),
        database.as_str(),
        &key.as_str()[7..]
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DispositionData {
    Fresh,
    MayHaveBeenSent,
    Created,
    Unknown,
}

/// A local single-use codec turn, not a durable gate. The native driver must
/// retain its genuine authenticated action and permanent uncertainty discipline.
/// In particular an absent remote row after an ambiguous create is NOT proof
/// that a new turn may be authorized. No rehydration/resume API exists here.
struct CreateTurn {
    name: String,
    record: AttemptRecord,
    disposition: DispositionData,
}

impl CreateTurn {
    fn new_data(selected: &EpochStore, intent: Intent) -> Result<Self> {
        intent.require_selection_data(selected)?;
        let name = document_name_data(selected, &intent.slot)?;
        let record = AttemptRecord::new_data(intent)?;
        ensure!(
            serde_json::to_vec(&record)?.len() <= MAX_PAYLOAD,
            "backup_attempt_payload_bound"
        );
        Ok(Self {
            name,
            record,
            disposition: DispositionData::Fresh,
        })
    }

    /// Encodes once; the actual writer must independently authorize and guard
    /// dispatch. No key/generation/recipient can be replaced after this point.
    fn submit_data(&mut self) -> Result<Value> {
        let before = std::mem::replace(&mut self.disposition, DispositionData::Unknown);
        ensure!(before == DispositionData::Fresh, "backup_attempt_spent");
        let payload = serde_json::to_string(&self.record)?;
        ensure!(payload.len() <= MAX_PAYLOAD, "backup_attempt_payload_bound");
        let write = json!({"writes":[{
            "update":{"name":self.name,"fields":{
                "attempt_json":{"stringValue":payload},
                "attempt_digest":{"stringValue":Digest::of(&(RECORD_DOMAIN,&self.record))?}
            }},
            "currentDocument":{"exists":false}
        }]});
        self.disposition = DispositionData::MayHaveBeenSent;
        Ok(write)
    }

    /// An acknowledgement is comparison DATA, never source permission. Unknown,
    /// malformed, non-success or duplicate outcomes permanently poison this turn.
    fn observe_commit_data(&mut self, status: u16, bytes: &[u8]) -> Result<UpdateTime> {
        let before = std::mem::replace(&mut self.disposition, DispositionData::Unknown);
        ensure!(
            before == DispositionData::MayHaveBeenSent,
            "backup_attempt_reply_without_send"
        );
        ensure!(
            status == 200 && bytes.len() <= MAX_REPLY,
            "backup_attempt_commit_unknown"
        );
        let value: Value = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("backup_attempt_commit_encoding"))?;
        let object = value.as_object().context("backup_attempt_commit_map")?;
        ensure!(
            object.len() == 2
                && object.contains_key("writeResults")
                && object.contains_key("commitTime"),
            "backup_attempt_commit_fields"
        );
        let results = object
            .get("writeResults")
            .and_then(Value::as_array)
            .context("backup_attempt_commit_results")?;
        ensure!(results.len() == 1, "backup_attempt_commit_count");
        let result = results[0]
            .as_object()
            .context("backup_attempt_commit_result_map")?;
        ensure!(
            result.len() == 1 && result.contains_key("updateTime"),
            "backup_attempt_commit_result_fields"
        );
        let updated: UpdateTime = result
            .get("updateTime")
            .and_then(Value::as_str)
            .context("backup_attempt_commit_time")?
            .to_owned()
            .try_into()?;
        let committed: UpdateTime = object
            .get("commitTime")
            .and_then(Value::as_str)
            .context("backup_attempt_commit_time")?
            .to_owned()
            .try_into()?;
        ensure!(
            !updated.is_strictly_after_data(&committed)?,
            "backup_attempt_commit_time_order"
        );
        self.disposition = DispositionData::Created;
        Ok(updated)
    }

    fn lose_result_data(&mut self) {
        self.disposition = DispositionData::Unknown;
    }
}

/// A stored row can only establish that the slot is already spent. It cannot
/// recreate a local turn, prove a new create or authorize a capture.
fn decode_spent_document_data(
    selected: &EpochStore,
    slot: &Slot,
    bytes: &[u8],
) -> Result<AttemptRecord> {
    ensure!(
        bytes.len() <= MAX_PAYLOAD * 2,
        "backup_attempt_document_bound"
    );
    let value: Value = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("backup_attempt_document_encoding"))?;
    let object = value.as_object().context("backup_attempt_document_map")?;
    ensure!(
        object.len() == 4
            && ["name", "fields", "createTime", "updateTime"]
                .iter()
                .all(|k| object.contains_key(*k)),
        "backup_attempt_document_fields"
    );
    ensure!(
        object.get("name").and_then(Value::as_str)
            == Some(document_name_data(selected, slot)?.as_str()),
        "backup_attempt_document_name"
    );
    let fields = object
        .get("fields")
        .and_then(Value::as_object)
        .context("backup_attempt_document_fields")?;
    ensure!(
        fields.len() == 2
            && fields.contains_key("attempt_json")
            && fields.contains_key("attempt_digest"),
        "backup_attempt_document_fields"
    );
    let text = |key: &str| -> Result<&str> {
        let field = fields
            .get(key)
            .and_then(Value::as_object)
            .context("backup_attempt_document_field")?;
        ensure!(field.len() == 1, "backup_attempt_document_field");
        field
            .get("stringValue")
            .and_then(Value::as_str)
            .context("backup_attempt_document_string")
    };
    let record = AttemptRecord::decode_data(text("attempt_json")?.as_bytes(), slot)?;
    ensure!(
        text("attempt_digest")? == Digest::of(&(RECORD_DOMAIN, &record))?.as_str(),
        "backup_attempt_document_commitment"
    );
    let version = |key: &str| -> Result<UpdateTime> {
        object
            .get(key)
            .and_then(Value::as_str)
            .context("backup_attempt_document_time")?
            .to_owned()
            .try_into()
    };
    ensure!(
        !version("createTime")?.is_strictly_after_data(&version("updateTime")?)?,
        "backup_attempt_document_time_order"
    );
    Ok(record)
}
