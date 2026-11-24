//! Fixed external create-only root binding DATA. No native writer, activated
//! root, acknowledgement witness, recovery or source factory exists here.
//! In particular a stored row or an absent row cannot activate/adopt a local
//! orphan, renew an original, retry an uncertain birth or authorize capture.
use super::{HeaderData, ROOT_DOMAIN, RootBindingData};
use crate::security_epoch::{
    kernel::UpdateTime,
    scheduled_backup::{MAX_PAYLOAD, decode_canonical, reservation::single_write_ack_data},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochProvider, EpochStore},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const COLLECTION: &str = "day2_scheduled_backup_roots_v1";
const RECORD_DOMAIN: &str = "day2-scheduled-backup-root-record-v1";

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootRecordData {
    format: u8,
    binding: RootBindingData,
    header: Digest,
    database_uid: String,
}

impl RootRecordData {
    fn new_data(selected: &EpochStore, binding: RootBindingData) -> Result<Self> {
        selected.validate()?;
        ensure!(selected.scope == binding.scope, "backup_root_scope_changed");
        let EpochProvider::FirestoreNativeV1 { database_uid, .. } = &selected.provider;
        let header = Digest::of(&(
            ROOT_DOMAIN,
            HeaderData {
                format: 1,
                binding: binding.clone(),
            },
        ))?;
        let record = Self {
            format: 1,
            binding,
            header,
            database_uid: database_uid.clone(),
        };
        ensure!(
            serde_json::to_vec(&record)?.len() <= MAX_PAYLOAD,
            "backup_root_record_bound"
        );
        Ok(record)
    }

    fn commitment_data(&self) -> Result<Digest> {
        Digest::of(&(RECORD_DOMAIN, self))
    }
}

fn document_data(selected: &EpochStore, binding: &RootBindingData) -> Result<String> {
    selected.validate()?;
    ensure!(selected.scope == binding.scope, "backup_root_scope_changed");
    let EpochProvider::FirestoreNativeV1 {
        project, database, ..
    } = &selected.provider;
    let key = binding.key_data()?;
    Ok(format!(
        "projects/{}/databases/{}/documents/{COLLECTION}/{}",
        project.as_str(),
        database.as_str(),
        &key.as_str()[7..]
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispositionData {
    Fresh,
    May,
    Known,
    Confirming,
    Confirmed,
    Unknown,
}

/// Local one-shot metadata codec only. Genuine creation requires the actual
/// retained pending local creator, current writer and SAME native original.
/// There is no deserialize/reopen/reset operation on this turn. Native callers
/// must durably mark uncertainty before dispatch and never reconstruct from it.
pub(in crate::security_epoch) struct BirthTurn {
    name: String,
    record: RootRecordData,
    disposition: DispositionData,
    // Only the real strict single-write ACK supplies this version. A matching
    // row or caller argument can never manufacture the original creation time.
    known_update: Option<UpdateTime>,
}

impl BirthTurn {
    pub(super) fn new_data(selected: &EpochStore, binding: RootBindingData) -> Result<Self> {
        Ok(Self {
            name: document_data(selected, &binding)?,
            record: RootRecordData::new_data(selected, binding)?,
            disposition: DispositionData::Fresh,
            known_update: None,
        })
    }

    pub(in crate::security_epoch) fn submit_data(&mut self) -> Result<Value> {
        let before = std::mem::replace(&mut self.disposition, DispositionData::Unknown);
        ensure!(before == DispositionData::Fresh, "backup_root_turn_spent");
        let payload = serde_json::to_string(&self.record)?;
        ensure!(payload.len() <= MAX_PAYLOAD, "backup_root_record_bound");
        let write = json!({"writes":[{"update":{"name":self.name,"fields":{
            "root_json":{"stringValue":payload},
            "root_digest":{"stringValue":self.record.commitment_data()?}}},
            "currentDocument":{"exists":false}}]});
        self.disposition = DispositionData::May;
        Ok(write)
    }

    pub(in crate::security_epoch) fn observe_data(
        &mut self,
        status: u16,
        bytes: &[u8],
    ) -> Result<UpdateTime> {
        let before = std::mem::replace(&mut self.disposition, DispositionData::Unknown);
        ensure!(
            before == DispositionData::May,
            "backup_root_ack_without_send"
        );
        let updated = single_write_ack_data(status, bytes)?;
        self.known_update = Some(updated.clone());
        self.disposition = DispositionData::Known;
        // Strict metadata ACK only. Real postchecks, local activation and final
        // consuming settlement have NOT happened and cannot be inferred here.
        Ok(updated)
    }

    /// Fixed one-document, default-strong request DATA. This is not recovery,
    /// a source grant or a new native original. Unknown is set before work.
    pub(in crate::security_epoch) fn begin_confirmation_data(
        &mut self,
        selected: &EpochStore,
    ) -> Result<Value> {
        let before = std::mem::replace(&mut self.disposition, DispositionData::Unknown);
        ensure!(before == DispositionData::Known && self.known_update.is_some(),
            "backup_root_confirmation_requires_known_create");
        ensure!(self.name == document_data(selected, &self.record.binding)?
            && self.record == RootRecordData::new_data(selected, self.record.binding.clone())?,
            "backup_root_confirmation_selection_changed");
        // No mask hides added fields, and no transaction/readTime selector
        // can request an old snapshot or start an unfinished transaction.
        let body = json!({"documents":[self.name]});
        self.disposition = DispositionData::Confirming;
        Ok(body)
    }

    pub(in crate::security_epoch) fn observe_confirmation_data(
        &mut self,
        selected: &EpochStore,
        status: u16,
        bytes: &[u8],
    ) -> Result<()> {
        let before = std::mem::replace(&mut self.disposition, DispositionData::Unknown);
        ensure!(before == DispositionData::Confirming && status == 200
            && bytes.len() <= MAX_PAYLOAD * 2, "backup_root_confirmation_unknown");
        let known = self.known_update.as_ref().context("backup_root_known_version_missing")?;
        let value: Value = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("backup_root_confirmation_encoding"))?;
        let entries = value.as_array().context("backup_root_confirmation_array")?;
        ensure!(entries.len() == 1, "backup_root_confirmation_count");
        let entry = entries[0].as_object().context("backup_root_confirmation_map")?;
        ensure!(entry.len() == 2 && entry.contains_key("found") && entry.contains_key("readTime"),
            "backup_root_confirmation_fields");
        let read: UpdateTime = entry.get("readTime").and_then(Value::as_str)
            .context("backup_root_confirmation_read_time")?.to_owned().try_into()?;
        ensure!(!known.is_strictly_after_data(&read)?, "backup_root_confirmation_before_create");
        compare_existing_data(selected, &self.record.binding, known,
            &serde_json::to_vec(entry.get("found").context("backup_root_confirmation_found")?)?)?;
        self.disposition = DispositionData::Confirmed;
        Ok(())
    }

    pub(in crate::security_epoch) fn require_confirmed_data(&self) -> Result<()> {
        ensure!(self.disposition == DispositionData::Confirmed && self.known_update.is_some(),
            "backup_root_confirmation_incomplete");
        Ok(())
    }

    pub(in crate::security_epoch) fn lose_data(&mut self) {
        self.disposition = DispositionData::Unknown;
    }
}

/// Compare an immutable existing binding only. A match is historical DATA, not
/// birth completion or permission to recreate/activate a missing local root.
fn compare_existing_data(
    selected: &EpochStore,
    binding: &RootBindingData,
    known_update: &UpdateTime,
    bytes: &[u8],
) -> Result<()> {
    ensure!(bytes.len() <= MAX_PAYLOAD * 2, "backup_root_document_bound");
    let expected = RootRecordData::new_data(selected, binding.clone())?;
    let value: Value =
        crate::json::decode(bytes).map_err(|_| anyhow::anyhow!("backup_root_document_encoding"))?;
    let object = value.as_object().context("backup_root_document_map")?;
    ensure!(
        object.len() == 4
            && ["name", "fields", "createTime", "updateTime"]
                .iter()
                .all(|name| object.contains_key(*name)),
        "backup_root_document_fields"
    );
    ensure!(
        object.get("name").and_then(Value::as_str)
            == Some(document_data(selected, binding)?.as_str()),
        "backup_root_document_name"
    );
    let fields = object
        .get("fields")
        .and_then(Value::as_object)
        .context("backup_root_fields_map")?;
    ensure!(
        fields.len() == 2 && fields.contains_key("root_json") && fields.contains_key("root_digest"),
        "backup_root_fields"
    );
    let field = |name: &str| -> Result<&str> {
        let map = fields
            .get(name)
            .and_then(Value::as_object)
            .context("backup_root_field_map")?;
        ensure!(
            map.len() == 1 && map.contains_key("stringValue"),
            "backup_root_field_kind"
        );
        map.get("stringValue")
            .and_then(Value::as_str)
            .context("backup_root_field_text")
    };
    let record: RootRecordData = decode_canonical(field("root_json")?.as_bytes())?;
    ensure!(
        record == expected && field("root_digest")? == record.commitment_data()?.as_str(),
        "backup_root_binding_changed"
    );
    let time = |name: &str| -> Result<UpdateTime> {
        object
            .get(name)
            .and_then(Value::as_str)
            .context("backup_root_timestamp")?
            .to_owned()
            .try_into()
    };
    ensure!(
        time("createTime")? == *known_update && time("updateTime")? == *known_update,
        "backup_root_record_mutated"
    );
    Ok(())
}
