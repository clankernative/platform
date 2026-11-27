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
}

impl BirthTurn {
    pub(super) fn new_data(selected: &EpochStore, binding: RootBindingData) -> Result<Self> {
        Ok(Self {
            name: document_data(selected, &binding)?,
            record: RootRecordData::new_data(selected, binding)?,
            disposition: DispositionData::Fresh,
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
        self.disposition = DispositionData::Known;
        // Strict metadata ACK only. Real postchecks, local activation and final
        // consuming settlement have NOT happened and cannot be inferred here.
        Ok(updated)
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
        time("createTime")? == time("updateTime")?,
        "backup_root_record_mutated"
    );
    Ok(())
}
