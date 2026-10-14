//! Pure same-database control-slot provider codec. Encoded writes are DATA,
//! never permission to send. No live writer or production authority factory is
//! registered here; native consuming permits must guard every future dispatch.

use super::{
    control_slot::{LogicalCore, Slot, SlotState, Stage},
    kernel::UpdateTime,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochProvider, EpochStore},
};
use serde_json::{Value, json};

pub(super) struct VersionedSlot {
    pub slot: Slot,
    pub version: UpdateTime,
}

pub(super) fn name(selection: &EpochStore, core: &LogicalCore) -> Result<String> {
    core.validate(selection)?;
    let EpochProvider::FirestoreNativeV1 {
        project, database, ..
    } = &selection.provider;
    let authority = core
        .counter
        .bootstrap()
        .authority
        .as_str()
        .strip_prefix("sha256:")
        .context("control_slot_authority_key")?;
    let stage = match core.stage {
        Stage::Create => "create",
        Stage::Complete => "complete",
    };
    Ok(format!(
        "projects/{}/databases/{}/documents/day2_credential_control_v1/{authority}-{stage}",
        project.as_str(),
        database.as_str()
    ))
}

fn document(selection: &EpochStore, slot: &Slot) -> Result<Value> {
    slot.validate(selection)?;
    let payload = serde_json::to_string(slot)?;
    ensure!(payload.len() <= 32_768, "control_slot_payload_bound");
    Ok(json!({"name":name(selection,&slot.logical)?,"fields":{
        "control_json":{"stringValue":payload},"control_digest":{"stringValue":Digest::of(&("day2-control-document-v1",slot))?}}}))
}

pub(super) fn create_data(selection: &EpochStore, slot: &Slot) -> Result<Value> {
    ensure!(
        matches!(slot.state, SlotState::Prepared { .. }),
        "control_slot_accept_prepared_only"
    );
    Ok(json!({"update":document(selection,slot)?,"currentDocument":{"exists":false}}))
}

/// Closed mutable transitions. In particular there is no reset, release,
/// reseed, generic patch, delete or Observed-to-send transition.
pub(super) fn cas_data(
    selection: &EpochStore,
    before: &VersionedSlot,
    after: &Slot,
) -> Result<Value> {
    before.slot.validate(selection)?;
    after.validate(selection)?;
    ensure!(
        after.logical == before.slot.logical,
        "control_slot_immutable_replacement"
    );
    let expected = match (&before.slot.state, &after.state) {
        (
            SlotState::Prepared { .. } | SlotState::Retryable { .. },
            SlotState::MayHaveBeenSent { attempt },
        ) => before
            .slot
            .claim_data(selection, &before.version, attempt.core.clone())?,
        (SlotState::MayHaveBeenSent { .. }, SlotState::Retryable { rearm, .. }) => before
            .slot
            .rearm_data(selection, &before.version, rearm.core.clone())?,
        (
            SlotState::MayHaveBeenSent { .. } | SlotState::Retryable { .. },
            SlotState::Observed {
                receipt,
                settlement,
                ..
            },
        ) => before.slot.settle_data(
            selection,
            &before.version,
            settlement.core.clone(),
            receipt.clone(),
        )?,
        _ => anyhow::bail!("control_slot_cas_transition_refused"),
    };
    ensure!(*after == expected, "control_slot_cas_after_mismatch");
    Ok(json!({"update":document(selection,after)?,"currentDocument":{"updateTime":before.version}}))
}

pub(super) fn decode(
    selection: &EpochStore,
    expected: &LogicalCore,
    bytes: &[u8],
) -> Result<VersionedSlot> {
    ensure!(bytes.len() <= 65_536, "control_slot_reply_bound");
    let value: Value = crate::json::decode(bytes)?;
    let object = value.as_object().context("control_slot_document_map")?;
    ensure!(
        object.len() == 4
            && object
                .keys()
                .all(|key| ["name", "fields", "createTime", "updateTime"].contains(&key.as_str())),
        "control_slot_document_fields"
    );
    ensure!(
        value.get("name").and_then(Value::as_str) == Some(name(selection, expected)?.as_str()),
        "control_slot_document_name"
    );
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .context("control_slot_document_fields")?;
    ensure!(
        fields.len() == 2
            && fields.contains_key("control_json")
            && fields.contains_key("control_digest"),
        "control_slot_document_fields"
    );
    let text = |key: &str| -> Result<&str> {
        let field = fields
            .get(key)
            .and_then(Value::as_object)
            .context("control_slot_field_shape")?;
        ensure!(field.len() == 1, "control_slot_field_shape");
        field
            .get("stringValue")
            .and_then(Value::as_str)
            .context("control_slot_field_shape")
    };
    let payload = text("control_json")?;
    ensure!(payload.len() <= 32_768, "control_slot_payload_bound");
    let slot: Slot = crate::json::decode(payload.as_bytes())?;
    // Requiring exact canonical bytes also refuses sequence-shaped records,
    // missing fields defaulted by Serde and noncanonical numeric/string forms.
    ensure!(
        serde_json::to_string(&slot)? == payload
            && slot.logical == *expected
            && Digest::of(&("day2-control-document-v1", &slot))?.as_str()
                == text("control_digest")?,
        "control_slot_payload_or_core_mismatch"
    );
    slot.validate(selection)?;
    let version: UpdateTime = value
        .get("updateTime")
        .and_then(Value::as_str)
        .context("control_slot_provider_version")?
        .to_owned()
        .try_into()?;
    let created: UpdateTime = value
        .get("createTime")
        .and_then(Value::as_str)
        .context("control_slot_provider_version")?
        .to_owned()
        .try_into()?;
    let created = time::OffsetDateTime::parse(
        &String::from(created),
        &time::format_description::well_known::Rfc3339,
    )?;
    let updated = time::OffsetDateTime::parse(
        &String::from(version.clone()),
        &time::format_description::well_known::Rfc3339,
    )?;
    ensure!(created <= updated, "control_slot_document_time_order");
    Ok(VersionedSlot { slot, version })
}
