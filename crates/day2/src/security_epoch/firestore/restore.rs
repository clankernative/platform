//! Exact restore provider messages. These are bounded DATA codecs, not an
//! approval verifier, native dispatch permit, retry policy or consumed owner.
//! The future native sender must retain both genuine approval and storage owners.
use super::{Entry, Names as InitialNames, decode_snapshot, encode_fields};
use crate::security_epoch::{
    journal::snapshot_digest,
    kernel::{
        Snapshot, UpdateTime, Versioned, advance,
        restore::{self, approval_use},
    },
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeSet, marker::PhantomData, rc::Rc};

const MAX_RECORD_BYTES: usize = 32_768;

/// Names and full original-plan commitment, never caller-selected paths.
pub(in crate::security_epoch) struct Names {
    selection: EpochStore,
    initial: InitialNames,
    advance: String,
    reservation: String,
    grant: String,
    plan: Digest,
}

fn plan_digest(plan: &approval_use::Plan) -> Result<Digest> {
    Digest::of(&(
        "day2-restore-provider-plan-v1",
        &plan.reservation.receipt,
        &plan.approval_use,
        snapshot_digest(&plan.reservation.before)?,
    ))
}

impl Names {
    pub(in crate::security_epoch) fn new(
        selection: &EpochStore,
        plan: &approval_use::Plan,
    ) -> Result<Self> {
        let selectors = plan.selectors(selection)?;
        let initial =
            InitialNames::new(selection, &selectors.bootstrap, Some(&selectors.activation))?;
        let key = |value: &Digest| value.as_str()[7..].to_owned();
        let names = Self {
            selection: selection.clone(),
            advance: format!("{}/operations/{}", initial.root, key(&selectors.advance)),
            reservation: format!(
                "{}/restore_reservations/{}",
                initial.root,
                key(&selectors.operation)
            ),
            grant: format!("{}/restore_grants/{}", initial.root, key(&selectors.grant)),
            initial,
            plan: plan_digest(plan)?,
        };
        ensure!(
            names.documents().into_iter().collect::<BTreeSet<_>>().len() == 7,
            "restore_provider_document_alias"
        );
        Ok(names)
    }

    fn documents(&self) -> Vec<&str> {
        let mut names = self.initial.documents();
        names.extend([
            self.advance.as_str(),
            self.reservation.as_str(),
            self.grant.as_str(),
        ]);
        names
    }

    /// Starts one read-write transaction and reads ALL four original records
    /// and three create-only names. No field mask or retryTransaction is used.
    pub(in crate::security_epoch) fn begin_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"documents":self.documents(),"newTransaction":{"readWrite":{}}}),
        )?)
    }

    /// The post-send read has the existing default strong consistency, never
    /// the pre-send transaction's old snapshot or a caller-supplied readTime.
    pub(in crate::security_epoch) fn strong_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"documents":self.documents()}))?)
    }

    pub(in crate::security_epoch) fn endpoint(&self, operation: &'static str) -> Result<String> {
        ensure!(
            ["batchGet", "commit", "rollback"].contains(&operation),
            "restore_provider_operation"
        );
        Ok(self.initial.endpoint(operation))
    }

    /// Once a canonical header is known, retain this object through semantic
    /// decoding so a rejected document can still be rolled back by its sender.
    pub(in crate::security_epoch) fn transaction(self, bytes: &[u8]) -> Result<Transaction> {
        let mut entries = entries(bytes)?;
        let token = entries
            .first_mut()
            .context("restore_provider_stream_empty")?
            .transaction
            .take()
            .context("restore_provider_transaction_missing")?;
        let decoded = STANDARD
            .decode(&token)
            .map_err(|_| anyhow::anyhow!("restore_provider_transaction_encoding"))?;
        ensure!(
            !decoded.is_empty() && decoded.len() <= 1024 && STANDARD.encode(decoded) == token,
            "restore_provider_transaction_encoding"
        );
        if entries[0].found.is_none() && entries[0].missing.is_none() {
            ensure!(
                entries[0].read_time.is_none(),
                "restore_provider_header_fields"
            );
            entries.remove(0);
        }
        Ok(Transaction {
            names: self,
            token,
            entries,
            local: PhantomData,
        })
    }

    pub(in crate::security_epoch) fn strong(&self, bytes: &[u8]) -> Result<Observed> {
        self.decode(entries(bytes)?)
    }

    fn decode(&self, entries: Vec<RawEntry>) -> Result<Observed> {
        let expected = self.documents();
        let mut seen = BTreeSet::new();
        let mut previous = None;
        let mut first = None;
        let mut initial = Vec::new();
        let (mut advance, mut reservation, mut grant) = (None, None, None);
        for entry in entries {
            ensure!(
                entry.transaction.is_none(),
                "restore_provider_duplicate_transaction"
            );
            let at = entry
                .read_time
                .as_deref()
                .context("restore_provider_read_time")?;
            let at = timestamp(at)?;
            first.get_or_insert(at);
            ensure!(
                previous.is_none_or(|old| old <= at),
                "restore_provider_read_rewind"
            );
            previous = Some(at);
            let name = match (&entry.found, &entry.missing) {
                (Some(value), None) => value
                    .get("name")
                    .and_then(Value::as_str)
                    .context("restore_provider_document_name")?,
                (None, Some(name)) => name,
                _ => anyhow::bail!("restore_provider_result_shape"),
            };
            ensure!(
                expected.contains(&name),
                "restore_provider_foreign_document"
            );
            ensure!(
                seen.insert(name.to_owned()),
                "restore_provider_duplicate_document"
            );
            if let Some(found) = &entry.found {
                field_shapes(
                    found
                        .get("fields")
                        .context("restore_provider_document_fields")?,
                    0,
                )?;
            }
            if self.initial.documents().contains(&name) {
                initial.push(Entry {
                    transaction: None,
                    read_time: entry.read_time,
                    found: entry
                        .found
                        .map(|value| {
                            serde_json::from_value(value)
                                .map_err(|_| anyhow::anyhow!("restore_provider_initial_document"))
                        })
                        .transpose()?,
                    missing: entry.missing,
                });
            } else if name == self.advance {
                advance = record(entry.found, "day2-restore-advance-document-v1", at)?;
            } else if name == self.reservation {
                reservation = record(entry.found, "day2-restore-reservation-document-v1", at)?;
            } else {
                grant = record(entry.found, "day2-restore-grant-document-v1", at)?;
            }
        }
        ensure!(
            seen.len() == expected.len(),
            "restore_provider_incomplete_snapshot"
        );
        Ok(Observed {
            snapshot: decode_snapshot(&self.initial, initial)
                .map_err(|_| anyhow::anyhow!("restore_provider_initial_snapshot"))?,
            advance,
            reservation,
            grant,
            first_read: first.context("restore_provider_read_time")?,
        })
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEntry {
    transaction: Option<String>,
    read_time: Option<String>,
    found: Option<Value>,
    missing: Option<String>,
}

fn entries(bytes: &[u8]) -> Result<Vec<RawEntry>> {
    ensure!(
        bytes.len() <= super::MAX_BYTES,
        "restore_provider_reply_bound"
    );
    let values: Vec<Value> = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("restore_provider_reply_encoding"))?;
    ensure!(
        !values.is_empty() && values.len() <= 8,
        "restore_provider_stream_bound"
    );
    values
        .into_iter()
        .map(|value| {
            ensure!(value.is_object(), "restore_provider_entry_object");
            serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("restore_provider_reply_encoding"))
        })
        .collect()
}

fn field_shapes(value: &Value, depth: usize) -> Result<()> {
    ensure!(depth <= 32, "restore_provider_fields_depth");
    let fields = value
        .as_object()
        .context("restore_provider_fields_object")?;
    for field in fields.values() {
        let object = field.as_object().context("restore_provider_field_object")?;
        ensure!(object.len() == 1, "restore_provider_field_shape");
        match (object.get("stringValue"), object.get("mapValue")) {
            (Some(value), None) => ensure!(value.is_string(), "restore_provider_string_field"),
            (None, Some(value)) => {
                let map = value.as_object().context("restore_provider_map_object")?;
                ensure!(map.len() == 1, "restore_provider_map_shape");
                field_shapes(
                    map.get("fields").context("restore_provider_map_fields")?,
                    depth + 1,
                )?;
            }
            _ => anyhow::bail!("restore_provider_field_shape"),
        }
    }
    Ok(())
}

fn timestamp(text: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .map_err(|_| anyhow::anyhow!("restore_provider_timestamp"))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordDocument {
    name: String,
    fields: RecordFields,
    create_time: UpdateTime,
    update_time: UpdateTime,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFields {
    restore_json: Text,
    restore_digest: Text,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Text {
    string_value: String,
}

fn record<T: DeserializeOwned + Serialize>(
    value: Option<Value>,
    domain: &str,
    read: time::OffsetDateTime,
) -> Result<Option<Versioned<T>>> {
    value
        .map(|value| {
            let document: RecordDocument = serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("restore_provider_record_shape"))?;
            let _ = document.name; // exact name already checked in the complete stream
            let updated = timestamp(&String::from(document.update_time.clone()))?;
            ensure!(
                timestamp(&String::from(document.create_time))? <= updated && updated <= read,
                "restore_provider_document_time_order"
            );
            let payload = document.fields.restore_json.string_value;
            ensure!(
                payload.len() <= MAX_RECORD_BYTES,
                "restore_provider_record_bound"
            );
            let value: T = crate::json::decode(payload.as_bytes())
                .map_err(|_| anyhow::anyhow!("restore_provider_record_encoding"))?;
            ensure!(
                serde_json::to_string(&value)? == payload
                    && Digest::of(&(domain, &value))?.as_str()
                        == document.fields.restore_digest.string_value,
                "restore_provider_record_commitment"
            );
            Ok(Versioned {
                value,
                version: document.update_time,
            })
        })
        .transpose()
}

/// Historical provider DATA only, including an occupied grant-use record.
pub(in crate::security_epoch) struct Observed {
    pub snapshot: Snapshot,
    pub advance: Option<Versioned<advance::Receipt>>,
    pub reservation: Option<Versioned<restore::Receipt>>,
    pub grant: Option<Versioned<approval_use::UseRecord>>,
    first_read: time::OffsetDateTime,
}

impl Observed {
    /// Provider-time ordering only, not a local clock, freshness original or
    /// permission. The real sender must also keep its native postchecks.
    pub(in crate::security_epoch) fn after_commit(&self, commit: &CommitRecord) -> Result<()> {
        ensure!(
            self.first_read >= commit.committed,
            "restore_provider_read_before_commit"
        );
        Ok(())
    }
}

/// Historical HTTP acknowledgement DATA. Parsing it cannot construct a consumed
/// approval: actual native postchecks and complete current readback remain owed.
pub(in crate::security_epoch) struct CommitRecord {
    committed: time::OffsetDateTime,
}

pub(in crate::security_epoch) fn commit_reply(bytes: &[u8]) -> Result<CommitRecord> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Reply {
        write_results: [WriteResult; 5],
        commit_time: UpdateTime,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WriteResult {
        update_time: UpdateTime,
    }
    ensure!(
        bytes.len() <= super::MAX_BYTES,
        "restore_provider_reply_bound"
    );
    let value: Value = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("restore_provider_commit_encoding"))?;
    ensure!(
        value.is_object()
            && value
                .get("writeResults")
                .and_then(Value::as_array)
                .is_some_and(|rows| rows.iter().all(Value::is_object)),
        "restore_provider_commit_object"
    );
    let reply: Reply = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("restore_provider_commit_encoding"))?;
    let committed = timestamp(&String::from(reply.commit_time))?;
    for write in reply.write_results {
        ensure!(
            timestamp(&String::from(write.update_time))? <= committed,
            "restore_provider_commit_time_order"
        );
    }
    Ok(CommitRecord { committed })
}

/// Transient provider transaction, not native approval or counter permission.
/// No clone, serialization, supplied-token constructor or automatic retry.
pub(in crate::security_epoch) struct Transaction {
    names: Names,
    token: String,
    entries: Vec<RawEntry>,
    local: PhantomData<Rc<()>>,
}

impl Transaction {
    pub(in crate::security_epoch) fn observed(&self) -> Result<Observed> {
        // Keep ownership of the header for bounded cleanup even on a semantic
        // failure. Copy bounded DATA only, without another network read or
        // copying the opaque transaction token itself.
        self.names.decode(self.entries.clone())
    }

    pub(in crate::security_epoch) fn rollback_body(self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"transaction":self.token}))?)
    }

    // Preparation retains the token on failure for bounded pre-send cleanup.
    // Rebuilding DATA never grants a second send: the future native consumer
    // must mark its actual approval May before consuming a dispatch attempt.
    pub(in crate::security_epoch) fn commit_body(
        &self,
        selection: &EpochStore,
        plan: &approval_use::Plan,
        current: &restore::Current,
        at: i64,
    ) -> Result<Vec<u8>> {
        ensure!(
            self.names.selection == *selection && self.names.plan == plan_digest(plan)?,
            "restore_provider_plan_changed"
        );
        let observed = self.observed()?;
        ensure!(
            observed.advance.is_none(),
            "restore_provider_advance_already_exists"
        );
        plan.revalidate(
            selection,
            current,
            at,
            &observed.snapshot,
            observed.reservation.as_ref(),
            observed.grant.as_ref(),
        )?;
        let initial_write = |name: &str, value: Value, condition: Value| -> Result<Value> {
            Ok(
                json!({"update":{"name":name,"fields":encode_fields(value)?},"currentDocument":condition}),
            )
        };
        let root_version = &observed
            .snapshot
            .root
            .as_ref()
            .context("restore_provider_root_missing")?
            .version;
        let sentinel_version = &observed
            .snapshot
            .sentinel
            .as_ref()
            .context("restore_provider_sentinel_missing")?
            .version;
        let advance = &plan.reservation.advance;
        let bytes = serde_json::to_vec(&json!({"transaction":self.token,"writes":[
            initial_write(&self.names.initial.root, serde_json::to_value(&advance.root)?, json!({"updateTime":root_version}))?,
            initial_write(&self.names.initial.sentinel, serde_json::to_value(&advance.sentinel)?, json!({"updateTime":sentinel_version}))?,
            receipt_write(&self.names.advance, &advance.receipt, "day2-restore-advance-document-v1")?,
            receipt_write(&self.names.reservation, &plan.reservation.receipt, "day2-restore-reservation-document-v1")?,
            receipt_write(&self.names.grant, &plan.approval_use, "day2-restore-grant-document-v1")?,
        ]}))?;
        ensure!(
            bytes.len() <= super::MAX_BYTES,
            "restore_provider_request_bound"
        );
        Ok(bytes)
    }
}

fn receipt_write<T: Serialize>(name: &str, value: &T, domain: &str) -> Result<Value> {
    let payload = serde_json::to_string(value)?;
    ensure!(
        payload.len() <= MAX_RECORD_BYTES,
        "restore_provider_record_bound"
    );
    Ok(json!({"update":{"name":name,"fields":{
        "restore_json":{"stringValue":payload},
        "restore_digest":{"stringValue":Digest::of(&(domain,value))?}
    }},"currentDocument":{"exists":false}}))
}
