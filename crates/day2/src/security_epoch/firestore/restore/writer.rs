//! Bounded messages for the distinct restored-writer transition. These codecs
//! carry DATA only; the native sender retains the actual approval, original,
//! exclusion, creator/P3 and authenticated new holder around every request.
use super::{
    RawEntry, Stream, document_times, entries, field_shapes, receipt_write, record, timestamp,
    transaction_header,
};
use crate::security_epoch::kernel::restore::writer as kernel;
use crate::security_epoch::kernel::{UpdateTime, Versioned, restore};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, marker::PhantomData, rc::Rc};

pub(in crate::security_epoch) struct Names {
    base: super::Names,
    terminal: String,
    writer: String,
    plan: Digest,
}

impl Names {
    pub(in crate::security_epoch) fn new(
        selected: &EpochStore,
        request: &kernel::Request,
        plan: &kernel::Plan,
    ) -> Result<Self> {
        let base = super::Names::new(selected, request.reservation_data())?;
        let operation = &request.operation().as_str()[7..];
        let names = Self {
            terminal: format!("{}/restore_settlements/{operation}", base.initial.root),
            writer: format!("{}/restore_writers/{operation}", base.initial.root),
            base,
            plan: plan.commitment()?,
        };
        ensure!(
            names.documents().into_iter().collect::<BTreeSet<_>>().len() == 9,
            "restore_writer_provider_document_alias"
        );
        Ok(names)
    }

    fn documents(&self) -> Vec<&str> {
        let mut names = self.base.documents();
        names.extend([self.terminal.as_str(), self.writer.as_str()]);
        names
    }

    pub(in crate::security_epoch) fn begin_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"documents":self.documents(),"newTransaction":{"readWrite":{}}}),
        )?)
    }

    pub(in crate::security_epoch) fn strong_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"documents":self.documents()}))?)
    }

    pub(in crate::security_epoch) fn endpoint(&self, operation: &'static str) -> Result<String> {
        self.base.endpoint(operation)
    }

    pub(in crate::security_epoch) fn transaction(self, bytes: &[u8]) -> Result<Transaction> {
        let (token, entries) = transaction_header(bytes, Stream::Writer)?;
        Ok(Transaction {
            names: self,
            token,
            entries,
            local: PhantomData,
        })
    }

    pub(in crate::security_epoch) fn strong(&self, bytes: &[u8]) -> Result<Observed> {
        self.decode(entries(bytes, Stream::Writer)?)
    }

    fn decode(&self, values: Vec<Value>) -> Result<Observed> {
        let expected = self.documents();
        let mut seen = BTreeSet::new();
        let mut base = Vec::new();
        let (mut terminal, mut writer) = (None, None);
        let (mut first, mut previous) = (None, None);
        for value in values {
            ensure!(value.is_object(), "restore_writer_provider_entry_object");
            let entry: RawEntry = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("restore_writer_provider_entry_encoding"))?;
            ensure!(
                entry.transaction.is_none(),
                "restore_writer_provider_duplicate_transaction"
            );
            let at = timestamp(
                entry
                    .read_time
                    .as_deref()
                    .context("restore_writer_provider_read_time")?,
            )?;
            ensure!(
                previous.is_none_or(|prior| prior <= at),
                "restore_writer_provider_read_rewind"
            );
            first.get_or_insert(at);
            previous = Some(at);
            let name = match (&entry.found, &entry.missing) {
                (Some(value), None) => value
                    .get("name")
                    .and_then(Value::as_str)
                    .context("restore_writer_provider_name")?,
                (None, Some(name)) => name,
                _ => anyhow::bail!("restore_writer_provider_result_shape"),
            };
            ensure!(
                expected.contains(&name) && seen.insert(name.to_owned()),
                "restore_writer_provider_foreign_or_duplicate"
            );
            if self.base.documents().contains(&name) {
                base.push(value);
            } else {
                if let Some(found) = &entry.found {
                    document_times(found, at)?;
                    field_shapes(
                        found
                            .get("fields")
                            .context("restore_writer_provider_fields")?,
                        0,
                    )?;
                }
                if name == self.terminal {
                    terminal = record(entry.found, "day2-restore-settlement-document-v1", at)?;
                } else {
                    writer = record(entry.found, "day2-restore-writer-document-v1", at)?;
                }
            }
        }
        ensure!(seen.len() == 9, "restore_writer_provider_incomplete");
        let base = self.base.decode(base)?;
        Ok(Observed {
            state: kernel::State {
                settled: crate::security_epoch::kernel::restore::completion::State {
                    snapshot: base.snapshot,
                    advance: base
                        .advance
                        .context("restore_writer_provider_advance_missing")?,
                    reservation: base
                        .reservation
                        .context("restore_writer_provider_reservation_missing")?,
                },
                consumed: base
                    .grant
                    .context("restore_writer_provider_grant_missing")?,
                terminal: terminal.context("restore_writer_provider_settlement_missing")?,
            },
            writer,
            first_read: first.context("restore_writer_provider_read_time")?,
        })
    }
}

pub(in crate::security_epoch) struct Observed {
    pub state: kernel::State,
    pub writer: Option<Versioned<kernel::Receipt>>,
    first_read: time::OffsetDateTime,
}

pub(in crate::security_epoch) struct Transaction {
    names: Names,
    token: String,
    entries: Vec<Value>,
    local: PhantomData<Rc<()>>,
}

impl Transaction {
    pub(in crate::security_epoch) fn observed(&self) -> Result<Observed> {
        self.names.decode(self.entries.clone())
    }

    pub(in crate::security_epoch) fn rollback_body(self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"transaction":self.token}))?)
    }

    pub(in crate::security_epoch) fn commit_body(
        &self,
        selected: &EpochStore,
        request: &kernel::Request,
        plan: &kernel::Plan,
        current: &restore::Current,
        at: i64,
    ) -> Result<Vec<u8>> {
        ensure!(
            self.names.base.selection == *selected && self.names.plan == plan.commitment()?,
            "restore_writer_provider_plan_changed"
        );
        let observed = self.observed()?;
        plan.revalidate(
            selected,
            request,
            current,
            at,
            &observed.state,
            observed.writer.as_ref(),
        )?;
        let root = observed
            .state
            .settled
            .snapshot
            .root
            .as_ref()
            .context("restore_writer_provider_root_missing")?;
        let sentinel = observed
            .state
            .settled
            .snapshot
            .sentinel
            .as_ref()
            .context("restore_writer_provider_sentinel_missing")?;
        // All nine names were read in THIS read-write transaction. Firestore
        // validates the read set atomically, including all six unchanged
        // records and writer absence; neither extra no-op writes nor a second
        // ledger are introduced. Root/sentinel retain explicit version CAS.
        let bytes = serde_json::to_vec(&json!({"transaction":self.token,"writes":[
            {"update":{"name":self.names.base.initial.root,"fields":encode_fields(serde_json::to_value(&plan.root)?)?},
                "currentDocument":{"updateTime":root.version}},
            {"update":{"name":self.names.base.initial.sentinel,"fields":encode_fields(serde_json::to_value(&plan.sentinel)?)?},
                "currentDocument":{"updateTime":sentinel.version}},
            receipt_write(&self.names.writer, &plan.receipt, "day2-restore-writer-document-v1")?,
        ]}))?;
        ensure!(
            bytes.len() <= super::super::MAX_BYTES,
            "restore_writer_provider_request_bound"
        );
        Ok(bytes)
    }
}

pub(in crate::security_epoch) struct CommitRecord {
    committed: time::OffsetDateTime,
    versions: [UpdateTime; 3],
}

pub(in crate::security_epoch) fn commit_reply(bytes: &[u8]) -> Result<CommitRecord> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Reply {
        write_results: [WriteResult; 3],
        commit_time: UpdateTime,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WriteResult {
        update_time: UpdateTime,
    }
    ensure!(
        bytes.len() <= super::super::MAX_BYTES,
        "restore_writer_provider_reply_bound"
    );
    let value: Value = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("restore_writer_provider_commit_encoding"))?;
    ensure!(
        value.is_object()
            && value
                .get("writeResults")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().all(Value::is_object)),
        "restore_writer_provider_commit_shape"
    );
    let reply: Reply = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("restore_writer_provider_commit_encoding"))?;
    let committed = timestamp(&String::from(reply.commit_time))?;
    let versions = reply.write_results.map(|w| w.update_time);
    for version in &versions {
        ensure!(
            timestamp(&String::from(version.clone()))? <= committed,
            "restore_writer_provider_commit_order"
        );
    }
    Ok(CommitRecord {
        committed,
        versions,
    })
}

impl Observed {
    pub(in crate::security_epoch) fn after_commit(&self, commit: &CommitRecord) -> Result<()> {
        let root = self
            .state
            .settled
            .snapshot
            .root
            .as_ref()
            .context("restore_writer_post_root_missing")?;
        let sentinel = self
            .state
            .settled
            .snapshot
            .sentinel
            .as_ref()
            .context("restore_writer_post_sentinel_missing")?;
        let writer = self
            .writer
            .as_ref()
            .context("restore_writer_post_receipt_missing")?;
        ensure!(
            self.first_read >= commit.committed
                && root.version == commit.versions[0]
                && sentinel.version == commit.versions[1]
                && writer.version == commit.versions[2],
            "restore_writer_post_commit_or_versions_changed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
