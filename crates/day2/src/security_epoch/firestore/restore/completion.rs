//! Fixed terminal-settlement messages. Parsed records remain DATA; the native
//! sender separately retains the genuine stopped owner, completed target and
//! original around its one possible commit and complete strong post-read.
use super::{
    RawEntry, Stream, document_times, entries, field_shapes, receipt_write, record, timestamp,
    transaction_header,
};
use crate::security_epoch::kernel::{
    UpdateTime, Versioned,
    restore::{self, approval_use, completion as kernel},
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, marker::PhantomData, rc::Rc};

/// Exact immutable dispatch DATA. Only the separate native loan supplies
/// authority and checks that these are its actual borrowed inputs.
pub(in crate::security_epoch) struct Input<'data> {
    pub reservation: &'data approval_use::Plan,
    pub known: &'data super::Observed,
    pub confirmation: &'data super::ReservationConfirmation,
    pub request: &'data kernel::Request,
    pub plan: &'data kernel::Plan,
    pub current: &'data restore::Current,
    pub at: i64,
}

pub(in crate::security_epoch) struct Names {
    base: super::Names,
    terminal: String,
    before: Digest,
    plan: Digest,
}

fn state(observed: &super::Observed) -> Result<kernel::State> {
    Ok(kernel::State {
        snapshot: observed.snapshot.clone(),
        advance: observed
            .advance
            .clone()
            .context("restore_target_advance_missing")?,
        reservation: observed
            .reservation
            .clone()
            .context("restore_target_reservation_missing")?,
    })
}

fn plan_data(plan: &kernel::Plan, before: &Digest) -> Result<Digest> {
    Digest::of(&(
        "day2-native-target-settlement-plan-v1",
        &plan.receipt,
        before,
    ))
}

impl Names {
    pub(in crate::security_epoch) fn new(
        selected: &EpochStore,
        reservation: &approval_use::Plan,
        known: &super::Observed,
        confirmation: &super::ReservationConfirmation,
        plan: &kernel::Plan,
    ) -> Result<Self> {
        let before = known.commitment_data()?;
        ensure!(
            before == confirmation.records
                && known.first_read >= timestamp(&String::from(confirmation.committed_at.clone()))?
                && known
                    .grant
                    .as_ref()
                    .is_some_and(|row| row.value.grant_id_data() == &confirmation.grant_id),
            "restore_target_known_reservation_changed"
        );
        let versions = [
            known.snapshot.root.as_ref().map(|row| &row.version),
            known.snapshot.sentinel.as_ref().map(|row| &row.version),
            known.advance.as_ref().map(|row| &row.version),
            known.reservation.as_ref().map(|row| &row.version),
            known.grant.as_ref().map(|row| &row.version),
        ];
        ensure!(
            versions
                .iter()
                .zip(&confirmation.written_versions)
                .all(|(actual, written)| *actual == Some(written))
                && plan.before == state(known)?
                && matches!(
                    approval_use::reconcile(
                        selected,
                        reservation,
                        &known.snapshot,
                        known.advance.as_ref(),
                        known.reservation.as_ref(),
                        known.grant.as_ref()
                    )?,
                    restore::Outcome::Applied(_)
                ),
            "restore_target_known_versions_changed"
        );
        let base = super::Names::new(selected, reservation, &known.publication.value)?;
        let operation = reservation.selectors(selected)?.operation;
        let names = Self {
            terminal: format!(
                "{}/restore_settlements/{}",
                base.read.initial.root,
                &operation.as_str()[7..]
            ),
            base,
            plan: plan_data(plan, &before)?,
            before,
        };
        ensure!(
            names.documents().into_iter().collect::<BTreeSet<_>>().len() == 9,
            "restore_target_document_alias"
        );
        Ok(names)
    }

    fn documents(&self) -> Vec<&str> {
        let mut names = self.base.documents();
        names.push(&self.terminal);
        names
    }

    pub(in crate::security_epoch) fn endpoint(&self, operation: &'static str) -> Result<String> {
        self.base.endpoint(operation)
    }

    pub(in crate::security_epoch) fn begin_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"documents":self.documents(),"newTransaction":{"readWrite":{}}}),
        )?)
    }

    fn strong_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"documents":self.documents()}))?)
    }

    pub(in crate::security_epoch) fn transaction(self, bytes: &[u8]) -> Result<Transaction> {
        let (token, entries) = transaction_header(bytes, Stream::Settlement)?;
        Ok(Transaction {
            names: self,
            token,
            entries,
            local: PhantomData,
        })
    }

    fn strong(&self, bytes: &[u8]) -> Result<TargetObserved> {
        self.decode(entries(bytes, Stream::Settlement)?)
    }

    fn decode(&self, values: Vec<Value>) -> Result<TargetObserved> {
        let expected = self.documents();
        let mut seen = BTreeSet::new();
        let mut base = Vec::new();
        let mut terminal = None;
        let (mut first, mut previous) = (None, None);
        for value in values {
            ensure!(value.is_object(), "restore_target_entry_object");
            let entry: RawEntry = serde_json::from_value(value.clone())
                .map_err(|_| anyhow::anyhow!("restore_target_entry_encoding"))?;
            ensure!(
                entry.transaction.is_none(),
                "restore_target_duplicate_transaction"
            );
            let at = timestamp(
                entry
                    .read_time
                    .as_deref()
                    .context("restore_target_read_time")?,
            )?;
            ensure!(
                previous.is_none_or(|prior| prior <= at),
                "restore_target_read_rewind"
            );
            first.get_or_insert(at);
            previous = Some(at);
            let name = match (&entry.found, &entry.missing) {
                (Some(value), None) => value
                    .get("name")
                    .and_then(Value::as_str)
                    .context("restore_target_document_name")?,
                (None, Some(name)) => name,
                _ => anyhow::bail!("restore_target_result_shape"),
            };
            ensure!(
                expected.contains(&name) && seen.insert(name.to_owned()),
                "restore_target_foreign_or_duplicate"
            );
            if name == self.terminal {
                if let Some(found) = &entry.found {
                    document_times(found, at)?;
                    field_shapes(found.get("fields").context("restore_target_fields")?, 0)?;
                }
                terminal = record(entry.found, "day2-restore-settlement-document-v1", at)?;
            } else {
                base.push(value);
            }
        }
        ensure!(seen.len() == 9, "restore_target_incomplete_readset");
        let base = self.base.decode(base)?;
        ensure!(
            base.commitment_data()? == self.before,
            "restore_target_before_changed"
        );
        Ok(TargetObserved {
            base,
            terminal,
            first_read: first.context("restore_target_read_time")?,
        })
    }
}

pub(in crate::security_epoch) struct TargetObserved {
    pub base: super::Observed,
    pub terminal: Option<Versioned<kernel::Receipt>>,
    first_read: time::OffsetDateTime,
}

pub(in crate::security_epoch) struct Transaction {
    names: Names,
    token: String,
    entries: Vec<Value>,
    local: PhantomData<Rc<()>>,
}

impl Transaction {
    fn observed(&self) -> Result<TargetObserved> {
        self.names.decode(self.entries.clone())
    }

    fn rollback_body(self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"transaction":self.token}))?)
    }

    fn commit_body(
        &self,
        selected: &EpochStore,
        request: &kernel::Request,
        plan: &kernel::Plan,
        current: &restore::Current,
        at: i64,
    ) -> Result<Vec<u8>> {
        ensure!(
            self.names.base.read.selection == *selected
                && self.names.plan == plan_data(plan, &self.names.before)?,
            "restore_target_plan_changed"
        );
        let observed = self.observed()?;
        plan.revalidate(
            selected,
            request,
            current,
            at,
            &state(&observed.base)?,
            observed.terminal.as_ref(),
        )?;
        let body = serde_json::to_vec(&json!({"transaction":self.token,"writes":[
            receipt_write(&self.names.terminal, &plan.receipt, "day2-restore-settlement-document-v1")?
        ]}))?;
        ensure!(
            body.len() <= super::super::MAX_BYTES,
            "restore_target_request_bound"
        );
        Ok(body)
    }

    /// The actual native loan is spent before entry. This consumes the one
    /// retained token into at most one commit and never adopts an uncertain send.
    pub(in crate::security_epoch) fn commit_and_readback(
        self,
        port: &mut impl super::super::Port,
        mut budget: super::super::Budget,
        selected: &EpochStore,
        request: &kernel::Request,
        plan: &kernel::Plan,
        authorization: (&restore::Current, i64),
    ) -> Result<KnownSettlement> {
        let (current, at) = authorization;
        let body = match self.commit_body(selected, request, plan, current, at) {
            Ok(body) => body,
            Err(primary) => {
                let cleanup = (|| {
                    let endpoint = self.names.endpoint("rollback")?;
                    let body = self.rollback_body()?;
                    budget.call(port, &endpoint, &body)
                })();
                let _closed = cleanup;
                port.refuse();
                return Err(primary);
            }
        };
        let requested = (|| {
            let bytes = budget.call(port, &self.names.endpoint("commit")?, &body)?;
            let acknowledged = commit_reply(&bytes)?;
            let bytes = budget.call(
                port,
                &self.names.endpoint("batchGet")?,
                &self.names.strong_body()?,
            )?;
            let observed = self.names.strong(&bytes)?;
            let terminal = observed
                .terminal
                .as_ref()
                .context("restore_target_terminal_missing")?;
            ensure!(
                observed.first_read >= acknowledged.committed
                    && terminal.version == acknowledged.version,
                "restore_target_ack_or_version_changed"
            );
            ensure!(
                matches!(
                    kernel::reconcile(
                        selected,
                        request,
                        plan,
                        &state(&observed.base)?,
                        Some(terminal)
                    )?,
                    kernel::Outcome::Recorded(_)
                ),
                "restore_target_not_recorded"
            );
            budget.remaining_decoding(port)?;
            Ok(KnownSettlement {
                observed,
                acknowledged,
            })
        })();
        if requested.is_err() {
            port.refuse();
        }
        requested
    }
}

struct CommitRecord {
    committed: time::OffsetDateTime,
    version: UpdateTime,
}

fn commit_reply(bytes: &[u8]) -> Result<CommitRecord> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Reply {
        write_results: [WriteResult; 1],
        commit_time: UpdateTime,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WriteResult {
        update_time: UpdateTime,
    }
    ensure!(
        bytes.len() <= super::super::MAX_BYTES,
        "restore_target_reply_bound"
    );
    let value: Value = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("restore_target_commit_encoding"))?;
    ensure!(
        value.is_object()
            && value
                .get("writeResults")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().all(Value::is_object)),
        "restore_target_commit_shape"
    );
    let reply: Reply = serde_json::from_value(value)
        .map_err(|_| anyhow::anyhow!("restore_target_commit_encoding"))?;
    let committed = timestamp(&String::from(reply.commit_time))?;
    let [result] = reply.write_results;
    ensure!(
        timestamp(&String::from(result.update_time.clone()))? <= committed,
        "restore_target_commit_order"
    );
    Ok(CommitRecord {
        committed,
        version: result.update_time,
    })
}

/// Provider DATA only. No constructor from a journal/receipt or native owner.
pub(in crate::security_epoch) struct KnownSettlement {
    observed: TargetObserved,
    acknowledged: CommitRecord,
}

impl KnownSettlement {
    /// Complete acknowledged predecessor DATA for the distinct writer CAS.
    /// The native caller still retains the same approval, creator and holder;
    /// this view cannot create any of those owners or repeat settlement.
    pub(in crate::security_epoch) fn writer_state_data(
        &self,
    ) -> Result<crate::security_epoch::kernel::restore::writer::State> {
        self.receipt_data()?;
        let before = &self.observed.base;
        Ok(crate::security_epoch::kernel::restore::writer::State {
            settled: kernel::State {
                snapshot: before.snapshot.clone(),
                advance: before
                    .advance
                    .clone()
                    .context("restore_target_advance_missing")?,
                reservation: before
                    .reservation
                    .clone()
                    .context("restore_target_reservation_missing")?,
            },
            terminal: self
                .observed
                .terminal
                .clone()
                .context("restore_target_terminal_missing")?,
            consumed: before
                .grant
                .clone()
                .context("restore_target_grant_missing")?,
        })
    }

    pub(in crate::security_epoch) fn receipt_data(&self) -> Result<kernel::Receipt> {
        let terminal = self
            .observed
            .terminal
            .as_ref()
            .context("restore_target_terminal_missing")?;
        ensure!(
            terminal.version == self.acknowledged.version
                && self.observed.first_read >= self.acknowledged.committed,
            "restore_target_known_ack_changed"
        );
        Ok(terminal.value.clone())
    }
}

#[cfg(test)]
mod tests;
