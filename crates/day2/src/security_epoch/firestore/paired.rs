//! One bounded read-only transaction for the exact counter and control slot.
//! Parsed observations retain the same original time DATA; neither is native
//! role, physical-file, writer or counter-send authority.

use super::{Budget, Entry, EpochObservation, Names, Port, ReadTransaction, decode_snapshot};
use crate::security_epoch::{
    control_slot::LogicalCore,
    control_slot_firestore::{self as slot_codec, VersionedSlot},
    kernel::{self, AuthorityRecord, Phase, Request, Snapshot, Versioned},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, marker::PhantomData};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PairEntry {
    transaction: Option<String>,
    read_time: Option<String>,
    found: Option<Value>,
    missing: Option<String>,
}

pub(in crate::security_epoch) fn read_with_slot(
    selection: &EpochStore,
    core: &LogicalCore,
    port: &mut impl Port,
    mut budget: Budget,
) -> Result<(EpochObservation, Option<VersionedSlot>, Budget)> {
    let result = (|| {
        // Both selectors come only from the same fully validated logical core.
        // There is no caller-supplied document list or observation constructor.
        let slot_name = slot_codec::name(selection, core)?;
        let activate = match &core.counter {
            Request::CreateInitialAuthority { .. } => None,
            Request::CompleteInitialFirstActivation { operation, .. } => Some(operation),
        };
        let names = Names::new(selection, core.counter.bootstrap(), activate)?;
        let (mut snapshot, mut slot) = read_once(port, &mut budget, &names, core, &slot_name)?;
        if names.activate.is_none()
            && let Some(Versioned {
                value:
                    AuthorityRecord {
                        phase: Phase::ActiveFirstHolder { completion },
                        ..
                    },
                ..
            }) = &snapshot.root
        {
            // Discovery is bounded selector DATA only. Discard BOTH first-read
            // values and reread the whole counter/slot pair in a fresh coherent
            // transaction under this same original deadline.
            let operation = completion.operation.clone();
            let complete = Names::new(selection, core.counter.bootstrap(), Some(&operation))?;
            (snapshot, slot) = read_once(port, &mut budget, &complete, core, &slot_name)?;
            ensure!(
                matches!(&snapshot.root, Some(root) if matches!(&root.value.phase, Phase::ActiveFirstHolder { completion } if completion.operation == operation)),
                "security_epoch_discovery_state_changed"
            );
        }
        kernel::reconcile(
            selection,
            &Request::CreateInitialAuthority {
                bootstrap: core.counter.bootstrap().clone(),
            },
            &snapshot,
        )?;
        let selection = Digest::of(selection)?;
        // All whole-stream, counter and slot decoding/binding work is charged
        // before copying only this actual retained budget's time DATA. Every
        // actual HTTP request still owns its full native pre/post envelope.
        budget.remaining_decoding(port)?;
        let slot_budget = Budget {
            domain: budget.domain.clone(),
            start: budget.start,
            latest: budget.latest,
            limit: budget.limit,
        };
        Ok((
            EpochObservation {
                selection,
                snapshot,
                budget,
                valid: true,
                local: PhantomData,
            },
            slot,
            slot_budget,
        ))
    })();
    if result.is_err() {
        port.refuse();
    }
    result
}

fn read_once(
    port: &mut impl Port,
    budget: &mut Budget,
    names: &Names,
    core: &LogicalCore,
    slot_name: &str,
) -> Result<(Snapshot, Option<VersionedSlot>)> {
    let mut expected = names.documents();
    ensure!(
        !expected.contains(&slot_name),
        "security_epoch_paired_document_selection"
    );
    expected.push(slot_name);
    let body = serde_json::to_vec(&json!({"documents":expected,"newTransaction":{"readOnly":{}}}))?;
    let bytes = budget.call(port, &names.endpoint("batchGet"), &body)?;
    // The strict JSON decoder rejects duplicate/escaped object keys before
    // either generic document payload is converted to its closed record codec.
    let mut entries: Vec<PairEntry> = crate::json::decode(&bytes)?;
    ensure!(!entries.is_empty(), "security_epoch_batch_size");
    let token = entries[0]
        .transaction
        .take()
        .context("security_epoch_transaction_missing")?;
    let decoded = STANDARD.decode(&token)?;
    ensure!(
        !decoded.is_empty() && decoded.len() <= 1024 && STANDARD.encode(decoded) == token,
        "security_epoch_invalid_transaction"
    );
    let transaction = ReadTransaction { token };
    let result = (|| {
        ensure!(
            entries.len() <= expected.len() + 1,
            "security_epoch_batch_size"
        );
        // The first entry may hold just the token or also the first document.
        if entries[0].found.is_none() && entries[0].missing.is_none() {
            ensure!(
                entries[0].read_time.is_none(),
                "security_epoch_transaction_header_fields"
            );
            entries.remove(0);
        }
        validate_stream(&entries, &expected)?;

        // Partition only AFTER the entire stream's transaction, monotonic
        // readTime and exact requested-document set have been checked. Firestore
        // may reorder documents and may advance readTime while guaranteeing all
        // earlier returned documents remained unchanged through the later time.
        let mut counter_entries = Vec::new();
        let mut slot = None;
        for entry in entries {
            if document_name(&entry)? == slot_name {
                slot = entry
                    .found
                    .map(|document| {
                        slot_codec::decode(&names.selection, core, &serde_json::to_vec(&document)?)
                    })
                    .transpose()?;
            } else {
                counter_entries.push(Entry {
                    transaction: None,
                    read_time: entry.read_time,
                    found: entry.found.map(serde_json::from_value).transpose()?,
                    missing: entry.missing,
                });
            }
        }
        Ok((decode_snapshot(names, counter_entries)?, slot))
    })();
    // All semantic errors after obtaining a valid token still attempt to close
    // that exact transaction. Preserve the first semantic cause if bounded cleanup
    // also fails; successful decoding still requires complete unexpired cleanup.
    let cleanup: Result<()> = (|| {
        transaction.rollback(port, budget, names)?;
        budget.remaining_decoding(port)?;
        Ok(())
    })();
    let pair = result?;
    cleanup?;
    Ok(pair)
}

fn document_name(entry: &PairEntry) -> Result<&str> {
    match (&entry.found, &entry.missing) {
        (Some(document), None) => document
            .get("name")
            .and_then(Value::as_str)
            .context("security_epoch_document_name"),
        (None, Some(missing)) => Ok(missing),
        _ => anyhow::bail!("security_epoch_invalid_batch_result"),
    }
}

fn validate_stream(entries: &[PairEntry], expected: &[&str]) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut previous_time = None;
    for entry in entries {
        ensure!(
            entry.transaction.is_none(),
            "security_epoch_duplicate_transaction"
        );
        let read_time = entry
            .read_time
            .as_ref()
            .context("security_epoch_read_time_missing")?;
        let read_time =
            time::OffsetDateTime::parse(read_time, &time::format_description::well_known::Rfc3339)?;
        ensure!(
            previous_time.is_none_or(|previous| previous <= read_time),
            "security_epoch_provider_read_time_rewind"
        );
        previous_time = Some(read_time);
        let name = document_name(entry)?;
        ensure!(
            expected.contains(&name),
            "security_epoch_unrequested_document"
        );
        ensure!(seen.insert(name), "security_epoch_duplicate_document");
    }
    ensure!(
        seen.len() == expected.len(),
        "security_epoch_incomplete_snapshot"
    );
    Ok(())
}
