//! Fixed external safe-floor protocol. A successful exchange is DATA; the
//! actual native producer must retain its host clock, current action and native
//! port throughout. No initializer, generic write or retry is provided here.
use super::{Budget, Document, Entry, Names, Port, ReadTransaction, decode_snapshot};
use crate::security_epoch::kernel::{
    Snapshot, UpdateTime, Versioned,
    approval_time::{self as model, Floor, Interval, Plan, Receipt},
};
use crate::security_epoch::restore_approval::{
    publication::{self, Publication},
    signed::SignedApprovalRecord,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const FLOOR_DOMAIN: &str = "day2-restore-time-floor-document-v1";
const RECEIPT_DOMAIN: &str = "day2-restore-time-receipt-document-v1";
const MAX_PAYLOAD: usize = 20_480;
const PUBLICATION_DOMAIN: &str = "day2-restore-approval-publication-document-v1";

struct Selection {
    names: Names,
    floor: String,
    receipt: String,
    publication: Option<String>,
}

impl Selection {
    fn new(selected: &EpochStore, before: &Snapshot, operation: &Digest) -> Result<Self> {
        let active = before
            .activate
            .as_ref()
            .context("restore_time_activation_missing")?;
        let names = Names::new(
            selected,
            active.value.request.bootstrap(),
            Some(active.value.request.operation()),
        )?;
        let floor_key = model::key(selected)?;
        let receipt_key = model::receipt_key(selected, operation)?;
        let floor = format!(
            "{}/documents/day2_restore_time_floor_v1/{}",
            names.database,
            &floor_key.as_str()[7..]
        );
        let receipt = format!("{floor}/operations/{}", &receipt_key.as_str()[7..]);
        Ok(Self {
            names,
            floor,
            receipt,
            publication: None,
        })
    }

    fn documents(&self) -> Vec<&str> {
        let mut values = self.names.documents();
        values.extend([self.floor.as_str(), self.receipt.as_str()]);
        values.extend(self.publication.as_deref());
        values
    }
}

fn fields<T: Serialize>(domain: &str, value: &T) -> Result<Value> {
    let payload = serde_json::to_string(value)?;
    ensure!(payload.len() <= MAX_PAYLOAD, "restore_time_payload_bound");
    Ok(json!({
        "payload":{"stringValue":payload},
        "commitment":{"stringValue":Digest::of(&(domain, value))?}
    }))
}

fn decode<T: Serialize + DeserializeOwned>(
    domain: &str,
    document: Document,
) -> Result<Versioned<T>> {
    let value = serde_json::to_value(document.fields)?;
    let object = value.as_object().context("restore_time_document_fields")?;
    ensure!(object.len() == 2, "restore_time_document_fields");
    let payload = object
        .get("payload")
        .and_then(|v| v.get("stringValue"))
        .and_then(Value::as_str)
        .context("restore_time_payload_missing")?;
    ensure!(payload.len() <= MAX_PAYLOAD, "restore_time_payload_bound");
    let parsed: T = crate::json::decode(payload.as_bytes())
        .map_err(|_| anyhow::anyhow!("restore_time_payload_encoding"))?;
    ensure!(
        object
            .get("commitment")
            .and_then(|v| v.get("stringValue"))
            .and_then(Value::as_str)
            == Some(Digest::of(&(domain, &parsed))?.as_str()),
        "restore_time_payload_changed"
    );
    Ok(Versioned {
        value: parsed,
        version: document.update_time,
    })
}

struct Observed {
    root: Snapshot,
    floor: Option<Versioned<Floor>>,
    receipt: Option<Versioned<Receipt>>,
    token: String,
    publication: Option<Versioned<Publication>>,
}

fn read(
    port: &mut impl Port,
    budget: &mut Budget,
    selected: &Selection,
    write: bool,
) -> Result<Observed> {
    let body = serde_json::to_vec(&json!({
        "documents":selected.documents(),
        "newTransaction":if write {json!({"readWrite":{}})} else {json!({"readOnly":{}})}
    }))?;
    let bytes = budget.call(port, &selected.names.endpoint("batchGet"), &body)?;
    let mut entries: Vec<Entry> =
        crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("restore_time_batch_encoding"))?;
    ensure!(
        !entries.is_empty() && entries.len() <= selected.documents().len() + 1,
        "restore_time_batch_bound"
    );
    let token = entries[0]
        .transaction
        .take()
        .context("restore_time_transaction_missing")?;
    let decoded = STANDARD
        .decode(&token)
        .map_err(|_| anyhow::anyhow!("restore_time_transaction_encoding"))?;
    ensure!(
        !decoded.is_empty() && decoded.len() <= 1024 && STANDARD.encode(decoded) == token,
        "restore_time_transaction_encoding"
    );
    let observed = (|| {
        if entries[0].found.is_none() && entries[0].missing.is_none() {
            ensure!(entries[0].read_time.is_none(), "restore_time_header_fields");
            entries.remove(0);
        }
        ensure!(
            entries.len() == selected.documents().len(),
            "restore_time_incomplete_snapshot"
        );
        let mut roots = Vec::new();
        let mut floor = None;
        let mut receipt = None;
        let mut publication = None;
        let mut seen = std::collections::BTreeSet::new();
        let mut previous = None;
        for entry in entries {
            ensure!(
                entry.transaction.is_none(),
                "restore_time_duplicate_transaction"
            );
            let read_at = parse_time(
                entry
                    .read_time
                    .as_deref()
                    .context("restore_time_read_time_missing")?,
            )?;
            ensure!(
                previous.is_none_or(|at| at <= read_at),
                "restore_time_read_time_rewind"
            );
            previous = Some(read_at);
            let name = match (&entry.found, &entry.missing) {
                (Some(document), None) => {
                    ensure!(
                        parse_version(&document.create_time)?
                            <= parse_version(&document.update_time)?
                            && parse_version(&document.update_time)? <= read_at,
                        "restore_time_document_time_order"
                    );
                    document.name.clone()
                }
                (None, Some(name)) => name.clone(),
                _ => anyhow::bail!("restore_time_batch_entry_shape"),
            };
            ensure!(
                selected.documents().contains(&name.as_str()) && seen.insert(name.clone()),
                "restore_time_unrequested_or_duplicate_document"
            );
            if name == selected.floor {
                floor = entry
                    .found
                    .map(|doc| decode(FLOOR_DOMAIN, doc))
                    .transpose()?;
            } else if name == selected.receipt {
                receipt = entry
                    .found
                    .map(|doc| decode(RECEIPT_DOMAIN, doc))
                    .transpose()?;
            } else if selected.publication.as_deref() == Some(name.as_str()) {
                publication = entry
                    .found
                    .map(|doc| decode(PUBLICATION_DOMAIN, doc))
                    .transpose()?;
            } else {
                roots.push(entry);
            }
        }
        let root = decode_snapshot(&selected.names, roots)?;
        budget.remaining_decoding(port)?;
        Ok(Observed {
            root,
            floor,
            receipt,
            publication,
            token: token.clone(),
        })
    })();
    if write && observed.is_err() {
        // Close a known read/write transaction on semantic refusal. A cleanup
        // failure poisons the native port but cannot replace the primary error.
        let _closed = ReadTransaction { token }.rollback(port, budget, &selected.names);
    }
    // A read-only transaction holds no locks. Its fixed snapshot is the read
    // proof; rollback would supply no coherence/freshness evidence.
    observed
}

fn parse_version(value: &UpdateTime) -> Result<time::OffsetDateTime> {
    parse_time(&String::from(value.clone()))
}

fn parse_time(value: &str) -> Result<time::OffsetDateTime> {
    Ok(time::OffsetDateTime::parse(
        value,
        &time::format_description::well_known::Rfc3339,
    )?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Committed {
    write_results: Vec<WriteResult>,
    commit_time: UpdateTime,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriteResult {
    update_time: UpdateTime,
}

/// Read all four active-root records, floor and operation absence in ONE
/// read/write transaction. Its read set fences both writes; the floor update
/// additionally has the exact prior version and the receipt is create-only.
/// A lost/invalid ACK refuses; no receipt can recreate this live native call.
pub(in crate::security_epoch) fn advance_approval_time(
    port: &mut impl Port,
    mut budget: Budget,
    selected: &EpochStore,
    before: &Snapshot,
    operation: Digest,
    interval: Interval,
) -> Result<Plan> {
    let names = Selection::new(selected, before, &operation)?;
    let observed = read(port, &mut budget, &names, true)?;
    let requested = (|| {
        ensure!(observed.root == *before, "restore_time_counter_changed");
        let plan = Plan::prepare(
            selected,
            before,
            observed.floor.as_ref(),
            operation,
            interval,
        )?;
        plan.revalidate(
            selected,
            &observed.root,
            observed.floor.as_ref(),
            observed.receipt.as_ref(),
        )?;
        Ok(plan)
    })();
    let plan = match requested {
        Ok(plan) => plan,
        Err(error) => {
            let _closed = ReadTransaction {
                token: observed.token,
            }
            .rollback(port, &mut budget, &names.names);
            return Err(error);
        }
    };
    let body = serde_json::to_vec(&json!({"writes":[
        {"update":{"name":names.floor,"fields":fields(FLOOR_DOMAIN,&plan.after)?},"currentDocument":{"updateTime":plan.prior.version}},
        {"update":{"name":names.receipt,"fields":fields(RECEIPT_DOMAIN,&plan.receipt)?},"currentDocument":{"exists":false}}
    ],"transaction":observed.token}))?;
    let bytes = budget.call(port, &names.names.endpoint("commit"), &body)?;
    let committed: Committed =
        crate::json::decode(&bytes).map_err(|_| anyhow::anyhow!("restore_time_commit_encoding"))?;
    ensure!(
        committed.write_results.len() == 2,
        "restore_time_commit_count"
    );
    let first = &committed.write_results[0].update_time;
    ensure!(
        committed.write_results[1].update_time == *first
            && parse_version(first)? <= parse_version(&committed.commit_time)?,
        "restore_time_commit_versions"
    );
    let after = read(port, &mut budget, &names, false)?;
    ensure!(
        matches!(
            model::reconcile(
                &plan,
                selected,
                &after.root,
                after.floor.as_ref(),
                after.receipt.as_ref()
            )?,
            model::Outcome::Applied
        ),
        "restore_time_commit_not_observed"
    );
    ensure!(
        after
            .floor
            .as_ref()
            .is_some_and(|floor| floor.version == *first),
        "restore_time_ack_readback_changed"
    );
    budget.remaining_decoding(port)?;
    Ok(plan)
}

/// Create-only publication under the same complete root/time read set.
/// It contains the full immutable wire record, never a recovered native owner.
pub(in crate::security_epoch) fn publish_restore_approval(
    port: &mut impl Port,
    mut budget: Budget,
    selected: &EpochStore,
    before: &Snapshot,
    plan: &Plan,
    record: &SignedApprovalRecord,
) -> Result<()> {
    let mut names = Selection::new(selected, before, &plan.receipt.operation_data())?;
    let grant = &record.statement.request.grant_id;
    let key = publication::key(selected, grant)?;
    names.publication = Some(format!(
        "{}/documents/day2_restore_approval_publications_v1/{}",
        names.names.database,
        &key.as_str()[7..]
    ));
    let value = Publication::record_data(selected, record.clone())?;
    value.encode(selected)?;
    let observed = read(port, &mut budget, &names, true)?;
    let validated = (|| {
        ensure!(
            observed.publication.is_none(),
            "restore_approval_publication_already_exists"
        );
        ensure!(
            matches!(
                model::reconcile(
                    plan,
                    selected,
                    &observed.root,
                    observed.floor.as_ref(),
                    observed.receipt.as_ref()
                )?,
                model::Outcome::Applied
            ),
            "restore_approval_time_state_changed"
        );
        Ok(())
    })();
    if let Err(error) = validated {
        let _closed = ReadTransaction {
            token: observed.token,
        }
        .rollback(port, &mut budget, &names.names);
        return Err(error);
    }
    let body = serde_json::to_vec(&json!({"writes":[{
        "update":{"name":names.publication,"fields":fields(PUBLICATION_DOMAIN,&value)?},
        "currentDocument":{"exists":false}
    }],"transaction":observed.token}))?;
    let bytes = budget.call(port, &names.names.endpoint("commit"), &body)?;
    let committed: Committed = crate::json::decode(&bytes)
        .map_err(|_| anyhow::anyhow!("restore_approval_publication_commit_encoding"))?;
    ensure!(
        committed.write_results.len() == 1,
        "restore_approval_publication_commit_count"
    );
    let version = &committed.write_results[0].update_time;
    ensure!(
        parse_version(version)? <= parse_version(&committed.commit_time)?,
        "restore_approval_publication_time_order"
    );
    let after = read(port, &mut budget, &names, false)?;
    ensure!(
        matches!(
            model::reconcile(
                plan,
                selected,
                &after.root,
                after.floor.as_ref(),
                after.receipt.as_ref()
            )?,
            model::Outcome::Applied
        ),
        "restore_approval_publication_time_state_changed"
    );
    let published = after
        .publication
        .context("restore_approval_publication_missing")?;
    ensure!(
        published.version == *version,
        "restore_approval_publication_ack_changed"
    );
    published.value.require_exact(selected, record)?;
    budget.remaining_decoding(port)?;
    Ok(())
}

#[cfg(test)]
mod tests;
