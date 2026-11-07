//! Exact restore provider messages and one consuming guarded reservation send.
//! Results remain DATA, not an approval verifier, native dispatch permit or
//! consumed owner. The native caller must retain its real owners and original.
use super::{Entry, Names as InitialNames, decode_snapshot, encode_fields};
use crate::security_epoch::{
    journal::snapshot_digest,
    kernel::{
        Snapshot, UpdateTime, Versioned, advance,
        restore::{self, approval_use},
    },
    restore_approval::publication::{self, Publication},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{collections::BTreeSet, marker::PhantomData, rc::Rc};

const MAX_RECORD_BYTES: usize = 32_768;

mod writer;

/// Names and full original-plan commitment, never caller-selected paths.
pub(in crate::security_epoch) struct Names {
    read: ReadSet,
    plan: Digest,
    expected_publication: Publication,
}

/// One complete read set and decoder for sending and peer confirmation.
struct ReadSet {
    selection: EpochStore,
    initial: InitialNames,
    advance: String,
    reservation: String,
    grant: String,
    publication: String,
    grant_id: Digest,
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
        publication: &Publication,
    ) -> Result<Self> {
        plan.require_publication_data(selection, publication)?;
        let selectors = plan.selectors(selection)?;
        Ok(Self {
            read: ReadSet::new(selection, &selectors, publication.grant_id_data())?,
            plan: plan_digest(plan)?,
            expected_publication: publication.clone(),
        })
    }

    fn documents(&self) -> Vec<&str> {
        self.read.documents()
    }

    /// Starts one transaction over all eight names. The complete captured read
    /// set is validated with the five writes at the same atomic commit.
    pub(in crate::security_epoch) fn begin_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"documents":self.documents(),"newTransaction":{"readWrite":{}}}),
        )?)
    }

    pub(in crate::security_epoch) fn strong_body(&self) -> Result<Vec<u8>> {
        self.read.strong_body()
    }

    pub(in crate::security_epoch) fn endpoint(&self, operation: &'static str) -> Result<String> {
        ensure!(
            ["batchGet", "commit", "rollback"].contains(&operation),
            "restore_provider_operation"
        );
        Ok(self.read.initial.endpoint(operation))
    }

    /// Retain a canonical header through semantic refusal for bounded cleanup.
    pub(in crate::security_epoch) fn transaction(self, bytes: &[u8]) -> Result<Transaction> {
        let (token, entries) = transaction_header(bytes, Stream::Reservation)?;
        Ok(Transaction {
            names: self,
            token,
            entries,
            local: PhantomData,
        })
    }

    pub(in crate::security_epoch) fn strong(&self, bytes: &[u8]) -> Result<Observed> {
        self.decode(entries(bytes, Stream::Reservation)?)
    }

    fn decode(&self, entries: Vec<Value>) -> Result<Observed> {
        let observed = self.read.decode(entries)?;
        ensure!(
            observed.publication.value == self.expected_publication,
            "restore_provider_publication_changed"
        );
        Ok(observed)
    }
}

/// Read-only peer selectors from the actual retained initial completion,
/// independently captured original operation and Active before-observation.
/// No caller document paths, transaction tokens or send operation are exposed.
pub(in crate::security_epoch) struct ConfirmationNames {
    read: ReadSet,
    stop: restore::StopSelection,
    initial: crate::security_epoch::kernel::Request,
    operation: Digest,
    before: Snapshot,
    confirmation: ReservationConfirmation,
}

impl ConfirmationNames {
    pub(in crate::security_epoch) fn new(
        selected: &EpochStore,
        initial: &crate::security_epoch::kernel::Request,
        operation: &Digest,
        stop: &restore::StopSelection,
        before: &Snapshot,
        confirmation: &ReservationConfirmation,
    ) -> Result<Self> {
        stop.check_active_data(selected, operation, initial, before)?;
        let selectors = approval_use::Selectors {
            bootstrap: initial.bootstrap().clone(),
            activation: initial.operation().clone(),
            advance: stop.advance_operation.clone(),
            operation: operation.clone(),
            grant: approval_use::use_key_data(selected, &confirmation.grant_id)?,
        };
        Ok(Self {
            read: ReadSet::new(selected, &selectors, &confirmation.grant_id)?,
            stop: stop.clone(),
            initial: initial.clone(),
            operation: operation.clone(),
            before: before.clone(),
            confirmation: confirmation.clone(),
        })
    }

    pub(in crate::security_epoch) fn matches_selection(&self, selection: &EpochStore) -> bool {
        self.read.selection == *selection
    }

    pub(in crate::security_epoch) fn endpoint(&self) -> String {
        self.read.initial.endpoint("batchGet")
    }

    pub(in crate::security_epoch) fn body(&self) -> Result<Vec<u8>> {
        self.read.strong_body()
    }

    /// This DATA result requires its own real guarded provider read. A prior
    /// parsed observation or the Controller's projection cannot satisfy it.
    pub(in crate::security_epoch) fn confirm(&self, bytes: &[u8]) -> Result<Observed> {
        let observed = self.read.decode(entries(bytes, Stream::Reservation)?)?;
        self.stop.check_fenced_data(
            &self.read.selection,
            &self.operation,
            &self.initial,
            &self.before,
            &observed.snapshot,
        )?;
        ensure!(
            observed.first_read
                >= timestamp(&String::from(self.confirmation.committed_at.clone()))?,
            "restore_peer_read_before_commit"
        );
        let written = [
            observed.snapshot.root.as_ref().map(|row| &row.version),
            observed.snapshot.sentinel.as_ref().map(|row| &row.version),
            observed.advance.as_ref().map(|row| &row.version),
            observed.reservation.as_ref().map(|row| &row.version),
            observed.grant.as_ref().map(|row| &row.version),
        ];
        ensure!(
            written
                .iter()
                .zip(&self.confirmation.written_versions)
                .all(|(actual, acknowledged)| *actual == Some(acknowledged))
                && observed
                    .grant
                    .as_ref()
                    .is_some_and(|row| row.value.grant_id_data() == &self.confirmation.grant_id)
                && observed.commitment_data()? == self.confirmation.records,
            "restore_peer_known_readset_changed"
        );
        Ok(observed)
    }
}

impl ReadSet {
    fn new(
        selection: &EpochStore,
        selectors: &approval_use::Selectors,
        grant_id: &Digest,
    ) -> Result<Self> {
        ensure!(
            selectors.grant == approval_use::use_key_data(selection, grant_id)?,
            "restore_provider_grant_selector_changed"
        );
        let initial =
            InitialNames::new(selection, &selectors.bootstrap, Some(&selectors.activation))?;
        let key = |value: &Digest| value.as_str()[7..].to_owned();
        let names = Self {
            publication: format!(
                "{}/documents/day2_restore_approval_publications_v1/{}",
                initial.database,
                key(&publication::key(selection, grant_id)?),
            ),
            grant_id: grant_id.clone(),
            selection: selection.clone(),
            advance: format!("{}/operations/{}", initial.root, key(&selectors.advance)),
            reservation: format!(
                "{}/restore_reservations/{}",
                initial.root,
                key(&selectors.operation)
            ),
            grant: format!("{}/restore_grants/{}", initial.root, key(&selectors.grant)),
            initial,
        };
        ensure!(
            names.documents().into_iter().collect::<BTreeSet<_>>().len() == 8,
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
            self.publication.as_str(),
        ]);
        names
    }

    /// The post-send read has the existing default strong consistency, never
    /// the pre-send transaction's old snapshot or a caller-supplied readTime.
    fn strong_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&json!({"documents":self.documents()}))?)
    }

    fn decode(&self, entries: Vec<Value>) -> Result<Observed> {
        let expected = self.documents();
        let mut seen = BTreeSet::new();
        let mut previous = None;
        let mut first = None;
        let mut initial = Vec::new();
        let (mut advance, mut reservation, mut grant, mut publication) = (None, None, None, None);
        for value in entries {
            ensure!(value.is_object(), "restore_provider_entry_object");
            let entry: RawEntry = serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("restore_provider_reply_encoding"))?;
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
                document_times(found, at)?;
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
            } else if name == self.grant {
                grant = record(entry.found, "day2-restore-grant-document-v1", at)?;
            } else {
                publication = Some(publication_record(
                    entry
                        .found
                        .context("restore_provider_publication_missing")?,
                    &self.selection,
                    &self.grant_id,
                )?);
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
            publication: publication.context("restore_provider_publication_missing")?,
            first_read: first.context("restore_provider_read_time")?,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawEntry {
    transaction: Option<String>,
    read_time: Option<String>,
    found: Option<Value>,
    missing: Option<String>,
}

enum Stream {
    Reservation,
    Writer,
}

fn transaction_header(bytes: &[u8], stream: Stream) -> Result<(String, Vec<Value>)> {
    let mut entries = entries(bytes, stream)?;
    let first = entries
        .first_mut()
        .context("restore_provider_stream_empty")?
        .as_object_mut()
        .context("restore_provider_entry_object")?;
    let token = first
        .remove("transaction")
        .and_then(|value| value.as_str().map(str::to_owned))
        .context("restore_provider_transaction_missing")?;
    let decoded = STANDARD
        .decode(&token)
        .map_err(|_| anyhow::anyhow!("restore_provider_transaction_encoding"))?;
    ensure!(
        !decoded.is_empty() && decoded.len() <= 1024 && STANDARD.encode(decoded) == token,
        "restore_provider_transaction_encoding"
    );
    if first.is_empty() {
        entries.remove(0);
    }
    Ok((token, entries))
}

fn entries(bytes: &[u8], stream: Stream) -> Result<Vec<Value>> {
    ensure!(
        bytes.len() <= super::MAX_BYTES,
        "restore_provider_reply_bound"
    );
    let values: Vec<Value> = crate::json::decode(bytes)
        .map_err(|_| anyhow::anyhow!("restore_provider_reply_encoding"))?;
    let limit = match stream {
        Stream::Reservation => 9,
        Stream::Writer => 11,
    };
    ensure!(
        !values.is_empty() && values.len() <= limit,
        "restore_provider_stream_bound"
    );
    Ok(values)
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

fn document_times(value: &Value, read: time::OffsetDateTime) -> Result<()> {
    let created = value
        .get("createTime")
        .and_then(Value::as_str)
        .context("restore_provider_document_time")?;
    let updated = value
        .get("updateTime")
        .and_then(Value::as_str)
        .context("restore_provider_document_time")?;
    let (created, updated) = (timestamp(created)?, timestamp(updated)?);
    ensure!(
        created <= updated && updated <= read,
        "restore_provider_document_time_order"
    );
    Ok(())
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

// Exact414 publication envelope, not the restore receipt envelope. Both the
// full signed record and actual provider version survive the consuming read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationDocument {
    name: String,
    fields: PublicationFields,
    create_time: UpdateTime,
    update_time: UpdateTime,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationFields {
    payload: Text,
    commitment: Text,
}

fn publication_record(
    found: Value,
    selected: &EpochStore,
    grant_id: &Digest,
) -> Result<Versioned<Publication>> {
    let document: PublicationDocument = serde_json::from_value(found)
        .map_err(|_| anyhow::anyhow!("restore_provider_publication_shape"))?;
    // The complete stream already checked exact name and ordered timestamps.
    let _ = (document.name, document.create_time);
    let payload = document.fields.payload.string_value;
    let value = Publication::decode(payload.as_bytes(), selected, grant_id)?;
    ensure!(
        value.encode(selected)? == payload.as_bytes()
            && document.fields.commitment.string_value
                == Digest::of(&("day2-restore-approval-publication-document-v1", &value))?.as_str(),
        "restore_provider_publication_changed"
    );
    Ok(Versioned {
        value,
        version: document.update_time,
    })
}

/// Historical provider DATA only, including an occupied grant-use record.
pub(in crate::security_epoch) struct Observed {
    pub snapshot: Snapshot,
    pub advance: Option<Versioned<advance::Receipt>>,
    pub reservation: Option<Versioned<restore::Receipt>>,
    pub grant: Option<Versioned<approval_use::UseRecord>>,
    pub publication: Versioned<Publication>,
    first_read: time::OffsetDateTime,
}

impl Observed {
    /// Commitment to every value AND provider version in the complete read.
    /// This is DATA for same-peer confirmation, never freshness or authority.
    pub(in crate::security_epoch) fn commitment_data(&self) -> Result<Digest> {
        fn versioned<T: Serialize>(value: &Option<Versioned<T>>) -> Option<(&T, &UpdateTime)> {
            value.as_ref().map(|row| (&row.value, &row.version))
        }
        Digest::of(&(
            "day2-restore-reservation-observation-v1",
            snapshot_digest(&self.snapshot)?,
            versioned(&self.advance),
            versioned(&self.reservation),
            versioned(&self.grant),
            (&self.publication.value, &self.publication.version),
        ))
    }

    /// Provider-time ordering only, not a local clock, freshness original or
    /// permission. The real sender must also keep its native postchecks.
    fn after_commit(
        &self,
        commit: &CommitRecord,
        before_publication: &Versioned<Publication>,
    ) -> Result<()> {
        ensure!(
            self.publication == *before_publication,
            "restore_provider_publication_version_changed"
        );
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
    committed_at: UpdateTime,
    versions: [UpdateTime; 5],
}

/// Publicly encodable confirmation DATA. The actual owner must retain its
/// genuine known send, original and peer; this projection cannot adopt a send
/// after uncertainty or construct any consumed approval/fenced continuation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct ReservationConfirmation {
    pub grant_id: Digest,
    pub committed_at: UpdateTime,
    pub written_versions: [UpdateTime; 5],
    pub records: Digest,
}

impl ReservationConfirmation {
    pub(in crate::security_epoch) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-known-restore-reservation-v1", self))
    }
}

/// Both the actual parsed ACK and complete checked readback survive the one
/// consuming send. Private fields close accidental projection reconstruction;
/// even this whole object remains provider DATA, not a genuine native owner.
pub(in crate::security_epoch) struct KnownReservation {
    observed: Observed,
    acknowledged: CommitRecord,
}

impl KnownReservation {
    pub(in crate::security_epoch) fn confirmation_data(&self) -> Result<ReservationConfirmation> {
        Ok(ReservationConfirmation {
            grant_id: self
                .observed
                .grant
                .as_ref()
                .context("restore_known_grant_missing")?
                .value
                .grant_id_data()
                .clone(),
            committed_at: self.acknowledged.committed_at.clone(),
            written_versions: self.acknowledged.versions.clone(),
            records: self.observed.commitment_data()?,
        })
    }

    /// DATA move only. The native producer must still retain and check its
    /// actual owner before and after the peer exchange and every real effect.
    pub(in crate::security_epoch) fn into_data(
        self,
    ) -> Result<(Observed, ReservationConfirmation)> {
        let confirmation = self.confirmation_data()?;
        Ok((self.observed, confirmation))
    }
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
    let committed = timestamp(&String::from(reply.commit_time.clone()))?;
    let versions = reply.write_results.map(|write| write.update_time);
    for version in &versions {
        ensure!(
            timestamp(&String::from(version.clone()))? <= committed,
            "restore_provider_commit_time_order"
        );
    }
    Ok(CommitRecord {
        committed,
        committed_at: reply.commit_time,
        versions,
    })
}

/// Transient provider transaction, not native approval or counter permission.
/// No clone, serialization, supplied-token constructor or automatic retry.
pub(in crate::security_epoch) struct Transaction {
    names: Names,
    token: String,
    entries: Vec<Value>,
    local: PhantomData<Rc<()>>,
}

impl Transaction {
    /// Consume THIS transaction into at most one commit, then a default-strong
    /// read of all eight original names. There is no retry or readback adoption
    /// after an unknown/invalid send. Returned observations remain DATA: the
    /// actual port must keep authority, original and mandatory postchecks live,
    /// and the caller must mark its actual approval May before this method.
    pub(in crate::security_epoch) fn commit_and_readback(
        self,
        port: &mut impl super::Port,
        mut budget: super::Budget,
        selection: &EpochStore,
        plan: &approval_use::Plan,
        current: &restore::Current,
        at: i64,
    ) -> Result<KnownReservation> {
        let body = match self.commit_body(selection, plan, current, at) {
            Ok(body) => body,
            Err(primary) => {
                // Cleanup only before any commit attempt. Keep the semantic
                // refusal primary even if the same bounded port also refuses.
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
            let committed = commit_reply(&bytes)?;
            let bytes = budget.call(
                port,
                &self.names.endpoint("batchGet")?,
                &self.names.strong_body()?,
            )?;
            let after = self.names.strong(&bytes)?;
            self.check_commit(&committed, &after)?;
            ensure!(
                after.snapshot.create == plan.reservation.before.create
                    && after.snapshot.activate == plan.reservation.before.activate,
                "restore_provider_immutable_history_changed"
            );
            let versions = [
                after.snapshot.root.as_ref().map(|row| &row.version),
                after.snapshot.sentinel.as_ref().map(|row| &row.version),
                after.advance.as_ref().map(|row| &row.version),
                after.reservation.as_ref().map(|row| &row.version),
                after.grant.as_ref().map(|row| &row.version),
            ];
            ensure!(
                versions
                    .iter()
                    .zip(&committed.versions)
                    .all(|(actual, written)| *actual == Some(written)),
                "restore_provider_written_versions_changed"
            );
            ensure!(
                matches!(
                    approval_use::reconcile(
                        selection,
                        plan,
                        &after.snapshot,
                        after.advance.as_ref(),
                        after.reservation.as_ref(),
                        after.grant.as_ref(),
                    )?,
                    restore::Outcome::Applied(_)
                ),
                "restore_provider_reservation_not_applied"
            );
            budget.remaining_decoding(port)?;
            Ok(KnownReservation {
                observed: after,
                acknowledged: committed,
            })
        })();
        if requested.is_err() {
            port.refuse();
        }
        requested
    }

    /// Bind the post-read to the publication captured by THIS retained
    /// read-write transaction. Callers cannot substitute the post-read itself
    /// as its own before-version. This is still DATA, never consumption.
    pub(in crate::security_epoch) fn check_commit(
        &self,
        commit: &CommitRecord,
        after: &Observed,
    ) -> Result<()> {
        after.after_commit(commit, &self.observed()?.publication)
    }

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
            self.names.read.selection == *selection && self.names.plan == plan_digest(plan)?,
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
            initial_write(&self.names.read.initial.root, serde_json::to_value(&advance.root)?, json!({"updateTime":root_version}))?,
            initial_write(&self.names.read.initial.sentinel, serde_json::to_value(&advance.sentinel)?, json!({"updateTime":sentinel_version}))?,
            receipt_write(&self.names.read.advance, &advance.receipt, "day2-restore-advance-document-v1")?,
            receipt_write(&self.names.read.reservation, &plan.reservation.receipt, "day2-restore-reservation-document-v1")?,
            receipt_write(&self.names.read.grant, &plan.approval_use, "day2-restore-grant-document-v1")?,
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
