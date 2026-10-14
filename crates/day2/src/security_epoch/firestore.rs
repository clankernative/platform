//! Bounded Firestore REST codec over private native ports. There is deliberately
//! no production port implementation until immutable provider identity, current
//! role, execution and continuous-clock producers have been qualified together.
//! Parsing authenticated bytes alone would still not mint readiness.
use super::kernel::{
    self, AuthorityRecord, Bootstrap, Phase, Receipt, Request, SentinelRecord, Snapshot,
    UpdateTime, Versioned,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochProvider, EpochStore},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc, time::Duration};

const MAX_BYTES: usize = 65_536;
const ACQUISITION_BUDGET: Duration = Duration::from_secs(5);

/// A port sample is not a transferable clock proof. The unqualified live port
/// cannot be installed by an app, deserialized configuration or caller closure.
pub(super) struct Sample {
    pub domain: Digest,
    pub elapsed: Duration,
}

pub(super) struct EpochReply {
    pub status: u16,
    pub body: Vec<u8>,
}

pub(super) trait Port {
    fn sample(&mut self) -> Result<Sample>;
    // Exactly one bounded HTTPS request; no proxy, redirect or automatic retry.
    // A future live implementation must enforce the response limit while reading.
    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<EpochReply>;
}

pub(super) struct Budget {
    domain: Digest,
    start: Duration,
    latest: Duration,
    limit: Duration,
}

impl Budget {
    pub(super) fn from_native_origin(
        sample: Sample,
        origin: Duration,
        deadline: Duration,
    ) -> Result<Self> {
        ensure!(
            sample.elapsed >= origin
                && sample.elapsed < deadline
                && deadline > origin
                && deadline - origin <= ACQUISITION_BUDGET,
            "security_epoch_original_native_budget"
        );
        Ok(Self {
            domain: sample.domain,
            start: origin,
            latest: sample.elapsed,
            limit: deadline - origin,
        })
    }

    fn begin(port: &mut impl Port, max_lease_seconds: u32) -> Result<Self> {
        let sample = port.sample()?;
        Ok(Self {
            domain: sample.domain,
            start: sample.elapsed,
            latest: sample.elapsed,
            limit: ACQUISITION_BUDGET.min(Duration::from_secs(u64::from(max_lease_seconds))),
        })
    }

    pub(super) fn for_context(sample: Sample, deadline: Duration) -> Result<Self> {
        let limit = deadline
            .checked_sub(sample.elapsed)
            .context("security_epoch_context_expired")?;
        ensure!(
            !limit.is_zero() && limit <= ACQUISITION_BUDGET,
            "security_epoch_context_budget"
        );
        Ok(Self {
            domain: sample.domain,
            start: sample.elapsed,
            latest: sample.elapsed,
            limit,
        })
    }

    pub(super) fn remaining(&mut self, port: &mut impl Port) -> Result<Duration> {
        let sample = port.sample()?;
        self.observe(sample)
    }

    pub(super) fn remaining_native(&mut self, acquisition: &mut super::native_clock::NativeAcquisition) -> Result<Duration> {
        self.observe(acquisition.sample()?)
    }

    fn observe(&mut self, sample: Sample) -> Result<Duration> {
        ensure!(
            sample.domain == self.domain && sample.elapsed >= self.latest,
            "security_epoch_clock_domain_or_rewind"
        );
        self.latest = sample.elapsed;
        let elapsed = sample
            .elapsed
            .checked_sub(self.start)
            .context("security_epoch_clock_rewind")?;
        let remaining = self
            .limit
            .checked_sub(elapsed)
            .context("security_epoch_acquisition_expired")?;
        ensure!(!remaining.is_zero(), "security_epoch_acquisition_expired");
        Ok(remaining)
    }

    pub(super) fn call(&mut self, port: &mut impl Port, url: &str, body: &[u8]) -> Result<Vec<u8>> {
        ensure!(body.len() <= MAX_BYTES, "security_epoch_request_budget");
        let timeout = self.remaining(port)?;
        let response = port.post(url, body, timeout, MAX_BYTES)?;
        self.remaining(port)?;
        ensure!(
            response.status == 200,
            "security_epoch_provider_unavailable"
        );
        ensure!(
            response.body.len() <= MAX_BYTES,
            "security_epoch_response_budget"
        );
        Ok(response.body)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Names {
    selection: EpochStore,
    bootstrap: Bootstrap,
    database: String,
    pub root: String,
    pub sentinel: String,
    pub create: String,
    pub activate: Option<String>,
}

impl Names {
    pub(super) fn matches_selection(&self, selection: &EpochStore) -> bool {
        self.selection == *selection
    }

    pub(super) fn new(
        selection: &EpochStore,
        bootstrap: &Bootstrap,
        activate: Option<&Digest>,
    ) -> Result<Self> {
        bootstrap.validate_selection(selection)?;
        let EpochProvider::FirestoreNativeV1 {
            project, database, ..
        } = &selection.provider;
        let database = format!(
            "projects/{}/databases/{}",
            project.as_str(),
            database.as_str()
        );
        let key = bootstrap
            .authority
            .as_str()
            .strip_prefix("sha256:")
            .context("security_epoch_authority_key")?;
        let root = format!("{database}/documents/day2_credential_authority_v1/{key}");
        let sentinel = format!("{database}/documents/day2_credential_bootstrap_v1/{key}");
        let receipt =
            |operation: &Digest| format!("{root}/operations/{}", &operation.as_str()[7..]);
        ensure!(
            activate != Some(&bootstrap.create_operation),
            "security_epoch_operation_reused"
        );
        Ok(Self {
            selection: selection.clone(),
            bootstrap: bootstrap.clone(),
            database,
            root: root.clone(),
            sentinel,
            create: receipt(&bootstrap.create_operation),
            activate: activate.map(receipt),
        })
    }

    fn documents(&self) -> Vec<&str> {
        let mut names = vec![
            self.root.as_str(),
            self.sentinel.as_str(),
            self.create.as_str(),
        ];
        names.extend(self.activate.as_deref());
        names
    }

    fn endpoint(&self, operation: &str) -> String {
        format!(
            "https://firestore.googleapis.com/v1/{}/documents:{operation}",
            self.database
        )
    }

    pub(super) fn read_body(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &json!({"documents":self.documents(),"newTransaction":{"readOnly":{}}}),
        )?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Field {
    #[serde(rename = "stringValue")]
    String(String),
    #[serde(rename = "mapValue")]
    Map(Fields),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fields {
    fields: BTreeMap<String, Field>,
}

fn encode_fields(value: Value) -> Result<BTreeMap<String, Field>> {
    let Value::Object(values) = value else {
        bail!("security_epoch_record_not_object");
    };
    values
        .into_iter()
        .map(|(key, value)| {
            let field = match value {
                Value::String(value) => Field::String(value),
                Value::Object(_) => Field::Map(Fields {
                    fields: encode_fields(value)?,
                }),
                _ => bail!("security_epoch_record_field_type"),
            };
            Ok((key, field))
        })
        .collect()
}

fn decode_fields(fields: BTreeMap<String, Field>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    match value {
                        Field::String(value) => Value::String(value),
                        Field::Map(value) => decode_fields(value.fields),
                    },
                )
            })
            .collect::<Map<_, _>>(),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    name: String,
    fields: BTreeMap<String, Field>,
    create_time: UpdateTime,
    update_time: UpdateTime,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    transaction: Option<String>,
    read_time: Option<String>,
    found: Option<Document>,
    missing: Option<String>,
}

/// The token is only a transient provider read transaction. It cannot authorize
/// a write, survive serialization or become an app/process readiness handle.
pub(super) struct ReadTransaction {
    token: String,
}

impl ReadTransaction {
    fn rollback(self, port: &mut impl Port, budget: &mut Budget, names: &Names) -> Result<()> {
        let body = serde_json::to_vec(&json!({"transaction":self.token}))?;
        let bytes = budget.call(port, &names.endpoint("rollback"), &body)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Empty {}
        let _: Empty = crate::json::decode(&bytes)?;
        budget.remaining(port)?;
        Ok(())
    }
}

fn decode_snapshot(names: &Names, entries: Vec<Entry>) -> Result<Snapshot> {
    let mut documents = BTreeMap::new();
    let expected = names.documents();
    let mut previous_time = None;
    for entry in entries {
        ensure!(
            entry.transaction.is_none(),
            "security_epoch_duplicate_transaction"
        );
        let document = match (entry.found, entry.missing) {
            (Some(found), None) => (found.name.clone(), Some(found)),
            (None, Some(missing)) => (missing, None),
            _ => bail!("security_epoch_invalid_batch_result"),
        };
        let read_time = entry
            .read_time
            .context("security_epoch_read_time_missing")?;
        let read_time = time::OffsetDateTime::parse(
            &read_time,
            &time::format_description::well_known::Rfc3339,
        )?;
        ensure!(
            previous_time.is_none_or(|previous| previous <= read_time),
            "security_epoch_provider_read_time_rewind"
        );
        previous_time = Some(read_time);
        ensure!(
            expected.contains(&document.0.as_str()),
            "security_epoch_unrequested_document"
        );
        ensure!(
            documents.insert(document.0, document.1).is_none(),
            "security_epoch_duplicate_document"
        );
    }
    ensure!(
        documents.len() == expected.len(),
        "security_epoch_incomplete_snapshot"
    );
    fn take<T: DeserializeOwned>(
        documents: &mut BTreeMap<String, Option<Document>>,
        name: &str,
    ) -> Result<Option<Versioned<T>>> {
        documents
            .remove(name)
            .context("security_epoch_document_missing")?
            .map(|document| {
                let created = time::OffsetDateTime::parse(
                    &String::from(document.create_time),
                    &time::format_description::well_known::Rfc3339,
                )?;
                let updated = time::OffsetDateTime::parse(
                    &String::from(document.update_time.clone()),
                    &time::format_description::well_known::Rfc3339,
                )?;
                ensure!(created <= updated, "security_epoch_document_time_order");
                Ok(Versioned {
                    value: serde_json::from_value(decode_fields(document.fields))?,
                    version: document.update_time,
                })
            })
            .transpose()
    }
    Ok(Snapshot {
        root: take::<AuthorityRecord>(&mut documents, &names.root)?,
        sentinel: take::<SentinelRecord>(&mut documents, &names.sentinel)?,
        create: take::<Receipt>(&mut documents, &names.create)?,
        activate: names
            .activate
            .as_ref()
            .map(|name| take::<Receipt>(&mut documents, name))
            .transpose()?
            .flatten(),
    })
}

/// Keeps the original before-I/O acquisition interval with parsed DATA. The
/// controlled port is still unqualified: this is NOT a current role, physical
/// database identity or bootstrap permission, and cannot construct one.
pub(crate) struct EpochObservation {
    selection: Digest,
    snapshot: Snapshot,
    budget: Budget,
    valid: bool,
    local: PhantomData<Rc<()>>,
}

impl EpochObservation {
    pub(super) fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub(super) fn remaining(
        &mut self,
        selection: &EpochStore,
        port: &mut impl Port,
    ) -> Result<Duration> {
        ensure!(self.valid, "security_epoch_observation_refused");
        let result = (|| {
            ensure!(
                self.selection == Digest::of(selection)?,
                "security_epoch_observation_selection_changed"
            );
            self.budget.remaining(port)
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    /// Deliberately discards acquisition state. The result is historical DATA.
    pub(super) fn into_data(self) -> Snapshot {
        self.snapshot
    }
}

pub(super) fn read(port: &mut impl Port, names: &Names) -> Result<EpochObservation> {
    let budget = Budget::begin(port, names.selection.max_lease_seconds)?;
    read_with_budget(port, names, budget)
}

pub(super) fn read_with_budget(
    port: &mut impl Port,
    names: &Names,
    mut budget: Budget,
) -> Result<EpochObservation> {
    let mut snapshot = read_once(port, &mut budget, names)?;
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
        // Discovery supplies only a bounded document selector. Discard the first
        // snapshot and reread ALL four documents in a fresh coherent transaction
        // under the original deadline; never splice an old root and a new receipt.
        let operation = completion.operation.clone();
        let complete = Names::new(&names.selection, &names.bootstrap, Some(&operation))?;
        snapshot = read_once(port, &mut budget, &complete)?;
        ensure!(
            matches!(&snapshot.root, Some(root) if matches!(&root.value.phase, Phase::ActiveFirstHolder { completion } if completion.operation == operation)),
            "security_epoch_discovery_state_changed"
        );
    }
    kernel::reconcile(
        &names.selection,
        &Request::CreateInitialAuthority {
            bootstrap: names.bootstrap.clone(),
        },
        &snapshot,
    )?;
    budget.remaining(port)?;
    Ok(EpochObservation {
        selection: Digest::of(&names.selection)?,
        snapshot,
        budget,
        valid: true,
        local: PhantomData,
    })
}

fn read_once(port: &mut impl Port, budget: &mut Budget, names: &Names) -> Result<Snapshot> {
    let bytes = budget.call(port, &names.endpoint("batchGet"), &names.read_body()?)?;
    // Duplicate keys (including escaped keys) are rejected before serde maps.
    let mut entries: Vec<Entry> = crate::json::decode(&bytes)?;
    ensure!(
        !entries.is_empty() && entries.len() <= names.documents().len() + 1,
        "security_epoch_batch_size"
    );
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
    // The first streamed entry may contain only the transaction, or also a doc.
    let header_only = entries[0].found.is_none() && entries[0].missing.is_none();
    let result = if header_only && entries[0].read_time.is_some() {
        Err(anyhow::anyhow!("security_epoch_transaction_header_fields"))
    } else {
        if header_only {
            entries.remove(0);
        }
        decode_snapshot(names, entries)
    };
    // Semantic decode failures also close the observed read transaction. If the
    // bounded cleanup fails, no snapshot escapes as a successful observation.
    transaction.rollback(port, budget, names)?;
    budget.remaining(port)?;
    result
}

pub(super) fn commit_body(selection: &EpochStore, request: &Request) -> Result<Vec<u8>> {
    request.validate(selection)?;
    let activate = match request {
        Request::CreateInitialAuthority { .. } => None,
        Request::CompleteInitialFirstActivation { operation, .. } => Some(operation),
    };
    let names = Names::new(selection, request.bootstrap(), activate)?;
    let (root, sentinel) = request.records()?;
    fn write<T: Serialize>(name: &str, value: &T, condition: Value) -> Result<Value> {
        Ok(
            json!({"update":{"name":name,"fields":encode_fields(serde_json::to_value(value)?)?},"currentDocument":condition}),
        )
    }
    let (root_condition, sentinel_condition, receipt_name) = match request {
        Request::CreateInitialAuthority { .. } => (
            json!({"exists":false}),
            json!({"exists":false}),
            names.create.as_str(),
        ),
        Request::CompleteInitialFirstActivation { before, .. } => (
            json!({"updateTime":String::from(before.root.clone())}),
            json!({"updateTime":String::from(before.sentinel.clone())}),
            names
                .activate
                .as_deref()
                .context("security_epoch_activation_name")?,
        ),
    };
    let bytes = serde_json::to_vec(&json!({"writes":[
        write(&names.root, &root, root_condition)?,
        write(&names.sentinel, &sentinel, sentinel_condition)?,
        write(receipt_name, &request.receipt()?, json!({"exists":false}))?,
    ]}))?;
    ensure!(bytes.len() <= MAX_BYTES, "security_epoch_request_budget");
    Ok(bytes)
}

/// A successful HTTP response is only a historical acknowledgement. Callers
/// always reconcile the exact receipt and coherent current records separately.
pub(super) fn commit(
    port: &mut impl Port,
    selection: &EpochStore,
    dispatch: super::journal::AuthorizedDispatch,
) -> Result<()> {
    let (request, mut budget) = dispatch.prepare(selection, port)?;
    let names = Names::new(selection, request.bootstrap(), None)?;
    let bytes = budget.call(
        port,
        &names.endpoint("commit"),
        &commit_body(selection, &request)?,
    )?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CommitResponse {
        write_results: Vec<WriteResult>,
        commit_time: UpdateTime,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WriteResult {
        update_time: UpdateTime,
    }
    let response: CommitResponse = crate::json::decode(&bytes)?;
    ensure!(
        response.write_results.len() == 3,
        "security_epoch_commit_result_count"
    );
    let commit = time::OffsetDateTime::parse(
        &String::from(response.commit_time),
        &time::format_description::well_known::Rfc3339,
    )?;
    for write in response.write_results {
        let update = time::OffsetDateTime::parse(
            &String::from(write.update_time),
            &time::format_description::well_known::Rfc3339,
        )?;
        ensure!(update <= commit, "security_epoch_commit_time_order");
    }
    budget.remaining(port)?;
    Ok(())
}
