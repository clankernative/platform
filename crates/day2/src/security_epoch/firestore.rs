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

mod paired;
pub(super) use paired::{ActionTransaction, begin_action, read_with_slot};

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

    /// A native execution context may observe only its SAME retained phase.
    /// Unrelated/ordinary ports cannot substitute equal clock/selection DATA.
    fn sample_for_context(
        &mut self,
        _owner: &Rc<
            std::cell::RefCell<super::storage_authority::CurrentStorageBootstrapPhase<'_, '_>>,
        >,
    ) -> Result<Sample> {
        self.refuse();
        anyhow::bail!("security_epoch_native_context_port_required")
    }

    /// Clock DATA after a fixed context's full observation and pure checks.
    /// This never supplies a physical/role observation or a reusable witness.
    fn clock_for_context(
        &mut self,
        _owner: &Rc<
            std::cell::RefCell<super::storage_authority::CurrentStorageBootstrapPhase<'_, '_>>,
        >,
    ) -> Result<Sample> {
        self.refuse();
        anyhow::bail!("security_epoch_native_context_port_required")
    }

    /// DATA-only time spent decoding an already received response. The default
    /// retains full checks; only the closed Controller transport may borrow its
    /// SAME retained native clock here. This is never an authority observation.
    fn decoding_sample(&mut self) -> Result<Sample> {
        self.sample()
    }

    /// One guarded exchange under THIS actual caller budget. Implementations
    /// must charge all pre-send work before selecting the timeout and all full
    /// postchecks before returning. No proxy, redirect or automatic retry.
    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply>;

    /// Refusal only, including failures of the central response/budget contract.
    fn refuse(&mut self);
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
        Self::from_original_parts(sample, origin, deadline, ACQUISITION_BUDGET)
    }

    /// Only an ACTUAL purpose-bound clock can select the bootstrap ceiling.
    /// This budget still grants no port, writer or role permission.
    pub(super) fn from_storage_bootstrap(
        acquisition: &mut super::native_clock::NativeAcquisition,
    ) -> Result<Self> {
        acquisition.require_storage_bootstrap()?;
        let (origin, deadline) = acquisition.interval_data()?;
        let sample = acquisition.sample()?;
        Self::from_original_parts(
            sample,
            origin,
            deadline,
            super::native_clock::STORAGE_BOOTSTRAP_LIMIT,
        )
    }

    fn from_original_parts(
        sample: Sample,
        origin: Duration,
        deadline: Duration,
        maximum: Duration,
    ) -> Result<Self> {
        ensure!(
            sample.elapsed >= origin
                && sample.elapsed < deadline
                && deadline > origin
                && deadline - origin <= maximum,
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

    /// Derive only from this actual budget. A context cannot use a scalar
    /// deadline to select the storage-bootstrap ceiling or restart its origin.
    pub(super) fn narrow_for_context(
        &mut self,
        sample: Sample,
        deadline: Duration,
    ) -> Result<Self> {
        self.limit = self.limit.min(
            deadline
                .checked_sub(self.start)
                .context("security_epoch_context_expired")?,
        );
        self.observe(sample)?;
        Ok(Self {
            domain: self.domain.clone(),
            start: self.start,
            latest: self.latest,
            limit: self.limit,
        })
    }

    pub(super) fn remaining(&mut self, port: &mut impl Port) -> Result<Duration> {
        let sample = port.sample()?;
        self.observe(sample)
    }

    /// Pure clock checkpoint. A guarded post owns its full authority envelope;
    /// this also charges its completed work centrally. Context/budget issuance
    /// and observation consumers continue to use full `remaining`.
    pub(super) fn remaining_decoding(&mut self, port: &mut impl Port) -> Result<Duration> {
        self.observe(port.decoding_sample()?)
    }

    /// Intersect two ACTUAL retained time budgets at the supplied fresh clock
    /// DATA. Neither origin/latest is reset, and no role or permission is made.
    /// The caller must obtain this sample inside its same-owner full envelope.
    pub(super) fn constrain_to(&mut self, other: &mut Self, sample: &Sample) -> Result<Duration> {
        self.observe(Sample {
            domain: sample.domain.clone(),
            elapsed: sample.elapsed,
        })?;
        other.observe(Sample {
            domain: sample.domain.clone(),
            elapsed: sample.elapsed,
        })?;
        let ceiling = other
            .start
            .checked_add(other.limit)
            .context("security_epoch_clock_overflow")?;
        self.limit = self.limit.min(
            ceiling
                .checked_sub(self.start)
                .context("security_epoch_acquisition_expired")?,
        );
        self.observe(Sample {
            domain: sample.domain.clone(),
            elapsed: sample.elapsed,
        })
    }

    pub(super) fn remaining_native(
        &mut self,
        acquisition: &mut super::native_clock::NativeAcquisition,
    ) -> Result<Duration> {
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
        let result = (|| {
            ensure!(body.len() <= MAX_BYTES, "security_epoch_request_budget");
            // The closed transport spends this SAME budget inside its mandatory
            // authority envelope; a second full envelope here would duplicate
            // file/peer observations without adding another HTTP operation.
            let response = port.post(url, body, self, MAX_BYTES)?;
            // Charge all returned postwork centrally too. Ordinary ports keep
            // their previous full sample; only the closed Controller uses its
            // actual clock here after its mandatory full physical postguard.
            self.remaining_decoding(port)?;
            ensure!(
                response.status == 200,
                "security_epoch_provider_unavailable"
            );
            ensure!(
                response.body.len() <= MAX_BYTES,
                "security_epoch_response_budget"
            );
            Ok(response.body)
        })();
        if result.is_err() {
            port.refuse();
        }
        result
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

    pub(super) fn endpoint(&self, operation: &str) -> String {
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
        budget.remaining_decoding(port)?;
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
        let result = (|| {
            self.check_binding(selection)?;
            self.budget.remaining(port)
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    pub(super) fn check_binding(&mut self, selection: &EpochStore) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "security_epoch_observation_refused");
            ensure!(
                self.selection == Digest::of(selection)?,
                "security_epoch_observation_selection_changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    /// Time DATA only, within the fixed mutation's full context observation.
    /// The immutable selection is checked separately before that observation.
    pub(super) fn constrain_budget(&mut self, budget: &mut Budget, sample: &Sample) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "security_epoch_observation_refused");
            budget.constrain_to(&mut self.budget, sample)?;
            Ok(())
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
    budget.remaining_decoding(port)?;
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
    budget.remaining_decoding(port)?;
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
    dispatch: super::journal::AuthorizedDispatch<'_, '_>,
) -> Result<()> {
    let reply = dispatch.prepare(selection, port)?.send(selection, port)?;
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
    let response: CommitResponse = crate::json::decode(reply.bytes())?;
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
    reply.finish(selection, port)
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    // Independent DATA transport model: successful time arithmetic must never
    // replace the full pre/post authority observations around a real operation.
    struct BoundaryPort {
        domain: Digest,
        now: Duration,
        full_checks: usize,
        clock_checks: usize,
        posts: usize,
        refused: bool,
        refuse_after_post: bool,
    }

    impl Port for BoundaryPort {
        fn sample(&mut self) -> Result<Sample> {
            self.full_checks += 1;
            ensure!(!self.refused, "model_authority_refused");
            Ok(Sample {
                domain: self.domain.clone(),
                elapsed: self.now,
            })
        }

        fn decoding_sample(&mut self) -> Result<Sample> {
            self.clock_checks += 1;
            Ok(Sample {
                domain: self.domain.clone(),
                elapsed: self.now,
            })
        }

        fn post(&mut self, _: &str, _: &[u8], budget: &mut Budget, _: usize) -> Result<EpochReply> {
            budget.remaining(self)?;
            self.posts += 1;
            self.refused |= self.refuse_after_post;
            budget.remaining(self)?;
            Ok(EpochReply {
                status: 200,
                body: Vec::new(),
            })
        }

        fn refuse(&mut self) {
            self.refused = true;
        }
    }

    fn boundary() -> (Budget, BoundaryPort) {
        let domain = Digest::new(b"decoding-time-is-not-authority");
        let budget = Budget::from_original_parts(
            Sample {
                domain: domain.clone(),
                elapsed: Duration::from_secs(100),
            },
            Duration::from_secs(100),
            Duration::from_secs(130),
            super::super::native_clock::STORAGE_BOOTSTRAP_LIMIT,
        )
        .unwrap();
        (
            budget,
            BoundaryPort {
                domain,
                now: Duration::from_secs(101),
                full_checks: 0,
                clock_checks: 0,
                posts: 0,
                refused: false,
                refuse_after_post: false,
            },
        )
    }

    #[test]
    fn decoding_time_cannot_substitute_for_http_or_consumer_authority() {
        for (refused, refuse_after_post, expected_posts) in [(true, false, 0), (false, true, 1)] {
            let (mut budget, mut port) = boundary();
            port.refused = refused;
            port.refuse_after_post = refuse_after_post;
            assert!(budget.remaining_decoding(&mut port).is_ok());
            assert_eq!((port.full_checks, port.clock_checks), (0, 1));
            assert!(budget.call(&mut port, "fixed-test-contract", &[]).is_err());
            assert_eq!(port.posts, expected_posts);
            assert_eq!(port.full_checks, expected_posts + 1);
            // Observation consumers still call the original full remaining.
            assert!(budget.remaining(&mut port).is_err());
        }
        let (mut budget, mut port) = boundary();
        budget.remaining_decoding(&mut port).unwrap();
        budget.call(&mut port, "fixed-test-contract", &[]).unwrap();
        assert_eq!((port.full_checks, port.clock_checks, port.posts), (2, 2, 1));
    }

    #[test]
    fn decoding_time_keeps_original_domain_monotonicity_and_exclusive_deadline() {
        for change in [0, 1, 2] {
            let (mut budget, mut port) = boundary();
            budget.remaining_decoding(&mut port).unwrap();
            match change {
                0 => port.domain = Digest::new(b"foreign-clock"),
                1 => port.now = Duration::from_millis(100_999),
                _ => port.now = Duration::from_secs(130),
            }
            assert!(budget.remaining_decoding(&mut port).is_err());
            assert_eq!(port.posts, 0);
            assert_eq!(budget.start, Duration::from_secs(100));
            assert_eq!(budget.limit, Duration::from_secs(30));
        }
    }

    // Arithmetic/transport-contract DATA only. This port owns no enrolled role,
    // file, native clock, credential, writable journal or provider connection.
    struct ObservedTimeout {
        domain: Digest,
        now: Duration,
        selected: Option<Duration>,
        refused: bool,
    }

    impl Port for ObservedTimeout {
        fn sample(&mut self) -> Result<Sample> {
            ensure!(!self.refused, "model_transport_refused");
            Ok(Sample {
                domain: self.domain.clone(),
                elapsed: self.now,
            })
        }

        fn post(
            &mut self,
            _url: &str,
            _body: &[u8],
            budget: &mut Budget,
            max_bytes: usize,
        ) -> Result<EpochReply> {
            assert_eq!(max_bytes, MAX_BYTES);
            let timeout = budget.remaining(self)?.min(ACQUISITION_BUDGET);
            self.selected = Some(timeout);
            Ok(EpochReply {
                status: 200,
                body: Vec::new(),
            })
        }

        fn refuse(&mut self) {
            self.refused = true;
        }
    }

    #[test]
    fn storage_budget_keeps_origin_and_caps_each_request_at_five_seconds() {
        let domain = Digest::new(b"budget-arithmetic-only");
        for (limit, expected) in [(5, 3), (10, 5), (30, 5), (60, 5)] {
            let mut port = ObservedTimeout {
                domain: domain.clone(),
                now: Duration::from_secs(102),
                selected: None,
                refused: false,
            };
            let mut budget = Budget::from_original_parts(
                port.sample().unwrap(),
                Duration::from_secs(100),
                Duration::from_secs(100 + limit),
                super::super::native_clock::STORAGE_BOOTSTRAP_LIMIT,
            )
            .unwrap();
            budget.call(&mut port, "fixed-test-contract", &[]).unwrap();
            assert_eq!(port.selected, Some(Duration::from_secs(expected)));
            assert_eq!(budget.start, Duration::from_secs(100));
            assert_eq!(
                budget.remaining(&mut port).unwrap(),
                Duration::from_secs(limit - 2)
            );
            port.now = Duration::from_secs(100 + limit);
            assert!(budget.call(&mut port, "fixed-test-contract", &[]).is_err());
        }
    }

    #[test]
    fn context_budget_consumes_actual_spent_time_and_only_tightens_its_deadline() {
        let domain = Digest::new(b"context-budget-data-only");
        let sample = |milliseconds| Sample {
            domain: domain.clone(),
            elapsed: Duration::from_millis(milliseconds),
        };
        let mut original = Budget::from_original_parts(
            sample(100_000),
            Duration::from_secs(100),
            Duration::from_secs(110),
            super::super::native_clock::STORAGE_BOOTSTRAP_LIMIT,
        )
        .unwrap();
        let mut context = original
            .narrow_for_context(sample(106_300), Duration::from_secs(109))
            .unwrap();
        assert_eq!(context.start, Duration::from_secs(100));
        assert_eq!(
            context.observe(sample(106_300)).unwrap(),
            Duration::from_millis(2700)
        );
        let mut next = context
            .narrow_for_context(sample(107_000), Duration::from_secs(112))
            .unwrap();
        assert_eq!(
            next.observe(sample(107_000)).unwrap(),
            Duration::from_secs(2)
        );
        assert!(
            next.narrow_for_context(sample(109_000), Duration::from_secs(112))
                .is_err()
        );
        assert!(
            context
                .narrow_for_context(sample(106_000), Duration::from_secs(109))
                .is_err()
        );
        assert!(
            original
                .narrow_for_context(
                    Sample {
                        domain: Digest::new(b"different-domain"),
                        elapsed: Duration::from_secs(107),
                    },
                    Duration::from_secs(109)
                )
                .is_err()
        );
        // The ordinary scalar context factory still cannot select ten seconds.
        assert!(Budget::for_context(sample(100_000), Duration::from_secs(110)).is_err());
    }
}
