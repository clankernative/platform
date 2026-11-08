//! Fixed receiving-App strong-read DATA. No controller plan, native stage,
//! role, port, original, file/P3 or keeper can be constructed from these values.
use super::super::{ReadSet, Stream, entries, timestamp};
use super::{KnownWriter, Observed, decode_observed, kernel};
use crate::security_epoch::{
    kernel::{Holder, UpdateTime, Versioned},
    native_enrollment::{
        RestoreFileProjectionData as Projection, RestoreWriterActivationData as Activation,
    },
};
use anyhow::{Context as _, Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};

/// Exact acknowledged-record expectations, signed inside Activated. This is
/// historical DATA only. The App must perform its OWN actual strong read and
/// original/native/file pre/postchecks before its first read-write keeper.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct ReadExpectation {
    records: [Digest; 10],
    versions: [UpdateTime; 10],
    committed_at: UpdateTime,
    read_floor: UpdateTime,
}

impl<'de> Deserialize<'de> for ReadExpectation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            records: [Digest; 10],
            versions: [UpdateTime; 10],
            committed_at: UpdateTime,
            read_floor: UpdateTime,
        }
        struct MapOnly;
        impl<'de> Visitor<'de> for MapOnly {
            type Value = ReadExpectation;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a closed writer read expectation")
            }
            fn visit_map<M: MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let Wire {
                    records,
                    versions,
                    committed_at,
                    read_floor,
                } = Wire::deserialize(MapAccessDeserializer::new(map))?;
                Ok(ReadExpectation {
                    records,
                    versions,
                    committed_at,
                    read_floor,
                })
            }
        }
        deserializer.deserialize_map(MapOnly)
    }
}

impl ReadExpectation {
    /// Acknowledged provider UTC DATA, never a native clock or new deadline.
    pub(in crate::security_epoch) fn committed_at_data(&self) -> &UpdateTime {
        &self.committed_at
    }

    fn check(&self, activation: &Activation) -> Result<()> {
        let commit = timestamp(&String::from(self.committed_at.clone()))?;
        let floor = timestamp(&String::from(self.read_floor.clone()))?;
        ensure!(
            floor >= commit,
            "restore_peer_writer_read_floor_before_commit"
        );
        for version in &self.versions {
            ensure!(
                timestamp(&String::from(version.clone()))? <= commit,
                "restore_peer_writer_version_after_commit"
            );
        }
        ensure!(
            self.versions[0] == activation.root_version
                && self.versions[1] == activation.sentinel_version
                && self.versions[9] == activation.receipt_version
                && activation.root_version == activation.sentinel_version
                && activation.root_version == activation.receipt_version,
            "restore_peer_writer_ack_versions_changed"
        );
        Ok(())
    }
}

fn record_data(observed: &Observed) -> Result<([Digest; 10], [UpdateTime; 10])> {
    fn slot<T: Serialize>(index: u8, row: &Versioned<T>) -> Result<(Digest, UpdateTime)> {
        Ok((
            Digest::of(&("day2-restore-writer-peer-record-v1", index, &row.value))?,
            row.version.clone(),
        ))
    }
    let snapshot = &observed.state.settled.snapshot;
    let rows = [
        slot(
            0,
            snapshot
                .root
                .as_ref()
                .context("restore_peer_writer_root_missing")?,
        )?,
        slot(
            1,
            snapshot
                .sentinel
                .as_ref()
                .context("restore_peer_writer_sentinel_missing")?,
        )?,
        slot(
            2,
            snapshot
                .create
                .as_ref()
                .context("restore_peer_writer_create_missing")?,
        )?,
        slot(
            3,
            snapshot
                .activate
                .as_ref()
                .context("restore_peer_writer_activation_missing")?,
        )?,
        slot(4, &observed.state.settled.advance)?,
        slot(5, &observed.state.settled.reservation)?,
        slot(6, &observed.state.consumed)?,
        slot(7, &observed.publication)?,
        slot(8, &observed.state.terminal)?,
        slot(
            9,
            observed
                .writer
                .as_ref()
                .context("restore_peer_writer_receipt_missing")?,
        )?,
    ];
    let versions = rows.each_ref().map(|(_, version)| version.clone());
    let records = rows.map(|(record, _)| record);
    Ok((records, versions))
}

fn binding<'a>(projection: &'a Projection, holder: &'a Holder) -> kernel::PeerBinding<'a> {
    kernel::PeerBinding {
        report: &projection.report,
        holder,
        operation: &projection.selection.operation,
        before: &projection.captured_records,
        consumed: &projection.consumed_use,
        approval_request: &projection.selection.approval_request,
        intent: &projection.selection.intent,
        full_archive: &projection.selection.full_archive,
        target: &projection.selection.target,
    }
}

impl KnownWriter {
    /// Exact activation/read DATA from the acknowledged writer and original
    /// request/plan. This supplies NO dispatch or keeper permission; only the
    /// genuine same-parent post-CAS signer may publish it to the actual peer.
    pub(in crate::security_epoch) fn peer_activation_data(
        &self,
        selected: &EpochStore,
        request: &kernel::Request,
        plan: &kernel::Plan,
        projection: &Projection,
        holder: &Holder,
    ) -> Result<Activation> {
        let receipt = self.receipt_data()?;
        ensure!(
            matches!(kernel::reconcile(selected, request, plan, &self.observed.state, self.observed.writer.as_ref())?, kernel::Outcome::Applied(ref applied) if applied.as_ref() == &receipt)
                && receipt == plan.receipt,
            "restore_peer_writer_not_same_known_plan"
        );
        request.require_peer_data(&binding(projection, holder))?;
        self.observed
            .state
            .consumed
            .value
            .require_peer_data(&binding(projection, holder))?;
        let selectors = request.reservation_data().selectors(selected)?;
        ensure!(
            projection.ledger.initial_create == selectors.bootstrap.create_operation
                && projection.ledger.initial_activation == selectors.activation
                && projection.ledger.advance == selectors.advance
                && projection.selection.operation == selectors.operation
                && crate::security_epoch::kernel::restore::approval_use::use_key_data(
                    selected,
                    &projection.ledger.grant
                )? == selectors.grant
                && self.observed.state.consumed.value.grant_id_data() == &projection.ledger.grant
                && projection.captured_records == plan.before.commitment_data()?
                && projection.consumed_use == Digest::of(&self.observed.state.consumed.value)?,
            "restore_peer_writer_original_selectors_changed"
        );
        receipt.require_peer_data(
            selected,
            &binding(projection, holder),
            &self.observed.state.settled.snapshot,
        )?;
        let activation = self.activation_records_data(plan)?;
        // This also proves the signed projection derives the exact same ten
        // names and selection as the Controller's captured request/plan.
        let peer = ReaderNames::new(selected, projection, &activation, holder)?;
        let controller = super::Names::new(selected, request, plan, &self.observed.publication)?;
        ensure!(
            peer.documents() == controller.documents(),
            "restore_peer_writer_names_changed"
        );
        Ok(activation)
    }

    /// Exact historical record comparison DATA, never a signing or release
    /// permission. The genuine parent retains all current authority checks.
    pub(in crate::security_epoch) fn require_activation_data(
        &self,
        plan: &kernel::Plan,
        actual: &Activation,
    ) -> Result<()> {
        ensure!(
            self.activation_records_data(plan)? == *actual,
            "restore_release_activation_changed"
        );
        Ok(())
    }

    fn activation_records_data(&self, plan: &kernel::Plan) -> Result<Activation> {
        let receipt = self.receipt_data()?;
        ensure!(
            receipt == plan.receipt,
            "restore_release_known_plan_changed"
        );
        let (records, versions) = record_data(&self.observed)?;
        let expectation = ReadExpectation {
            records,
            versions,
            committed_at: self.acknowledged.committed_at.clone(),
            read_floor: self
                .observed
                .first_read
                .format(&time::format_description::well_known::Rfc3339)?
                .try_into()?,
        };
        let activation = Activation {
            receipt: Digest::of(&receipt)?,
            root: Digest::of(&plan.root)?,
            sentinel: Digest::of(&plan.sentinel)?,
            root_version: expectation.versions[0].clone(),
            sentinel_version: expectation.versions[1].clone(),
            receipt_version: expectation.versions[9].clone(),
            expectation,
        };
        Ok(activation)
    }
}

/// Fixed selectors/decoder DATA only. There is deliberately no native HTTP
/// port, transaction, commit/rollback, Current or keeper factory here.
pub(in crate::security_epoch) struct ReaderNames {
    selected: EpochStore,
    read: ReadSet,
    terminal: String,
    writer: String,
    projection: Projection,
    activation: Activation,
    holder: Holder,
}

impl ReaderNames {
    pub(in crate::security_epoch) fn new(
        selected: &EpochStore,
        projection: &Projection,
        activation: &Activation,
        holder: &Holder,
    ) -> Result<Self> {
        holder.validate()?;
        activation.expectation.check(activation)?;
        let read = ReadSet::from_peer_data(selected, projection)?;
        let operation = &projection.selection.operation.as_str()[7..];
        let names = Self {
            terminal: format!("{}/restore_settlements/{operation}", read.initial.root),
            writer: format!("{}/restore_writers/{operation}", read.initial.root),
            selected: selected.clone(),
            read,
            projection: projection.clone(),
            activation: activation.clone(),
            holder: holder.clone(),
        };
        ensure!(
            names
                .documents()
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == 10,
            "restore_peer_writer_document_alias"
        );
        Ok(names)
    }

    fn documents(&self) -> Vec<&str> {
        let mut documents = self.read.documents();
        documents.extend([self.terminal.as_str(), self.writer.as_str()]);
        documents
    }

    /// Exact comparison binding, including the expected lineage and holder,
    /// not only its document paths. This is never a read or authority permit.
    pub(in crate::security_epoch) fn binding_data(&self) -> Result<Digest> {
        Digest::of(&(
            "day2-restored-writer-reader-binding-v1",
            &self.selected,
            &self.projection,
            &self.activation,
            &self.holder,
        ))
    }

    pub(in crate::security_epoch) fn matches_selection_data(&self, selected: &EpochStore) -> bool {
        self.selected == *selected
    }

    pub(in crate::security_epoch) fn endpoint_data(&self) -> String {
        self.read.initial.endpoint("batchGet")
    }

    /// Default strong consistency only: no old transaction/readTime token.
    pub(in crate::security_epoch) fn strong_body_data(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(
            &serde_json::json!({"documents":self.documents()}),
        )?)
    }

    /// A successful comparison is DATA, never proof that a request was sent or
    /// that native authority/file/original remained live. The real App reader
    /// must retain those owners and independently evaluate its final posts.
    pub(in crate::security_epoch) fn validate_response_data(&self, bytes: &[u8]) -> Result<()> {
        self.response_commitment_data(bytes).map(|_| ())
    }

    /// Canonical comparison DATA for the complete validated history. Response
    /// order and readTime do not change this commitment; the original-bound
    /// read and its freshness checks remain the real reader's responsibility.
    /// This neither constructs an observation nor grants authority to use one.
    pub(in crate::security_epoch) fn response_commitment_data(
        &self,
        bytes: &[u8],
    ) -> Result<Digest> {
        let observed = decode_observed(
            &self.read,
            &self.terminal,
            &self.writer,
            entries(bytes, Stream::Writer)?,
        )?;
        let expectation = &self.activation.expectation;
        let (records, versions) = record_data(&observed)?;
        ensure!(
            records == expectation.records
                && versions == expectation.versions
                && observed.first_read
                    >= timestamp(&String::from(expectation.committed_at.clone()))?
                && observed.first_read >= timestamp(&String::from(expectation.read_floor.clone()))?,
            "restore_peer_writer_records_or_read_floor_changed"
        );
        let receipt = &observed
            .writer
            .as_ref()
            .context("restore_peer_writer_receipt_missing")?
            .value;
        receipt.require_peer_data(
            &self.selected,
            &binding(&self.projection, &self.holder),
            &observed.state.settled.snapshot,
        )?;
        observed
            .state
            .consumed
            .value
            .require_peer_data(&binding(&self.projection, &self.holder))?;
        ensure!(
            observed.state.consumed.value.grant_id_data() == &self.projection.ledger.grant
                && Digest::of(&observed.state.consumed.value)? == self.projection.consumed_use
                && Digest::of(receipt)? == self.activation.receipt
                && Digest::of(
                    &observed
                        .state
                        .settled
                        .snapshot
                        .root
                        .as_ref()
                        .context("restore_peer_writer_root_missing")?
                        .value
                )? == self.activation.root
                && Digest::of(
                    &observed
                        .state
                        .settled
                        .snapshot
                        .sentinel
                        .as_ref()
                        .context("restore_peer_writer_sentinel_missing")?
                        .value
                )? == self.activation.sentinel,
            "restore_peer_writer_activation_changed"
        );
        Digest::of(&(
            "day2-restore-writer-peer-observation-v1",
            &self.selected,
            self.documents(),
            records,
            versions,
        ))
    }
}
