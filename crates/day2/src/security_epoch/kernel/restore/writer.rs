//! Distinct restored-writer activation DATA. The native caller must retain the
//! actual consumed approval, complete incumbent exclusion, staged creator and
//! qualified new holder/P3 owners around its one conditional send and postread.
//! Neither this plan nor historical reconciliation constructs those owners.
use super::{Current, EpochStore, approval_use, completion};
use crate::security_epoch::kernel::{AuthorityRecord, Holder, Phase, SentinelRecord, Versioned};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

/// All eight records, including the immutable grant-ID use. No newer or
/// equal-value rewritten input may be silently substituted during admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) struct State {
    pub settled: completion::State,
    pub terminal: Versioned<completion::Receipt>,
    pub consumed: Versioned<approval_use::UseRecord>,
}

impl State {
    /// Complete eight-record predecessor commitment DATA only. It cannot
    /// admit a writer, reconstruct a clock or authorize another attempt.
    pub(in crate::security_epoch) fn commitment_data(&self) -> Result<Digest> {
        self.commitment()
    }

    fn commitment(&self) -> Result<Digest> {
        Digest::of(&(
            "day2-restored-writer-before-v1",
            crate::security_epoch::journal::snapshot_digest(&self.settled.snapshot)?,
            (&self.settled.advance.value, &self.settled.advance.version),
            (
                &self.settled.reservation.value,
                &self.settled.reservation.version,
            ),
            (&self.terminal.value, &self.terminal.version),
            (&self.consumed.value, &self.consumed.version),
        ))
    }

    fn same_history(&self, other: &Self) -> bool {
        self.settled.snapshot.create == other.settled.snapshot.create
            && self.settled.snapshot.activate == other.settled.snapshot.activate
            && self.settled.advance == other.settled.advance
            && self.settled.reservation == other.settled.reservation
            && self.terminal == other.terminal
            && self.consumed == other.consumed
    }
}

/// Closed inputs from the existing reservation and completion protocols. These
/// are DATA; the actual native source must independently authenticate the holder
/// and compare the report with its retained creator/reset image before sending.
pub(in crate::security_epoch) struct Input {
    pub reservation: approval_use::Plan,
    pub completion_request: completion::Request,
    pub completion_plan: completion::Plan,
    pub before: State,
    pub holder: Holder,
}

pub(in crate::security_epoch) struct Request {
    input: Input,
    authorization: Current,
    prepared_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Completion {
    operation: Digest,
    request: Digest,
    before: Digest,
    consumed: Digest,
    // The existing Firestore authority schema admits only string/map fields.
    // Keep that codec closed: this bounded canonical report is one string,
    // rather than broadening every authority decoder for its integer epoch.
    #[serde(with = "report_json")]
    report: completion::TargetReport,
    holder: Holder,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct Receipt {
    format: Format,
    restoration: Completion,
    after_root: Digest,
    after_sentinel: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    Day2RestoredWriterV1,
}

mod report_json {
    use super::*;

    pub fn serialize<S: serde::Serializer>(
        report: &completion::TargetReport,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let text = serde_json::to_string(report).map_err(serde::ser::Error::custom)?;
        if text.len() > 2048 {
            return Err(serde::ser::Error::custom("restore_writer_report_bound"));
        }
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<completion::TargetReport, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() > 2048 {
            return Err(serde::de::Error::custom("restore_writer_report_bound"));
        }
        let report: completion::TargetReport = crate::json::decode(text.as_bytes())
            .map_err(|_| serde::de::Error::custom("restore_writer_report_encoding"))?;
        if serde_json::to_string(&report).map_err(serde::de::Error::custom)? != text {
            return Err(serde::de::Error::custom(
                "restore_writer_report_noncanonical",
            ));
        }
        Ok(report)
    }
}

/// Expected historical bindings at the receiving App's own read boundary.
/// This contains no native owner or fresh authorization.
pub(in crate::security_epoch) struct PeerBinding<'data> {
    pub report: &'data completion::TargetReport,
    pub holder: &'data Holder,
    pub operation: &'data Digest,
    pub before: &'data Digest,
    pub consumed: &'data Digest,
    pub approval_request: &'data Digest,
    pub intent: &'data Digest,
    pub full_archive: &'data Digest,
    pub target: &'data crate::security_epoch::restore_approval::TargetBinding,
}

impl Receipt {
    pub(in crate::security_epoch) fn require_peer_data(
        &self,
        selected: &EpochStore,
        binding: &PeerBinding<'_>,
        snapshot: &super::super::Snapshot,
    ) -> Result<()> {
        let root = snapshot
            .root
            .as_ref()
            .context("restore_peer_writer_root_missing")?;
        let sentinel = snapshot
            .sentinel
            .as_ref()
            .context("restore_peer_writer_sentinel_missing")?;
        root.value.bootstrap.validate_selection(selected)?;
        sentinel.value.bootstrap.validate_selection(selected)?;
        binding.holder.validate()?;
        ensure!(
            &self.restoration.report == binding.report
                && &self.restoration.holder == binding.holder
                && &self.restoration.operation == binding.operation
                && &self.restoration.before == binding.before
                && &self.restoration.consumed == binding.consumed
                && root.value.bootstrap == sentinel.value.bootstrap
                && root.value.epoch.value() == 2
                && sentinel.value.initial_epoch.value() == 1
                && matches!(&root.value.phase, Phase::RestoredFirstHolder { restoration } if restoration.as_ref() == &self.restoration)
                && sentinel.value.phase == root.value.phase
                && self.after_root == Digest::of(&root.value)?
                && self.after_sentinel == Digest::of(&sentinel.value)?,
            "restore_peer_writer_binding_changed"
        );
        Ok(())
    }
}

pub(in crate::security_epoch) struct Plan {
    pub before: State,
    pub root: AuthorityRecord,
    pub sentinel: SentinelRecord,
    pub receipt: Receipt,
}

impl Request {
    /// Historical metadata equality only; this never checks or renews a
    /// native original or makes a parsed approval into permission.
    pub(in crate::security_epoch) fn require_peer_data(
        &self,
        binding: &PeerBinding<'_>,
    ) -> Result<()> {
        ensure!(
            self.authorization.grant.approval.commitment()? == *binding.approval_request
                && self.authorization.grant.intent == *binding.intent
                && self.authorization.grant.approval.full_archive_digest == *binding.full_archive
                && self.authorization.target == *binding.target
                && self.input.holder == *binding.holder,
            "restore_peer_writer_request_binding_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn reservation_data(&self) -> &approval_use::Plan {
        &self.input.reservation
    }

    pub(in crate::security_epoch) fn operation(&self) -> &Digest {
        &self
            .input
            .reservation
            .reservation
            .receipt
            .request
            .intent
            .operation
    }

    pub(in crate::security_epoch) fn new(
        selected: &EpochStore,
        input: Input,
        current: &Current,
        at: i64,
    ) -> Result<Self> {
        let request = Self {
            input,
            authorization: current.clone(),
            prepared_at: at,
        };
        request.prepare(selected, current, at, &request.input.before, None)?;
        Ok(request)
    }

    /// One conditional root/sentinel update plus create-only writer receipt.
    /// The provider must compare ALL eight captured records and receipt absence
    /// atomically. A previously completed settlement is never itself permission.
    pub(in crate::security_epoch) fn prepare(
        &self,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        observed: &State,
        writer: Option<&Versioned<Receipt>>,
    ) -> Result<Plan> {
        ensure!(
            observed == &self.input.before && writer.is_none(),
            "restore_writer_before_or_receipt_changed"
        );
        ensure!(
            at >= self.prepared_at
                && current.observed_at >= self.authorization.observed_at
                && current.grant == self.authorization.grant,
            "restore_writer_original_authority_or_clock_changed"
        );
        let report = self.input.completion_plan.completed_report(
            selected,
            &self.input.completion_request,
            current,
            at,
            &observed.settled,
            &observed.terminal,
        )?;
        ensure!(
            matches!(
                approval_use::reconcile(
                    selected,
                    &self.input.reservation,
                    &observed.settled.snapshot,
                    Some(&observed.settled.advance),
                    Some(&observed.settled.reservation),
                    Some(&observed.consumed),
                )?,
                super::Outcome::Applied(_)
            ),
            "restore_writer_consumed_reservation_changed"
        );
        // The completion plan and grant-use plan must describe the SAME
        // reservation. Equal target metadata from another operation is not it.
        ensure!(
            observed.settled.reservation.value == self.input.reservation.reservation.receipt,
            "restore_writer_reservation_changed"
        );
        self.input.holder.validate()?;
        let source = &self.input.reservation.reservation.before;
        let Phase::ActiveFirstHolder {
            completion: incumbent,
        } = &source
            .root
            .as_ref()
            .context("restore_writer_source_missing")?
            .value
            .phase
        else {
            anyhow::bail!("restore_writer_incumbent_missing");
        };
        ensure!(
            self.input.holder.process_incarnation != incumbent.holder.process_incarnation
                && self.input.holder.ephemeral_key != incumbent.holder.ephemeral_key,
            "restore_writer_incumbent_cannot_be_readopted"
        );
        let before = observed.commitment()?;
        let request = Digest::of(&(
            "day2-restored-writer-request-v1",
            &before,
            report,
            &self.input.holder,
            &self.authorization,
            self.prepared_at,
        ))?;
        let restoration = Completion {
            operation: self
                .input
                .reservation
                .reservation
                .receipt
                .request
                .intent
                .operation
                .clone(),
            request,
            before,
            consumed: Digest::of(&observed.consumed.value)?,
            report: report.clone(),
            holder: self.input.holder.clone(),
        };
        let snapshot = &observed.settled.snapshot;
        let mut root = snapshot
            .root
            .as_ref()
            .context("restore_writer_root_missing")?
            .value
            .clone();
        let mut sentinel = snapshot
            .sentinel
            .as_ref()
            .context("restore_writer_sentinel_missing")?
            .value
            .clone();
        ensure!(
            root.epoch.value() == report.target_epoch
                && report.target_epoch == 2
                && matches!(&root.phase, Phase::Fenced { .. })
                && sentinel.phase == root.phase,
            "restore_writer_epoch_not_fenced"
        );
        root.phase = Phase::RestoredFirstHolder {
            restoration: Box::new(restoration.clone()),
        };
        sentinel.phase = root.phase.clone();
        let receipt = Receipt {
            format: Format::Day2RestoredWriterV1,
            restoration,
            after_root: Digest::of(&root)?,
            after_sentinel: Digest::of(&sentinel)?,
        };
        Ok(Plan {
            before: observed.clone(),
            root,
            sentinel,
            receipt,
        })
    }
}

impl Plan {
    /// Equality DATA for the narrow interval in which THIS writer CAS may
    /// already have applied. A single coherent snapshot must be either the
    /// exact captured predecessor or the exact planned root/sentinel pair.
    /// This never authorizes a send, reconstructs Known, or admits a reader
    /// for serving. The native send loan separately retains all ten records,
    /// the consumed grant, actual peer/target and the unchanged original.
    pub(in crate::security_epoch) fn require_may_snapshot_data(
        &self,
        snapshot: &crate::security_epoch::kernel::Snapshot,
    ) -> Result<()> {
        let before = &self.before.settled.snapshot;
        if snapshot == before {
            return Ok(());
        }
        let root = snapshot
            .root
            .as_ref()
            .context("restore_writer_may_root_missing")?;
        let sentinel = snapshot
            .sentinel
            .as_ref()
            .context("restore_writer_may_sentinel_missing")?;
        let old_root = before
            .root
            .as_ref()
            .context("restore_writer_may_before_root_missing")?;
        let old_sentinel = before
            .sentinel
            .as_ref()
            .context("restore_writer_may_before_sentinel_missing")?;
        ensure!(
            snapshot.create == before.create
                && snapshot.activate == before.activate
                && root.value == self.root
                && sentinel.value == self.sentinel
                && root.version == sentinel.version
                && root.version.is_strictly_after_data(&old_root.version)?
                && sentinel
                    .version
                    .is_strictly_after_data(&old_sentinel.version)?,
            "restore_writer_may_snapshot_changed"
        );
        Ok(())
    }

    pub(in crate::security_epoch) fn commitment(&self) -> Result<Digest> {
        Digest::of(&(
            "day2-restored-writer-plan-v1",
            self.before.commitment()?,
            &self.root,
            &self.sentinel,
            &self.receipt,
        ))
    }

    pub(in crate::security_epoch) fn revalidate(
        &self,
        selected: &EpochStore,
        request: &Request,
        current: &Current,
        at: i64,
        observed: &State,
        writer: Option<&Versioned<Receipt>>,
    ) -> Result<()> {
        let expected = request.prepare(selected, current, at, observed, writer)?;
        ensure!(
            self.before == expected.before
                && self.root == expected.root
                && self.sentinel == expected.sentinel
                && self.receipt == expected.receipt,
            "restore_writer_plan_changed"
        );
        Ok(())
    }
}

/// Historical classification only, including after expiry or a lost reply.
/// Applied cannot construct a writer, resend, renew or adopt a reopened file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum Outcome {
    NotApplied,
    Applied(Box<Receipt>),
    Conflict,
}

pub(in crate::security_epoch) fn reconcile(
    selected: &EpochStore,
    request: &Request,
    plan: &Plan,
    observed: &State,
    writer: Option<&Versioned<Receipt>>,
) -> Result<Outcome> {
    plan.revalidate(
        selected,
        request,
        &request.authorization,
        request.prepared_at,
        &request.input.before,
        None,
    )?;
    if observed == &plan.before && writer.is_none() {
        return Ok(Outcome::NotApplied);
    }
    if !observed.same_history(&plan.before) {
        return Ok(Outcome::Conflict);
    }
    let root = observed.settled.snapshot.root.as_ref();
    let sentinel = observed.settled.snapshot.sentinel.as_ref();
    Ok(match (root, sentinel, writer) {
        (Some(root), Some(sentinel), Some(writer))
            if root.value == plan.root
                && sentinel.value == plan.sentinel
                && writer.value == plan.receipt
                && root.version.is_strictly_after_data(
                    &plan.before.settled.snapshot.root.as_ref().unwrap().version,
                )?
                && sentinel.version.is_strictly_after_data(
                    &plan
                        .before
                        .settled
                        .snapshot
                        .sentinel
                        .as_ref()
                        .unwrap()
                        .version,
                )?
                && root.version == sentinel.version
                && root.version == writer.version =>
        {
            Outcome::Applied(Box::new(writer.value.clone()))
        }
        _ => Outcome::Conflict,
    })
}

#[cfg(test)]
pub(in crate::security_epoch) mod tests;
