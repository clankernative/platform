//! Pure, permanent control-slot DATA. A proposal below is never a write or
//! counter-send permit. Actual creator, app, role, clock and provider evidence
//! must be held by separate native authority; its production factory is absent.

use super::{
    kernel::{Receipt, Request, UpdateTime},
    seed_core::OriginalSeedCore,
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    Create,
    Complete,
}

impl Stage {
    pub(super) fn of(request: &Request) -> Self {
        match request {
            Request::CreateInitialAuthority { .. } => Self::Create,
            Request::CompleteInitialFirstActivation { .. } => Self::Complete,
        }
    }
}

/// Separate from security epoch and token versions. Wire strings preserve the
/// whole nonzero u64 domain without Firestore integer or numeric coercion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(super) struct AttemptOrdinal(u64);

impl AttemptOrdinal {
    pub(super) fn first() -> Self {
        Self(1)
    }

    pub(super) fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| anyhow::anyhow!("control_slot_attempt_exhausted"))
    }
}

impl TryFrom<String> for AttemptOrdinal {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        ensure!(
            !value.is_empty()
                && value.len() <= 20
                && !value.starts_with('0')
                && value.bytes().all(|b| b.is_ascii_digit()),
            "control_slot_attempt_shape"
        );
        Ok(Self(value.parse()?))
    }
}

impl From<AttemptOrdinal> for String {
    fn from(value: AttemptOrdinal) -> Self {
        value.0.to_string()
    }
}

/// An immutable request reservation. Seed is a public DATA selection here,
/// not a reconstruction of the original native prepared file or durable ACK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogicalCore {
    pub selection: Digest,
    pub policy: InitialBootstrapPolicy,
    pub seed: OriginalSeedCore,
    pub stage: Stage,
    pub counter: Request,
    pub canonical_counter: String,
    pub request_digest: Digest,
}

pub(super) fn create_operation(authority: &Digest, seed: &Digest) -> Result<Digest> {
    Digest::of(&("day2-control-create-operation-v1", authority, seed))
}

pub(super) fn complete_operation(request: &Request, seed: &Digest) -> Result<Digest> {
    let Request::CompleteInitialFirstActivation {
        bootstrap,
        parent_receipt,
        before,
        holder,
        ..
    } = request
    else {
        anyhow::bail!("control_slot_complete_request_required");
    };
    // Original holder core excludes its own operation, request/receipt hashes
    // and every attempt/challenge/time. No after state feeds back into this ID.
    let holder_core = Digest::of(&(
        "day2-control-holder-core-v1",
        seed,
        parent_receipt,
        before,
        holder,
    ))?;
    Digest::of(&(
        "day2-control-complete-operation-v1",
        &bootstrap.authority,
        seed,
        holder_core,
    ))
}

impl LogicalCore {
    pub(super) fn new(
        selection: &EpochStore,
        policy: InitialBootstrapPolicy,
        seed: OriginalSeedCore,
        counter: &Request,
    ) -> Result<Self> {
        let core = Self {
            selection: Digest::of(selection)?,
            policy,
            seed,
            stage: Stage::of(counter),
            canonical_counter: serde_json::to_string(counter)?,
            request_digest: counter.digest()?,
            counter: counter.clone(),
        };
        core.validate(selection)?;
        Ok(core)
    }

    pub(super) fn validate(&self, selection: &EpochStore) -> Result<()> {
        self.counter.validate(selection)?;
        self.seed.validate(&self.policy, selection)?;
        ensure!(
            self.selection == Digest::of(selection)?
                && self.stage == Stage::of(&self.counter)
                && self.canonical_counter == serde_json::to_string(&self.counter)?
                && self.request_digest == self.counter.digest()?,
            "control_slot_logical_core_mismatch"
        );
        let bootstrap = self.counter.bootstrap();
        ensure!(
            *bootstrap == self.seed.bootstrap()?,
            "control_slot_seed_request_mismatch"
        );
        if matches!(self.counter, Request::CompleteInitialFirstActivation { .. }) {
            ensure!(
                *self.counter.operation()
                    == complete_operation(&self.counter, &self.seed.digest()?)?,
                "control_slot_complete_id_mismatch"
            );
        }
        Ok(())
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-control-logical-core-v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AttemptCore {
    pub logical: Digest,
    pub request: Digest,
    pub ordinal: AttemptOrdinal,
    pub expected: UpdateTime,
    pub controller_incarnation: Digest,
    pub nonce: Digest,
}

impl AttemptCore {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-control-attempt-v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Attempt {
    pub core: AttemptCore,
    pub id: Digest,
}

impl Attempt {
    pub(super) fn new(core: AttemptCore) -> Result<Self> {
        Ok(Self {
            id: core.digest()?,
            core,
        })
    }

    fn validate(&self, logical: &LogicalCore) -> Result<()> {
        ensure!(
            self.id == self.core.digest()?
                && self.core.logical == logical.digest()?
                && self.core.request == logical.request_digest,
            "control_slot_attempt_mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RearmCore {
    pub logical: Digest,
    pub request: Digest,
    pub previous: Digest,
    pub expected: UpdateTime,
    /// Historical observation digest; it cannot authorize this mutation.
    pub not_applied_observation: Digest,
    pub next: AttemptOrdinal,
}

impl RearmCore {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-control-rearm-v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rearm {
    pub core: RearmCore,
    pub id: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettlementCore {
    pub logical: Digest,
    pub expected: UpdateTime,
    /// Control lineage only, never the winning physical HTTP attempt.
    pub control_attempt: Digest,
    pub receipt: Digest,
}

impl SettlementCore {
    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-control-settlement-v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settlement {
    pub core: SettlementCore,
    pub id: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum SlotState {
    Prepared {
        next: AttemptOrdinal,
    },
    MayHaveBeenSent {
        attempt: Attempt,
    },
    Retryable {
        previous: Attempt,
        rearm: Rearm,
    },
    Observed {
        control_lineage: Attempt,
        receipt: Box<Receipt>,
        settlement: Settlement,
    },
    Fenced {
        last_attempt: Option<Attempt>,
        reason: FenceReason,
    },
}

impl<'de> Deserialize<'de> for SlotState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Prepared {
                next: AttemptOrdinal,
            },
            MayHaveBeenSent {
                attempt: Attempt,
            },
            Retryable {
                previous: Attempt,
                rearm: Rearm,
            },
            Observed {
                control_lineage: Attempt,
                receipt: Box<Receipt>,
                settlement: Settlement,
            },
            Fenced {
                last_attempt: Option<Attempt>,
                reason: FenceReason,
            },
        }
        struct MapOnly;
        impl<'de> Visitor<'de> for MapOnly {
            type Value = SlotState;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed control-slot state map")
            }

            fn visit_map<M: MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                Ok(match Wire::deserialize(MapAccessDeserializer::new(map))? {
                    Wire::Prepared { next } => SlotState::Prepared { next },
                    Wire::MayHaveBeenSent { attempt } => SlotState::MayHaveBeenSent { attempt },
                    Wire::Retryable { previous, rearm } => SlotState::Retryable { previous, rearm },
                    Wire::Observed {
                        control_lineage,
                        receipt,
                        settlement,
                    } => SlotState::Observed {
                        control_lineage,
                        receipt,
                        settlement,
                    },
                    Wire::Fenced {
                        last_attempt,
                        reason,
                    } => SlotState::Fenced {
                        last_attempt,
                        reason,
                    },
                })
            }
        }
        deserializer.deserialize_map(MapOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FenceReason {
    ConflictingCounter,
    PartialCounter,
    UnresolvedOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SlotFormat {
    Day2CredentialControlSlotV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Slot {
    pub format: SlotFormat,
    pub logical: LogicalCore,
    pub state: SlotState,
}

impl Slot {
    pub(super) fn prepared(logical: LogicalCore) -> Self {
        Self {
            format: SlotFormat::Day2CredentialControlSlotV1,
            logical,
            state: SlotState::Prepared {
                next: AttemptOrdinal::first(),
            },
        }
    }

    pub(super) fn validate(&self, selection: &EpochStore) -> Result<()> {
        self.logical.validate(selection)?;
        match &self.state {
            SlotState::Prepared { next } => ensure!(
                *next == AttemptOrdinal::first(),
                "control_slot_prepared_ordinal"
            ),
            SlotState::MayHaveBeenSent { attempt } => attempt.validate(&self.logical)?,
            SlotState::Retryable { previous, rearm } => {
                previous.validate(&self.logical)?;
                ensure!(
                    rearm.id == rearm.core.digest()?
                        && rearm.core.logical == self.logical.digest()?
                        && rearm.core.request == self.logical.request_digest
                        && rearm.core.previous == previous.id
                        && rearm.core.next == previous.core.ordinal.next()?,
                    "control_slot_rearm_mismatch"
                );
            }
            SlotState::Observed {
                control_lineage,
                receipt,
                settlement,
            } => {
                control_lineage.validate(&self.logical)?;
                ensure!(
                    **receipt == self.logical.counter.receipt()?
                        && settlement.id == settlement.core.digest()?
                        && settlement.core.logical == self.logical.digest()?
                        && settlement.core.control_attempt == control_lineage.id
                        && settlement.core.receipt == receipt.digest()?,
                    "control_slot_settlement_mismatch"
                );
            }
            SlotState::Fenced { last_attempt, .. } => {
                if let Some(attempt) = last_attempt {
                    attempt.validate(&self.logical)?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn claim_data(
        &self,
        selection: &EpochStore,
        version: &UpdateTime,
        core: AttemptCore,
    ) -> Result<Self> {
        self.validate(selection)?;
        let next = match &self.state {
            SlotState::Prepared { next } => *next,
            SlotState::Retryable { rearm, .. } => rearm.core.next,
            _ => anyhow::bail!("control_slot_claim_state_refused"),
        };
        let attempt = Attempt::new(core)?;
        attempt.validate(&self.logical)?;
        ensure!(
            attempt.core.expected == *version && attempt.core.ordinal == next,
            "control_slot_claim_version_or_ordinal"
        );
        Ok(Self {
            state: SlotState::MayHaveBeenSent { attempt },
            ..self.clone()
        })
    }

    pub(super) fn rearm_data(
        &self,
        selection: &EpochStore,
        version: &UpdateTime,
        core: RearmCore,
    ) -> Result<Self> {
        self.validate(selection)?;
        let SlotState::MayHaveBeenSent { attempt } = &self.state else {
            anyhow::bail!("control_slot_rearm_state_refused");
        };
        ensure!(
            core.expected == *version
                && core.logical == self.logical.digest()?
                && core.request == self.logical.request_digest
                && core.previous == attempt.id
                && core.next == attempt.core.ordinal.next()?,
            "control_slot_rearm_version_or_lineage"
        );
        let rearm = Rearm {
            id: core.digest()?,
            core,
        };
        Ok(Self {
            state: SlotState::Retryable {
                previous: attempt.clone(),
                rearm,
            },
            ..self.clone()
        })
    }

    pub(super) fn settle_data(
        &self,
        selection: &EpochStore,
        version: &UpdateTime,
        core: SettlementCore,
        receipt: Receipt,
    ) -> Result<Self> {
        self.validate(selection)?;
        let lineage = match &self.state {
            SlotState::MayHaveBeenSent { attempt } => attempt,
            SlotState::Retryable { previous, .. } => previous,
            _ => anyhow::bail!("control_slot_settlement_state_refused"),
        };
        ensure!(
            core.expected == *version
                && core.logical == self.logical.digest()?
                && core.control_attempt == lineage.id
                && core.receipt == receipt.digest()?
                && receipt == self.logical.counter.receipt()?,
            "control_slot_settlement_version_or_result"
        );
        let settlement = Settlement {
            id: core.digest()?,
            core,
        };
        Ok(Self {
            state: SlotState::Observed {
                control_lineage: lineage.clone(),
                receipt: Box::new(receipt),
                settlement,
            },
            ..self.clone()
        })
    }
}
