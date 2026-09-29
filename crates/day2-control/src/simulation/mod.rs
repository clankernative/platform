//! Deterministic host laboratory, not a cloud or application capability.
//! Roc owns campaign composition; this module executes one bounded schedule.
pub mod coverage;
pub mod generation;
mod provider;
mod release_provider;
mod releases;
mod retirements;
pub mod shrink;
mod workflows;

use crate::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    engine::{EffectResult, ExecutionHost},
    journal::{Claim, CompletionRejection, HostFault, Journal, Lease, RecoveryMode},
    kernel::{EffectKind, Observation, State},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const MAX_ACTIONS: usize = 256;
pub const MAX_TRACE_BYTES: usize = 4 * 1024 * 1024;
const MAX_EVENTS: usize = 1024;
pub(super) const BUILD_COUNT: usize = 6;
pub(super) const TARGET_BUILDS: [usize; 3] = [0, 2, 3];
const LEASE_TICK: u64 = 1_200_001;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    #[default]
    None,
    NotApplied,
    LostAck,
    Delayed,
    Unavailable,
    Reject,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadSelection {
    #[default]
    Current,
    Previous,
    Oldest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadStrength {
    #[default]
    Qualified,
    Observed,
    Opaque,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Submit {
        build: u8,
    },
    Claim {
        build: u8,
        slot: u8,
    },
    Perform {
        slot: u8,
        fault: Fault,
    },
    Settle {
        slot: u8,
    },
    Tick {
        millis: u32,
    },
    Restart {},
    Cancel {
        build: u8,
    },
    Binding {
        tenant: u8,
        revoked: bool,
    },
    ProbeIsolation {
        build: u8,
        wrong_binding: bool,
    },
    PoisonCompletion {
        slot: u8,
        other_build: u8,
    },
    Approve {
        build: u8,
        wrong_commit: bool,
        wrong_tenant: bool,
    },
    Secret {
        build: u8,
        enabled: bool,
        access: bool,
        ready: bool,
    },
    Prepare {
        build: u8,
    },
    Activate {
        build: u8,
    },
    RevokeRelease {
        build: u8,
    },
    ReleaseCancel {
        build: u8,
    },
    RevokeAuthority {
        tenant: u8,
    },
    ReleaseStart {
        build: u8,
    },
    ReleaseClaim {
        build: u8,
        slot: u8,
    },
    ReleasePerform {
        slot: u8,
        fault: Fault,
    },
    ReleaseSettle {
        slot: u8,
    },
    ReleaseSecret {
        build: u8,
        enabled: bool,
        access: bool,
        ready: bool,
        delay: u32,
    },
    ReleaseUncertain {
        build: u8,
        uncertain: bool,
    },
    ReleaseDeliverSecret {
        build: u8,
    },
    RetireSecret {
        version: u8,
    },
    RetirementClaim {
        version: u8,
        slot: u8,
    },
    RetirementPerform {
        slot: u8,
        fault: Fault,
    },
    RetirementSettle {
        slot: u8,
    },
    ReleaseDrain {
        build: u8,
    },
    QuiesceDeployment {
        build: u8,
        delay: u32,
    },
    ReleaseRollback {
        build: u8,
    },
    SecretReadMode {
        version: u8,
        selection: ReadSelection,
        strength: ReadStrength,
    },
    HoldRetirement {
        version: u8,
    },
    DeliverRetirement {
        version: u8,
    },
    ExternalSecretState {
        version: u8,
        enabled: bool,
    },
    ObserveStoppedDeployment {
        build: u8,
    },
    RecreateDeployment {
        build: u8,
    },
    Heal {},
}

impl Action {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Claim { build, slot }
            | Self::ReleaseClaim { build, slot }
            | Self::PoisonCompletion {
                slot,
                other_build: build,
            } => ensure!(
                (*build as usize) < BUILD_COUNT && *slot < 4,
                "simulation index budget"
            ),
            Self::Perform { slot, .. }
            | Self::Settle { slot }
            | Self::ReleasePerform { slot, .. }
            | Self::ReleaseSettle { slot }
            | Self::RetirementPerform { slot, .. }
            | Self::RetirementSettle { slot } => {
                ensure!(*slot < 4, "simulation slot budget")
            }
            Self::Submit { build }
            | Self::Cancel { build }
            | Self::ProbeIsolation { build, .. }
            | Self::Approve { build, .. }
            | Self::Secret { build, .. }
            | Self::Prepare { build }
            | Self::Activate { build }
            | Self::RevokeRelease { build }
            | Self::ReleaseCancel { build }
            | Self::ReleaseDrain { build }
            | Self::ReleaseRollback { build }
            | Self::ObserveStoppedDeployment { build }
            | Self::RecreateDeployment { build } => {
                ensure!((*build as usize) < BUILD_COUNT, "simulation build budget")
            }
            Self::ReleaseStart { build }
            | Self::ReleaseUncertain { build, .. }
            | Self::ReleaseDeliverSecret { build } => {
                ensure!((*build as usize) < BUILD_COUNT, "simulation release budget")
            }
            Self::ReleaseSecret { build, delay, .. } => ensure!(
                (*build as usize) < BUILD_COUNT && *delay <= 4_000_000,
                "simulation secret observation budget"
            ),
            Self::QuiesceDeployment { build, delay } => ensure!(
                (*build as usize) < BUILD_COUNT && *delay <= 4_000_000,
                "simulation quiescence budget"
            ),
            Self::Binding { tenant, .. } | Self::RevokeAuthority { tenant } => {
                ensure!(*tenant < 2, "simulation tenant budget")
            }
            Self::Tick { millis } => ensure!(*millis <= 4_000_000, "simulation clock step budget"),
            Self::RetireSecret { version }
            | Self::SecretReadMode { version, .. }
            | Self::HoldRetirement { version }
            | Self::DeliverRetirement { version }
            | Self::ExternalSecretState { version, .. } => ensure!(
                (1..=3).contains(version),
                "simulation secret version budget"
            ),
            Self::RetirementClaim { version, slot } => ensure!(
                (1..=3).contains(version) && *slot < 4,
                "simulation retirement budget"
            ),
            Self::Restart {} | Self::Heal {} => {}
        }
        Ok(())
    }

    fn extended_catalog(&self) -> bool {
        match self {
            Self::RetireSecret { .. }
            | Self::RetirementClaim { .. }
            | Self::RetirementPerform { .. }
            | Self::RetirementSettle { .. }
            | Self::ReleaseDrain { .. }
            | Self::ReleaseRollback { .. }
            | Self::QuiesceDeployment { .. } => true,
            Self::Submit { build }
            | Self::Claim { build, .. }
            | Self::Cancel { build }
            | Self::ProbeIsolation { build, .. }
            | Self::Approve { build, .. }
            | Self::Secret { build, .. }
            | Self::Prepare { build }
            | Self::Activate { build }
            | Self::RevokeRelease { build }
            | Self::ReleaseCancel { build }
            | Self::ReleaseStart { build }
            | Self::ReleaseClaim { build, .. }
            | Self::ReleaseSecret { build, .. }
            | Self::ReleaseUncertain { build, .. }
            | Self::ReleaseDeliverSecret { build }
            | Self::PoisonCompletion {
                other_build: build, ..
            } => *build >= 3,
            _ => false,
        }
    }

    fn weak_provider(&self) -> bool {
        matches!(
            self,
            Self::SecretReadMode { .. }
                | Self::HoldRetirement { .. }
                | Self::DeliverRetirement { .. }
                | Self::ExternalSecretState { .. }
                | Self::ObserveStoppedDeployment { .. }
                | Self::RecreateDeployment { .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub format: u32,
    pub seed: u64,
    pub actions: Vec<Action>,
}
impl Scenario {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.format, 1..=4) && self.actions.len() <= MAX_ACTIONS,
            "simulation scenario budget/version"
        );
        let mut secret_sources = [0_u8; BUILD_COUNT];
        for action in &self.actions {
            action.validate()?;
            ensure!(
                self.format >= 3 || !action.extended_catalog(),
                "extended catalog requires scenario format 3"
            );
            ensure!(
                self.format >= 4 || !action.weak_provider(),
                "weak provider actions require scenario format 4"
            );
            let source = match action {
                Action::Secret { build, .. } => Some((*build, 1)),
                Action::ReleaseSecret { build, .. } | Action::ReleaseDeliverSecret { build } => {
                    Some((*build, 2))
                }
                _ => None,
            };
            if let Some((build, source)) = source {
                secret_sources[build as usize] |= source;
                ensure!(
                    secret_sources[build as usize] != 3,
                    "legacy and workflow secret sources cannot be mixed for one build"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionView {
    pub id: Digest,
    pub state: State,
    pub revision: u64,
    pub cancelled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub index: u32,
    pub now: u64,
    pub action: Action,
    pub outcome: String,
    pub journal: Digest,
    pub provider: Digest,
    pub executions: Vec<ExecutionView>,
    pub release_states: Vec<crate::release::ReleaseState>,
    pub release_executions: Vec<crate::release_execution::ReleaseSnapshot>,
    pub release_mutations: u32,
    pub release_observations: u32,
    pub recovery: Option<ObservedRecovery>,
    pub retirement: retirements::Snapshot,
}

/// Serializable evidence only; it cannot construct a native lease or recovery grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedRecovery {
    Execute,
    Reconcile,
}

impl From<RecoveryMode> for ObservedRecovery {
    fn from(value: RecoveryMode) -> Self {
        match value {
            RecoveryMode::Execute => Self::Execute,
            RecoveryMode::Reconcile => Self::Reconcile,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Violation {
    pub step: u32,
    pub code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum Disposition {
    Terminal { build: u8, state: State },
    NeedsInterventionUnknownPublication { build: u8, effect: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub format: u32,
    pub implementation: Digest,
    pub scenario: Scenario,
    pub plans: Vec<BuildPlan>,
    pub events: Vec<Event>,
    /// Events caused by the input schedule, before the bounded fair recovery pass.
    pub schedule_events: u32,
    pub dispositions: Vec<Disposition>,
    pub provider_records: Vec<provider::Record>,
    pub publications: Vec<provider::Mutation>,
    pub releases: Vec<crate::release::ReleaseState>,
    pub workflow: workflows::Evidence,
    pub retirement: retirements::Evidence,
    pub violation: Option<Violation>,
}

impl Trace {
    pub fn validate(&self) -> Result<()> {
        self.scenario.validate()?;
        ensure!(
            self.format == 5 && self.implementation == implementation_digest()?,
            "simulation implementation/version mismatch"
        );
        self.workflow.validate()?;
        self.retirement.validate()?;
        ensure!(
            self.plans == plans()?
                && self.events.len() <= MAX_EVENTS
                && self.provider_records.len() <= BUILD_COUNT * 3
                && self.publications.len() <= BUILD_COUNT
                && self.dispositions.len() <= BUILD_COUNT
                && self.releases.len() == TARGET_BUILDS.len(),
            "simulation trace budget/catalog"
        );
        let mut now = 0;
        let plan_ids: Vec<_> = self
            .plans
            .iter()
            .map(BuildPlan::execution_id)
            .collect::<Result<_>>()?;
        let scheduled = self.schedule_events as usize;
        ensure!(
            scheduled <= self.events.len()
                && scheduled <= self.scenario.actions.len()
                && self.events[..scheduled]
                    .iter()
                    .map(|event| &event.action)
                    .eq(self.scenario.actions[..scheduled].iter())
                && (scheduled == self.scenario.actions.len()
                    || self
                        .violation
                        .as_ref()
                        .is_some_and(|violation| violation.step as usize <= scheduled)),
            "simulation scheduled event boundary mismatch"
        );
        for (index, event) in self.events.iter().enumerate() {
            event.action.validate()?;
            event.retirement.validate()?;
            ensure!(
                event.index == index as u32
                    && event.now >= now
                    && event.now <= 2_000_000_000
                    && event.outcome.len() <= 80
                    && event
                        .outcome
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    && event.executions.len() <= BUILD_COUNT
                    && event.release_states.len() == TARGET_BUILDS.len()
                    && event.release_executions.len() <= 12
                    && event.release_mutations <= 256
                    && event.release_observations <= 2048,
                "invalid simulation event"
            );
            let execution_ids: BTreeSet<_> = event.executions.iter().map(|view| &view.id).collect();
            ensure!(
                execution_ids.len() == event.executions.len()
                    && execution_ids.iter().all(|id| plan_ids.contains(id)),
                "simulation event has duplicate or unknown executions"
            );
            now = event.now;
        }
        let mut finished = BTreeSet::new();
        for disposition in &self.dispositions {
            let (build, terminal) = match disposition {
                Disposition::Terminal { build, state } => (*build, Some(state)),
                Disposition::NeedsInterventionUnknownPublication { build, effect } => {
                    let plan = self
                        .plans
                        .get(*build as usize)
                        .context("unknown disposition build")?;
                    ensure!(
                        *effect == crate::kernel::effect_id(plan, EffectKind::PublishCheck)?,
                        "intervention effect identity mismatch"
                    );
                    (*build, None)
                }
            };
            let id = plan_ids
                .get(build as usize)
                .context("unknown disposition build")?;
            let view = self
                .events
                .last()
                .and_then(|event| event.executions.iter().find(|view| &view.id == id))
                .context("disposition without admitted execution")?;
            ensure!(finished.insert(build), "duplicate simulation disposition");
            if let Some(state) = terminal {
                ensure!(
                    state == &view.state && state.next_effect().is_none(),
                    "terminal disposition mismatch"
                );
            } else {
                ensure!(
                    view.state.next_effect() == Some(EffectKind::PublishCheck),
                    "intervention disposition mismatch"
                );
            }
        }
        if let Some(violation) = &self.violation {
            ensure!(
                violation.step <= MAX_EVENTS as u32
                    && violation.code.len() <= 80
                    && violation
                        .code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'_'),
                "invalid simulation violation"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_TRACE_BYTES,
            "simulation trace byte budget"
        );
        Ok(())
    }
    pub fn require_success(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.violation.is_none(),
            "simulation invariant failure: {:?}",
            self.violation
        );
        let admitted = if self.scenario.format == 1 {
            3
        } else {
            self.events.last().map_or(0, |event| event.executions.len())
        };
        ensure!(
            self.dispositions.len() == admitted,
            "incomplete simulation drain"
        );
        ensure!(
            self.workflow.dispositions.len() == self.workflow.executions.len(),
            "incomplete release workflow drain"
        );
        Ok(())
    }
}

pub fn implementation_digest() -> Result<Digest> {
    Digest::of(&[
        Digest::new(include_bytes!("mod.rs")),
        Digest::new(include_bytes!("generation.rs")),
        Digest::new(include_bytes!("shrink.rs")),
        Digest::new(include_bytes!("coverage.rs")),
        Digest::new(include_bytes!("provider.rs")),
        Digest::new(include_bytes!("releases.rs")),
        Digest::new(include_bytes!("workflows.rs")),
        Digest::new(include_bytes!("release_provider.rs")),
        Digest::new(include_bytes!("weak_provider.rs")),
        Digest::new(include_bytes!("../provider_evidence.rs")),
        Digest::new(include_bytes!("retirements.rs")),
        Digest::new(include_bytes!("../runtime_secret.rs")),
        Digest::new(include_bytes!("../secret_retirement.rs")),
        Digest::new(include_bytes!("../secret_retirement_recipe.rs")),
        Digest::new(include_bytes!("../release_execution.rs")),
        Digest::new(include_bytes!("../release_recipe.rs")),
        crate::release_recipe::CompiledReleaseRecipe::installed()?.identity()?,
        Digest::new(include_bytes!("../kernel.rs")),
        Digest::new(include_bytes!("../journal.rs")),
        Digest::new(include_bytes!("../engine.rs")),
        Digest::new(include_bytes!("../release.rs")),
        Digest::new(include_bytes!("../contracts.rs")),
        Digest::new(include_bytes!("../source.rs")),
        Digest::new(include_bytes!("../../Cargo.toml")),
        Digest::new(include_bytes!("../../../../Cargo.lock")),
        Digest::new(include_bytes!("../../../day2-capabilities/src/lib.rs")),
        Digest::new(include_bytes!("../../../day2/src/json.rs")),
        Digest::of(&regressions()?)?,
    ])
}

fn name(value: &str) -> Result<Name> {
    Name::try_from(value.to_owned())
}

fn plans() -> Result<Vec<BuildPlan>> {
    (0..BUILD_COUNT)
        .map(|index| {
            let company = if index == 2 { "beta" } else { "alpha" };
            Ok(BuildPlan {
                version: 1,
                company: name(company)?,
                app: name(if matches!(index, 3 | 4) {
                    "spend"
                } else {
                    "reports"
                })?,
                request: name(&format!("revision_{index}"))?,
                commit: GitOid::try_from(format!("{:040x}", index + 1))?,
                profile: day2_capabilities::BuildProfile {
                    source: BindingRef::pin(name("source")?, &(company, "repository_42"))?,
                    builder: BindingRef::pin(name("builder")?, &(company, "pinned_builder"))?,
                    durability: BindingRef::pin(name("durability")?, &(company, "queue"))?,
                    platform: Digest::new(b"simulation-platform-v1"),
                    recipe: Digest::new(b"simulation-recipe-v1"),
                },
            })
        })
        .collect()
}

pub fn generated(seed: u64, case: u32) -> Result<Scenario> {
    generation::generated(seed, case)
}

pub fn regressions() -> Result<Vec<Scenario>> {
    [
        include_str!("../../../../fixtures/control-simulation/lost-publication.json"),
        include_str!("../../../../fixtures/control-simulation/unknown-publication.json"),
        include_str!("../../../../fixtures/control-simulation/release-readiness.json"),
        include_str!("../../../../fixtures/control-simulation/workflow-competition.json"),
        include_str!("../../../../fixtures/control-simulation/workflow-lost-ack.json"),
        include_str!("../../../../fixtures/control-simulation/workflow-secret-revision.json"),
    ]
    .into_iter()
    .map(|source| {
        let scenario: Scenario = serde_json::from_str(source)?;
        scenario.validate()?;
        Ok(scenario)
    })
    .collect()
}

#[derive(Clone)]
enum Outcome {
    Completed(Observation),
    Retry,
    Ambiguous,
}
impl Outcome {
    fn capture(result: EffectResult) -> Self {
        match result {
            EffectResult::Completed(value) => Self::Completed(value),
            EffectResult::RetryNotApplied => Self::Retry,
            EffectResult::Ambiguous => Self::Ambiguous,
        }
    }
    fn effect(&self) -> EffectResult {
        match self {
            Self::Completed(value) => EffectResult::Completed(value.clone()),
            Self::Retry => EffectResult::RetryNotApplied,
            Self::Ambiguous => EffectResult::Ambiguous,
        }
    }
}
#[derive(Clone)]
struct Slot {
    lease: Lease,
    outcome: Option<Outcome>,
}

struct World {
    path: PathBuf,
    now: u64,
    plans: Vec<BuildPlan>,
    submitted: BTreeSet<usize>,
    provider: Arc<provider::Provider>,
    slots: [Option<Slot>; 4],
    events: Vec<Event>,
    releases: releases::Releases,
    workflows: workflows::Workflows,
    retirements: retirements::Retirements,
}

impl World {
    fn host(&self, build: usize, slot: usize) -> ExecutionHost {
        let plan = &self.plans[build];
        ExecutionHost::new(
            self.path.clone(),
            plan.company.clone(),
            name(&format!("worker_{slot}")).expect("fixed owner"),
            plan.profile.durability.clone(),
            self.provider.clone(),
        )
    }
    fn views(&self) -> Result<Vec<ExecutionView>> {
        let journal = Journal::open(&self.path)?;
        self.plans
            .iter()
            .enumerate()
            .filter(|(index, _)| self.submitted.contains(index))
            .map(|(_, plan)| {
                let value = journal.get(&plan.execution_id()?)?;
                Ok(ExecutionView {
                    id: value.id,
                    state: value.state,
                    revision: value.revision,
                    cancelled: value.cancel_requested,
                })
            })
            .collect()
    }
    fn perform(&mut self, action: &Action) -> Result<String> {
        let outcome = match *action {
            Action::Submit { build } => {
                let index = build as usize;
                let duplicate = self.submitted.contains(&index);
                let host = self.host(index, 0);
                match host.accept_as(&self.plans[index], "simulation_operator") {
                    Ok(id) => {
                        ensure!(
                            id == self.plans[index].execution_id()?,
                            "submission identity mismatch"
                        );
                        self.submitted.insert(index);
                        if duplicate {
                            "duplicate_submission"
                        } else {
                            "submitted"
                        }
                        .into()
                    }
                    Err(error) if self.binding_denial(&error, &self.plans[index])? => {
                        "submission_refused".into()
                    }
                    Err(error) => return Err(error),
                }
            }
            Action::Claim { build, slot } => {
                self.slots[slot as usize] = None;
                match self
                    .host(build as usize, slot as usize)
                    .claim_at(&self.plans[build as usize].execution_id()?, self.now)
                {
                    Ok(Claim::Acquired(lease)) => {
                        self.slots[slot as usize] = Some(Slot {
                            lease: *lease,
                            outcome: None,
                        });
                        "claimed".into()
                    }
                    Ok(Claim::Busy) => "busy".into(),
                    Ok(Claim::Terminal(_)) => "terminal".into(),
                    Err(error) if self.binding_denial(&error, &self.plans[build as usize])? => {
                        "refused".into()
                    }
                    Err(error) => return Err(error),
                }
            }
            Action::Perform { slot, fault } => {
                self.provider.configure(self.now, fault)?;
                if let Some(pending) = self.slots[slot as usize].clone() {
                    let build = self
                        .plans
                        .iter()
                        .position(|plan| *plan == pending.lease.execution.plan)
                        .context("slot plan")?;
                    match self.host(build, slot as usize).perform(&pending.lease) {
                        Ok(result) => {
                            let result = Outcome::capture(result);
                            let label = match result {
                                Outcome::Completed(_) => "provider_completed",
                                Outcome::Retry => "provider_not_applied",
                                Outcome::Ambiguous => "provider_ambiguous",
                            };
                            self.slots[slot as usize].as_mut().context("slot")?.outcome =
                                Some(result);
                            label.into()
                        }
                        Err(error)
                            if self.binding_denial(&error, &pending.lease.execution.plan)? =>
                        {
                            "provider_refused".into()
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    "empty_slot".into()
                }
            }
            Action::Settle { slot } => {
                if let Some(pending) = self.slots[slot as usize].clone() {
                    if let Some(result) = pending.outcome {
                        let build = self
                            .plans
                            .iter()
                            .position(|plan| *plan == pending.lease.execution.plan)
                            .context("slot plan")?;
                        match self.host(build, slot as usize).settle_at(
                            &pending.lease,
                            result.effect(),
                            self.now,
                        ) {
                            Ok(_) => "accepted".into(),
                            Err(error)
                                if completion_denial(
                                    &self.path,
                                    &pending.lease,
                                    &result,
                                    self.now,
                                    &error,
                                )? =>
                            {
                                "refused".into()
                            }
                            Err(error) => return Err(error),
                        }
                    } else {
                        "no_outcome".into()
                    }
                } else {
                    "empty_slot".into()
                }
            }
            Action::Tick { millis } => {
                self.now = self
                    .now
                    .checked_add(u64::from(millis))
                    .context("clock overflow")?;
                "clock_advanced".into()
            }
            Action::Restart {} => {
                self.slots = std::array::from_fn(|_| None);
                self.releases.restart(&self.path)?;
                self.workflows.restart(&self.path, &self.plans)?;
                self.retirements.restart(&self.path, &self.plans)?;
                let journal = Journal::open(&self.path)?;
                let mut persisted = BTreeSet::new();
                for (index, plan) in self.plans.iter().enumerate() {
                    match journal.get(&plan.execution_id()?) {
                        Ok(_) => {
                            persisted.insert(index);
                        }
                        Err(error)
                            if matches!(
                                error.downcast_ref::<rusqlite::Error>(),
                                Some(rusqlite::Error::QueryReturnedNoRows)
                            ) => {}
                        Err(error) => return Err(error),
                    }
                }
                ensure!(
                    persisted == self.submitted,
                    "restart changed durable request admissions"
                );
                self.submitted = persisted;
                "host_restarted".into()
            }
            Action::Cancel { build } => {
                let id = self.plans[build as usize].execution_id()?;
                let mut journal = Journal::open(&self.path)?;
                let pending = journal.get(&id)?.state.next_effect().is_some();
                journal.request_cancel(&id)?;
                if pending {
                    ensure!(
                        journal.get(&id)?.cancel_requested,
                        "accepted build cancellation was not persisted"
                    );
                    self.releases.cancel_build(id);
                }
                "accepted".into()
            }
            Action::Binding { tenant, revoked } => {
                self.provider.revoke(tenant as usize, revoked)?;
                "binding_observed".into()
            }
            Action::Heal {} => {
                self.provider.revoke(0, false)?;
                self.provider.revoke(1, false)?;
                self.provider.configure(self.now, Fault::None)?;
                self.workflows.heal(self.now)?;
                self.workflows.provider().end_read_faults()?;
                "finite_faults_ended".into()
            }
            Action::ProbeIsolation {
                build,
                wrong_binding,
            } => {
                let plan = &self.plans[build as usize];
                let company = if wrong_binding {
                    plan.company.clone()
                } else {
                    name(if plan.company.as_str() == "alpha" {
                        "beta"
                    } else {
                        "alpha"
                    })?
                };
                let durability = if wrong_binding {
                    BindingRef::pin(name("wrong")?, &"other_queue")?
                } else {
                    plan.profile.durability.clone()
                };
                let host = ExecutionHost::new(
                    self.path.clone(),
                    company,
                    name("intruder")?,
                    durability,
                    self.provider.clone(),
                );
                let before = journal_digest(&self.path)?;
                match host.claim_at(&plan.execution_id()?, self.now) {
                    Err(error)
                        if error.to_string()
                            == if wrong_binding {
                                "execution runtime binding mismatch"
                            } else {
                                "company authority mismatch"
                            } =>
                    {
                        if journal_digest(&self.path)? == before {
                            "isolation_refused".into()
                        } else {
                            "isolation_bypass".into()
                        }
                    }
                    Err(error) => return Err(error),
                    Ok(_) => "isolation_bypass".into(),
                }
            }
            Action::PoisonCompletion { slot, other_build } => {
                if let Some(pending) = self.slots[slot as usize].clone() {
                    if pending.lease.kind == EffectKind::VerifyArtifact
                        && pending.lease.execution.plan != self.plans[other_build as usize]
                    {
                        let other = &self.plans[other_build as usize];
                        let forged = Observation::Verified {
                            evidence: crate::kernel::VerificationEvidence {
                                plan: other.fingerprint()?,
                                source: provider::Provider::source(other)?,
                                platform: other.profile.platform.clone(),
                                recipe: other.profile.recipe.clone(),
                                builder: other.profile.builder.clone(),
                                artifact: provider::Provider::artifact(other)?,
                                checks: Digest::new(b"forged"),
                                credential_presence: crate::kernel::CredentialPresence::Absent,
                            },
                        };
                        let before = Journal::open(&self.path)?.get(&pending.lease.execution.id)?;
                        let result =
                            Journal::open(&self.path)?.complete(&pending.lease, &forged, self.now);
                        let after = Journal::open(&self.path)?.get(&pending.lease.execution.id)?;
                        let expected = match result {
                            Err(error)
                                if error.to_string() == "evidence belongs to another plan" =>
                            {
                                true
                            }
                            Err(error)
                                if completion_denial(
                                    &self.path,
                                    &pending.lease,
                                    &Outcome::Completed(forged),
                                    self.now,
                                    &error,
                                )? =>
                            {
                                true
                            }
                            Err(error) => return Err(error),
                            Ok(_) => false,
                        };
                        if expected
                            && before.state == after.state
                            && before.revision == after.revision
                        {
                            "forged_evidence_refused".into()
                        } else {
                            "isolation_bypass".into()
                        }
                    } else {
                        "inapplicable".into()
                    }
                } else {
                    "empty_slot".into()
                }
            }
            Action::ReleaseStart { .. }
            | Action::ReleaseClaim { .. }
            | Action::ReleasePerform { .. }
            | Action::ReleaseSettle { .. }
            | Action::ReleaseSecret { .. }
            | Action::ReleaseUncertain { .. }
            | Action::ReleaseDeliverSecret { .. } => self.workflows.perform(
                &self.path,
                &self.plans,
                &mut self.releases,
                action,
                self.now,
            )?,
            Action::RetireSecret { .. }
            | Action::RetirementClaim { .. }
            | Action::RetirementPerform { .. }
            | Action::RetirementSettle { .. }
            | Action::ReleaseDrain { .. }
            | Action::ReleaseRollback { .. }
            | Action::QuiesceDeployment { .. }
            | Action::SecretReadMode { .. }
            | Action::HoldRetirement { .. }
            | Action::DeliverRetirement { .. }
            | Action::ExternalSecretState { .. }
            | Action::ObserveStoppedDeployment { .. }
            | Action::RecreateDeployment { .. } => self.retirements.perform(
                &self.path,
                &self.plans,
                &self.workflows.provider(),
                &mut self.releases,
                action,
                self.now,
            )?,
            _ => self
                .releases
                .perform(&self.path, &self.plans, action, self.events.len())?,
        };
        Ok(outcome)
    }
    fn event(&mut self, action: Action) -> Result<Option<Violation>> {
        ensure!(self.events.len() < MAX_EVENTS, "simulation event budget");
        let unsubmitted = match &action {
            Action::Claim { build, .. }
            | Action::Cancel { build }
            | Action::Approve { build, .. }
            | Action::ProbeIsolation { build, .. } => !self.submitted.contains(&(*build as usize)),
            _ => false,
        };
        let (outcome, unexpected) = match self.perform(&action) {
            Ok(outcome) => (outcome, false),
            Err(error)
                if unsubmitted
                    && (matches!(
                        error.downcast_ref::<rusqlite::Error>(),
                        Some(rusqlite::Error::QueryReturnedNoRows)
                    ) || matches!(
                        error.downcast_ref::<HostFault>(),
                        Some(HostFault::JournalRead)
                    )) =>
            {
                ("build_not_submitted".into(), false)
            }
            Err(_) => ("unexpected_host_failure".into(), true),
        };
        let workflow = self.workflows.evidence(&self.path, &self.plans)?;
        let recovery = match &action {
            Action::Claim { slot, .. } if outcome == "claimed" => self.slots[*slot as usize]
                .as_ref()
                .map(|slot| slot.lease.recovery),
            Action::ReleaseClaim { slot, .. } if outcome == "release_claimed" => {
                self.workflows.claim_recovery(*slot as usize)
            }
            _ => None,
        };
        let retirement_recovery = match &action {
            Action::RetirementClaim { slot, .. } if outcome == "retirement_claimed" => {
                self.retirements.recovery(*slot as usize)
            }
            _ => None,
        };
        let event = Event {
            index: self.events.len() as u32,
            now: self.now,
            action,
            outcome,
            journal: journal_digest(&self.path)?,
            provider: Digest::of(&(
                self.provider.records()?,
                self.provider.mutations()?,
                &workflow,
            ))?,
            executions: self.views()?,
            release_states: self.releases.states(&self.path, &self.plans)?,
            release_executions: workflow.executions,
            release_mutations: workflow.provider.mutations.len() as u32,
            release_observations: workflow.provider.observations.len() as u32,
            recovery: recovery.map(ObservedRecovery::from).or(retirement_recovery),
            retirement: self.retirements.snapshot(
                &self.path,
                &self.plans,
                &self.workflows.provider(),
            )?,
        };
        self.events.push(event);
        if unexpected {
            return Ok(Some(Violation {
                step: self.events.len() as u32,
                code: "unexpected_host_failure".into(),
            }));
        }
        Ok(self.invariant()?.map(|code| Violation {
            step: self.events.len() as u32,
            code: code.into(),
        }))
    }

    fn binding_denial(&self, error: &anyhow::Error, plan: &BuildPlan) -> Result<bool> {
        Ok((matches!(
            error.downcast_ref::<HostFault>(),
            Some(HostFault::CapabilityBinding)
        ) || error.downcast_ref::<provider::RevokedBinding>().is_some())
            && self.provider.binding_revoked(plan)?)
    }
    fn invariant(&self) -> Result<Option<&'static str>> {
        if self
            .events
            .last()
            .is_some_and(|event| event.outcome == "isolation_bypass")
        {
            return Ok(Some("isolation_bypass"));
        }
        let connection = rusqlite::Connection::open_with_flags(
            &self.path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut statement = connection.prepare("SELECT id FROM executions ORDER BY id")?;
        let persisted: BTreeSet<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let expected: BTreeSet<String> = self
            .submitted
            .iter()
            .map(|index| {
                self.plans[*index]
                    .execution_id()
                    .map(|id| id.as_str().to_owned())
            })
            .collect::<Result<_>>()?;
        if persisted != expected {
            return Ok(Some("unrequested_durable_admission"));
        }
        let records = self.provider.records()?;
        for record in &records {
            let Some(plan) = self.plans.iter().find(|plan| {
                plan.company.as_str() == record.company
                    && plan.app.as_str() == record.app
                    && plan.commit.as_str() == record.commit
            }) else {
                return Ok(Some("provider_record_wrong_scope"));
            };
            if !expected.contains(plan.execution_id()?.as_str()) {
                return Ok(Some("provider_effect_without_admission"));
            }
            let binding = if record.kind == EffectKind::VerifyArtifact {
                &plan.profile.builder
            } else {
                &plan.profile.source
            };
            if record.binding != *binding
                || record.effect != crate::kernel::effect_id(plan, record.kind)?
            {
                return Ok(Some("provider_record_wrong_binding"));
            }
            let valid = match (&record.kind, &record.observation) {
                (EffectKind::FetchSource, Observation::Source { source }) => {
                    *source == provider::Provider::source(plan)?
                }
                (EffectKind::VerifyArtifact, Observation::Verified { evidence }) => {
                    evidence.plan == plan.fingerprint()?
                        && evidence.source == provider::Provider::source(plan)?
                        && evidence.platform == plan.profile.platform
                        && evidence.recipe == plan.profile.recipe
                        && evidence.builder == plan.profile.builder
                        && evidence.artifact == provider::Provider::artifact(plan)?
                }
                (EffectKind::VerifyArtifact, Observation::BuildRejected { evidence }) => {
                    evidence.plan == plan.fingerprint()?
                        && evidence.source == provider::Provider::source(plan)?
                        && evidence.platform == plan.profile.platform
                        && evidence.recipe == plan.profile.recipe
                        && evidence.builder == plan.profile.builder
                }
                (EffectKind::PublishCheck, Observation::Published { evidence, .. }) => {
                    records.iter().any(|verified| {
                        verified.kind == EffectKind::VerifyArtifact
                            && verified.company == record.company
                            && verified.app == record.app
                            && verified.commit == record.commit
                            && match &verified.observation {
                                Observation::Verified { evidence: proof } => {
                                    Digest::of(proof).is_ok_and(|digest| digest == *evidence)
                                }
                                Observation::BuildRejected { evidence: proof } => {
                                    Digest::of(proof).is_ok_and(|digest| digest == *evidence)
                                }
                                _ => false,
                            }
                    })
                }
                (
                    EffectKind::FetchSource | EffectKind::PublishCheck,
                    Observation::Rejected {
                        code: crate::kernel::FailureCode::Denied,
                    },
                ) => true,
                _ => false,
            };
            if !valid {
                return Ok(Some("provider_record_invalid_evidence"));
            }
        }
        let mut unique = BTreeSet::new();
        for mutation in self.provider.mutations()? {
            if !unique.insert(mutation.effect.clone()) {
                return Ok(Some("duplicate_publication"));
            }
            if !records.iter().any(|record| {
                record.effect == mutation.effect
                    && record.kind == EffectKind::PublishCheck
                    && record.company == mutation.company
                    && record.commit == mutation.commit
                    && Digest::of(&record.observation)
                        .is_ok_and(|digest| digest == mutation.receipt)
            }) {
                return Ok(Some("publication_ledger_mismatch"));
            }
        }
        for view in self.views()? {
            let plan = self
                .plans
                .iter()
                .find(|plan| plan.execution_id().is_ok_and(|id| id == view.id))
                .context("execution view outside admitted catalog")?;
            let State::Succeeded {
                artifact,
                evidence,
                publication,
            } = view.state
            else {
                continue;
            };
            let scoped_receipt = records.iter().any(|record| {
                record.company == plan.company.as_str()
                    && record.commit == plan.commit.as_str()
                    && matches!(&record.observation,
                        Observation::Published { evidence: other, publication: receipt }
                        if *other == evidence && *receipt == publication)
            });
            if artifact != provider::Provider::artifact(plan)? || !scoped_receipt {
                return Ok(Some("success_without_scoped_receipt"));
            }
        }
        if let Some(violation) = self.releases.invariant(&self.path, &self.plans)? {
            return Ok(Some(violation));
        }
        self.retirements.invariant(
            &self.path,
            &self.plans,
            &self.workflows.provider(),
            &self.releases,
        )
    }
}

fn completion_denial(
    path: &Path,
    lease: &Lease,
    result: &Outcome,
    now: u64,
    error: &anyhow::Error,
) -> Result<bool> {
    use rusqlite::{Connection, OpenFlags};
    let Some(reason) = error.downcast_ref::<CompletionRejection>() else {
        return Ok(false);
    };
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (status, epoch, owner, until, previous): (String, i64, String, i64, Option<String>) =
        connection.query_row(
            "SELECT status,epoch,owner,lease_until,observation FROM effects WHERE id=?1",
            [lease.effect.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    let epoch = u64::try_from(epoch)?;
    let until = u64::try_from(until)?;
    Ok(match reason {
        CompletionRejection::FencedLease => {
            status != "running"
                || epoch != lease.epoch
                || owner != lease.owner.as_str()
                || until <= now
        }
        CompletionRejection::ConflictingCompletion => {
            status == "complete"
                && matches!(result, Outcome::Completed(observation) if previous.as_ref().is_some_and(|body|serde_json::to_string(observation).is_ok_and(|encoded|encoded!=*body)))
        }
        CompletionRejection::UncertainPublication => {
            lease.kind == EffectKind::PublishCheck
                && lease.recovery == RecoveryMode::Reconcile
                && matches!(
                    result,
                    Outcome::Retry | Outcome::Completed(Observation::Rejected { .. })
                )
        }
    })
}

fn journal_digest(path: &Path) -> Result<Digest> {
    use rusqlite::{Connection, OpenFlags, types::ValueRef};
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut snapshot = BTreeMap::new();
    for table in [
        "executions",
        "outbox",
        "execution_acceptance",
        "effects",
        "events",
        "release_slots",
        "release_observed",
        "release_observation_receipts",
        "release_approvals",
        "release_status",
        "release_readiness",
        "release_activations",
        "release_stops",
        "release_workflows",
        "release_workflow_outbox",
        "release_steps",
        "release_events",
        "runtime_secret_resources",
        "runtime_secret_authority",
        "runtime_secret_authority_requests",
        "runtime_secret_versions",
        "runtime_secret_bindings",
        "runtime_secret_consumers",
        "runtime_secret_consumer_receipts",
        "runtime_secret_retirements",
        "runtime_secret_events",
        "secret_retirements",
        "secret_retirement_outbox",
        "secret_retirement_steps",
        "secret_retirement_events",
    ] {
        let mut statement =
            connection.prepare(&format!("SELECT * FROM {table} ORDER BY 1 LIMIT 4097"))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            ensure!(values.len() < 4096, "simulation journal row budget");
            let mut fields = Vec::new();
            for column in 0..columns {
                fields.push(match row.get_ref(column)? {
                    ValueRef::Null => serde_json::Value::Null,
                    ValueRef::Integer(value) => serde_json::json!(value),
                    ValueRef::Text(value) => {
                        serde_json::Value::String(std::str::from_utf8(value)?.into())
                    }
                    _ => anyhow::bail!("unexpected simulation journal storage"),
                });
            }
            values.push(fields);
        }
        // Composite keys may share the first column; canonicalize complete rows.
        values.sort_by_cached_key(|row| serde_json::to_vec(row).expect("JSON scalar rows"));
        snapshot.insert(table, values);
    }
    Digest::of(&snapshot)
}

pub fn run(scenario: &Scenario, directory: &Path) -> Result<Trace> {
    scenario.validate()?;
    if directory.exists() {
        ensure!(
            fs::read_dir(directory)?.next().is_none(),
            "simulation requires fresh directory"
        );
    } else {
        fs::create_dir_all(directory)?;
    }
    let mut world = World {
        path: directory.join("journal.sqlite"),
        now: 1000,
        plans: plans()?,
        submitted: BTreeSet::new(),
        provider: Arc::new(provider::Provider::default()),
        slots: std::array::from_fn(|_| None),
        events: Vec::new(),
        releases: releases::Releases::default(),
        workflows: workflows::Workflows::new()?,
        retirements: retirements::Retirements::new()?,
    };
    if scenario.format == 1 {
        for index in 0..3 {
            world
                .host(index, 0)
                .accept_as(&world.plans[index], "simulation_operator")?;
            world.submitted.insert(index);
        }
    }
    world.releases.initialize(&world.path, &world.plans)?;
    world.workflows.initialize(&world.plans)?;
    world.retirements.initialize(&world.path, &world.plans)?;
    let mut violation = None;
    for action in &scenario.actions {
        violation = world.event(action.clone())?;
        if violation.is_some() {
            break;
        }
    }
    let schedule_events = world.events.len() as u32;
    if violation.is_none() {
        violation = world.event(Action::Heal {})?;
        for _ in 0..8 {
            if violation.is_some() {
                break;
            }
            violation = world.event(Action::Tick {
                millis: (LEASE_TICK * 3) as u32,
            })?;
            for build in 0..BUILD_COUNT as u8 {
                if !world.submitted.contains(&(build as usize)) {
                    continue;
                }
                for action in [
                    Action::Claim {
                        build,
                        slot: build % 4,
                    },
                    Action::Perform {
                        slot: build % 4,
                        fault: Fault::None,
                    },
                    Action::Settle { slot: build % 4 },
                ] {
                    if violation.is_none() {
                        violation = world.event(action)?;
                    }
                }
            }
            if world
                .views()?
                .iter()
                .all(|view| view.state.next_effect().is_none())
            {
                break;
            }
        }
    }
    if violation.is_none() {
        for _ in 0..20 {
            if world.workflows.drain_complete(&world.path, &world.plans)? {
                break;
            }
            violation = world.event(Action::Tick {
                millis: (LEASE_TICK * 3) as u32,
            })?;
            for build in 0..BUILD_COUNT as u8 {
                for action in [
                    Action::ReleaseClaim {
                        build,
                        slot: build % 4,
                    },
                    Action::ReleasePerform {
                        slot: build % 4,
                        fault: Fault::None,
                    },
                    Action::ReleaseSettle { slot: build % 4 },
                ] {
                    if violation.is_none() {
                        violation = world.event(action)?;
                    }
                }
            }
            if violation.is_some() {
                break;
            }
        }
        if violation.is_none()
            && world
                .workflows
                .finish(&world.path, &world.plans, &world.releases, world.now)
                .is_err()
        {
            violation = Some(Violation {
                step: world.events.len() as u32,
                code: "release_fair_drain_exhausted".into(),
            });
        }
    }
    if violation.is_none() {
        for _ in 0..16 {
            if world.retirements.drain_complete(
                &world.path,
                &world.plans,
                &world.workflows.provider(),
            )? {
                break;
            }
            violation = world.event(Action::Tick { millis: 60_000 })?;
            for version in world.retirements.versions() {
                let slot = version % 4;
                for action in [
                    Action::RetirementClaim { version, slot },
                    Action::RetirementPerform {
                        slot,
                        fault: Fault::None,
                    },
                    Action::RetirementSettle { slot },
                ] {
                    if violation.is_none() {
                        violation = world.event(action)?;
                    }
                }
            }
            if violation.is_some() {
                break;
            }
        }
        if violation.is_none()
            && !world.retirements.drain_complete(
                &world.path,
                &world.plans,
                &world.workflows.provider(),
            )?
        {
            violation = Some(Violation {
                step: world.events.len() as u32,
                code: "retirement_fair_drain_exhausted".into(),
            });
        }
    }
    let mut dispositions = Vec::new();
    let records = world.provider.records()?;
    for view in world.views()? {
        let build = world
            .plans
            .iter()
            .position(|plan| plan.execution_id().is_ok_and(|id| id == view.id))
            .context("drain execution outside admitted catalog")?;
        if view.state.next_effect().is_none() {
            dispositions.push(Disposition::Terminal {
                build: build as u8,
                state: view.state,
            });
        } else if view.state.next_effect() == Some(EffectKind::PublishCheck) {
            let effect = crate::kernel::effect_id(&world.plans[build], EffectKind::PublishCheck)?;
            let connection = rusqlite::Connection::open(&world.path)?;
            let uncertain:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM effects WHERE id=?1 AND status='ambiguous' AND recovery=1)",[effect.as_str()],|row|row.get(0))?;
            if uncertain && !records.iter().any(|record| record.effect == effect) {
                dispositions.push(Disposition::NeedsInterventionUnknownPublication {
                    build: build as u8,
                    effect,
                });
            } else if violation.is_none() {
                violation = Some(Violation {
                    step: world.events.len() as u32,
                    code: "fair_drain_exhausted".into(),
                });
            }
        } else if violation.is_none() {
            violation = Some(Violation {
                step: world.events.len() as u32,
                code: "fair_drain_exhausted".into(),
            });
        }
    }
    let trace = Trace {
        format: 5,
        implementation: implementation_digest()?,
        scenario: scenario.clone(),
        plans: world.plans.clone(),
        events: world.events,
        schedule_events,
        dispositions,
        provider_records: records,
        publications: world.provider.mutations()?,
        releases: world.releases.states(&world.path, &world.plans)?,
        workflow: world.workflows.evidence(&world.path, &world.plans)?,
        retirement: world.retirements.evidence(
            &world.path,
            &world.plans,
            &world.workflows.provider(),
        )?,
        violation,
    };
    trace.validate()?;
    Ok(trace)
}

pub fn replay(trace: &Trace, directory: &Path) -> Result<()> {
    trace.validate()?;
    ensure!(
        run(&trace.scenario, directory)? == *trace,
        "simulation trace replay diverged"
    );
    Ok(())
}
