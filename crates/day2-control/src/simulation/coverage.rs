//! Coverage of observed host behavior, separate from generated action intent.
//! Recovery-drain progress cannot satisfy the scheduled campaign requirements.
use super::{Action, Event, ExecutionView, ObservedRecovery as RecoveryMode, Trace};
use crate::{
    Digest,
    kernel::{EffectKind, Observation, State},
    provider_evidence::{RevisionRelation, RevisionToken, StateEvidence},
    release::ReleaseState,
    release_execution::{
        ReleaseObserved, ReleaseOperation, ReleaseProviderFact, ReleaseSnapshot, ReleaseTerminal,
    },
    runtime_secret::{
        ConsumerQuiescenceProof, ConsumerStage, ConsumerView, SecretVersionKey, VersionState,
    },
    secret_retirement::{
        RetirementFact, RetirementObserved, RetirementPhase, RetirementSnapshot,
        RetirementTerminal, RetirementWait,
    },
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transition {
    BuildSubmitted,
    SourceReady,
    ArtifactVerified,
    BuildSucceeded,
    BuildCancelled,
    ReleaseApproved,
    ReleaseStarted,
    ReleaseAdvanced,
    ReleaseProviderMutation,
    ReleaseProviderObservation,
    WorkflowActivated,
    LegacyActivated,
    ReleaseRevoked,
    ReleaseCancelled,
    AuthorityChanged,
    SecretChanged,
    SecretDelivered,
    ProviderCompleted,
    ProviderAmbiguous,
    ProviderNotApplied,
    ReconcileClaimed,
    ReconciledTransition,
    PendingRestart,
    IsolationRefused,
    ForgedCompletionRefused,
    CrossExecutionInterleave,
    CrossCompanyInterleave,
    SharedSecretConsumers,
    SharedSecretRollover,
    ProtectedRetirementWait,
    DeploymentDrained,
    DeploymentQuiesced,
    RollbackReleased,
    RetirementRequested,
    RetirementProviderMutation,
    RetirementReconciled,
    SecretDisabled,
    StaleProviderRead,
    OpaqueProviderRead,
    QueuedRetirement,
    QueuedRetirementReconciliation,
    OriginalRequestDelivered,
    ExternalDisableUnattributed,
    UnqualifiedDrainRefused,
    ControllerRecreated,
    FencedRecreationRefused,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub attempted: u64,
    pub admitted: u64,
    pub refused: u64,
    pub inert: u64,
    pub transitions: BTreeMap<Transition, u64>,
}

impl Counts {
    pub fn observed(&self, transition: Transition) -> u64 {
        self.transitions.get(&transition).copied().unwrap_or(0)
    }

    fn record(&mut self, transition: Transition, count: u64) -> Result<()> {
        if count != 0 {
            add(self.transitions.entry(transition).or_default(), count)?;
        }
        Ok(())
    }

    fn merge(&mut self, other: &Self) -> Result<()> {
        add(&mut self.attempted, other.attempted)?;
        add(&mut self.admitted, other.admitted)?;
        add(&mut self.refused, other.refused)?;
        add(&mut self.inert, other.inert)?;
        for (&transition, &count) in &other.transitions {
            self.record(transition, count)?;
        }
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.admitted
                .checked_add(self.refused)
                .and_then(|value| value.checked_add(self.inert))
                == Some(self.attempted),
            "simulation coverage outcome partition"
        );
        ensure!(
            self.transitions.values().all(|value| *value != 0),
            "simulation coverage contains an unwitnessed transition"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub format: u32,
    pub cases: u64,
    pub meaningful_scheduled_cases: u64,
    pub scheduled: Counts,
    pub drain: Counts,
}

impl Default for Coverage {
    fn default() -> Self {
        Self {
            format: 1,
            cases: 0,
            meaningful_scheduled_cases: 0,
            scheduled: Counts::default(),
            drain: Counts::default(),
        }
    }
}

impl Coverage {
    pub fn from_trace(trace: &Trace) -> Result<Self> {
        from_trace(trace)
    }

    pub fn merge(&mut self, other: &Self) -> Result<()> {
        self.validate()?;
        other.validate()?;
        let mut merged = self.clone();
        add(&mut merged.cases, other.cases)?;
        add(
            &mut merged.meaningful_scheduled_cases,
            other.meaningful_scheduled_cases,
        )?;
        merged.scheduled.merge(&other.scheduled)?;
        merged.drain.merge(&other.drain)?;
        merged.validate()?;
        *self = merged;
        Ok(())
    }

    pub fn require_campaign(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.cases >= 8,
            "simulation coverage needs eight generated cases"
        );
        ensure!(
            self.meaningful_scheduled_cases >= 2,
            "simulation coverage needs progress in multiple generated schedules"
        );
        for transition in [
            Transition::BuildSubmitted,
            Transition::BuildSucceeded,
            Transition::ReleaseApproved,
            Transition::ReleaseStarted,
            Transition::ReleaseProviderMutation,
            Transition::WorkflowActivated,
            Transition::IsolationRefused,
            Transition::CrossExecutionInterleave,
            Transition::PendingRestart,
            Transition::SharedSecretConsumers,
            Transition::SharedSecretRollover,
            Transition::ProtectedRetirementWait,
            Transition::DeploymentDrained,
            Transition::DeploymentQuiesced,
            Transition::RollbackReleased,
            Transition::SecretDisabled,
            Transition::RetirementReconciled,
            Transition::StaleProviderRead,
            Transition::OpaqueProviderRead,
            Transition::QueuedRetirement,
            Transition::QueuedRetirementReconciliation,
            Transition::OriginalRequestDelivered,
            Transition::ExternalDisableUnattributed,
            Transition::UnqualifiedDrainRefused,
            Transition::ControllerRecreated,
            Transition::FencedRecreationRefused,
        ] {
            ensure!(
                self.scheduled.observed(transition) > 0,
                "simulation generated coverage missing {transition:?} before recovery drain"
            );
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1 && self.meaningful_scheduled_cases <= self.cases,
            "simulation coverage version/case count"
        );
        self.scheduled.validate()?;
        self.drain.validate()
    }
}

fn add(target: &mut u64, value: u64) -> Result<()> {
    *target = target
        .checked_add(value)
        .context("simulation coverage overflow")?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Work {
    Build(u8),
    Release(Digest),
    Retirement(Digest),
}

#[derive(Clone)]
struct Slot {
    work: Work,
    recovery: RecoveryMode,
    build_effect: Option<EffectKind>,
}

struct Observer {
    builds: BTreeMap<Digest, ExecutionView>,
    releases: Vec<ReleaseState>,
    workflows: BTreeMap<Digest, ReleaseSnapshot>,
    release_builds: BTreeMap<Digest, u8>,
    build_slots: [Option<Slot>; 4],
    release_slots: [Option<Slot>; 4],
    mutations: usize,
    observations: usize,
    journal: Option<Digest>,
    provider: Option<Digest>,
    now: u64,
    previous_work: Option<Work>,
    last_work: Option<Work>,
    retirements: RetirementObserver,
}

impl Observer {
    fn new(trace: &Trace) -> Result<Self> {
        let builds = if trace.scenario.format == 1 {
            trace
                .plans
                .iter()
                .take(3)
                .map(|plan| {
                    let id = plan.execution_id()?;
                    Ok((
                        id.clone(),
                        ExecutionView {
                            id,
                            state: State::Accepted,
                            revision: 0,
                            cancelled: false,
                        },
                    ))
                })
                .collect::<Result<_>>()?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            builds,
            releases: vec![
                ReleaseState {
                    generation: 0,
                    desired: None,
                    active: None
                };
                trace.releases.len()
            ],
            workflows: BTreeMap::new(),
            release_builds: BTreeMap::new(),
            build_slots: std::array::from_fn(|_| None),
            release_slots: std::array::from_fn(|_| None),
            mutations: 0,
            observations: 0,
            journal: None,
            provider: None,
            now: 0,
            previous_work: None,
            last_work: None,
            retirements: RetirementObserver::default(),
        })
    }

    fn observe(&mut self, trace: &Trace, event: &Event, counts: &mut Counts) -> Result<()> {
        add(&mut counts.attempted, 1)?;
        ensure!(
            event.release_states.len() == self.releases.len(),
            "coverage release target count"
        );
        let builds: BTreeMap<_, _> = event
            .executions
            .iter()
            .map(|view| (view.id.clone(), view.clone()))
            .collect();
        let workflows: BTreeMap<_, _> = event
            .release_executions
            .iter()
            .map(|view| (view.id.clone(), view.clone()))
            .collect();
        ensure!(
            builds.len() == event.executions.len()
                && workflows.len() == event.release_executions.len(),
            "coverage duplicate execution"
        );
        ensure!(
            self.builds.keys().all(|id| builds.contains_key(id))
                && self.workflows.keys().all(|id| workflows.contains_key(id)),
            "coverage execution disappeared"
        );
        let mut witnessed = false;
        let mut subject = self.subject(&event.action, &workflows);
        let mut progressed = false;
        for (id, current) in &builds {
            let build = trace
                .plans
                .iter()
                .position(|plan| plan.execution_id().is_ok_and(|known| known == *id))
                .context("coverage unknown build")? as u8;
            let Some(previous) = self.builds.get(id) else {
                ensure!(
                    matches!(event.action, Action::Submit { build: submitted } if submitted == build)
                        && current.state == State::Accepted,
                    "coverage build appeared without submission"
                );
                counts.record(Transition::BuildSubmitted, 1)?;
                witnessed = true;
                subject = Some(Work::Build(build));
                continue;
            };
            ensure!(
                current.revision >= previous.revision,
                "coverage build revision regressed"
            );
            if current.state != previous.state {
                ensure!(
                    match event.action {
                        Action::Settle { slot } => self.build_slots[slot as usize]
                            .as_ref()
                            .is_some_and(|pending| pending.work == Work::Build(build)),
                        Action::Claim { build: claimed, .. } => {
                            claimed == build
                                && previous.cancelled
                                && current.state == State::Cancelled
                        }
                        _ => false,
                    },
                    "coverage build transition outside matching claim settlement"
                );
                ensure!(
                    current.revision > previous.revision,
                    "coverage build changed without revision"
                );
                witness_build(trace, build, &current.state)?;
                match &current.state {
                    State::SourceReady { .. } => counts.record(Transition::SourceReady, 1)?,
                    State::Verified { .. } => counts.record(Transition::ArtifactVerified, 1)?,
                    State::Succeeded { .. } => counts.record(Transition::BuildSucceeded, 1)?,
                    State::Cancelled => counts.record(Transition::BuildCancelled, 1)?,
                    _ => {}
                }
                progressed = true;
                witnessed = true;
                subject = Some(Work::Build(build));
            }
            witnessed |= current.cancelled != previous.cancelled;
        }
        for (index, current) in event.release_states.iter().enumerate() {
            let previous = &self.releases[index];
            ensure!(
                current.generation >= previous.generation,
                "coverage release generation regressed"
            );
            if current.desired != previous.desired {
                ensure!(
                    matches!(
                        event.action,
                        Action::Approve {
                            wrong_commit: false,
                            wrong_tenant: false,
                            ..
                        }
                    ) && current.desired.is_some()
                        && current.generation > previous.generation,
                    "coverage desired release changed without approval"
                );
                counts.record(Transition::ReleaseApproved, 1)?;
                witnessed = true;
            }
            if current.active != previous.active {
                let receipt = current
                    .active
                    .as_ref()
                    .context("coverage active release disappeared")?;
                if matches!(event.action, Action::ReleaseSettle { .. }) {
                    ensure!(
                        trace.workflow.activations.contains(receipt)
                            && workflows
                                .values()
                                .any(|execution| execution.plan.release == receipt.release
                                    && execution.terminal == Some(ReleaseTerminal::Activated)),
                        "coverage activation lacks native receipt"
                    );
                    counts.record(Transition::WorkflowActivated, 1)?;
                } else {
                    ensure!(
                        matches!(event.action, Action::Activate { .. }),
                        "coverage activation outside settlement"
                    );
                    counts.record(Transition::LegacyActivated, 1)?;
                }
                witnessed = true;
                progressed = true;
            }
        }
        for (id, current) in &workflows {
            if let Some(previous) = self.workflows.get(id) {
                ensure!(
                    current.revision >= previous.revision
                        && current.next_step >= previous.next_step,
                    "coverage release revision regressed"
                );
                if current.phase != previous.phase
                    || current.next_step != previous.next_step
                    || current.terminal != previous.terminal
                {
                    ensure!(
                        match event.action {
                            Action::ReleaseSettle { slot } => self.release_slots[slot as usize]
                                .as_ref()
                                .is_some_and(|pending| pending.work == Work::Release(id.clone())),
                            Action::ReleaseClaim { build, .. } => {
                                self.release_builds.get(id) == Some(&build)
                            }
                            _ => false,
                        },
                        "coverage release transition outside matching claim settlement"
                    );
                    ensure!(
                        current.revision > previous.revision,
                        "coverage release changed without revision"
                    );
                    counts.record(Transition::ReleaseAdvanced, 1)?;
                    witnessed = true;
                    progressed = true;
                    subject = Some(Work::Release(id.clone()));
                }
            } else {
                let Action::ReleaseStart { build } = event.action else {
                    anyhow::bail!("coverage release appeared without admission");
                };
                ensure!(
                    trace
                        .workflow
                        .executions
                        .iter()
                        .any(|execution| execution.id == *id && execution.plan == current.plan),
                    "coverage release admission lacks final journal evidence"
                );
                self.release_builds.insert(id.clone(), build);
                counts.record(Transition::ReleaseStarted, 1)?;
                witnessed = true;
                subject = Some(Work::Release(id.clone()));
            }
        }
        let mutations = event.release_mutations as usize;
        let observations = event.release_observations as usize;
        ensure!(
            mutations >= self.mutations
                && mutations <= trace.workflow.provider.mutations.len()
                && observations >= self.observations
                && observations <= trace.workflow.provider.observations.len(),
            "coverage provider evidence count"
        );
        if mutations != self.mutations || observations != self.observations {
            ensure!(
                matches!(event.action, Action::ReleasePerform { .. }),
                "coverage provider evidence outside dispatch"
            );
            for mutation in &trace.workflow.provider.mutations[self.mutations..mutations] {
                let execution = workflows
                    .get(&mutation.fact.execution)
                    .context("coverage mutation without execution")?;
                ensure!(
                    matches!(
                        mutation.operation,
                        ReleaseOperation::PrepareDependency | ReleaseOperation::PrepareDeployment
                    ) && mutation.fact.plan == execution.plan.fingerprint()?
                        && mutation.fact.release == execution.plan.release
                        && mutation.fact.target == execution.target,
                    "coverage mutation scope mismatch"
                );
            }
            counts.record(
                Transition::ReleaseProviderMutation,
                (mutations - self.mutations) as u64,
            )?;
            counts.record(
                Transition::ReleaseProviderObservation,
                (observations - self.observations) as u64,
            )?;
            witnessed = true;
        }
        let retirement_witness = self.retirements.observe(trace, event, counts)?;
        witnessed |= retirement_witness;
        if retirement_witness && let Some(work) = self.retirements.subject(&event.action) {
            subject = Some(work);
        }
        let claimed = match event.action {
            Action::RetirementClaim { .. } if event.outcome == "retirement_claimed" => true,
            Action::Claim { build, slot } if event.outcome == "claimed" => {
                let recovery = event
                    .recovery
                    .context("coverage native claim missing recovery")?;
                let work = Work::Build(build);
                ensure!(
                    self.pending(trace, &work),
                    "coverage claim for inactive build"
                );
                self.build_slots[slot as usize] = Some(Slot {
                    work: work.clone(),
                    recovery,
                    build_effect: trace.plans[build as usize]
                        .execution_id()
                        .ok()
                        .and_then(|id| self.builds.get(&id))
                        .and_then(|view| view.state.next_effect()),
                });
                subject = Some(work);
                true
            }
            Action::ReleaseClaim { build, slot } if event.outcome == "release_claimed" => {
                let recovery = event
                    .recovery
                    .context("coverage release claim missing recovery")?;
                let execution = workflows
                    .values()
                    .find(|execution| {
                        self.release_builds.get(&execution.id) == Some(&build)
                            && execution.terminal.is_none()
                    })
                    .context("coverage claim without active release")?;
                let work = Work::Release(execution.id.clone());
                self.release_slots[slot as usize] = Some(Slot {
                    work: work.clone(),
                    recovery,
                    build_effect: None,
                });
                subject = Some(work);
                true
            }
            Action::Claim { slot, .. } => {
                self.build_slots[slot as usize] = None;
                false
            }
            Action::ReleaseClaim { slot, .. } => {
                self.release_slots[slot as usize] = None;
                false
            }
            _ => false,
        };
        ensure!(
            claimed == event.recovery.is_some(),
            "coverage recovery evidence without acquired claim"
        );
        if event.recovery == Some(RecoveryMode::Reconcile) {
            counts.record(Transition::ReconcileClaimed, 1)?;
        }
        witnessed |= claimed;
        if let Action::Perform { slot, .. } = event.action
            && self.build_slots[slot as usize].is_some()
        {
            let transition = match event.outcome.as_str() {
                "provider_completed" => Some(Transition::ProviderCompleted),
                "provider_ambiguous" => Some(Transition::ProviderAmbiguous),
                "provider_not_applied" => Some(Transition::ProviderNotApplied),
                _ => None,
            };
            if let Some(transition) = transition {
                if transition == Transition::ProviderCompleted {
                    let pending = self.build_slots[slot as usize]
                        .as_ref()
                        .context("coverage provider completion without claim")?;
                    let Work::Build(build) = pending.work else {
                        anyhow::bail!("coverage build provider has wrong slot");
                    };
                    let plan = &trace.plans[build as usize];
                    let kind = pending
                        .build_effect
                        .context("coverage missing build effect")?;
                    let effect = crate::kernel::effect_id(plan, kind)?;
                    ensure!(
                        trace
                            .provider_records
                            .iter()
                            .any(|record| record.effect == effect
                                && record.kind == kind
                                && record.company == plan.company.as_str()
                                && record.commit == plan.commit.as_str()),
                        "coverage provider completion lacks effect receipt"
                    );
                }
                counts.record(transition, 1)?;
                witnessed = true;
            }
        }
        if progressed
            && self
                .settlement_slot(&event.action)
                .is_some_and(|slot| slot.recovery == RecoveryMode::Reconcile)
        {
            counts.record(Transition::ReconciledTransition, 1)?;
        }
        let journal_changed = self
            .journal
            .as_ref()
            .is_some_and(|digest| *digest != event.journal);
        let provider_changed = self
            .provider
            .as_ref()
            .is_some_and(|digest| *digest != event.provider);
        if let Action::ReleasePerform { slot, .. } = event.action
            && self.release_slots[slot as usize].is_some()
            && event.outcome == "release_provider_observed"
            && (journal_changed || provider_changed)
        {
            witnessed = true;
        }
        match event.action {
            Action::RevokeRelease { .. }
                if journal_changed && event.outcome == "release_accepted" =>
            {
                counts.record(Transition::ReleaseRevoked, 1)?;
                witnessed = true;
            }
            Action::ReleaseCancel { .. }
                if journal_changed && event.outcome == "release_accepted" =>
            {
                counts.record(Transition::ReleaseCancelled, 1)?;
                witnessed = true;
            }
            Action::RevokeAuthority { .. }
                if journal_changed && event.outcome == "release_accepted" =>
            {
                counts.record(Transition::AuthorityChanged, 1)?;
                witnessed = true;
            }
            Action::Secret { .. } | Action::ReleaseSecret { .. }
                if journal_changed || provider_changed =>
            {
                counts.record(Transition::SecretChanged, 1)?;
                witnessed = true;
            }
            Action::ReleaseDeliverSecret { .. }
                if journal_changed && event.outcome == "release_secret_delivered" =>
            {
                counts.record(Transition::SecretDelivered, 1)?;
                witnessed = true;
            }
            Action::Restart {} if event.outcome == "host_restarted" => {
                if self
                    .builds
                    .values()
                    .any(|execution| execution.state.next_effect().is_some())
                    || self
                        .workflows
                        .values()
                        .any(|execution| execution.terminal.is_none())
                    || self
                        .retirements
                        .snapshot
                        .executions
                        .iter()
                        .any(|execution| execution.terminal.is_none())
                {
                    counts.record(Transition::PendingRestart, 1)?;
                    witnessed = true;
                }
                self.build_slots = std::array::from_fn(|_| None);
                self.release_slots = std::array::from_fn(|_| None);
            }
            Action::Tick { .. } if event.now > self.now => witnessed = true,
            Action::Binding { .. } | Action::ReleaseUncertain { .. } | Action::Heal {}
                if provider_changed =>
            {
                witnessed = true
            }
            _ => {}
        }
        let refused = matches!(
            event.outcome.as_str(),
            "submission_refused"
                | "refused"
                | "provider_refused"
                | "isolation_refused"
                | "forged_evidence_refused"
                | "release_refused"
                | "release_start_refused"
                | "release_fenced"
                | "retirement_refused"
                | "retirement_fenced"
        );
        if event.outcome == "isolation_refused" {
            ensure!(
                matches!(event.action, Action::ProbeIsolation { .. })
                    && self.builds == builds
                    && self.releases == event.release_states
                    && self.workflows == workflows,
                "coverage isolation refusal changed authority"
            );
            counts.record(Transition::IsolationRefused, 1)?;
        }
        if event.outcome == "forged_evidence_refused" {
            ensure!(
                matches!(event.action, Action::PoisonCompletion { .. }) && self.builds == builds,
                "coverage forged completion changed state"
            );
            counts.record(Transition::ForgedCompletionRefused, 1)?;
        }
        if refused {
            add(&mut counts.refused, 1)?;
        } else if witnessed {
            add(&mut counts.admitted, 1)?;
            if let Some(work) = subject {
                self.interleave(trace, work, counts)?;
            }
        } else {
            add(&mut counts.inert, 1)?;
        }
        self.builds = builds;
        self.releases = event.release_states.clone();
        self.workflows = workflows;
        self.mutations = mutations;
        self.observations = observations;
        self.journal = Some(event.journal.clone());
        self.provider = Some(event.provider.clone());
        self.now = event.now;
        Ok(())
    }

    fn settlement_slot(&self, action: &Action) -> Option<&Slot> {
        match action {
            Action::Settle { slot } => self.build_slots[*slot as usize].as_ref(),
            Action::ReleaseSettle { slot } => self.release_slots[*slot as usize].as_ref(),
            _ => None,
        }
    }

    fn subject(
        &self,
        action: &Action,
        workflows: &BTreeMap<Digest, ReleaseSnapshot>,
    ) -> Option<Work> {
        match action {
            Action::Submit { build }
            | Action::Claim { build, .. }
            | Action::Cancel { build }
            | Action::Approve { build, .. } => Some(Work::Build(*build)),
            Action::Perform { slot, .. } | Action::Settle { slot } => self.build_slots
                [*slot as usize]
                .as_ref()
                .map(|slot| slot.work.clone()),
            Action::ReleasePerform { slot, .. } | Action::ReleaseSettle { slot } => self
                .release_slots[*slot as usize]
                .as_ref()
                .map(|slot| slot.work.clone()),
            Action::ReleaseClaim { build, .. } => workflows
                .values()
                .find(|execution| {
                    self.release_builds.get(&execution.id) == Some(build)
                        && execution.terminal.is_none()
                })
                .map(|execution| Work::Release(execution.id.clone())),
            _ => None,
        }
    }

    fn pending(&self, trace: &Trace, work: &Work) -> bool {
        match work {
            Work::Build(build) => trace
                .plans
                .get(*build as usize)
                .and_then(|plan| plan.execution_id().ok())
                .and_then(|id| self.builds.get(&id))
                .is_some_and(|execution| execution.state.next_effect().is_some()),
            Work::Release(id) => self
                .workflows
                .get(id)
                .is_some_and(|execution| execution.terminal.is_none()),
            Work::Retirement(id) => self
                .retirements
                .snapshot
                .executions
                .iter()
                .any(|execution| execution.id == *id && execution.terminal.is_none()),
        }
    }

    fn company<'a>(&'a self, trace: &'a Trace, work: &Work) -> Option<&'a str> {
        match work {
            Work::Build(build) => trace
                .plans
                .get(*build as usize)
                .map(|plan| plan.company.as_str()),
            Work::Release(id) => self
                .workflows
                .get(id)
                .map(|execution| execution.target.company.as_str()),
            Work::Retirement(id) => self
                .retirements
                .snapshot
                .executions
                .iter()
                .find(|execution| execution.id == *id)
                .map(|execution| execution.plan.scope.company.as_str()),
        }
    }

    fn interleave(&mut self, trace: &Trace, work: Work, counts: &mut Counts) -> Result<()> {
        if self.last_work.as_ref() == Some(&work) {
            return Ok(());
        }
        if let Some(last) = &self.last_work
            && self.previous_work.as_ref() == Some(&work)
            && self.pending(trace, &work)
            && self.pending(trace, last)
        {
            counts.record(Transition::CrossExecutionInterleave, 1)?;
            if self.company(trace, &work) != self.company(trace, last) {
                counts.record(Transition::CrossCompanyInterleave, 1)?;
            }
        }
        self.previous_work = self.last_work.replace(work);
        Ok(())
    }
}

#[derive(Clone)]
struct RetirementSlot {
    execution: RetirementSnapshot,
    effect: Digest,
    recovery: RecoveryMode,
    observation: Option<crate::secret_retirement::RetirementObservation>,
}

impl RetirementSlot {
    fn new(execution: &RetirementSnapshot, recovery: RecoveryMode) -> Result<Self> {
        let operation = match execution.phase {
            RetirementPhase::WaitingConsumers => "wait_consumers",
            RetirementPhase::Eligible => "disable_version",
            RetirementPhase::WaitingDisabled => "observe_disabled",
            RetirementPhase::Disabled => "complete",
            _ => anyhow::bail!("coverage claimed terminal retirement"),
        };
        Ok(Self {
            effect: Digest::of(&(
                "day2-secret-retirement-step-v1",
                &execution.id,
                &execution.plan.recipe,
                operation,
                execution.next_step,
            ))?,
            execution: execution.clone(),
            recovery,
            observation: None,
        })
    }

    fn matches(&self, fact: &RetirementFact) -> Result<bool> {
        Ok(fact.execution == self.execution.id
            && fact.effect == self.effect
            && fact.plan == self.execution.plan.fingerprint()?
            && fact.key == self.execution.plan.key
            && fact.scope == self.execution.plan.scope
            && fact.binding == self.execution.plan.resources)
    }
}

#[derive(Default)]
struct RetirementObserver {
    snapshot: super::retirements::Snapshot,
    slots: [Option<RetirementSlot>; 4],
    shared: BTreeMap<Digest, (SecretVersionKey, BTreeSet<Digest>)>,
    rolled: BTreeSet<Digest>,
    queued_reconciled: BTreeSet<Digest>,
}

fn protected(consumer: &ConsumerView) -> bool {
    matches!(
        consumer.stage,
        ConsumerStage::Pending | ConsumerStage::Active | ConsumerStage::Draining
    ) || consumer.rollback_protected
}

impl RetirementObserver {
    fn subject(&self, action: &Action) -> Option<Work> {
        match action {
            Action::RetirementPerform { slot, .. } | Action::RetirementSettle { slot } => self
                .slots[*slot as usize]
                .as_ref()
                .map(|slot| Work::Retirement(slot.execution.id.clone())),
            Action::RetireSecret { version } | Action::RetirementClaim { version, .. } => self
                .snapshot
                .executions
                .iter()
                .find(|execution| execution.plan.key.version.get() == u64::from(*version))
                .map(|execution| Work::Retirement(execution.id.clone())),
            _ => None,
        }
    }

    fn observe(&mut self, trace: &Trace, event: &Event, counts: &mut Counts) -> Result<bool> {
        let current = &event.retirement;
        let before = &self.snapshot;
        let mut witnessed = false;
        ensure!(
            current.observations >= before.observations
                && current.observations as usize <= trace.retirement.provider.observations.len()
                && current.weak_events >= before.weak_events
                && current.weak_events as usize <= trace.retirement.provider.weak_events.len()
                && current.attempts >= before.attempts
                && current.attempts as usize <= trace.retirement.provider.attempts.len(),
            "coverage retirement observation budget"
        );
        ensure!(
            before
                .executions
                .iter()
                .all(|old| current.executions.iter().any(|new| new.id == old.id))
                && before.consumers.iter().all(|old| current
                    .consumers
                    .iter()
                    .any(|new| new.release == old.release)),
            "coverage retirement state disappeared"
        );
        for execution in &current.executions {
            if let Some(old) = before.executions.iter().find(|old| old.id == execution.id) {
                ensure!(
                    execution.plan == old.plan
                        && execution.revision >= old.revision
                        && execution.next_step >= old.next_step,
                    "coverage retirement identity/revision changed"
                );
                if execution.revision > old.revision {
                    let settlement = match event.action {
                        Action::RetirementSettle { slot } => self.slots[slot as usize]
                            .as_ref()
                            .filter(|slot| slot.execution.id == execution.id),
                        _ => None,
                    };
                    ensure!(
                        settlement.is_some()
                            || matches!(event.action, Action::RetirementClaim { version, .. } if u64::from(version) == execution.plan.key.version.get()),
                        "coverage retirement transition without matching step"
                    );
                    if execution.waiting == Some(RetirementWait::Consumers)
                        && execution.next_step > old.next_step
                    {
                        ensure!(
                            settlement
                                .is_some_and(|slot| slot.execution.phase
                                    == RetirementPhase::WaitingConsumers)
                                && current
                                    .consumers
                                    .iter()
                                    .any(|consumer| consumer.key == execution.plan.key
                                        && protected(consumer)),
                            "coverage protected wait lacks consumer guard witness"
                        );
                        counts.record(Transition::ProtectedRetirementWait, 1)?;
                    }
                    if execution.next_step > old.next_step
                        && settlement.is_some_and(|slot| slot.recovery == RecoveryMode::Reconcile)
                        && old.phase == RetirementPhase::Eligible
                        && old.waiting == Some(RetirementWait::Reconciliation)
                        && execution.phase == RetirementPhase::WaitingDisabled
                    {
                        let slot = settlement.context("coverage reconciliation slot")?;
                        ensure!(
                            before.disabled_effects.contains(&slot.effect)
                                && trace.retirement.provider.mutations.iter().any(|mutation| {
                                    slot.matches(&mutation.fact).unwrap_or(false)
                                        && matches!(
                                            mutation.outcome,
                                            RetirementObserved::DisableAcknowledged { .. }
                                        )
                                        && trace.retirement.provider.observations
                                            [..current.observations as usize]
                                            .contains(mutation)
                                }),
                            "coverage disable reconciliation lacks prior mutation and exact acknowledged receipt"
                        );
                        counts.record(Transition::RetirementReconciled, 1)?;
                    }
                    if let Some(slot) = settlement
                        && slot.recovery == RecoveryMode::Reconcile
                        && slot.execution.phase == RetirementPhase::Eligible
                        && execution.phase == RetirementPhase::Eligible
                        && execution.next_step == old.next_step
                        && execution.waiting == Some(RetirementWait::Reconciliation)
                        && slot.observation.as_ref().is_some_and(|observation| {
                            matches!(
                                observation.outcome,
                                RetirementObserved::Disabled {
                                    evidence: StateEvidence::Observed { .. },
                                    ..
                                }
                            )
                        })
                    {
                        let history =
                            &trace.retirement.provider.weak_events[..before.weak_events as usize];
                        if history.iter().any(|event| matches!(event, super::release_provider::WeakEvent::Queued { fact, .. } if slot.matches(fact).unwrap_or(false)))
                            && !history.iter().any(|event| matches!(event, super::release_provider::WeakEvent::Delivered { fact, .. } if fact.effect == slot.effect))
                        {
                            self.queued_reconciled.insert(slot.effect.clone());
                            counts.record(Transition::QueuedRetirementReconciliation, 1)?;
                        }
                    }
                    if old.terminal != Some(RetirementTerminal::Disabled)
                        && execution.terminal == Some(RetirementTerminal::Disabled)
                    {
                        ensure!(
                            settlement.is_some_and(
                                |slot| slot.execution.phase == RetirementPhase::Disabled
                            ) && current
                                .versions
                                .iter()
                                .any(|version| version.key == execution.plan.key
                                    && version.state == VersionState::Disabled)
                                && !current
                                    .consumers
                                    .iter()
                                    .any(|consumer| consumer.key == execution.plan.key
                                        && protected(consumer)),
                            "coverage disabled retirement lacks final guard"
                        );
                        ensure!(trace.retirement.provider.mutations.iter().any(|mutation| {
                            mutation.fact.key == execution.plan.key
                                && current.disabled_effects.contains(&mutation.fact.effect)
                                && matches!(&mutation.outcome, RetirementObserved::DisableAcknowledged { acknowledgement } if acknowledgement.effect == mutation.fact.effect)
                                && trace.retirement.provider.observations[..current.observations as usize].iter().any(|observation| {
                                    observation.fact.execution == execution.id && observation.fact.key == execution.plan.key
                                        && matches!(&observation.outcome, RetirementObserved::Disabled { disabled: true, evidence: StateEvidence::Qualified { revision, barrier } }
                                            if barrier.authority == execution.plan.resources
                                            && Digest::of(&execution.plan.key).is_ok_and(|key| key == barrier.resource)
                                            && barrier.after_effect.as_ref() == Some(&mutation.fact.effect)
                                            && matches!(&mutation.outcome, RetirementObserved::DisableAcknowledged { acknowledgement }
                                                if matches!(revision.relation(&acknowledgement.revision), RevisionRelation::Same | RevisionRelation::Newer)))
                                })
                        }), "coverage disabled retirement lacks exact acknowledged mutation and qualified readback");
                        counts.record(Transition::SecretDisabled, 1)?;
                    }
                    witnessed = true;
                }
            } else {
                ensure!(
                    matches!(event.action, Action::RetireSecret { version } if u64::from(version) == execution.plan.key.version.get())
                        && trace
                            .retirement
                            .snapshot
                            .executions
                            .iter()
                            .any(|known| known.id == execution.id && known.plan == execution.plan),
                    "coverage retirement appeared without admission"
                );
                counts.record(Transition::RetirementRequested, 1)?;
                witnessed = true;
            }
        }

        let prior_effects: BTreeSet<_> = before.disabled_effects.iter().collect();
        let effects: BTreeSet<_> = current.disabled_effects.iter().collect();
        let prior_drains: BTreeSet<_> = before.drained_releases.iter().collect();
        let drains: BTreeSet<_> = current.drained_releases.iter().collect();
        let prior_quiescence: BTreeSet<_> = before.quiesced_receipts.iter().collect();
        let quiescence: BTreeSet<_> = current.quiesced_receipts.iter().collect();
        ensure!(
            effects.len() == current.disabled_effects.len()
                && current.mutations as usize == effects.len()
                && drains.len() == current.drained_releases.len()
                && current.drains as usize == drains.len()
                && prior_effects.is_subset(&effects)
                && prior_drains.is_subset(&drains)
                && quiescence.len() == current.quiesced_receipts.len()
                && prior_quiescence.is_subset(&quiescence)
                && current.observations >= before.observations
                && current.observations as usize <= trace.retirement.provider.observations.len(),
            "coverage retirement provider counts/identities mismatch"
        );
        for receipt in quiescence.difference(&prior_quiescence) {
            let Action::QuiesceDeployment { build, delay } = event.action else {
                anyhow::bail!("coverage quiescence outside provider environment event");
            };
            let proof = trace
                .retirement
                .provider
                .quiesced
                .iter()
                .find(|proof| Digest::of(proof).is_ok_and(|digest| &digest == *receipt))
                .context("coverage quiescence lacks provider proof")?;
            ensure!(
                proof.release == proof.deployment.release
                    && current
                        .consumers
                        .iter()
                        .any(|consumer| consumer.release == proof.release
                            && consumer.key == proof.key
                            && consumer.target == proof.deployment.target)
                    && proof.deployment.target
                        == super::releases::target(&trace.plans[build as usize])?
                    && proof.deployment.artifact
                        == super::provider::Provider::artifact(&trace.plans[build as usize])?
                    && proof.visible_at
                        == event
                            .now
                            .checked_add(u64::from(delay))
                            .context("quiescence clock overflow")?
                    && trace.workflow.provider.mutations[..event.release_mutations as usize]
                        .iter()
                        .any(|mutation| mutation.fact == proof.deployment
                            && mutation.operation == ReleaseOperation::PrepareDeployment),
                "coverage quiescence is not bound to an existing deployment"
            );
            counts.record(Transition::DeploymentQuiesced, 1)?;
            witnessed = true;
        }
        for effect in effects.difference(&prior_effects) {
            let mutation = trace
                .retirement
                .provider
                .mutations
                .iter()
                .find(|mutation| &mutation.fact.effect == *effect)
                .context("coverage disable lacks provider fact")?;
            let authorized = match event.action {
                Action::RetirementPerform { slot, .. } => self.slots[slot as usize].as_ref().is_some_and(|lease|
                    lease.matches(&mutation.fact).unwrap_or(false)
                        && lease.execution.phase == RetirementPhase::Eligible
                        && lease.recovery == RecoveryMode::Execute),
                Action::DeliverRetirement { version } => u64::from(version) == mutation.fact.key.version.get()
                    && trace.retirement.provider.weak_events[..before.weak_events as usize].iter().any(|event|
                        matches!(event, super::release_provider::WeakEvent::Queued { fact, .. } if fact == &mutation.fact))
                    && trace.retirement.provider.weak_events[before.weak_events as usize..current.weak_events as usize].iter().any(|event|
                        matches!(event, super::release_provider::WeakEvent::Delivered { fact, applied: true } if fact == &mutation.fact)),
                _ => false,
            };
            ensure!(
                authorized
                    && matches!(&mutation.outcome, RetirementObserved::DisableAcknowledged { acknowledgement } if acknowledgement.effect == mutation.fact.effect)
                    && !current
                        .consumers
                        .iter()
                        .any(|consumer| consumer.key == mutation.fact.key && protected(consumer)),
                "coverage destructive effect lacks exact unprotected execute lease"
            );
            counts.record(Transition::RetirementProviderMutation, 1)?;
            witnessed = true;
        }
        for observation in &trace.retirement.provider.observations
            [before.observations as usize..current.observations as usize]
        {
            let Action::RetirementPerform { slot, .. } = event.action else {
                anyhow::bail!("coverage retirement readback outside dispatch");
            };
            let lease = self.slots[slot as usize]
                .as_ref()
                .context("coverage retirement observation lacks lease")?;
            ensure!(
                lease.matches(&observation.fact)?
                    && trace.retirement.provider.attempts
                        [before.attempts as usize..current.attempts as usize]
                        .iter()
                        .any(|attempt| attempt.fact == observation.fact
                            && attempt.recovery == lease.recovery
                            && attempt.now == event.now),
                "coverage retirement observation scope mismatch"
            );
            witnessed = true;
        }
        witnessed |= self.observe_weak(trace, event, counts)?;
        for release in drains.difference(&prior_drains) {
            let Action::ReleaseDrain { build } = event.action else {
                anyhow::bail!("coverage deployment readback outside drain operation");
            };
            let proof = trace
                .retirement
                .provider
                .drains
                .iter()
                .find(|proof| &proof.release == *release)
                .context("coverage drain lacks provider proof")?;
            let consumer = current
                .consumers
                .iter()
                .find(|consumer| consumer.release == proof.release)
                .context("coverage drain missing consumer")?;
            self.witness_quiescence(trace, event, proof)?;
            ensure!(
                consumer.target == super::releases::target(&trace.plans[build as usize])?
                    && proof.key == consumer.key
                    && proof.deployment.release == consumer.release
                    && proof.deployment.target == consumer.target
                    && proof.deployment.artifact
                        == super::provider::Provider::artifact(&trace.plans[build as usize])?
                    && consumer.successor.as_ref() == Some(&proof.successor),
                "coverage drain proof scope/deployment mismatch"
            );
            witnessed = true;
        }
        for consumer in &current.consumers {
            let Some(old) = before
                .consumers
                .iter()
                .find(|old| old.release == consumer.release)
            else {
                continue;
            };
            ensure!(
                old.key == consumer.key && old.target == consumer.target,
                "coverage consumer changed identity"
            );
            if old.stage != ConsumerStage::Drained && consumer.stage == ConsumerStage::Drained {
                let Action::ReleaseDrain { build } = event.action else {
                    anyhow::bail!("coverage consumer drained outside explicit observation");
                };
                let proof = consumer
                    .drain
                    .as_ref()
                    .context("coverage drained consumer lacks proof")?;
                self.witness_quiescence(trace, event, proof)?;
                ensure!(
                    consumer.target == super::releases::target(&trace.plans[build as usize])?
                        && old.stage == ConsumerStage::Draining
                        && current.drained_releases.contains(&consumer.release)
                        && trace.retirement.provider.drains.contains(proof)
                        && proof.release == consumer.release
                        && proof.key == consumer.key
                        && consumer.successor.as_ref() == Some(&proof.successor),
                    "coverage drain transition lacks exact provider proof"
                );
                counts.record(Transition::DeploymentDrained, 1)?;
                witnessed = true;
            }
            if old.rollback_protected && !consumer.rollback_protected {
                let Action::ReleaseRollback { build } = event.action else {
                    anyhow::bail!("coverage rollback pin removed without release operation");
                };
                ensure!(
                    consumer.target == super::releases::target(&trace.plans[build as usize])?
                        && old.stage == ConsumerStage::Drained
                        && consumer.stage == ConsumerStage::Drained
                        && old.drain.is_some()
                        && old.drain == consumer.drain,
                    "coverage rollback release lacks completed drain"
                );
                counts.record(Transition::RollbackReleased, 1)?;
                witnessed = true;
            }
        }
        let mut active: BTreeMap<Digest, (SecretVersionKey, BTreeSet<Digest>)> = BTreeMap::new();
        for consumer in current
            .consumers
            .iter()
            .filter(|consumer| consumer.stage == ConsumerStage::Active)
        {
            ensure!(
                event
                    .release_states
                    .iter()
                    .filter_map(|state| state.active.as_ref())
                    .any(|receipt| receipt.release == consumer.release
                        && receipt.target == consumer.target)
                    && (trace
                        .workflow
                        .activations
                        .iter()
                        .any(|receipt| receipt.release == consumer.release
                            && receipt.target == consumer.target)
                        || matches!(trace.scenario.format, 1 | 2)),
                "coverage active consumer lacks native activation receipt"
            );
            active
                .entry(Digest::of(&consumer.key)?)
                .or_insert_with(|| (consumer.key.clone(), BTreeSet::new()))
                .1
                .insert(Digest::of(&consumer.target)?);
        }
        for (id, (key, targets)) in &active {
            if targets.len() >= 2 && !self.shared.contains_key(id) {
                self.shared
                    .insert(id.clone(), (key.clone(), targets.clone()));
                counts.record(Transition::SharedSecretConsumers, 1)?;
            }
        }
        for (id, (key, targets)) in &self.shared {
            if key.version.get() == 1
                && !self.rolled.contains(id)
                && active.values().any(|(next, next_targets)| {
                    next.resource == key.resource
                        && next.version.get() == 2
                        && targets.is_subset(next_targets)
                })
            {
                self.rolled.insert(id.clone());
                counts.record(Transition::SharedSecretRollover, 1)?;
            }
        }
        match event.action {
            Action::RetirementPerform { slot, .. } => {
                if let Some(lease) = self.slots[slot as usize].as_mut() {
                    lease.observation = trace.retirement.provider.observations
                        [before.observations as usize..current.observations as usize]
                        .iter()
                        .find(|observation| lease.matches(&observation.fact).unwrap_or(false))
                        .cloned();
                }
            }
            Action::RetirementClaim { version, slot } if event.outcome == "retirement_claimed" => {
                let execution = current
                    .executions
                    .iter()
                    .find(|execution| {
                        execution.plan.key.version.get() == u64::from(version)
                            && execution.terminal.is_none()
                    })
                    .context("coverage retirement claim missing execution")?;
                self.slots[slot as usize] = Some(RetirementSlot::new(
                    execution,
                    event
                        .recovery
                        .context("coverage retirement claim missing recovery")?,
                )?);
                witnessed = true;
            }
            Action::RetirementClaim { slot, .. } => self.slots[slot as usize] = None,
            Action::Restart {} => self.slots = std::array::from_fn(|_| None),
            _ => {}
        }
        self.snapshot = current.clone();
        Ok(witnessed)
    }

    fn observe_weak(&self, trace: &Trace, event: &Event, counts: &mut Counts) -> Result<bool> {
        use super::release_provider::WeakEvent;
        let before = &self.snapshot;
        let current = &event.retirement;
        let history = &trace.retirement.provider.weak_events[..before.weak_events as usize];
        let added = &trace.retirement.provider.weak_events
            [before.weak_events as usize..current.weak_events as usize];
        let observations = &trace.retirement.provider.observations
            [before.observations as usize..current.observations as usize];
        let attempts = &trace.retirement.provider.attempts
            [before.attempts as usize..current.attempts as usize];
        let previous_reads = event
            .index
            .checked_sub(1)
            .and_then(|index| trace.events.get(index as usize))
            .map_or(0, |prior| prior.release_observations as usize);
        for weak in added {
            match weak {
                WeakEvent::Read {
                    key,
                    current: revision,
                    returned,
                    after_effect,
                } => {
                    let actual = observations.iter().any(|observation| observation.fact.key == *key
                        && matches!(&observation.outcome, RetirementObserved::Disabled { evidence: StateEvidence::Observed { revision }, .. } if revision == returned))
                        || trace.workflow.provider.observations[previous_reads..event.release_observations as usize].iter().any(|observation| {
                            matches!(&observation.outcome, ReleaseObserved::Secret { metadata: Some(metadata) }
                                if metadata.reference.version == key.version && metadata.provider_state.barrier().is_none() && metadata.provider_state.revision() == returned)
                                && trace.plans.iter().any(|plan| plan.company == observation.fact.target.company
                                    && super::releases::resource(plan).is_ok_and(|resource| resource == key.resource))
                        });
                    ensure!(
                        actual,
                        "coverage weak read lacks an actual unqualified provider observation"
                    );
                    if returned.relation(revision) == RevisionRelation::Older {
                        counts.record(Transition::StaleProviderRead, 1)?;
                    }
                    if matches!(returned, RevisionToken::Opaque { .. }) {
                        counts.record(Transition::OpaqueProviderRead, 1)?;
                    }
                    if let Some(effect) = after_effect
                        && history
                            .iter()
                            .rev()
                            .find_map(|event| match event {
                                WeakEvent::ExternalChanged {
                                    key: changed,
                                    revision,
                                    enabled,
                                } if changed == key => Some((revision, enabled)),
                                _ => None,
                            })
                            .is_some_and(|(external, enabled)| !enabled && external == returned)
                        && observations.iter().any(|observation| {
                            observation.fact.key == *key
                                && observation.fact.effect == *effect
                                && matches!(
                                    observation.outcome,
                                    RetirementObserved::Disabled {
                                        disabled: true,
                                        evidence: StateEvidence::Observed { .. }
                                    }
                                )
                        })
                    {
                        ensure!(
                            !trace
                                .retirement
                                .provider
                                .mutations
                                .iter()
                                .any(|mutation| mutation.fact.key == *key
                                    && current.disabled_effects.contains(&mutation.fact.effect)),
                            "external state was attributed to a platform mutation"
                        );
                        ensure!(
                            current
                                .executions
                                .iter()
                                .any(|execution| execution.plan.key == *key
                                    && execution.phase == RetirementPhase::Eligible
                                    && execution.terminal.is_none()),
                            "external disabled observation completed retirement"
                        );
                        counts.record(Transition::ExternalDisableUnattributed, 1)?;
                    }
                }
                WeakEvent::Queued { fact, .. } => {
                    let Action::RetirementPerform { slot, .. } = event.action else {
                        anyhow::bail!("coverage queued write outside dispatch");
                    };
                    let lease = self.slots[slot as usize]
                        .as_ref()
                        .context("coverage queued write missing lease")?;
                    ensure!(
                        lease.matches(fact)?
                            && lease.execution.phase == RetirementPhase::Eligible
                            && lease.recovery == RecoveryMode::Execute
                            && attempts.iter().any(|attempt| attempt.fact == *fact
                                && attempt.recovery == RecoveryMode::Execute
                                && !attempt.had_disable_receipt)
                            && !current.disabled_effects.contains(&fact.effect),
                        "coverage queued write lacks exact unapplied dispatch"
                    );
                    counts.record(Transition::QueuedRetirement, 1)?;
                }
                WeakEvent::Delivered { fact, applied } => {
                    ensure!(matches!(event.action, Action::DeliverRetirement { version } if u64::from(version) == fact.key.version.get())
                        && history.iter().any(|event| matches!(event, WeakEvent::Queued { fact: queued, .. } if queued == fact))
                        && !history.iter().any(|event| matches!(event, WeakEvent::Delivered { fact: prior, .. } if prior.effect == fact.effect)),
                        "coverage delivered write lacks unique original queued identity");
                    if *applied {
                        ensure!(current.disabled_effects.contains(&fact.effect)
                            && trace.retirement.provider.mutations.iter().any(|mutation| mutation.fact == *fact
                                && matches!(&mutation.outcome, RetirementObserved::DisableAcknowledged { acknowledgement } if acknowledgement.effect == fact.effect)),
                            "coverage delivery lacks original mutation acknowledgement");
                        if self.queued_reconciled.contains(&fact.effect) {
                            counts.record(Transition::OriginalRequestDelivered, 1)?;
                        }
                    } else {
                        ensure!(
                            !current.disabled_effects.contains(&fact.effect),
                            "condition-refused delivery applied a mutation"
                        );
                    }
                }
                WeakEvent::ExternalChanged {
                    key,
                    revision,
                    enabled,
                } => {
                    ensure!(
                        matches!(event.action, Action::ExternalSecretState { version, enabled: expected } if u64::from(version) == key.version.get() && expected == *enabled)
                            && !current
                                .consumers
                                .iter()
                                .any(|consumer| consumer.key == *key && protected(consumer))
                            && trace.workflow.provider.secrets.iter().any(|secret| secret
                                .metadata
                                .provider_state
                                .revision()
                                == revision
                                && secret.metadata.enabled == *enabled),
                        "coverage external state has no exact provider mutation witness"
                    );
                }
                WeakEvent::ObservationStopped {
                    release,
                    incarnation,
                } => {
                    ensure!(matches!(event.action, Action::ObserveStoppedDeployment { .. })
                        && trace.workflow.provider.observations[..event.release_observations as usize].iter().any(|observation|
                            observation.fact.release == *release && matches!(&observation.outcome, ReleaseObserved::DeploymentPrepared { incarnation: prepared } if prepared == incarnation)),
                        "coverage observed stop lacks an actual deployment incarnation");
                }
                WeakEvent::UnqualifiedDrain { observation } => {
                    ensure!(matches!(event.action, Action::ReleaseDrain { .. }) && event.outcome == "retirement_refused"
                        && matches!(observation.proof, ConsumerQuiescenceProof::ObservationOnly { .. })
                        && before.consumers == current.consumers
                        && !current.drained_releases.contains(&observation.release)
                        && history.iter().any(|event| matches!(event, WeakEvent::ObservationStopped { release, incarnation }
                            if release == &observation.release && matches!(&observation.proof, ConsumerQuiescenceProof::ObservationOnly { incarnation: observed, .. } if observed == incarnation))),
                        "coverage weak drain lacks refusal preserving protected consumers");
                    counts.record(Transition::UnqualifiedDrainRefused, 1)?;
                }
                WeakEvent::Recreated {
                    release,
                    incarnation,
                    accepted,
                } => {
                    ensure!(
                        matches!(event.action, Action::RecreateDeployment { .. }),
                        "coverage recreation outside environment action"
                    );
                    let fenced = trace.retirement.provider.quiesced.iter().any(|proof| {
                        proof.release == *release
                            && proof.incarnation == *incarnation
                            && Digest::of(proof)
                                .is_ok_and(|id| before.quiesced_receipts.contains(&id))
                    });
                    if *accepted {
                        ensure!(
                            !fenced,
                            "coverage accepted recreation crossed a controller fence"
                        );
                        let was_stopped = history
                            .iter()
                            .rev()
                            .find_map(|event| match event {
                                WeakEvent::ObservationStopped {
                                    release: prior,
                                    incarnation: observed,
                                } if prior == release && observed == incarnation => Some(true),
                                WeakEvent::Recreated {
                                    release: prior,
                                    incarnation: observed,
                                    accepted: true,
                                } if prior == release && observed == incarnation => Some(false),
                                _ => None,
                            })
                            .unwrap_or(false);
                        if was_stopped {
                            counts.record(Transition::ControllerRecreated, 1)?;
                        }
                    } else {
                        ensure!(
                            fenced,
                            "coverage refused recreation lacks prior exact controller fence"
                        );
                        counts.record(Transition::FencedRecreationRefused, 1)?;
                    }
                }
            }
        }
        Ok(!added.is_empty())
    }

    fn witness_quiescence(
        &self,
        trace: &Trace,
        event: &Event,
        drain: &crate::runtime_secret::ConsumerDrainObservation,
    ) -> Result<()> {
        let ConsumerQuiescenceProof::TerminatedAndFenced {
            subject,
            incarnation,
            authority,
            fence,
            coverage: _,
            receipt,
        } = &drain.proof
        else {
            anyhow::bail!("coverage drain is only an observation");
        };
        ensure!(
            subject.release == drain.release
                && subject.key == drain.key
                && subject.successor == drain.successor
                && subject.deployment == Digest::of(&drain.deployment)?,
            "coverage drain subject mismatch"
        );
        ensure!(
            trace.workflow.provider.observations[..event.release_observations as usize]
                .iter()
                .any(|observation| observation.fact == drain.deployment
                    && matches!(&observation.outcome, ReleaseObserved::DeploymentPrepared { incarnation: prepared } if prepared == incarnation)),
            "coverage drain lacks prior exact deployment acknowledgement"
        );
        ensure!(
            trace.retirement.provider.quiesced.iter().any(|proof| {
                proof.release == drain.release
                    && proof.key == drain.key
                    && same_deployment_identity(&proof.deployment, &drain.deployment)
                    && proof.incarnation == *incarnation
                    && proof.authority.as_ref() == Some(authority)
                    && proof.fence == *fence
                    && proof.visible_at <= event.now
                    && Digest::of(&(
                        "provider-quiescence-v1",
                        &proof.deployment,
                        proof.provider_revision,
                    ))
                    .is_ok_and(|digest| digest == proof.evidence)
                    && Digest::of(&("provider-deployment-drained-v1", proof, &drain.successor))
                        .is_ok_and(|digest| digest == *receipt)
                    && Digest::of(proof)
                        .is_ok_and(|digest| self.snapshot.quiesced_receipts.contains(&digest))
                    && trace.workflow.provider.mutations[..event.release_mutations as usize]
                        .iter()
                        .rfind(|mutation| {
                            mutation.operation == ReleaseOperation::PrepareDeployment
                                && mutation.fact.resource == proof.deployment.resource
                        })
                        .is_some_and(|mutation| mutation.fact == proof.deployment)
            }),
            "coverage drain lacks prior visible exact quiescence"
        );
        Ok(())
    }
}

/// The mutation and its acknowledgement have distinct evidence, not distinct
/// deployment identities. Both receipts must independently be witnessed above.
fn same_deployment_identity(left: &ReleaseProviderFact, right: &ReleaseProviderFact) -> bool {
    let ReleaseProviderFact {
        execution,
        effect,
        plan,
        release,
        target,
        artifact,
        secret,
        binding,
        resource,
        readiness,
        evidence: _,
    } = left;
    execution == &right.execution
        && effect == &right.effect
        && plan == &right.plan
        && release == &right.release
        && target == &right.target
        && artifact == &right.artifact
        && secret == &right.secret
        && binding == &right.binding
        && resource == &right.resource
        && readiness == &right.readiness
}

fn witness_build(trace: &Trace, build: u8, state: &State) -> Result<()> {
    let plan = trace
        .plans
        .get(build as usize)
        .context("coverage build index")?;
    let record = |kind: EffectKind| -> Result<_> {
        let effect = crate::kernel::effect_id(plan, kind)?;
        trace
            .provider_records
            .iter()
            .find(|record| {
                record.effect == effect
                    && record.kind == kind
                    && record.company == plan.company.as_str()
                    && record.app == plan.app.as_str()
                    && record.commit == plan.commit.as_str()
            })
            .context("coverage build transition lacks provider record")
    };
    match state {
        State::SourceReady { source } => ensure!(
            matches!(&record(EffectKind::FetchSource)?.observation, Observation::Source { source: observed } if observed == source),
            "coverage source receipt mismatch"
        ),
        State::Verified {
            artifact, evidence, ..
        } => ensure!(
            matches!(&record(EffectKind::VerifyArtifact)?.observation, Observation::Verified { evidence: observed } if observed.artifact == *artifact && Digest::of(observed)? == *evidence),
            "coverage verification receipt mismatch"
        ),
        State::Succeeded {
            artifact,
            evidence,
            publication,
        } => {
            ensure!(
                matches!(&record(EffectKind::VerifyArtifact)?.observation, Observation::Verified { evidence: observed } if observed.artifact == *artifact && Digest::of(observed)? == *evidence),
                "coverage success lacks verification"
            );
            ensure!(
                matches!(&record(EffectKind::PublishCheck)?.observation, Observation::Published { evidence: observed, publication: receipt } if observed == evidence && receipt == publication),
                "coverage success lacks publication"
            );
        }
        _ => {}
    }
    Ok(())
}

pub fn from_trace(trace: &Trace) -> Result<Coverage> {
    ensure!(
        trace.format == 5 && trace.violation.is_none(),
        "coverage requires a successful current trace"
    );
    trace.scenario.validate()?;
    ensure!(trace.plans.len() == 6, "coverage build catalog size");
    let scheduled = trace.schedule_events as usize;
    ensure!(
        scheduled == trace.scenario.actions.len() && scheduled <= trace.events.len(),
        "coverage scheduled boundary mismatch"
    );
    ensure!(
        trace
            .events
            .iter()
            .take(scheduled)
            .map(|event| &event.action)
            .eq(trace.scenario.actions.iter()),
        "coverage scheduled actions mismatch"
    );
    let mut coverage = Coverage {
        cases: 1,
        ..Coverage::default()
    };
    let mut observer = Observer::new(trace)?;
    for (index, event) in trace.events.iter().enumerate() {
        ensure!(
            event.index == index as u32 && event.now >= observer.now,
            "coverage event sequence mismatch"
        );
        event.action.validate()?;
        ensure!(
            event.outcome != "unexpected_host_failure" && event.outcome != "isolation_bypass",
            "coverage contains failed host evidence"
        );
        if index == scheduled {
            observer.previous_work = None;
            observer.last_work = None;
        }
        observer.observe(
            trace,
            event,
            if index < scheduled {
                &mut coverage.scheduled
            } else {
                &mut coverage.drain
            },
        )?;
    }
    ensure!(
        observer.mutations == trace.workflow.provider.mutations.len()
            && observer.observations == trace.workflow.provider.observations.len()
            && observer.retirements.snapshot == trace.retirement.snapshot,
        "coverage omitted provider evidence"
    );
    ensure!(
        observer.releases == trace.releases
            && observer
                .workflows
                .values()
                .eq(trace.workflow.executions.iter()),
        "coverage final journal evidence mismatch"
    );
    let activated: BTreeSet<_> = trace
        .workflow
        .activations
        .iter()
        .map(|receipt| &receipt.id)
        .collect();
    ensure!(
        activated.len() == trace.workflow.activations.len()
            && coverage.scheduled.observed(Transition::WorkflowActivated)
                + coverage.drain.observed(Transition::WorkflowActivated)
                == activated.len() as u64,
        "coverage activation evidence mismatch"
    );
    coverage.meaningful_scheduled_cases = u64::from(
        [
            Transition::SourceReady,
            Transition::ArtifactVerified,
            Transition::BuildSucceeded,
            Transition::ReleaseStarted,
            Transition::ReleaseAdvanced,
        ]
        .into_iter()
        .any(|transition| coverage.scheduled.observed(transition) != 0),
    );
    coverage.validate()?;
    Ok(coverage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_trace() -> Trace {
        Trace {
            format: 5,
            implementation: Digest::new(b"coverage-unit-test"),
            scenario: super::super::Scenario {
                format: 4,
                seed: 7,
                actions: Vec::new(),
            },
            plans: super::super::plans().unwrap(),
            events: Vec::new(),
            schedule_events: 0,
            dispositions: Vec::new(),
            provider_records: Vec::new(),
            publications: Vec::new(),
            releases: vec![
                ReleaseState {
                    generation: 0,
                    desired: None,
                    active: None
                };
                3
            ],
            workflow: super::super::workflows::Evidence {
                recipe: Digest::new(b"coverage-recipe"),
                executions: Vec::new(),
                provider: super::super::release_provider::Evidence::default(),
                activations: Vec::new(),
                dispositions: Vec::new(),
                delivered_secrets: Vec::new(),
                delivered_readbacks: Vec::new(),
            },
            retirement: super::super::retirements::Evidence {
                recipe: Digest::new(b"coverage-retirement-recipe"),
                snapshot: super::super::retirements::Snapshot::default(),
                provider: super::super::release_provider::RetirementEvidence::default(),
            },
            violation: None,
        }
    }

    fn push(
        trace: &mut Trace,
        action: Action,
        outcome: &str,
        views: Vec<ExecutionView>,
        recovery: Option<RecoveryMode>,
        scheduled: bool,
    ) {
        if scheduled {
            trace.scenario.actions.push(action.clone());
            trace.schedule_events += 1;
        }
        trace.events.push(Event {
            index: trace.events.len() as u32,
            now: 0,
            action,
            outcome: outcome.into(),
            journal: Digest::of(&(trace.events.len(), &views)).unwrap(),
            provider: Digest::new(b"unchanged-provider"),
            executions: views,
            release_states: trace.releases.clone(),
            release_executions: Vec::new(),
            release_mutations: 0,
            release_observations: 0,
            retirement: trace.retirement.snapshot.clone(),
            recovery,
        });
    }

    fn accepted(trace: &Trace, build: usize) -> ExecutionView {
        ExecutionView {
            id: trace.plans[build].execution_id().unwrap(),
            state: State::Accepted,
            revision: 0,
            cancelled: false,
        }
    }

    fn retirement_fact(trace: &Trace) -> Result<RetirementFact> {
        let target = super::super::releases::target(&trace.plans[0])?;
        Ok(RetirementFact {
            execution: Digest::new(b"retirement"),
            effect: Digest::new(b"disable"),
            plan: Digest::new(b"retirement-plan"),
            key: super::super::retirements::key(&trace.plans, 3)?,
            scope: crate::runtime_secret::ResourceScope {
                company: target.company,
                environment: target.environment,
            },
            binding: trace.plans[0].profile.builder.clone(),
            evidence: Digest::new(b"retirement-evidence"),
        })
    }

    #[test]
    fn weak_read_coverage_requires_actual_prefix_and_cannot_borrow_future_readbacks() -> Result<()>
    {
        use super::super::release_provider::WeakEvent;
        for opaque in [false, true] {
            let mut trace = empty_trace();
            let fact = retirement_fact(&trace)?;
            let current = RevisionToken::Ordered {
                stream: Digest::new(b"physical-version"),
                sequence: 2_u64.try_into()?,
            };
            let returned = if opaque {
                RevisionToken::Opaque {
                    token: "unorderable-etag".to_owned().try_into()?,
                }
            } else {
                RevisionToken::Ordered {
                    stream: Digest::new(b"physical-version"),
                    sequence: 1_u64.try_into()?,
                }
            };
            trace.retirement.provider.observations.push(
                crate::secret_retirement::RetirementObservation {
                    fact: fact.clone(),
                    outcome: RetirementObserved::Disabled {
                        disabled: false,
                        evidence: StateEvidence::Observed {
                            revision: returned.clone(),
                        },
                    },
                },
            );
            trace.retirement.provider.weak_events.push(WeakEvent::Read {
                key: fact.key,
                current,
                returned,
                after_effect: Some(fact.effect),
            });
            push(
                &mut trace,
                Action::RetirementPerform {
                    slot: 0,
                    fault: super::super::Fault::None,
                },
                "retirement_performed",
                vec![],
                None,
                true,
            );
            let mut event = trace.events[0].clone();
            let observer = RetirementObserver::default();
            let transition = if opaque {
                Transition::OpaqueProviderRead
            } else {
                Transition::StaleProviderRead
            };
            let mut counts = Counts::default();
            observer.observe_weak(&trace, &event, &mut counts)?;
            assert_eq!(counts.observed(transition), 0);
            event.retirement.weak_events = 1;
            assert!(observer.observe_weak(&trace, &event, &mut counts).is_err());
            assert_eq!(counts.observed(transition), 0);
            event.retirement.observations = 1;
            observer.observe_weak(&trace, &event, &mut counts)?;
            assert_eq!(counts.observed(transition), 1);
        }
        Ok(())
    }

    #[test]
    fn original_delivery_cannot_borrow_a_queue_record_from_a_later_event() -> Result<()> {
        use super::super::release_provider::WeakEvent;
        let mut trace = empty_trace();
        let fact = retirement_fact(&trace)?;
        trace.retirement.provider.weak_events = vec![
            WeakEvent::Delivered {
                fact: fact.clone(),
                applied: false,
            },
            WeakEvent::Queued {
                fact,
                condition: RevisionToken::Opaque {
                    token: "original-etag".to_owned().try_into()?,
                },
            },
        ];
        push(
            &mut trace,
            Action::DeliverRetirement { version: 3 },
            "provider_original_request_delivered",
            vec![],
            None,
            true,
        );
        let mut event = trace.events[0].clone();
        event.retirement.weak_events = 1;
        let observer = RetirementObserver::default();
        let mut counts = Counts::default();
        assert!(observer.observe_weak(&trace, &event, &mut counts).is_err());
        assert_eq!(counts.observed(Transition::OriginalRequestDelivered), 0);
        Ok(())
    }

    #[test]
    fn drain_witness_distinguishes_deployment_identity_from_receipt_evidence() -> Result<()> {
        use super::super::release_provider::{QuiescedDeployment, Resource};
        use crate::{
            provider_evidence::DeploymentIncarnation,
            release_execution::ReleaseObservation,
            runtime_secret::{
                ConsumerDrainObservation, ConsumerQuiescenceSubject, QuiescenceAuthorityRef,
                QuiescenceCoverage,
            },
        };
        use std::num::NonZeroU64;

        let mut trace = empty_trace();
        let plan = &trace.plans[0];
        let deployment = ReleaseProviderFact {
            execution: Digest::new(b"release-execution"),
            effect: Digest::new(b"prepare-deployment-effect"),
            plan: Digest::new(b"release-plan"),
            release: Digest::new(b"release"),
            target: super::super::releases::target(plan)?,
            artifact: super::super::provider::Provider::artifact(plan)?,
            secret: super::super::releases::secret(plan, 0)?,
            binding: plan.profile.builder.clone(),
            resource: Digest::new(b"deployment-resource"),
            readiness: Some(Digest::new(b"readiness")),
            evidence: Digest::new(b"prepare-mutation-evidence"),
        };
        let mut acknowledgement = deployment.clone();
        acknowledgement.evidence = Digest::new(b"prepare-acknowledgement-evidence");
        let incarnation = DeploymentIncarnation {
            controller: "controller-uid".to_owned().try_into()?,
            generation: "generation-1".to_owned().try_into()?,
        };
        trace.workflow.provider.mutations.push(Resource {
            fact: deployment.clone(),
            operation: ReleaseOperation::PrepareDeployment,
            visible_at: 0,
        });
        trace
            .workflow
            .provider
            .observations
            .push(ReleaseObservation {
                fact: acknowledgement.clone(),
                outcome: ReleaseObserved::DeploymentPrepared {
                    incarnation: incarnation.clone(),
                },
            });
        let revision = NonZeroU64::new(1).unwrap();
        let quiesced = QuiescedDeployment {
            release: deployment.release.clone(),
            key: super::super::retirements::key(&trace.plans, 1)?,
            evidence: Digest::of(&("provider-quiescence-v1", &deployment, revision))?,
            deployment,
            provider_revision: revision,
            visible_at: 0,
            incarnation: incarnation.clone(),
            authority: Some(serde_json::from_value::<QuiescenceAuthorityRef>(
                serde_json::json!({"id": Digest::new(b"fixture-qualification"), "revision": 1}),
            )?),
            fence: "exact-controller-fence".to_owned().try_into()?,
        };
        let successor = Digest::new(b"successor");
        let drain = ConsumerDrainObservation {
            release: quiesced.release.clone(),
            key: quiesced.key.clone(),
            deployment: acknowledgement.clone(),
            successor: successor.clone(),
            proof: ConsumerQuiescenceProof::TerminatedAndFenced {
                subject: Box::new(ConsumerQuiescenceSubject {
                    release: quiesced.release.clone(),
                    key: quiesced.key.clone(),
                    successor: successor.clone(),
                    deployment: Digest::of(&acknowledgement)?,
                }),
                incarnation,
                authority: quiesced.authority.clone().unwrap(),
                fence: quiesced.fence.clone(),
                coverage: QuiescenceCoverage::CompleteDescendantsAndDelegatedWork,
                receipt: Digest::of(&("provider-deployment-drained-v1", &quiesced, &successor))?,
            },
        };
        let mut observer = RetirementObserver::default();
        observer
            .snapshot
            .quiesced_receipts
            .push(Digest::of(&quiesced)?);
        trace.retirement.provider.quiesced.push(quiesced);
        push(
            &mut trace,
            Action::ReleaseDrain { build: 0 },
            "deployment_drain_observed",
            Vec::new(),
            None,
            true,
        );
        let mut event = trace.events[0].clone();
        event.release_mutations = 1;
        event.release_observations = 1;
        observer.witness_quiescence(&trace, &event, &drain)?;

        for altered in [
            ReleaseProviderFact {
                effect: Digest::new(b"another-effect"),
                ..drain.deployment.clone()
            },
            ReleaseProviderFact {
                readiness: Some(Digest::new(b"another-readiness")),
                ..drain.deployment.clone()
            },
        ] {
            let mut candidate = drain.clone();
            candidate.deployment = altered;
            let mut changed_trace = trace.clone();
            changed_trace.workflow.provider.observations[0].fact = candidate.deployment.clone();
            assert!(
                observer
                    .witness_quiescence(&changed_trace, &event, &candidate)
                    .is_err()
            );
        }
        let mut forged = drain.clone();
        let ConsumerQuiescenceProof::TerminatedAndFenced { receipt, .. } = &mut forged.proof else {
            unreachable!()
        };
        *receipt = Digest::new(b"unbound-drain-evidence");
        assert!(
            observer
                .witness_quiescence(&trace, &event, &forged)
                .is_err()
        );
        let mut unobserved = event.clone();
        unobserved.release_observations = 0;
        assert!(
            observer
                .witness_quiescence(&trace, &unobserved, &drain)
                .is_err()
        );
        observer.snapshot.quiesced_receipts.clear();
        assert!(observer.witness_quiescence(&trace, &event, &drain).is_err());
        Ok(())
    }

    #[test]
    fn labels_without_transitions_do_not_create_coverage() {
        let mut trace = empty_trace();
        push(
            &mut trace,
            Action::Settle { slot: 0 },
            "accepted",
            Vec::new(),
            None,
            true,
        );
        push(
            &mut trace,
            Action::ReleaseSettle { slot: 0 },
            "release_settled",
            Vec::new(),
            None,
            true,
        );
        let result = from_trace(&trace).unwrap();
        assert_eq!(result.scheduled.inert, 2);
        assert_eq!(result.scheduled.admitted, 0);
        assert!(result.scheduled.transitions.is_empty());
    }

    #[test]
    fn retirement_labels_cannot_supply_disable_or_cleanup_coverage() {
        let mut trace = empty_trace();
        for (action, label) in [
            (Action::RetirementSettle { slot: 0 }, "retirement_settled"),
            (
                Action::ReleaseDrain { build: 0 },
                "deployment_drain_observed",
            ),
            (
                Action::ReleaseRollback { build: 0 },
                "rollback_protection_released",
            ),
            (
                Action::QuiesceDeployment { build: 0, delay: 0 },
                "deployment_quiesced",
            ),
        ] {
            push(&mut trace, action, label, Vec::new(), None, true);
        }
        let result = from_trace(&trace).unwrap();
        assert_eq!(result.scheduled.inert, 4);
        assert_eq!(result.scheduled.observed(Transition::SecretDisabled), 0);
        assert_eq!(result.scheduled.observed(Transition::DeploymentDrained), 0);
        assert_eq!(result.scheduled.observed(Transition::RollbackReleased), 0);
        assert_eq!(result.scheduled.observed(Transition::DeploymentQuiesced), 0);
    }

    #[test]
    fn shared_consumer_count_requires_real_activated_applications() -> Result<()> {
        let mut trace = empty_trace();
        let key = super::super::retirements::key(&trace.plans, 1)?;
        for build in [0, 3] {
            trace.retirement.snapshot.consumers.push(ConsumerView {
                release: Digest::of(&("forged-active-release", build))?,
                target: super::super::releases::target(&trace.plans[build])?,
                key: key.clone(),
                stage: ConsumerStage::Active,
                successor: None,
                rollback_protected: false,
                drain: None,
            });
        }
        push(
            &mut trace,
            Action::Tick { millis: 1 },
            "clock_advanced",
            Vec::new(),
            None,
            true,
        );
        assert!(
            from_trace(&trace)
                .unwrap_err()
                .to_string()
                .contains("active consumer lacks native activation")
        );
        Ok(())
    }

    #[test]
    fn retirement_claim_recovery_requires_an_execution_witness() {
        let mut trace = empty_trace();
        push(
            &mut trace,
            Action::RetirementClaim {
                version: 1,
                slot: 0,
            },
            "retirement_claimed",
            Vec::new(),
            Some(RecoveryMode::Reconcile),
            true,
        );
        assert!(
            from_trace(&trace)
                .unwrap_err()
                .to_string()
                .contains("retirement claim missing execution")
        );
    }

    #[test]
    fn retirement_provider_counts_without_exact_identities_are_rejected() {
        let mut trace = empty_trace();
        trace.retirement.snapshot.mutations = 1;
        push(
            &mut trace,
            Action::RetirementPerform {
                slot: 0,
                fault: super::super::Fault::None,
            },
            "retirement_performed",
            Vec::new(),
            None,
            true,
        );
        assert!(
            from_trace(&trace)
                .unwrap_err()
                .to_string()
                .contains("retirement provider counts/identities")
        );
    }

    #[test]
    fn quiescence_requires_an_existing_exact_provider_fact() {
        let mut trace = empty_trace();
        trace
            .retirement
            .snapshot
            .quiesced_receipts
            .push(Digest::new(b"unknown-quiescence"));
        push(
            &mut trace,
            Action::QuiesceDeployment { build: 0, delay: 0 },
            "deployment_quiesced",
            Vec::new(),
            None,
            true,
        );
        assert!(
            from_trace(&trace)
                .unwrap_err()
                .to_string()
                .contains("quiescence lacks provider proof")
        );
    }

    #[test]
    fn recovery_drain_cannot_supply_scheduled_submission() {
        let mut trace = empty_trace();
        let views = vec![accepted(&trace, 0)];
        push(
            &mut trace,
            Action::Submit { build: 0 },
            "submitted",
            views,
            None,
            false,
        );
        let result = from_trace(&trace).unwrap();
        assert_eq!(result.scheduled.observed(Transition::BuildSubmitted), 0);
        assert_eq!(result.drain.observed(Transition::BuildSubmitted), 1);
    }

    #[test]
    fn duplicate_submission_and_cancellation_are_inert() {
        let mut trace = empty_trace();
        let views = vec![accepted(&trace, 0)];
        push(
            &mut trace,
            Action::Submit { build: 0 },
            "submitted",
            views.clone(),
            None,
            true,
        );
        push(
            &mut trace,
            Action::Submit { build: 0 },
            "already_submitted",
            views.clone(),
            None,
            true,
        );
        push(
            &mut trace,
            Action::Cancel { build: 0 },
            "accepted",
            views,
            None,
            true,
        );
        let result = from_trace(&trace).unwrap();
        assert_eq!(result.scheduled.admitted, 1);
        assert_eq!(result.scheduled.inert, 2);
    }

    #[test]
    fn claim_recovery_requires_native_witness() {
        let mut trace = empty_trace();
        let views = vec![accepted(&trace, 0)];
        push(
            &mut trace,
            Action::Submit { build: 0 },
            "submitted",
            views.clone(),
            None,
            true,
        );
        push(
            &mut trace,
            Action::Claim { build: 0, slot: 0 },
            "claimed",
            views,
            None,
            true,
        );
        assert!(
            from_trace(&trace)
                .unwrap_err()
                .to_string()
                .contains("missing recovery")
        );
    }

    #[test]
    fn actual_pending_restart_counts_but_idle_restart_does_not() {
        let mut trace = empty_trace();
        push(
            &mut trace,
            Action::Restart {},
            "host_restarted",
            Vec::new(),
            None,
            true,
        );
        let views = vec![accepted(&trace, 0)];
        push(
            &mut trace,
            Action::Submit { build: 0 },
            "submitted",
            views.clone(),
            None,
            true,
        );
        push(
            &mut trace,
            Action::Restart {},
            "host_restarted",
            views,
            None,
            true,
        );
        let result = from_trace(&trace).unwrap();
        assert_eq!(result.scheduled.observed(Transition::PendingRestart), 1);
        assert_eq!(result.scheduled.inert, 1);
    }

    #[test]
    fn interleaving_needs_live_execution_switches_not_action_mentions() {
        let mut trace = empty_trace();
        let first = accepted(&trace, 0);
        let second = accepted(&trace, 2);
        push(
            &mut trace,
            Action::Submit { build: 0 },
            "submitted",
            vec![first.clone()],
            None,
            true,
        );
        let views = vec![first, second];
        push(
            &mut trace,
            Action::Submit { build: 2 },
            "submitted",
            views.clone(),
            None,
            true,
        );
        push(
            &mut trace,
            Action::Claim { build: 0, slot: 0 },
            "claimed",
            views.clone(),
            Some(RecoveryMode::Execute),
            true,
        );
        push(
            &mut trace,
            Action::Claim { build: 2, slot: 1 },
            "claimed",
            views.clone(),
            Some(RecoveryMode::Execute),
            true,
        );
        push(
            &mut trace,
            Action::Perform {
                slot: 0,
                fault: super::super::Fault::Unavailable,
            },
            "provider_ambiguous",
            views,
            None,
            true,
        );
        let result = from_trace(&trace).unwrap();
        assert!(
            result
                .scheduled
                .observed(Transition::CrossExecutionInterleave)
                > 0
        );
        assert!(
            result
                .scheduled
                .observed(Transition::CrossCompanyInterleave)
                > 0
        );
    }

    #[test]
    fn missing_provider_record_cannot_claim_build_success() {
        let trace = empty_trace();
        let state = State::Succeeded {
            artifact: Digest::new(b"artifact"),
            evidence: Digest::new(b"evidence"),
            publication: Digest::new(b"publication"),
        };
        assert!(witness_build(&trace, 0, &state).is_err());
    }

    #[test]
    fn build_transition_cannot_be_relocated_into_a_scheduled_clock_event() {
        let mut trace = empty_trace();
        let mut view = accepted(&trace, 0);
        push(
            &mut trace,
            Action::Submit { build: 0 },
            "submitted",
            vec![view.clone()],
            None,
            true,
        );
        let source = Digest::new(b"real-final-source");
        let plan = &trace.plans[0];
        trace.provider_records.push(super::super::provider::Record {
            company: plan.company.as_str().into(),
            app: plan.app.as_str().into(),
            commit: plan.commit.as_str().into(),
            binding: plan.profile.source.clone(),
            effect: crate::kernel::effect_id(plan, EffectKind::FetchSource).unwrap(),
            kind: EffectKind::FetchSource,
            observation: Observation::Source {
                source: source.clone(),
            },
            visible_at: 0,
        });
        view.state = State::SourceReady { source };
        view.revision = 1;
        push(
            &mut trace,
            Action::Tick { millis: 1 },
            "clock_advanced",
            vec![view],
            None,
            true,
        );
        assert!(
            from_trace(&trace)
                .unwrap_err()
                .to_string()
                .contains("matching claim settlement")
        );
    }

    #[test]
    fn noop_and_drain_only_campaigns_fail_non_vacuity() {
        let mut campaign = Coverage::default();
        for _ in 0..8 {
            campaign
                .merge(&from_trace(&empty_trace()).unwrap())
                .unwrap();
        }
        assert!(campaign.require_campaign().is_err());
        campaign.meaningful_scheduled_cases = 8;
        campaign
            .drain
            .transitions
            .insert(Transition::WorkflowActivated, 8);
        assert!(campaign.require_campaign().is_err());
    }

    #[test]
    fn merge_rejects_forged_partitions_and_overflow_without_partial_update() {
        let mut coverage = Coverage::default();
        let mut forged = Coverage::default();
        forged.scheduled.admitted = 1;
        assert!(coverage.merge(&forged).is_err());
        assert_eq!(coverage, Coverage::default());
        coverage.cases = u64::MAX;
        assert!(
            coverage
                .merge(&Coverage {
                    cases: 1,
                    ..Coverage::default()
                })
                .is_err()
        );
        assert_eq!(coverage.cases, u64::MAX);
    }

    #[test]
    fn coverage_schema_rejects_unknown_counters() {
        let mut value = serde_json::to_value(Coverage::default()).unwrap();
        value["scheduled"]["transitions"]["imaginary_activation"] = 1.into();
        assert!(serde_json::from_value::<Coverage>(value).is_err());
    }
}
