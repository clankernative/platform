//! Shared-version lifecycle observations and an independent consumer oracle.
//! The real retirement host executes every lease and mutation guard.
use super::{
    Action, Fault, ObservedRecovery, name,
    release_provider::{Provider, RetirementEvidence},
    releases::{self, Releases},
};
use crate::{
    BindingRef, BuildPlan, Digest,
    journal::{Journal, OperatorActor},
    runtime_secret::{
        ConsumerStage, ConsumerView, QuiescenceAuthorityDecision, ResourceScope,
        RuntimeSecretRejection, SecretVersionKey, VersionState,
    },
    secret_retirement::{
        Recipe, RetirementClaim, RetirementEffectResult, RetirementExecutionHost, RetirementLease,
        RetirementPlan, RetirementRejection, RetirementSnapshot, RetirementTerminal,
    },
    secret_retirement_recipe::CompiledSecretRetirementRecipe,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    path::Path,
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionView {
    pub key: SecretVersionKey,
    pub state: VersionState,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub executions: Vec<RetirementSnapshot>,
    pub versions: Vec<VersionView>,
    pub consumers: Vec<ConsumerView>,
    pub mutations: u32,
    pub observations: u32,
    pub drains: u32,
    pub disabled_effects: Vec<Digest>,
    pub drained_releases: Vec<Digest>,
    pub quiesced_receipts: Vec<Digest>,
    pub weak_events: u32,
    pub attempts: u32,
}

impl Snapshot {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.executions.len() <= 3
                && self.versions.len() <= 4
                && self.consumers.len() <= 64
                && self.mutations <= 3
                && self.observations <= 2048
                && self.drains <= 64
                && self.quiesced_receipts.len() <= 128,
            "retirement event budget"
        );
        ensure!(
            self.weak_events <= 1024 && self.attempts <= 2048,
            "weak provider event budget"
        );
        ensure!(
            self.disabled_effects.len() == self.mutations as usize
                && self.drained_releases.len() == self.drains as usize
                && self.disabled_effects.iter().collect::<BTreeSet<_>>().len()
                    == self.disabled_effects.len()
                && self.drained_releases.iter().collect::<BTreeSet<_>>().len()
                    == self.drained_releases.len(),
            "retirement event provider identities"
        );
        ensure!(
            self.executions
                .iter()
                .map(|value| &value.id)
                .collect::<BTreeSet<_>>()
                .len()
                == self.executions.len()
                && self
                    .consumers
                    .iter()
                    .map(|value| &value.release)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.consumers.len(),
            "retirement event duplicate identities"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub recipe: Digest,
    pub snapshot: Snapshot,
    pub provider: RetirementEvidence,
}

impl Evidence {
    pub fn validate(&self) -> Result<()> {
        self.snapshot.validate()?;
        ensure!(
            self.recipe == CompiledSecretRetirementRecipe::installed()?.identity()?
                && self.snapshot.executions.len() <= 3
                && self.snapshot.versions.len() == 4
                && self.snapshot.consumers.len() <= 64
                && self.provider.mutations.len() <= 3
                && self.provider.observations.len() <= 2048
                && self.provider.drains.len() <= 64
                && self.provider.quiesced.len() <= 128
                && self.provider.attempts.len() <= 2048,
            "retirement evidence identity/budget"
        );
        ensure!(
            self.provider.weak_events.len() <= 1024
                && self.snapshot.weak_events as usize == self.provider.weak_events.len(),
            "weak provider evidence budget"
        );
        ensure!(
            self.snapshot.mutations as usize == self.provider.mutations.len()
                && self.snapshot.observations as usize == self.provider.observations.len()
                && self.snapshot.drains as usize == self.provider.drains.len(),
            "retirement evidence count mismatch"
        );
        ensure!(
            self.snapshot.attempts as usize == self.provider.attempts.len(),
            "retirement attempt count mismatch"
        );
        ensure!(
            self.snapshot.disabled_effects
                == self
                    .provider
                    .mutations
                    .iter()
                    .map(|value| value.fact.effect.clone())
                    .collect::<Vec<_>>()
                && self.snapshot.drained_releases
                    == self
                        .provider
                        .drains
                        .iter()
                        .map(|value| value.release.clone())
                        .collect::<Vec<_>>(),
            "retirement evidence identity mismatch"
        );
        ensure!(
            self.snapshot.quiesced_receipts
                == self
                    .provider
                    .quiesced
                    .iter()
                    .map(Digest::of)
                    .collect::<Result<Vec<_>>>()?,
            "retirement quiescence history mismatch"
        );
        Ok(())
    }
}

#[derive(Clone)]
struct Slot {
    lease: RetirementLease,
    result: Option<RetirementEffectResult>,
}

pub struct Retirements {
    recipe: Arc<CompiledSecretRetirementRecipe>,
    executions: BTreeMap<u8, Digest>,
    slots: [Option<Slot>; 4],
    drained: BTreeSet<Digest>,
    rollback_released: BTreeSet<Digest>,
}

fn actor() -> Result<OperatorActor> {
    "simulation_operator".to_owned().try_into()
}
pub(super) fn key(plans: &[BuildPlan], version: u8) -> Result<SecretVersionKey> {
    ensure!((1..=3).contains(&version), "secret version catalog");
    Ok(SecretVersionKey {
        resource: releases::resource(&plans[0])?,
        version: NonZeroU64::new(u64::from(version)).context("secret version")?,
    })
}

impl Retirements {
    pub fn new() -> Result<Self> {
        Ok(Self {
            recipe: Arc::new(CompiledSecretRetirementRecipe::installed()?),
            executions: BTreeMap::new(),
            slots: std::array::from_fn(|_| None),
            drained: BTreeSet::new(),
            rollback_released: BTreeSet::new(),
        })
    }

    pub fn initialize(&self, path: &Path, plans: &[BuildPlan]) -> Result<()> {
        for index in [0, 2] {
            let target = releases::target(&plans[index])?;
            Journal::open(path)?.observe_runtime_secret_authority(
                &releases::resource(&plans[index])?,
                &ResourceScope::from(&target),
                &name("initial_secret_authority")?,
                0,
                &Digest::new(b"protected-secret-retirement-policy-v1"),
                &actor()?,
            )?;
        }
        Ok(())
    }

    fn host(
        &self,
        path: &Path,
        plans: &[BuildPlan],
        provider: &Arc<Provider>,
        slot: usize,
    ) -> Result<RetirementExecutionHost> {
        Ok(RetirementExecutionHost::new(
            path.to_owned(),
            plans[0].company.clone(),
            name(&format!("retirement_worker_{slot}"))?,
            plans[0].profile.durability.clone(),
            provider.clone(),
            self.recipe.clone(),
        ))
    }

    pub fn restart(&mut self, path: &Path, plans: &[BuildPlan]) -> Result<()> {
        self.slots = std::array::from_fn(|_| None);
        let expected = self.executions.clone();
        self.executions.clear();
        self.recipe = Arc::new(CompiledSecretRetirementRecipe::installed()?);
        for execution in Journal::open(path)?.secret_retirements(
            &plans[0].company,
            &plans[0].profile.durability,
            4,
        )? {
            ensure!(
                execution.plan.key.resource == releases::resource(&plans[0])?,
                "retirement restart resource scope"
            );
            self.executions.insert(
                u8::try_from(execution.plan.key.version.get())?,
                execution.id,
            );
        }
        ensure!(
            self.executions == expected,
            "restart changed retirement admissions"
        );
        Ok(())
    }

    pub fn recovery(&self, slot: usize) -> Option<ObservedRecovery> {
        self.slots[slot]
            .as_ref()
            .map(|slot| slot.lease.recovery.into())
    }

    pub fn snapshot(
        &self,
        path: &Path,
        plans: &[BuildPlan],
        provider: &Arc<Provider>,
    ) -> Result<Snapshot> {
        let journal = Journal::open(path)?;
        let executions = self
            .executions
            .values()
            .map(|id| journal.secret_retirement(id))
            .collect::<Result<Vec<_>>>()?;
        let mut versions = Vec::new();
        let mut consumers = Vec::new();
        let mut keys = (1..=3)
            .map(|version| key(plans, version))
            .collect::<Result<Vec<_>>>()?;
        keys.push(SecretVersionKey {
            resource: releases::resource(&plans[2])?,
            version: NonZeroU64::new(3).expect("fixed version"),
        });
        for key in keys {
            versions.push(VersionView {
                state: journal.runtime_secret_version(&key)?,
                key: key.clone(),
            });
            let page = journal.runtime_secret_consumers(&key, None)?;
            ensure!(
                page.next.is_none() && consumers.len() + page.items.len() <= 64,
                "simulation consumer catalog budget"
            );
            consumers.extend(page.items);
        }
        let evidence = provider.retirement_evidence()?;
        Ok(Snapshot {
            executions,
            versions,
            consumers,
            mutations: evidence.mutations.len() as u32,
            observations: evidence.observations.len() as u32,
            drains: evidence.drains.len() as u32,
            disabled_effects: evidence
                .mutations
                .iter()
                .map(|value| value.fact.effect.clone())
                .collect(),
            drained_releases: evidence
                .drains
                .iter()
                .map(|value| value.release.clone())
                .collect(),
            quiesced_receipts: evidence
                .quiesced
                .iter()
                .map(Digest::of)
                .collect::<Result<Vec<_>>>()?,
            weak_events: evidence.weak_events.len() as u32,
            attempts: evidence.attempts.len() as u32,
        })
    }

    pub fn evidence(
        &self,
        path: &Path,
        plans: &[BuildPlan],
        provider: &Arc<Provider>,
    ) -> Result<Evidence> {
        Ok(Evidence {
            recipe: self.recipe.identity()?,
            snapshot: self.snapshot(path, plans, provider)?,
            provider: provider.retirement_evidence()?,
        })
    }

    pub fn perform(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        provider: &Arc<Provider>,
        releases: &mut Releases,
        action: &Action,
        now: u64,
    ) -> Result<String> {
        let result = self.apply(path, plans, provider, releases, action, now);
        match result {
            Ok(value) => Ok(value),
            Err(error)
                if matches!(
                    error.downcast_ref::<RuntimeSecretRejection>(),
                    Some(
                        RuntimeSecretRejection::VersionUnavailable
                            | RuntimeSecretRejection::ProtectedConsumers
                            | RuntimeSecretRejection::ActiveConsumer
                            | RuntimeSecretRejection::UnsettledEffects
                            | RuntimeSecretRejection::StaleDrain
                            | RuntimeSecretRejection::ConsumerConflict
                            | RuntimeSecretRejection::QuiescenceUnproven
                    )
                ) =>
            {
                Ok("retirement_refused".into())
            }
            Err(error)
                if error.downcast_ref::<RetirementRejection>()
                    == Some(&RetirementRejection::FencedLease) =>
            {
                Ok("retirement_fenced".into())
            }
            Err(error) => Err(error),
        }
    }

    fn apply(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        provider: &Arc<Provider>,
        releases: &mut Releases,
        action: &Action,
        now: u64,
    ) -> Result<String> {
        match *action {
            Action::SecretReadMode {
                version,
                selection,
                strength,
            } => {
                provider.read_mode(&key(plans, version)?, selection, strength)?;
                Ok("provider_read_mode_changed".into())
            }
            Action::HoldRetirement { version } => {
                provider.hold_retirement(&key(plans, version)?)?;
                Ok("provider_delivery_held".into())
            }
            Action::DeliverRetirement { version } => Ok(if provider
                .deliver_retirement(&key(plans, version)?, now)?
            {
                "provider_original_request_delivered"
            } else {
                "provider_no_queued_request"
            }
            .into()),
            Action::ExternalSecretState { version, enabled } => {
                let key = key(plans, version)?;
                let journal = Journal::open(path)?;
                if journal.runtime_secret_version(&key)? != VersionState::Retiring
                    || journal.runtime_secret_consumer_counts(&key)?.protected()
                {
                    return Ok("external_change_outside_bounded_scope".into());
                }
                Ok(if provider.external_secret_state(&key, enabled, now)? {
                    "external_provider_state_changed"
                } else {
                    "external_change_outside_bounded_scope"
                }
                .into())
            }
            Action::RetireSecret { version } => {
                let key = key(plans, version)?;
                let authority = Journal::open(path)?.runtime_secret_authority(&key.resource)?;
                let plan = RetirementPlan {
                    key,
                    scope: authority.scope,
                    request: name(&format!("retire_version_{version}"))?,
                    authority_revision: authority.revision,
                    policy: authority.policy,
                    actor: actor()?,
                    approval: Digest::of(&("approved-retirement", version))?,
                    resources: BindingRef::pin(
                        name("runtime_secret_retirement")?,
                        &releases::resource(&plans[0])?,
                    )?,
                    durability: plans[0].profile.durability.clone(),
                    recipe: self.recipe.identity()?,
                };
                provider.register_retirement(&plan)?;
                let id = self.host(path, plans, provider, 0)?.accept(&plan)?;
                self.executions.insert(version, id);
                releases.retire(plans, version)?;
                Ok("retirement_requested".into())
            }
            Action::RetirementClaim { version, slot } => {
                self.slots[slot as usize] = None;
                let Some(id) = self.executions.get(&version) else {
                    return Ok("retirement_not_started".into());
                };
                let host = self.host(path, plans, provider, slot as usize)?;
                let snapshot = host.inspect(id)?;
                if snapshot.terminal.is_some() {
                    return Ok("retirement_terminal".into());
                }
                let step = self.recipe.choose(&snapshot)?;
                match host.claim_at(id, &step, now)? {
                    RetirementClaim::Acquired(lease) => {
                        self.slots[slot as usize] = Some(Slot {
                            lease: *lease,
                            result: None,
                        });
                        Ok("retirement_claimed".into())
                    }
                    RetirementClaim::Busy => Ok("retirement_busy".into()),
                    RetirementClaim::Terminal(_) => Ok("retirement_terminal".into()),
                }
            }
            Action::RetirementPerform { slot, fault } => {
                provider.configure(now, fault)?;
                let Some(pending) = self.slots[slot as usize].clone() else {
                    return Ok("retirement_empty_slot".into());
                };
                let result = self
                    .host(path, plans, provider, slot as usize)?
                    .perform_at(&pending.lease, now)?;
                let label = match &result {
                    RetirementEffectResult::Ambiguous {} => "retirement_provider_ambiguous",
                    RetirementEffectResult::ReconciledAbsent { .. } => "retirement_provider_absent",
                    _ => "retirement_performed",
                };
                self.slots[slot as usize]
                    .as_mut()
                    .context("retirement slot")?
                    .result = Some(result);
                Ok(label.into())
            }
            Action::RetirementSettle { slot } => {
                let Some(pending) = self.slots[slot as usize].clone() else {
                    return Ok("retirement_empty_slot".into());
                };
                let Some(result) = pending.result else {
                    return Ok("retirement_no_outcome".into());
                };
                self.host(path, plans, provider, slot as usize)?.settle_at(
                    &pending.lease,
                    result,
                    now,
                )?;
                Ok("retirement_settled".into())
            }
            Action::ReleaseDrain { build } | Action::ReleaseRollback { build } => {
                let Some((id, _)) = releases.approval(build as usize) else {
                    return Ok("retirement_consumer_missing".into());
                };
                let mut journal = Journal::open(path)?;
                let consumer = journal.runtime_secret_consumer(&id)?;
                let Some(successor) = consumer.successor.clone() else {
                    return Ok("retirement_consumer_active_or_pending".into());
                };
                if matches!(action, Action::ReleaseRollback { .. }) {
                    journal.release_runtime_secret_rollback(&id, &successor, &actor()?)?;
                    self.rollback_released.insert(id);
                    Ok("rollback_protection_released".into())
                } else {
                    let Some(deployment) = journal.release_deployment_fact(&id)? else {
                        return Ok("retirement_deployment_missing".into());
                    };
                    provider.configure(now, Fault::None)?;
                    let Some(proof) = provider.observe_drain(&consumer, &deployment, &successor)?
                    else {
                        return Ok("retirement_drain_not_ready".into());
                    };
                    journal.observe_runtime_secret_drain(&proof, &actor()?)?;
                    self.drained.insert(id);
                    Ok("deployment_drain_observed".into())
                }
            }
            Action::QuiesceDeployment { build, delay } => {
                let Some((id, _)) = releases.approval(build as usize) else {
                    return Ok("retirement_consumer_missing".into());
                };
                // This environment action models retirement cleanup, not arbitrary
                // process failure. Physical quiescence and its readback remain separate.
                let consumer = Journal::open(path)?.runtime_secret_consumer(&id)?;
                if !matches!(
                    consumer.stage,
                    ConsumerStage::Draining | ConsumerStage::Drained
                ) || consumer.successor.is_none()
                {
                    return Ok("retirement_consumer_not_superseded".into());
                }
                let mut journal = Journal::open(path)?;
                let Some(deployment) = journal.release_deployment_fact(&id)? else {
                    return Ok("retirement_deployment_missing".into());
                };
                let authority = journal.observe_quiescence_authority(
                    &deployment,
                    &name("simulation_attestation_v1")?,
                    0,
                    &QuiescenceAuthorityDecision::QualifiedTerminatedAndFenced {
                        review: Digest::new(b"synthetic-provider-only-not-cloud-qualification"),
                    },
                    &actor()?,
                )?;
                provider.grant_quiescence(&id, authority)?;
                Ok(if provider.quiesce_deployment(&id, now, delay)? {
                    "provider_deployment_quiesced"
                } else {
                    "provider_deployment_missing"
                }
                .into())
            }
            Action::ObserveStoppedDeployment { build } | Action::RecreateDeployment { build } => {
                let Some((id, _)) = releases.approval(build as usize) else {
                    return Ok("retirement_consumer_missing".into());
                };
                let consumer = Journal::open(path)?.runtime_secret_consumer(&id)?;
                if !matches!(
                    consumer.stage,
                    ConsumerStage::Draining | ConsumerStage::Drained
                ) || consumer.successor.is_none()
                {
                    return Ok("retirement_consumer_not_superseded".into());
                }
                if matches!(action, Action::ObserveStoppedDeployment { .. }) {
                    Ok(if provider.observe_stopped(&id)? {
                        "provider_stopped_observed"
                    } else {
                        "provider_deployment_missing"
                    }
                    .into())
                } else {
                    Ok(if provider.recreate_deployment(&id)? {
                        "provider_controller_recreated"
                    } else {
                        "provider_controller_fenced"
                    }
                    .into())
                }
            }
            _ => anyhow::bail!("unknown retirement action"),
        }
    }

    pub fn invariant(
        &self,
        path: &Path,
        plans: &[BuildPlan],
        provider: &Arc<Provider>,
        releases: &Releases,
    ) -> Result<Option<&'static str>> {
        if let Some(violation) = provider.invariant_retirement()? {
            return Ok(Some(violation));
        }
        let snapshot = self.snapshot(path, plans, provider)?;
        let provider = provider.retirement_evidence()?;
        let current = releases
            .states(path, plans)?
            .into_iter()
            .filter_map(|state| state.active)
            .map(|receipt| receipt.release)
            .collect::<BTreeSet<_>>();
        let activated = releases
            .activations()
            .iter()
            .map(|receipt| receipt.release.clone())
            .collect::<BTreeSet<_>>();
        if snapshot.consumers.len() != releases.approvals().len() {
            return Ok(Some("runtime_consumer_accounting_missing"));
        }
        for consumer in &snapshot.consumers {
            let Some(approval) = releases.approvals().get(&consumer.release) else {
                return Ok(Some("runtime_unrequested_consumer"));
            };
            let index = plans
                .iter()
                .position(|plan| {
                    plan.execution_id()
                        .is_ok_and(|id| id == approval.build_execution)
                })
                .context("consumer build catalog")?;
            let expected_key = SecretVersionKey {
                resource: releases::resource(&plans[index])?,
                version: approval.secret.version,
            };
            let stage = if current.contains(&consumer.release) {
                ConsumerStage::Active
            } else if self.drained.contains(&consumer.release) {
                ConsumerStage::Drained
            } else if activated.contains(&consumer.release) {
                ConsumerStage::Draining
            } else {
                ConsumerStage::Pending
            };
            let rollback = activated.contains(&consumer.release)
                && !current.contains(&consumer.release)
                && !self.rollback_released.contains(&consumer.release);
            if consumer.key != expected_key
                || consumer.target != approval.target
                || consumer.stage != stage
                || consumer.rollback_protected != rollback
            {
                return Ok(Some("runtime_consumer_protection_mismatch"));
            }
            let protected = matches!(
                stage,
                ConsumerStage::Pending | ConsumerStage::Active | ConsumerStage::Draining
            ) || rollback;
            if protected
                && provider
                    .mutations
                    .iter()
                    .any(|mutation| mutation.fact.key == expected_key)
            {
                return Ok(Some("shared_secret_disabled_while_protected"));
            }
        }
        for version in &snapshot.versions {
            if version.state == VersionState::Disabled
                && !provider
                    .mutations
                    .iter()
                    .any(|mutation| mutation.fact.key == version.key)
            {
                return Ok(Some("secret_disabled_without_provider_receipt"));
            }
        }
        for execution in &snapshot.executions {
            if matches!(
                execution.phase,
                crate::secret_retirement::RetirementPhase::WaitingDisabled
                    | crate::secret_retirement::RetirementPhase::Disabled
                    | crate::secret_retirement::RetirementPhase::Complete
            ) && !provider.mutations.iter().any(|receipt| {
                receipt.fact.execution == execution.id && receipt.fact.key == execution.plan.key
            }) {
                return Ok(Some(
                    "retirement_state_promoted_without_effect_acknowledgement",
                ));
            }
            // This campaign never changes resource-level retirement authority.
            // App Git-authority revocation is a separate operation and cannot
            // justify silently stopping an otherwise eligible retirement.
            if execution.terminal == Some(RetirementTerminal::AuthorityLost) {
                return Ok(Some("retirement_stopped_without_authority_change"));
            }
            if execution.terminal == Some(RetirementTerminal::Disabled)
                && !snapshot.versions.iter().any(|version| {
                    version.key == execution.plan.key && version.state == VersionState::Disabled
                })
            {
                return Ok(Some("retirement_succeeded_without_disabled_version"));
            }
        }
        Ok(None)
    }

    pub fn drain_complete(
        &self,
        path: &Path,
        plans: &[BuildPlan],
        provider: &Arc<Provider>,
    ) -> Result<bool> {
        let snapshot = self.snapshot(path, plans, provider)?;
        let evidence = provider.retirement_evidence()?;
        for execution in &snapshot.executions {
            if execution.terminal.is_some()
                || snapshot.consumers.iter().any(|consumer| {
                    consumer.key == execution.plan.key
                        && (matches!(
                            consumer.stage,
                            ConsumerStage::Pending
                                | ConsumerStage::Active
                                | ConsumerStage::Draining
                        ) || consumer.rollback_protected)
                })
            {
                continue;
            }
            // Missing provider material is an explicit prerequisite, not a
            // successful retirement or an invented provider absence receipt.
            if execution.waiting == Some(crate::secret_retirement::RetirementWait::ProviderRetry)
                && !provider.has_secret_version(&execution.plan.key)?
            {
                continue;
            }
            let physical_disabled = provider.unattributed_disabled_revision(&execution.plan.key)?;
            let observed_current_disabled = physical_disabled.as_ref().is_some_and(|current| {
                evidence.observations.iter().any(|observation| {
                    observation.fact.execution == execution.id
                        && observation.fact.key == execution.plan.key
                        && matches!(&observation.outcome,
                            crate::secret_retirement::RetirementObserved::Disabled { disabled: true, evidence }
                                if evidence.barrier().is_none() && evidence.revision() == current)
                })
            });
            // A queued original request, or unrelated external state, cannot be
            // healed into an acknowledgement. Require native reconciliation and
            // an actual weak result for this execution, not just a fault label.
            if execution.phase == crate::secret_retirement::RetirementPhase::Eligible
                && execution.waiting
                    == Some(crate::secret_retirement::RetirementWait::Reconciliation)
                && evidence.observations.iter().any(|observation| {
                    observation.fact.execution == execution.id
                        && observation.fact.key == execution.plan.key
                        && matches!(
                            observation.outcome,
                            crate::secret_retirement::RetirementObserved::Disabled { .. }
                        )
                })
                && (unresolved_original(&evidence, &execution.id, &execution.plan.key)
                    || observed_current_disabled)
            {
                continue;
            }
            return Ok(false);
        }
        Ok(true)
    }

    pub fn versions(&self) -> Vec<u8> {
        self.executions.keys().copied().collect()
    }
}

fn unresolved_original(
    evidence: &RetirementEvidence,
    execution: &Digest,
    key: &SecretVersionKey,
) -> bool {
    use super::release_provider::WeakEvent;
    if evidence
        .mutations
        .iter()
        .any(|value| &value.fact.key == key)
    {
        return false;
    }
    let mut queued = BTreeSet::new();
    for event in &evidence.weak_events {
        match event {
            WeakEvent::Queued { fact, .. } if &fact.execution == execution && &fact.key == key => {
                queued.insert(fact.effect.clone());
            }
            WeakEvent::Delivered { fact, .. }
                if &fact.execution == execution && &fact.key == key =>
            {
                queued.remove(&fact.effect);
            }
            _ => {}
        }
    }
    !queued.is_empty()
}
