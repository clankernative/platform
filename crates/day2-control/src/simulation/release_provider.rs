use super::{Fault, ReadSelection, ReadStrength, name};
#[path = "weak_provider.rs"]
mod weak;
use crate::{
    BindingRef, Digest,
    journal::RecoveryMode,
    provider_evidence::{
        DeploymentIncarnation, EffectAcknowledgement, OpaqueToken, ReadBarrier, RevisionToken,
        StateEvidence,
    },
    release::{ImmutableSecretRef, ReleaseApproval, SecretObservation},
    release_execution::{
        Capabilities, ReleaseEffectResult, ReleaseExecutionPlan, ReleaseLease, ReleaseObservation,
        ReleaseObserved, ReleaseOperation, ReleaseProviderFact,
    },
};
use crate::{
    runtime_secret::{
        ConsumerDrainObservation, ConsumerQuiescenceProof, ConsumerQuiescenceSubject, ConsumerView,
        QuiescenceAuthorityRef, QuiescenceCoverage, SecretVersionKey,
    },
    secret_retirement as retirement,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    sync::Mutex,
};
pub use weak::WeakEvent;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub fact: ReleaseProviderFact,
    pub operation: ReleaseOperation,
    pub visible_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretVersion {
    pub metadata: SecretObservation,
    pub visible_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub resources: Vec<Resource>,
    pub mutations: Vec<Resource>,
    pub observations: Vec<ReleaseObservation>,
    pub secrets: Vec<SecretVersion>,
    pub unknown_absence: Vec<Digest>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementEvidence {
    pub mutations: Vec<retirement::RetirementObservation>,
    pub observations: Vec<retirement::RetirementObservation>,
    pub drains: Vec<ConsumerDrainObservation>,
    pub quiesced: Vec<QuiescedDeployment>,
    pub attempts: Vec<RetirementAttempt>,
    pub weak_events: Vec<WeakEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuiescedDeployment {
    pub release: Digest,
    pub key: SecretVersionKey,
    pub deployment: ReleaseProviderFact,
    pub provider_revision: NonZeroU64,
    pub evidence: Digest,
    pub visible_at: u64,
    pub incarnation: DeploymentIncarnation,
    pub authority: Option<QuiescenceAuthorityRef>,
    pub fence: OpaqueToken,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementAttempt {
    pub fact: retirement::RetirementFact,
    pub operation: retirement::RetirementOperation,
    pub recovery: super::ObservedRecovery,
    pub now: u64,
    pub had_disable_receipt: bool,
}

#[derive(Default)]
struct State {
    now: u64,
    fault: Fault,
    bindings: BTreeMap<Digest, (ReleaseExecutionPlan, ReleaseApproval)>,
    resources: BTreeMap<Digest, Resource>,
    mutations: Vec<Resource>,
    observations: Vec<ReleaseObservation>,
    secrets: BTreeMap<Digest, Vec<SecretVersion>>,
    aliases: BTreeMap<Digest, Digest>,
    physical_keys: BTreeMap<Digest, SecretVersionKey>,
    retirements: BTreeMap<Digest, retirement::RetirementPlan>,
    disabled: BTreeMap<Digest, retirement::RetirementObservation>,
    retirement_observations: Vec<retirement::RetirementObservation>,
    drains: BTreeMap<Digest, ConsumerDrainObservation>,
    quiesced: BTreeMap<Digest, QuiescedDeployment>,
    quiescence_history: Vec<QuiescedDeployment>,
    retirement_attempts: Vec<RetirementAttempt>,
    unknown_absence: BTreeSet<Digest>,
    weak: weak::WeakState,
}

/// Logical external resources survive host reconstruction. The model provides
/// qualified absence only when explicitly enabled; it never infers it from timeout.
#[derive(Default)]
pub struct Provider {
    state: Mutex<State>,
}

impl Provider {
    pub fn has_secret_version(&self, key: &SecretVersionKey) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        Ok(state
            .secrets
            .get(&physical_version(key)?)
            .is_some_and(|values| !values.is_empty()))
    }

    /// Physical environment state is not an acknowledgement of our mutation.
    /// This reads the current history entry, not a cached/selected readback.
    pub(super) fn unattributed_disabled_revision(
        &self,
        key: &SecretVersionKey,
    ) -> Result<Option<RevisionToken>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        let physical = physical_version(key)?;
        if state.disabled.contains_key(&physical) {
            return Ok(None);
        }
        Ok(state
            .secrets
            .get(&physical)
            .and_then(|history| history.last())
            .filter(|value| !value.metadata.enabled)
            .map(|value| value.metadata.provider_state.revision().clone()))
    }

    pub fn register_retirement(&self, plan: &retirement::RetirementPlan) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        let id = plan.execution_id()?;
        if let Some(prior) = state.retirements.get(&id) {
            ensure!(prior == plan, "retirement provider registration conflict");
        }
        state.retirements.insert(id, plan.clone());
        Ok(())
    }

    pub fn retirement_evidence(&self) -> Result<RetirementEvidence> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        Ok(RetirementEvidence {
            mutations: state.disabled.values().cloned().collect(),
            observations: state.retirement_observations.clone(),
            drains: state.drains.values().cloned().collect(),
            quiesced: state.quiescence_history.clone(),
            attempts: state.retirement_attempts.clone(),
            weak_events: state.weak.events.clone(),
        })
    }

    /// Simulator environment input, not a host capability or a journal inference.
    /// A deployment exists independently of whether the host made it active.
    pub fn quiesce_deployment(&self, release: &Digest, now: u64, delay: u32) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        state.now = now;
        let resources = state
            .resources
            .values()
            .filter(|resource| {
                resource.operation == ReleaseOperation::PrepareDeployment
                    && resource.fact.release == *release
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            resources.len() <= 1,
            "multiple provider deployment identities for a release"
        );
        let Some(resource) = resources.first() else {
            return Ok(false);
        };
        if state
            .quiesced
            .get(release)
            .is_some_and(|proof| same_deployment(&proof.deployment, &resource.fact))
        {
            return Ok(true);
        }
        let physical = state
            .aliases
            .get(&Digest::of(&resource.fact.secret)?)
            .context("quiescence secret alias")?;
        let key = state
            .physical_keys
            .get(physical)
            .context("quiescence physical secret identity")?
            .clone();
        let revision = state
            .quiescence_history
            .iter()
            .filter(|proof| proof.release == *release)
            .count() as u64
            + 1;
        let provider_revision =
            NonZeroU64::new(revision).context("quiescence provider revision")?;
        let proof = QuiescedDeployment {
            release: release.clone(),
            key,
            deployment: resource.fact.clone(),
            provider_revision,
            evidence: Digest::of(&("provider-quiescence-v1", &resource.fact, provider_revision))?,
            visible_at: now
                .checked_add(u64::from(delay))
                .context("quiescence visibility overflow")?,
            incarnation: state
                .weak
                .incarnations
                .get(&resource.fact.resource)
                .context("provider incarnation")?
                .clone(),
            authority: state.weak.authorities.get(release).cloned(),
            fence: Digest::of(&("simulated-non-recreation-fence-v1", &resource.fact))?
                .as_str()
                .to_owned()
                .try_into()?,
        };
        ensure!(
            state.quiescence_history.len() < 128,
            "provider quiescence history budget"
        );
        state.quiesced.insert(release.clone(), proof.clone());
        state.quiescence_history.push(proof);
        Ok(true)
    }

    /// A readback requires an independently delivered provider quiescence fact.
    /// Merely changing the active pointer or requesting a drain is insufficient.
    pub fn observe_drain(
        &self,
        consumer: &ConsumerView,
        deployment: &ReleaseProviderFact,
        successor: &Digest,
    ) -> Result<Option<ConsumerDrainObservation>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        ensure!(
            consumer.release == deployment.release && consumer.target == deployment.target,
            "drain provider scope"
        );
        let resource = state
            .resources
            .get(&deployment.resource)
            .context("drain provider deployment absent")?;
        if resource.operation != ReleaseOperation::PrepareDeployment
            || !same_deployment(&resource.fact, deployment)
            || resource.visible_at > state.now
        {
            return Ok(None);
        }
        let Some(quiesced) = state.quiesced.get(&consumer.release) else {
            if !state.weak.stopped.contains(&deployment.resource) {
                return Ok(None);
            }
            let incarnation = state
                .weak
                .incarnations
                .get(&deployment.resource)
                .context("provider incarnation")?
                .clone();
            let observation = ConsumerDrainObservation {
                release: consumer.release.clone(),
                key: consumer.key.clone(),
                successor: successor.clone(),
                deployment: deployment.clone(),
                proof: ConsumerQuiescenceProof::ObservationOnly {
                    incarnation,
                    evidence: Digest::of(&("observed-stopped-only-v1", deployment))?,
                },
            };
            weak::record(
                &mut state,
                WeakEvent::UnqualifiedDrain {
                    observation: Box::new(observation.clone()),
                },
            )?;
            return Ok(Some(observation));
        };
        if !same_deployment(&quiesced.deployment, deployment) || quiesced.visible_at > state.now {
            return Ok(None);
        }
        ensure!(
            quiesced.key == consumer.key,
            "drain physical secret identity mismatch"
        );
        let proof = ConsumerDrainObservation {
            release: consumer.release.clone(),
            key: consumer.key.clone(),
            successor: successor.clone(),
            deployment: deployment.clone(),
            proof: ConsumerQuiescenceProof::TerminatedAndFenced {
                subject: Box::new(ConsumerQuiescenceSubject {
                    release: consumer.release.clone(),
                    key: consumer.key.clone(),
                    successor: successor.clone(),
                    deployment: Digest::of(deployment)?,
                }),
                incarnation: quiesced.incarnation.clone(),
                authority: quiesced
                    .authority
                    .clone()
                    .context("missing explicit simulator attestation qualification")?,
                fence: quiesced.fence.clone(),
                coverage: QuiescenceCoverage::CompleteDescendantsAndDelegatedWork,
                receipt: Digest::of(&("provider-deployment-drained-v1", quiesced, successor))?,
            },
        };
        if let Some(prior) = state.drains.get(&consumer.release) {
            ensure!(prior == &proof, "conflicting provider drain");
        }
        state.drains.insert(consumer.release.clone(), proof.clone());
        Ok(Some(proof))
    }

    pub fn invariant_retirement(&self) -> Result<Option<&'static str>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        if state.retirement_attempts.iter().any(|attempt| {
            attempt.operation == retirement::RetirementOperation::DisableVersion
                && attempt.recovery == super::ObservedRecovery::Execute
                && attempt.had_disable_receipt
        }) {
            return Ok(Some("retirement_blind_repeat_mutation"));
        }
        for resource in state
            .resources
            .values()
            .filter(|resource| resource.operation == ReleaseOperation::PrepareDeployment)
        {
            let physical = state
                .aliases
                .get(&Digest::of(&resource.fact.secret)?)
                .context("deployment physical secret alias")?;
            if state.disabled.contains_key(physical)
                && !state
                    .quiesced
                    .get(&resource.fact.release)
                    .is_some_and(|proof| same_deployment(&proof.deployment, &resource.fact))
            {
                return Ok(Some("physical_secret_disabled_with_running_deployment"));
            }
        }
        Ok(None)
    }

    pub fn register_secret(
        &self,
        reference: &ImmutableSecretRef,
        resource: &crate::runtime_secret::ProviderResource,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        let alias = Digest::of(reference)?;
        let physical = Digest::of(&(resource, reference.version))?;
        if let Some(prior) = state.aliases.get(&alias) {
            ensure!(*prior == physical, "provider alias remapped");
        }
        state.aliases.insert(alias, physical);
        let key = SecretVersionKey {
            resource: resource.clone(),
            version: reference.version,
        };
        state.physical_keys.insert(physical_version(&key)?, key);
        Ok(())
    }

    pub fn register(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        let id = plan.execution_id()?;
        if let Some(existing) = state.bindings.get(&id) {
            ensure!(
                existing == &(plan.clone(), approval.clone()),
                "release provider binding changed"
            );
        }
        state.bindings.insert(id, (plan.clone(), approval.clone()));
        Ok(())
    }

    pub fn configure(&self, now: u64, fault: Fault) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        state.now = now;
        state.fault = fault;
        Ok(())
    }

    pub fn set_secret(
        &self,
        reference: ImmutableSecretRef,
        now: u64,
        delay: u32,
        enabled: bool,
        access: bool,
        ready: bool,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        let key = state
            .aliases
            .get(&Digest::of(&reference)?)
            .context("unregistered provider secret")?
            .clone();
        // Protected disable is terminal in this bounded provider model. External
        // re-enablement and irreversible destruction need separate capabilities.
        if state.disabled.contains_key(&key) {
            return Ok(());
        }
        let versions = state.secrets.entry(key.clone()).or_default();
        let revision =
            NonZeroU64::new(versions.len() as u64 + 1).context("secret provider revision")?;
        let metadata = SecretObservation {
            reference,
            provider_state: StateEvidence::Observed {
                revision: weak::revision(&key, revision),
            },
            evidence: Digest::of(&(
                "release-secret-provider",
                &key,
                revision,
                enabled,
                access,
                ready,
            ))?,
            enabled,
            access_granted: access,
            projection_ready: ready,
        };
        versions.push(SecretVersion {
            metadata,
            visible_at: now
                .checked_add(u64::from(delay))
                .context("secret visibility budget")?,
        });
        Ok(())
    }

    pub fn uncertain_absence(&self, release: &Digest, uncertain: bool) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        if uncertain {
            state.unknown_absence.insert(release.clone());
        } else {
            state.unknown_absence.remove(release);
        }
        Ok(())
    }

    pub fn evidence(&self) -> Result<Evidence> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        Ok(Evidence {
            resources: state.resources.values().cloned().collect(),
            mutations: state.mutations.clone(),
            observations: state.observations.clone(),
            secrets: state.secrets.values().flatten().cloned().collect(),
            unknown_absence: state.unknown_absence.iter().cloned().collect(),
        })
    }

    pub fn visible_secret(
        &self,
        reference: &ImmutableSecretRef,
        now: u64,
    ) -> Result<Option<SecretObservation>> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        visible_secret(&state, reference, now)
    }
}

fn visible_secret(
    state: &State,
    reference: &ImmutableSecretRef,
    now: u64,
) -> Result<Option<SecretObservation>> {
    let physical = state
        .aliases
        .get(&Digest::of(reference)?)
        .context("unregistered provider secret")?;
    weak::selected(state, physical, now)
        .map(|(version, current, strength)| {
            let mut metadata = version.metadata.clone();
            metadata.reference = reference.clone();
            metadata.provider_state = weak::state_evidence(
                version,
                current,
                strength,
                &reference.binding,
                Digest::of(reference)?,
                None,
            )?;
            Ok(metadata)
        })
        .transpose()
}

pub fn resources_binding(approval: &ReleaseApproval) -> Result<BindingRef> {
    Ok(approval.secret.binding.clone())
}

pub fn deployment_binding(approval: &ReleaseApproval) -> Result<BindingRef> {
    BindingRef::pin(
        name("release_deployment")?,
        &(&approval.target, "synthetic-deployment-v1"),
    )
}

impl Capabilities for Provider {
    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        ensure!(
            state.bindings.get(&plan.execution_id()?) == Some(&(plan.clone(), approval.clone())),
            "unapproved release provider binding"
        );
        ensure!(
            plan.resources == resources_binding(approval)?
                && plan.deployment == deployment_binding(approval)?,
            "wrong release provider scope"
        );
        Ok(())
    }

    fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult> {
        Capabilities::validate(self, &lease.execution.plan, &lease.approval)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        let evidence = Digest::of(&(
            "release-provider-receipt-v1",
            &lease.execution.id,
            lease.step.operation,
        ))?;
        let fact = lease.fact(evidence)?;
        if state.fault == Fault::Unavailable {
            return Ok(ReleaseEffectResult::Ambiguous {});
        }
        let operation = lease.step.operation;
        let mutation = matches!(
            operation,
            ReleaseOperation::PrepareDependency | ReleaseOperation::PrepareDeployment
        );
        if mutation {
            if let Some(resource) = state
                .resources
                .get(&fact.resource)
                .filter(|resource| resource.fact.readiness == fact.readiness)
            {
                ensure!(
                    resource.fact.release == fact.release
                        && resource.fact.artifact == fact.artifact
                        && resource.fact.binding == fact.binding,
                    "cross scoped resource"
                );
                if resource.visible_at > state.now {
                    return Ok(ReleaseEffectResult::Ambiguous {});
                }
            } else if lease.recovery == RecoveryMode::Reconcile {
                return Ok(if state.unknown_absence.contains(&fact.release) {
                    ReleaseEffectResult::Ambiguous {}
                } else {
                    ReleaseEffectResult::ReconciledAbsent {
                        fact: Box::new(fact),
                    }
                });
            } else if matches!(state.fault, Fault::NotApplied | Fault::Reject) {
                return Ok(ReleaseEffectResult::RetryNotApplied {});
            } else {
                let visible_at = state.now
                    + if state.fault == Fault::Delayed {
                        super::LEASE_TICK * 2
                    } else {
                        0
                    };
                let resource = Resource {
                    fact: fact.clone(),
                    operation,
                    visible_at,
                };
                if operation == ReleaseOperation::PrepareDeployment {
                    // A new physical deployment/readiness invalidates an older
                    // quiescence proof, but the historical evidence is retained.
                    state.quiesced.remove(&fact.release);
                    state.weak.stopped.remove(&fact.resource);
                    state
                        .weak
                        .incarnations
                        .insert(fact.resource.clone(), weak::incarnation(&fact)?);
                }
                state.mutations.push(resource.clone());
                state.resources.insert(fact.resource.clone(), resource);
                if matches!(state.fault, Fault::LostAck | Fault::Delayed) {
                    return Ok(ReleaseEffectResult::Ambiguous {});
                }
            }
        } else if matches!(state.fault, Fault::NotApplied | Fault::Reject) {
            return Ok(ReleaseEffectResult::RetryNotApplied {});
        }
        let outcome = match operation {
            ReleaseOperation::PrepareDependency => ReleaseObserved::DependencyPrepared {},
            ReleaseOperation::PrepareDeployment => ReleaseObserved::DeploymentPrepared {
                incarnation: state
                    .weak
                    .incarnations
                    .get(&fact.resource)
                    .context("provider incarnation")?
                    .clone(),
            },
            ReleaseOperation::ObserveSecret => {
                let metadata = visible_secret(&state, &fact.secret, state.now)?;
                if let Some(metadata) = &metadata {
                    let physical = state
                        .aliases
                        .get(&Digest::of(&fact.secret)?)
                        .context("provider alias")?;
                    let key = state
                        .physical_keys
                        .get(physical)
                        .context("physical secret key")?
                        .clone();
                    weak::record_read(&mut state, &key, &metadata.provider_state, None)?;
                }
                ReleaseObserved::Secret { metadata }
            }
            ReleaseOperation::ObserveDeployment => {
                let prepared = state
                    .resources
                    .get(&fact.resource)
                    .context("provider deployment absent")?;
                let incarnation = state
                    .weak
                    .incarnations
                    .get(&fact.resource)
                    .context("provider incarnation")?;
                let physical = state
                    .aliases
                    .get(&Digest::of(&fact.secret)?)
                    .context("provider alias")?;
                let (_, strength) = state.weak.modes.get(physical).copied().unwrap_or_default();
                let revision = RevisionToken::Ordered {
                    stream: Digest::of(incarnation)?,
                    sequence: NonZeroU64::new(1).unwrap(),
                };
                let evidence = match strength {
                    ReadStrength::Qualified => StateEvidence::Qualified {
                        revision,
                        barrier: ReadBarrier {
                            authority: fact.binding.clone(),
                            resource: fact.resource.clone(),
                            after_effect: Some(prepared.fact.effect.clone()),
                            receipt: Digest::of(&(
                                "simulated-deployment-read-v1",
                                incarnation,
                                &prepared.fact,
                            ))?,
                        },
                    },
                    ReadStrength::Observed => StateEvidence::Observed { revision },
                    ReadStrength::Opaque => StateEvidence::Observed {
                        revision: RevisionToken::Opaque {
                            token: Digest::of(&("opaque-deployment-read-v1", revision))?
                                .as_str()
                                .to_owned()
                                .try_into()?,
                        },
                    },
                };
                ReleaseObserved::Deployment {
                    evidence,
                    incarnation: incarnation.clone(),
                    ready: state.resources.get(&fact.resource).is_some_and(|resource| {
                        resource.visible_at <= state.now
                            && resource.fact.readiness == fact.readiness
                            && !state.weak.stopped.contains(&resource.fact.resource)
                            && !state
                                .quiesced
                                .get(&resource.fact.release)
                                .is_some_and(|proof| {
                                    same_deployment(&proof.deployment, &resource.fact)
                                })
                    }),
                }
            }
            ReleaseOperation::Activate => anyhow::bail!("provider cannot activate host authority"),
        };
        let mut fact = fact;
        fact.evidence = Digest::of(&("release-provider-observation-v1", &fact.resource, &outcome))?;
        let observation = ReleaseObservation { fact, outcome };
        ensure!(
            state.observations.len() < 2048,
            "release provider observation budget"
        );
        state.observations.push(observation.clone());
        Ok(if matches!(state.fault, Fault::LostAck | Fault::Delayed) {
            ReleaseEffectResult::Ambiguous {}
        } else {
            ReleaseEffectResult::Observed(Box::new(observation))
        })
    }
}

fn physical_version(key: &SecretVersionKey) -> Result<Digest> {
    Digest::of(&(&key.resource, key.version))
}

fn same_deployment(left: &ReleaseProviderFact, right: &ReleaseProviderFact) -> bool {
    // Mutation and readback may have different observation evidence; every
    // resource, scope, effect and readiness identity must still agree exactly.
    let mut identity = left.clone();
    identity.evidence = right.evidence.clone();
    identity == *right
}

impl retirement::Capabilities for Provider {
    fn validate(&self, plan: &retirement::RetirementPlan) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        ensure!(
            state.retirements.get(&plan.execution_id()?) == Some(plan),
            "unapproved retirement provider binding"
        );
        Ok(())
    }

    fn perform(
        &self,
        lease: &retirement::RetirementLease,
    ) -> Result<retirement::RetirementEffectResult> {
        use retirement::{
            RetirementEffectResult as ResultKind, RetirementObserved as Observed,
            RetirementOperation as Operation,
        };
        retirement::Capabilities::validate(self, &lease.execution.plan)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("release provider lock"))?;
        let physical = physical_version(&lease.execution.plan.key)?;
        let fact = lease.fact(Digest::of(&(
            "secret-retirement-provider-v1",
            &physical,
            &lease.effect,
        ))?)?;
        let had_disable_receipt = state.disabled.contains_key(&physical);
        ensure!(
            state.retirement_attempts.len() < 2048,
            "retirement provider attempt budget"
        );
        let now = state.now;
        state.retirement_attempts.push(RetirementAttempt {
            fact: fact.clone(),
            operation: lease.step.operation,
            recovery: lease.recovery.into(),
            now,
            had_disable_receipt,
        });
        ensure!(
            !(lease.step.operation == retirement::RetirementOperation::DisableVersion
                && lease.recovery == RecoveryMode::Execute
                && (had_disable_receipt || state.weak.queued.contains_key(&physical))),
            "retirement blind repeated disable dispatch"
        );
        if state.fault == Fault::Unavailable {
            return Ok(ResultKind::Ambiguous {});
        }
        let outcome = match lease.step.operation {
            Operation::DisableVersion => {
                if let Some(prior) = state.disabled.get(&physical).cloned() {
                    ensure!(
                        prior.fact == fact,
                        "secret disabled under different effect identity"
                    );
                    let visible = state
                        .secrets
                        .get(&physical)
                        .and_then(|values| values.last())
                        .is_some_and(|value| value.visible_at <= state.now);
                    if !visible {
                        return Ok(ResultKind::Ambiguous {});
                    }
                    prior.outcome
                } else {
                    let Some(metadata) = state
                        .secrets
                        .get(&physical)
                        .and_then(|values| values.last())
                        .map(|value| value.metadata.clone())
                    else {
                        return Ok(ResultKind::RetryNotApplied { fact });
                    };
                    if state.weak.queued.contains_key(&physical) || !metadata.enabled {
                        let evidence = StateEvidence::Observed {
                            revision: metadata.provider_state.revision().clone(),
                        };
                        weak::record_read(
                            &mut state,
                            &fact.key,
                            &evidence,
                            Some(fact.effect.clone()),
                        )?;
                        let observation = retirement::RetirementObservation {
                            fact,
                            outcome: Observed::Disabled {
                                disabled: !metadata.enabled,
                                evidence,
                            },
                        };
                        ensure!(
                            state.retirement_observations.len() < 2048,
                            "retirement provider observation budget"
                        );
                        state.retirement_observations.push(observation.clone());
                        return Ok(ResultKind::Observed(observation));
                    }
                    if lease.recovery == RecoveryMode::Reconcile {
                        return Ok(ResultKind::ReconciledAbsent { fact });
                    }
                    if matches!(state.fault, Fault::NotApplied | Fault::Reject) {
                        return Ok(ResultKind::RetryNotApplied { fact });
                    }
                    if state.weak.held.remove(&physical) {
                        let condition = metadata.provider_state.revision().clone();
                        state.weak.queued.insert(
                            physical.clone(),
                            weak::Queued {
                                fact: fact.clone(),
                                condition: condition.clone(),
                            },
                        );
                        weak::record(&mut state, WeakEvent::Queued { fact, condition })?;
                        return Ok(ResultKind::Ambiguous {});
                    }
                    let delay = if state.fault == Fault::Delayed {
                        20_000
                    } else {
                        0
                    };
                    let applied = weak::apply_disable(&mut state, &fact, delay)?;
                    if matches!(state.fault, Fault::LostAck | Fault::Delayed) {
                        return Ok(ResultKind::Ambiguous {});
                    }
                    applied.outcome
                }
            }
            Operation::ObserveDisabled => {
                if matches!(state.fault, Fault::NotApplied | Fault::Reject) {
                    return Ok(ResultKind::RetryNotApplied { fact });
                }
                let Some((observed, current, strength)) =
                    weak::selected(&state, &physical, state.now)
                else {
                    return Ok(ResultKind::RetryNotApplied { fact });
                };
                let disabled = !observed.metadata.enabled;
                let after_effect = state
                    .disabled
                    .get(&physical)
                    .map(|receipt| receipt.fact.effect.clone());
                let evidence = weak::state_evidence(
                    observed,
                    current,
                    strength,
                    &lease.execution.plan.resources,
                    Digest::of(&fact.key)?,
                    after_effect.clone(),
                )?;
                weak::record_read(&mut state, &fact.key, &evidence, after_effect)?;
                Observed::Disabled { disabled, evidence }
            }
            _ => anyhow::bail!("internal retirement capability reached provider"),
        };
        let observation = retirement::RetirementObservation { fact, outcome };
        ensure!(
            state.retirement_observations.len() < 2048,
            "retirement provider observation budget"
        );
        state.retirement_observations.push(observation.clone());
        Ok(if matches!(state.fault, Fault::LostAck | Fault::Delayed) {
            ResultKind::Ambiguous {}
        } else {
            ResultKind::Observed(observation)
        })
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use crate::{
        GitOid,
        journal::OperatorActor,
        release::{GitApproval, ReleaseTarget},
        release_execution::{ReleasePhase, ReleaseSnapshot, StepRequest},
        runtime_secret::{ConsumerStage, ProviderResource, ResourceScope},
        secret_retirement::{
            RetirementPhase, RetirementPlan, RetirementSnapshot, RetirementStepRequest,
        },
    };

    struct Fixture {
        provider: Provider,
        lease: ReleaseLease,
        consumer: ConsumerView,
        deployment: ReleaseProviderFact,
    }

    fn fixture() -> Result<Fixture> {
        let provider = Provider::default();
        let target = ReleaseTarget {
            company: name("alpha")?,
            environment: name("production")?,
            app: name("reports")?,
        };
        let reference = ImmutableSecretRef {
            binding: BindingRef::pin(name("secrets")?, &"shared-provider")?,
            secret: name("credential")?,
            version: NonZeroU64::new(1).unwrap(),
        };
        let key = SecretVersionKey {
            resource: ProviderResource {
                provider: name("simulated")?,
                account: name("alpha")?,
                secret: name("credential")?,
            },
            version: reference.version,
        };
        let approval = ReleaseApproval {
            target: target.clone(),
            request: name("release")?,
            expected_generation: 0,
            build_execution: Digest::new(b"build"),
            artifact: Digest::new(b"artifact"),
            evidence: Digest::new(b"checks"),
            git: GitApproval {
                source: BindingRef::pin(name("source")?, &"source")?,
                commit: GitOid::try_from("1".repeat(40))?,
                policy: Digest::new(b"policy"),
                receipt: Digest::new(b"approval"),
                actor: OperatorActor::try_from("operator".to_owned())?,
            },
            secret: reference.clone(),
        };
        let plan = ReleaseExecutionPlan {
            release: Digest::new(b"release"),
            recipe: Digest::new(b"recipe"),
            durability: BindingRef::pin(name("durability")?, &"runtime")?,
            resources: resources_binding(&approval)?,
            deployment: deployment_binding(&approval)?,
            deployment_input: None,
        };
        let snapshot = ReleaseSnapshot {
            id: plan.execution_id()?,
            plan: plan.clone(),
            target: target.clone(),
            phase: ReleasePhase::SecretReady,
            next_step: 0,
            revision: 0,
            waiting: None,
            terminal: None,
        };
        let lease = ReleaseLease {
            execution: snapshot,
            step: StepRequest {
                name: name("prepare_deployment")?,
                ordinal: 0,
                operation: ReleaseOperation::PrepareDeployment,
            },
            effect: Digest::new(b"deployment-effect"),
            epoch: 1,
            owner: name("worker")?,
            until: 100,
            recovery: RecoveryMode::Execute,
            approval: approval.clone(),
            readiness: Some(Digest::new(b"readiness-one")),
        };
        provider.register_secret(&reference, &key.resource)?;
        provider.set_secret(reference, 0, 0, true, true, true)?;
        provider.register(&plan, &approval)?;
        provider.configure(0, Fault::None)?;
        let ReleaseEffectResult::Observed(observation) = Capabilities::perform(&provider, &lease)?
        else {
            anyhow::bail!("expected prepared deployment")
        };
        let consumer = ConsumerView {
            release: plan.release,
            target,
            key,
            stage: ConsumerStage::Draining,
            successor: Some(Digest::new(b"successor")),
            rollback_protected: true,
            drain: None,
        };
        // Provider-only fixture identity, not a native qualification grant.
        provider.grant_quiescence(
            &consumer.release,
            serde_json::from_value(serde_json::json!({
                "id": Digest::new(b"provider-test-qualification"), "revision": 1
            }))?,
        )?;
        Ok(Fixture {
            provider,
            lease,
            consumer,
            deployment: observation.fact,
        })
    }

    #[test]
    fn unattributed_disablement_tracks_current_physical_revision_only() -> Result<()> {
        let fixture = fixture()?;
        let reference = fixture.lease.approval.secret.clone();
        let key = &fixture.consumer.key;
        assert!(
            fixture
                .provider
                .unattributed_disabled_revision(key)?
                .is_none()
        );
        fixture
            .provider
            .set_secret(reference.clone(), 1, 0, false, true, true)?;
        let first = fixture
            .provider
            .unattributed_disabled_revision(key)?
            .context("disabled state")?;
        fixture
            .provider
            .set_secret(reference.clone(), 2, 500, false, true, true)?;
        let current = fixture
            .provider
            .unattributed_disabled_revision(key)?
            .context("current disabled state")?;
        assert_ne!(
            first, current,
            "an older weak observation cannot justify the newer state"
        );
        fixture
            .provider
            .set_secret(reference, 3, 500, true, true, true)?;
        assert!(
            fixture
                .provider
                .unattributed_disabled_revision(key)?
                .is_none(),
            "a cached disabled read cannot justify intervention after physical reenable"
        );
        Ok(())
    }

    #[test]
    fn drain_readback_requires_independent_visible_provider_quiescence() -> Result<()> {
        let fixture = fixture()?;
        let successor = fixture.consumer.successor.as_ref().unwrap();
        assert!(
            fixture
                .provider
                .observe_drain(&fixture.consumer, &fixture.deployment, successor)?
                .is_none()
        );
        assert!(
            !fixture
                .provider
                .quiesce_deployment(&Digest::new(b"unknown"), 1, 0)?
        );
        assert!(
            fixture
                .provider
                .quiesce_deployment(&fixture.consumer.release, 1, 5)?
        );
        fixture.provider.configure(5, Fault::None)?;
        assert!(
            fixture
                .provider
                .observe_drain(&fixture.consumer, &fixture.deployment, successor)?
                .is_none()
        );
        fixture.provider.configure(6, Fault::None)?;
        let proof = fixture
            .provider
            .observe_drain(&fixture.consumer, &fixture.deployment, successor)?
            .context("visible quiescence")?;
        let evidence = fixture.provider.retirement_evidence()?;
        assert_eq!(evidence.quiesced.len(), 1);
        let ConsumerQuiescenceProof::TerminatedAndFenced {
            incarnation,
            authority,
            fence,
            receipt,
            ..
        } = &proof.proof
        else {
            anyhow::bail!("expected qualified synthetic proof")
        };
        assert_eq!(*incarnation, evidence.quiesced[0].incarnation);
        assert_eq!(Some(authority), evidence.quiesced[0].authority.as_ref());
        assert_eq!(*fence, evidence.quiesced[0].fence);
        assert_eq!(
            *receipt,
            Digest::of(&(
                "provider-deployment-drained-v1",
                &evidence.quiesced[0],
                successor
            ))?
        );
        Ok(())
    }

    #[test]
    fn stopped_pending_deployment_is_not_ready_even_before_drain_readback_is_visible() -> Result<()>
    {
        let fixture = fixture()?;
        let mut read = fixture.lease.clone();
        read.step.operation = ReleaseOperation::ObserveDeployment;
        read.step.name = name("observe_deployment")?;
        read.step.ordinal = 1;
        read.effect = Digest::new(b"deployment-read");
        let observed = Capabilities::perform(&fixture.provider, &read)?;
        assert!(matches!(
            observed,
            ReleaseEffectResult::Observed(observation) if matches!(observation.outcome, ReleaseObserved::Deployment { ready: true, .. })
        ));
        fixture
            .provider
            .quiesce_deployment(&fixture.consumer.release, 1, 100)?;
        fixture.provider.configure(1, Fault::None)?;
        let observed = Capabilities::perform(&fixture.provider, &read)?;
        assert!(matches!(
            observed,
            ReleaseEffectResult::Observed(observation) if matches!(observation.outcome, ReleaseObserved::Deployment { ready: false, .. })
        ));
        assert!(
            fixture
                .provider
                .observe_drain(
                    &fixture.consumer,
                    &fixture.deployment,
                    fixture.consumer.successor.as_ref().unwrap()
                )?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn replaced_deployment_invalidates_quiescence_but_retains_its_history() -> Result<()> {
        let fixture = fixture()?;
        let successor = fixture.consumer.successor.as_ref().unwrap();
        fixture
            .provider
            .quiesce_deployment(&fixture.consumer.release, 1, 0)?;
        fixture.provider.configure(1, Fault::None)?;
        assert!(
            fixture
                .provider
                .observe_drain(&fixture.consumer, &fixture.deployment, successor)?
                .is_some()
        );
        let original = fixture.provider.retirement_evidence()?.quiesced;
        let mut next = fixture.lease.clone();
        next.readiness = Some(Digest::new(b"readiness-two"));
        next.effect = Digest::new(b"new-deployment-effect");
        next.step.ordinal = 1;
        let ReleaseEffectResult::Observed(replacement) =
            Capabilities::perform(&fixture.provider, &next)?
        else {
            anyhow::bail!("expected replacement")
        };
        assert!(
            fixture
                .provider
                .observe_drain(&fixture.consumer, &fixture.deployment, successor)?
                .is_none()
        );
        assert!(
            fixture
                .provider
                .observe_drain(&fixture.consumer, &replacement.fact, successor)?
                .is_none()
        );
        assert_eq!(fixture.provider.retirement_evidence()?.quiesced, original);
        fixture
            .provider
            .quiesce_deployment(&fixture.consumer.release, 2, 0)?;
        let history = fixture.provider.retirement_evidence()?.quiesced;
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].provider_revision.get(), 2);
        assert_ne!(
            history[0].deployment.readiness,
            history[1].deployment.readiness
        );
        Ok(())
    }

    #[test]
    fn latest_visible_secret_is_unqualified_when_newer_physical_state_has_not_propagated()
    -> Result<()> {
        let fixture = fixture()?;
        let reference = fixture.consumer.key.clone();
        let alias = fixture.lease.approval.secret.clone();
        fixture
            .provider
            .set_secret(alias.clone(), 1, 10, false, true, true)?;
        let stale = fixture
            .provider
            .visible_secret(&alias, 2)?
            .context("old visible state")?;
        assert!(stale.enabled);
        assert!(stale.provider_state.barrier().is_none());
        let current = fixture
            .provider
            .visible_secret(&alias, 11)?
            .context("new visible state")?;
        assert!(!current.enabled);
        current
            .provider_state
            .require(&alias.binding, &Digest::of(&alias)?, None)?;
        fixture
            .provider
            .read_mode(&reference, ReadSelection::Oldest, ReadStrength::Qualified)?;
        let old = fixture
            .provider
            .visible_secret(&alias, 11)?
            .context("selected old state")?;
        assert!(old.enabled && old.provider_state.barrier().is_none());
        fixture
            .provider
            .read_mode(&reference, ReadSelection::Current, ReadStrength::Opaque)?;
        let opaque = fixture
            .provider
            .visible_secret(&alias, 11)?
            .context("opaque state")?;
        assert!(matches!(
            opaque.provider_state,
            StateEvidence::Observed {
                revision: RevisionToken::Opaque { .. }
            }
        ));
        Ok(())
    }

    #[test]
    fn observation_only_stop_allows_recreation_but_explicit_fence_does_not() -> Result<()> {
        let fixture = fixture()?;
        let successor = fixture.consumer.successor.as_ref().unwrap();
        assert!(
            fixture
                .provider
                .observe_stopped(&fixture.consumer.release)?
        );
        let observation = fixture
            .provider
            .observe_drain(&fixture.consumer, &fixture.deployment, successor)?
            .context("weak drain")?;
        assert!(matches!(
            observation.proof,
            ConsumerQuiescenceProof::ObservationOnly { .. }
        ));
        assert!(
            fixture
                .provider
                .recreate_deployment(&fixture.consumer.release)?
        );
        assert!(
            fixture
                .provider
                .observe_drain(&fixture.consumer, &fixture.deployment, successor)?
                .is_none()
        );
        fixture
            .provider
            .quiesce_deployment(&fixture.consumer.release, 1, 0)?;
        assert!(
            !fixture
                .provider
                .recreate_deployment(&fixture.consumer.release)?
        );
        Ok(())
    }

    fn retirement_lease(fixture: &Fixture) -> Result<retirement::RetirementLease> {
        let plan = RetirementPlan {
            key: fixture.consumer.key.clone(),
            scope: ResourceScope::from(&fixture.consumer.target),
            request: name("retire")?,
            authority_revision: 1,
            policy: Digest::new(b"policy"),
            actor: OperatorActor::try_from("operator".to_owned())?,
            approval: Digest::new(b"approved"),
            resources: fixture.lease.execution.plan.resources.clone(),
            durability: fixture.lease.execution.plan.durability.clone(),
            recipe: Digest::new(b"retirement-recipe"),
        };
        fixture.provider.register_retirement(&plan)?;
        let execution = RetirementSnapshot {
            id: plan.execution_id()?,
            plan,
            phase: RetirementPhase::Eligible,
            next_step: 1,
            revision: 1,
            waiting: None,
            terminal: None,
        };
        Ok(retirement::RetirementLease {
            execution,
            step: RetirementStepRequest {
                name: name("disable_version")?,
                ordinal: 1,
                operation: retirement::RetirementOperation::DisableVersion,
            },
            effect: Digest::new(b"disable-effect"),
            epoch: 1,
            owner: name("worker")?,
            until: 100,
            recovery: RecoveryMode::Execute,
        })
    }

    #[test]
    fn physical_oracle_detects_disable_with_running_deployment_independently_of_journal()
    -> Result<()> {
        let fixture = fixture()?;
        let lease = retirement_lease(&fixture)?;
        // Inject a host defect by invoking the provider without the native guard.
        retirement::Capabilities::perform(&fixture.provider, &lease)?;
        assert_eq!(
            fixture.provider.invariant_retirement()?,
            Some("physical_secret_disabled_with_running_deployment")
        );
        fixture
            .provider
            .quiesce_deployment(&fixture.consumer.release, 1, 0)?;
        assert_eq!(fixture.provider.invariant_retirement()?, None);
        Ok(())
    }

    #[test]
    fn provider_records_and_rejects_blind_execute_even_when_disable_would_deduplicate() -> Result<()>
    {
        let fixture = fixture()?;
        fixture
            .provider
            .quiesce_deployment(&fixture.consumer.release, 1, 0)?;
        let lease = retirement_lease(&fixture)?;
        retirement::Capabilities::perform(&fixture.provider, &lease)?;
        assert_eq!(fixture.provider.invariant_retirement()?, None);
        assert!(retirement::Capabilities::perform(&fixture.provider, &lease).is_err());
        let evidence = fixture.provider.retirement_evidence()?;
        assert_eq!(evidence.mutations.len(), 1);
        assert_eq!(evidence.attempts.len(), 2);
        assert!(!evidence.attempts[0].had_disable_receipt);
        assert!(evidence.attempts[1].had_disable_receipt);
        assert_eq!(
            fixture.provider.invariant_retirement()?,
            Some("retirement_blind_repeat_mutation")
        );
        Ok(())
    }
}
