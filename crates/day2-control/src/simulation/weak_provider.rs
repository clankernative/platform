//! Adversarial provider environment, independent of host transitions. Internal
//! history indices are not public revision ordering or evidence qualification.
use super::*;
use crate::secret_retirement::{RetirementFact, RetirementObservation, RetirementObserved};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WeakEvent {
    Read {
        key: SecretVersionKey,
        current: RevisionToken,
        returned: RevisionToken,
        after_effect: Option<Digest>,
    },
    Queued {
        fact: RetirementFact,
        condition: RevisionToken,
    },
    Delivered {
        fact: RetirementFact,
        applied: bool,
    },
    ExternalChanged {
        key: SecretVersionKey,
        revision: RevisionToken,
        enabled: bool,
    },
    ObservationStopped {
        release: Digest,
        incarnation: DeploymentIncarnation,
    },
    Recreated {
        release: Digest,
        incarnation: DeploymentIncarnation,
        accepted: bool,
    },
    UnqualifiedDrain {
        observation: Box<ConsumerDrainObservation>,
    },
}

#[derive(Clone)]
pub(super) struct Queued {
    pub fact: RetirementFact,
    pub condition: RevisionToken,
}

#[derive(Default)]
pub(super) struct WeakState {
    pub modes: BTreeMap<Digest, (ReadSelection, ReadStrength)>,
    pub held: BTreeSet<Digest>,
    pub queued: BTreeMap<Digest, Queued>,
    pub events: Vec<WeakEvent>,
    pub stopped: BTreeSet<Digest>,
    pub incarnations: BTreeMap<Digest, DeploymentIncarnation>,
    pub authorities: BTreeMap<Digest, QuiescenceAuthorityRef>,
}

pub(super) fn revision(physical: &Digest, sequence: NonZeroU64) -> RevisionToken {
    RevisionToken::Ordered {
        stream: physical.clone(),
        sequence,
    }
}

pub(super) fn incarnation(fact: &ReleaseProviderFact) -> Result<DeploymentIncarnation> {
    Ok(DeploymentIncarnation {
        controller: Digest::of(&("simulated-controller-v1", &fact.resource))?
            .as_str()
            .to_owned()
            .try_into()?,
        generation: Digest::of(&("simulated-incarnation-v1", &fact.effect, &fact.readiness))?
            .as_str()
            .to_owned()
            .try_into()?,
    })
}

pub(super) fn record(state: &mut State, event: WeakEvent) -> Result<()> {
    ensure!(state.weak.events.len() < 1024, "weak provider event budget");
    state.weak.events.push(event);
    Ok(())
}

pub(super) fn selected<'a>(
    state: &'a State,
    physical: &Digest,
    now: u64,
) -> Option<(&'a SecretVersion, bool, ReadStrength)> {
    let history = state.secrets.get(physical)?;
    let available: Vec<_> = history
        .iter()
        .enumerate()
        .filter(|(_, item)| item.visible_at <= now)
        .collect();
    let (selection, strength) = state.weak.modes.get(physical).copied().unwrap_or_default();
    let newest = available.len().checked_sub(1)?;
    let index = match selection {
        ReadSelection::Current => newest,
        ReadSelection::Previous => newest.saturating_sub(1),
        ReadSelection::Oldest => 0,
    };
    // The last visible observation is not a read barrier when a newer physical
    // mutation exists but its readback has not propagated yet.
    Some((
        available[index].1,
        available[index].0 + 1 == history.len(),
        strength,
    ))
}

pub(super) fn state_evidence(
    value: &SecretVersion,
    current: bool,
    strength: ReadStrength,
    authority: &BindingRef,
    resource: Digest,
    after_effect: Option<Digest>,
) -> Result<StateEvidence> {
    let original = value.metadata.provider_state.revision().clone();
    let revision = if strength == ReadStrength::Opaque {
        RevisionToken::Opaque {
            token: Digest::of(&("opaque-provider-token-v1", &original))?
                .as_str()
                .to_owned()
                .try_into()?,
        }
    } else {
        original
    };
    if current && strength == ReadStrength::Qualified {
        Ok(StateEvidence::Qualified {
            revision,
            barrier: ReadBarrier {
                authority: authority.clone(),
                resource,
                after_effect,
                receipt: Digest::of(&("simulated-qualified-read-v1", &value.metadata))?,
            },
        })
    } else {
        Ok(StateEvidence::Observed { revision })
    }
}

pub(super) fn record_read(
    state: &mut State,
    key: &SecretVersionKey,
    evidence: &StateEvidence,
    after_effect: Option<Digest>,
) -> Result<()> {
    if evidence.barrier().is_some() {
        return Ok(());
    }
    let physical = physical_version(key)?;
    if let Some(current) = state
        .secrets
        .get(&physical)
        .and_then(|values| values.last())
    {
        record(
            state,
            WeakEvent::Read {
                key: key.clone(),
                current: current.metadata.provider_state.revision().clone(),
                returned: evidence.revision().clone(),
                after_effect,
            },
        )?;
    }
    Ok(())
}

pub(super) fn apply_disable(
    state: &mut State,
    fact: &RetirementFact,
    delay: u64,
) -> Result<RetirementObservation> {
    let physical = physical_version(&fact.key)?;
    let versions = state
        .secrets
        .get_mut(&physical)
        .context("missing provider secret")?;
    let mut metadata = versions
        .last()
        .context("missing provider version")?
        .metadata
        .clone();
    ensure!(
        metadata.enabled,
        "cannot attribute an external disable to this effect"
    );
    metadata.enabled = false;
    let revision = revision(
        &physical,
        NonZeroU64::new(versions.len() as u64 + 1).context("provider sequence")?,
    );
    metadata.provider_state = StateEvidence::Observed {
        revision: revision.clone(),
    };
    metadata.evidence = fact.evidence.clone();
    versions.push(SecretVersion {
        metadata,
        visible_at: state.now.checked_add(delay).context("disable visibility")?,
    });
    let observation = RetirementObservation {
        fact: fact.clone(),
        outcome: RetirementObserved::DisableAcknowledged {
            acknowledgement: EffectAcknowledgement {
                effect: fact.effect.clone(),
                revision,
                receipt: fact.evidence.clone(),
            },
        },
    };
    state.disabled.insert(physical, observation.clone());
    Ok(observation)
}

impl Provider {
    pub fn read_mode(
        &self,
        key: &SecretVersionKey,
        selection: ReadSelection,
        strength: ReadStrength,
    ) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?
            .weak
            .modes
            .insert(physical_version(key)?, (selection, strength));
        Ok(())
    }

    pub fn end_read_faults(&self) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?
            .weak
            .modes
            .clear();
        Ok(())
    }

    pub fn hold_retirement(&self, key: &SecretVersionKey) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?
            .weak
            .held
            .insert(physical_version(key)?);
        Ok(())
    }

    pub fn deliver_retirement(&self, key: &SecretVersionKey, now: u64) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?;
        state.now = now;
        let physical = physical_version(key)?;
        let Some(pending) = state.weak.queued.remove(&physical) else {
            return Ok(false);
        };
        let applies = state
            .secrets
            .get(&physical)
            .and_then(|values| values.last())
            .is_some_and(|value| {
                value.metadata.enabled
                    && value.metadata.provider_state.revision() == &pending.condition
            });
        if applies {
            apply_disable(&mut state, &pending.fact, 0)?;
        }
        record(
            &mut state,
            WeakEvent::Delivered {
                fact: pending.fact,
                applied: applies,
            },
        )?;
        Ok(true)
    }

    pub fn external_secret_state(
        &self,
        key: &SecretVersionKey,
        enabled: bool,
        now: u64,
    ) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?;
        let physical = physical_version(key)?;
        let mut running = false;
        for resource in state.resources.values() {
            if resource.operation == ReleaseOperation::PrepareDeployment
                && state.aliases.get(&Digest::of(&resource.fact.secret)?) == Some(&physical)
                && !state.weak.stopped.contains(&resource.fact.resource)
                && !state.quiesced.contains_key(&resource.fact.release)
            {
                running = true;
            }
        }
        if state.disabled.contains_key(&physical) || running {
            return Ok(false);
        }
        let Some(versions) = state.secrets.get_mut(&physical) else {
            return Ok(false);
        };
        let Some(last) = versions.last() else {
            return Ok(false);
        };
        let mut metadata = last.metadata.clone();
        let revision = revision(
            &physical,
            NonZeroU64::new(versions.len() as u64 + 1).context("provider sequence")?,
        );
        metadata.enabled = enabled;
        metadata.provider_state = StateEvidence::Observed {
            revision: revision.clone(),
        };
        metadata.evidence = Digest::of(&("external-provider-state-v1", key, &revision, enabled))?;
        versions.push(SecretVersion {
            metadata,
            visible_at: now,
        });
        record(
            &mut state,
            WeakEvent::ExternalChanged {
                key: key.clone(),
                revision,
                enabled,
            },
        )?;
        Ok(true)
    }

    pub fn grant_quiescence(
        &self,
        release: &Digest,
        authority: QuiescenceAuthorityRef,
    ) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?
            .weak
            .authorities
            .insert(release.clone(), authority);
        Ok(())
    }

    pub fn observe_stopped(&self, release: &Digest) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?;
        let Some(resource) = state
            .resources
            .values()
            .find(|resource| {
                resource.fact.release == *release
                    && resource.operation == ReleaseOperation::PrepareDeployment
            })
            .cloned()
        else {
            return Ok(false);
        };
        let incarnation = state
            .weak
            .incarnations
            .get(&resource.fact.resource)
            .context("provider incarnation")?
            .clone();
        state.weak.stopped.insert(resource.fact.resource);
        record(
            &mut state,
            WeakEvent::ObservationStopped {
                release: release.clone(),
                incarnation,
            },
        )?;
        Ok(true)
    }

    pub fn recreate_deployment(&self, release: &Digest) -> Result<bool> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("provider lock"))?;
        let Some(resource) = state
            .resources
            .values()
            .find(|resource| {
                resource.fact.release == *release
                    && resource.operation == ReleaseOperation::PrepareDeployment
            })
            .cloned()
        else {
            return Ok(false);
        };
        let incarnation = state
            .weak
            .incarnations
            .get(&resource.fact.resource)
            .context("provider incarnation")?
            .clone();
        let accepted = !state.quiesced.contains_key(release);
        if accepted {
            state.weak.stopped.remove(&resource.fact.resource);
        }
        record(
            &mut state,
            WeakEvent::Recreated {
                release: release.clone(),
                incarnation,
                accepted,
            },
        )?;
        Ok(accepted)
    }
}
