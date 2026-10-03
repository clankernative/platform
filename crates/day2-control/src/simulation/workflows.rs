use super::{
    Action, Fault, name,
    release_provider::{self, Provider},
    releases::Releases,
};
use crate::{
    BuildPlan, Digest, Name,
    journal::Journal,
    provider_evidence::RevisionRelation,
    release::{ActivationReceipt, ReleaseState},
    release_execution::{
        Recipe, ReleaseClaim, ReleaseEffectResult, ReleaseExecutionHost, ReleaseExecutionPlan,
        ReleaseLease, ReleaseObserved, ReleaseOperation, ReleasePhase, ReleaseRejection,
        ReleaseSnapshot, ReleaseTerminal, ReleaseWait, StepRequest,
    },
    release_recipe::CompiledReleaseRecipe,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum Disposition {
    Terminal {
        execution: Digest,
        terminal: ReleaseTerminal,
    },
    WaitingPrerequisite {
        execution: Digest,
        reason: ReleaseWait,
    },
    NeedsIntervention {
        execution: Digest,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub recipe: Digest,
    pub executions: Vec<ReleaseSnapshot>,
    pub provider: release_provider::Evidence,
    pub activations: Vec<ActivationReceipt>,
    pub dispositions: Vec<Disposition>,
    pub delivered_secrets: Vec<crate::release::SecretObservation>,
    pub delivered_readbacks: Vec<(Digest, Digest)>,
}
impl Evidence {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.recipe == CompiledReleaseRecipe::installed()?.identity()?
                && self.executions.len() <= 12
                && self.provider.resources.len() <= 24
                && self.provider.mutations.len() <= 256
                && self.provider.observations.len() <= 2048
                && self.provider.secrets.len() <= 256
                && self.activations.len() <= 12
                && self.dispositions.len() <= 12,
            "release trace identity/budget"
        );
        let ids: BTreeSet<_> = self
            .executions
            .iter()
            .map(|execution| &execution.id)
            .collect();
        ensure!(
            ids.len() == self.executions.len(),
            "duplicate release execution trace"
        );
        Ok(())
    }
}

#[derive(Clone)]
struct Slot {
    lease: ReleaseLease,
    result: Option<ReleaseEffectResult>,
}

pub struct Workflows {
    recipe: Arc<CompiledReleaseRecipe>,
    recipe_identity: Digest,
    provider: Arc<Provider>,
    executions: BTreeMap<Digest, usize>,
    slots: [Option<Slot>; 4],
    activations: Vec<ActivationReceipt>,
    dispositions: Vec<Disposition>,
    delivered_secrets: BTreeMap<Digest, crate::release::SecretObservation>,
    prepared_secrets: BTreeMap<Digest, crate::release::SecretObservation>,
    ready_secrets: BTreeMap<Digest, crate::release::SecretObservation>,
    delivered_readbacks: BTreeSet<(Digest, Digest)>,
}

impl Workflows {
    pub fn initialize(&self, plans: &[BuildPlan]) -> Result<()> {
        for (index, plan) in plans.iter().enumerate() {
            self.provider.register_secret(
                &super::releases::secret(plan, index)?,
                &super::releases::resource(plan)?,
            )?;
        }
        Ok(())
    }

    pub(super) fn provider(&self) -> Arc<Provider> {
        self.provider.clone()
    }

    pub(super) fn claim_recovery(&self, slot: usize) -> Option<crate::journal::RecoveryMode> {
        self.slots[slot].as_ref().map(|slot| slot.lease.recovery)
    }

    pub fn new() -> Result<Self> {
        let recipe = Arc::new(CompiledReleaseRecipe::installed()?);
        let recipe_identity = recipe.identity()?;
        Ok(Self {
            recipe,
            recipe_identity,
            provider: Arc::new(Provider::default()),
            executions: BTreeMap::new(),
            slots: std::array::from_fn(|_| None),
            activations: Vec::new(),
            dispositions: Vec::new(),
            delivered_secrets: BTreeMap::new(),
            prepared_secrets: BTreeMap::new(),
            ready_secrets: BTreeMap::new(),
            delivered_readbacks: BTreeSet::new(),
        })
    }

    fn host(&self, path: &Path, plan: &BuildPlan, slot: usize) -> ReleaseExecutionHost {
        ReleaseExecutionHost::new(
            path.to_owned(),
            plan.company.clone(),
            name(&format!("release_worker_{slot}")).expect("fixed worker name"),
            plan.profile.durability.clone(),
            self.provider.clone(),
            self.recipe.clone(),
        )
    }

    pub fn restart(&mut self, path: &Path, plans: &[BuildPlan]) -> Result<()> {
        self.slots = std::array::from_fn(|_| None);
        self.executions.clear();
        self.recipe = Arc::new(CompiledReleaseRecipe::installed()?);
        self.recipe_identity = self.recipe.identity()?;
        let journal = Journal::open(path)?;
        for index in [0, 2] {
            for snapshot in journal.release_executions(
                &plans[index].company,
                &plans[index].profile.durability,
                12,
            )? {
                let approval = journal.release_execution_approval(&snapshot.id)?;
                let build = plans
                    .iter()
                    .position(|plan| {
                        plan.execution_id()
                            .is_ok_and(|id| id == approval.build_execution)
                    })
                    .context("persisted release belongs to unknown build")?;
                self.executions.insert(snapshot.id, build);
            }
        }
        Ok(())
    }

    pub fn heal(&self, now: u64) -> Result<()> {
        self.provider.configure(now, Fault::None)
    }

    pub fn evidence(&self, path: &Path, plans: &[BuildPlan]) -> Result<Evidence> {
        let executions = self
            .executions
            .iter()
            .map(|(id, build)| self.host(path, &plans[*build], 0).inspect(id))
            .collect::<Result<_>>()?;
        Ok(Evidence {
            recipe: self.recipe_identity.clone(),
            executions,
            provider: self.provider.evidence()?,
            activations: self.activations.clone(),
            dispositions: self.dispositions.clone(),
            delivered_secrets: self.delivered_secrets.values().cloned().collect(),
            delivered_readbacks: self.delivered_readbacks.iter().cloned().collect(),
        })
    }

    pub fn perform(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        releases: &mut Releases,
        action: &Action,
        now: u64,
    ) -> Result<String> {
        let before = releases.states(path, plans)?;
        let result = self.apply(path, plans, releases, action, now)?;
        let after = releases.states(path, plans)?;
        if before
            .iter()
            .map(|state| &state.active)
            .ne(after.iter().map(|state| &state.active))
        {
            ensure!(
                matches!(action, Action::ReleaseSettle { .. }),
                "release authority changed outside settlement"
            );
            self.observe_activation(path, plans, releases, &before, &after, now)?;
        }
        self.check_provider_facts(path, plans)?;
        Ok(result)
    }

    fn apply(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        releases: &Releases,
        action: &Action,
        now: u64,
    ) -> Result<String> {
        match *action {
            Action::ReleaseStart { build } => {
                let index = build as usize;
                let Some((release, approval)) = releases.approval(index) else {
                    return Ok("release_missing_approval".into());
                };
                let plan = ReleaseExecutionPlan {
                    release,
                    recipe: self.recipe.identity()?,
                    durability: plans[index].profile.durability.clone(),
                    resources: release_provider::resources_binding(&approval)?,
                    deployment: release_provider::deployment_binding(&approval)?,
                    deployment_input: None,
                };
                let id = plan.execution_id()?;
                if self.executions.contains_key(&id) {
                    return Ok("release_already_started".into());
                }
                ensure!(self.executions.len() < 12, "release execution budget");
                self.provider.register(&plan, &approval)?;
                match self.host(path, &plans[index], 0).accept(&plan) {
                    Ok(accepted) => {
                        ensure!(accepted == id, "release execution identity mismatch");
                        self.executions.insert(id, index);
                        Ok("release_started".into())
                    }
                    Err(error) if super::releases::expected_denial(&error) => {
                        Ok("release_start_refused".into())
                    }
                    Err(error) => Err(error),
                }
            }
            Action::ReleaseClaim { build, slot } => {
                self.slots[slot as usize] = None;
                let host = self.host(path, &plans[build as usize], slot as usize);
                let mut pending = None;
                for (id, index) in &self.executions {
                    if *index == build as usize {
                        let snapshot = host.inspect(id)?;
                        if snapshot.terminal.is_none() {
                            pending = Some(snapshot);
                            break;
                        }
                    }
                }
                let Some(snapshot) = pending else {
                    return Ok("release_idle".into());
                };
                let step = self.recipe.choose(&snapshot)?;
                match host.claim_at(&snapshot.id, &step, now)? {
                    ReleaseClaim::Acquired(lease) => {
                        self.slots[slot as usize] = Some(Slot {
                            lease: *lease,
                            result: None,
                        });
                        Ok("release_claimed".into())
                    }
                    ReleaseClaim::Busy => Ok("release_busy".into()),
                    ReleaseClaim::Terminal(_) => Ok("release_terminal".into()),
                }
            }
            Action::ReleasePerform { slot, fault } => {
                self.provider.configure(now, fault)?;
                let Some(pending) = self.slots[slot as usize].clone() else {
                    return Ok("release_empty_slot".into());
                };
                let build = *self
                    .executions
                    .get(&pending.lease.execution.id)
                    .context("release slot execution missing")?;
                let prior_mutations = self.provider.evidence()?.mutations.len();
                let result = match self
                    .host(path, &plans[build], slot as usize)
                    .perform_at(&pending.lease, now)
                {
                    Ok(result) => result,
                    Err(error)
                        if expected_fence(path, &pending.lease, None, now, &error, true)? =>
                    {
                        return Ok("release_fenced".into());
                    }
                    Err(error) => return Err(error),
                };
                for mutation in self
                    .provider
                    .evidence()?
                    .mutations
                    .iter()
                    .skip(prior_mutations)
                {
                    ensure!(
                        pending.lease.recovery == crate::journal::RecoveryMode::Execute
                            && releases.eligible(&pending.lease.execution.plan.release)?,
                        "release provider mutation without current authority"
                    );
                    if mutation.operation == ReleaseOperation::PrepareDeployment {
                        let ready = self
                            .ready_secrets
                            .get(&mutation.fact.execution)
                            .context("deployment without delivered secret readiness")?;
                        ensure!(
                            ready.enabled
                                && ready.access_granted
                                && ready.projection_ready
                                && self
                                    .delivered_secrets
                                    .get(&Digest::of(&mutation.fact.secret)?)
                                    == Some(ready)
                                && mutation.fact.readiness.is_some()
                                && self.provider.evidence()?.resources.iter().any(|resource| {
                                    resource.fact.execution == mutation.fact.execution
                                        && resource.operation == ReleaseOperation::PrepareDependency
                                        && resource.visible_at <= now
                                }),
                            "deployment mutation without current dependency and secret proof"
                        );
                    }
                }
                self.slots[slot as usize]
                    .as_mut()
                    .context("release slot")?
                    .result = Some(result);
                Ok("release_provider_observed".into())
            }
            Action::ReleaseSettle { slot } => {
                let Some(pending) = self.slots[slot as usize].clone() else {
                    return Ok("release_empty_slot".into());
                };
                let Some(result) = pending.result else {
                    return Ok("release_no_outcome".into());
                };
                let build = *self
                    .executions
                    .get(&pending.lease.execution.id)
                    .context("release slot execution missing")?;
                let before_revision = self
                    .host(path, &plans[build], slot as usize)
                    .inspect(&pending.lease.execution.id)?
                    .revision;
                match self.host(path, &plans[build], slot as usize).settle_at(
                    &pending.lease,
                    result.clone(),
                    now,
                ) {
                    Ok(_) => {
                        let after = self
                            .host(path, &plans[build], slot as usize)
                            .inspect(&pending.lease.execution.id)?;
                        if after.revision == before_revision {
                            return Ok("release_duplicate_settlement".into());
                        }
                        if let ReleaseEffectResult::Observed(observation) = &result
                            && let ReleaseObserved::Secret {
                                metadata: Some(metadata),
                            } = &observation.outcome
                            && after.terminal.is_none()
                            && metadata.provider_state.barrier().is_some()
                        {
                            let key = Digest::of(&metadata.reference)?;
                            let previous = self.delivered_secrets.get(&key);
                            if previous.is_none_or(|old| {
                                metadata
                                    .provider_state
                                    .revision()
                                    .relation(old.provider_state.revision())
                                    == RevisionRelation::Newer
                            }) {
                                self.delivered_secrets.insert(key, metadata.clone());
                            }
                            if after.phase == ReleasePhase::SecretReady
                                && self
                                    .delivered_secrets
                                    .get(&Digest::of(&metadata.reference)?)
                                    == Some(metadata)
                            {
                                self.ready_secrets
                                    .insert(observation.fact.execution.clone(), metadata.clone());
                            }
                        }
                        if let ReleaseEffectResult::Observed(observation) = &result
                            && matches!(
                                observation.outcome,
                                ReleaseObserved::DeploymentPrepared { .. }
                            )
                            && after.phase == ReleasePhase::WaitingDeployment
                        {
                            let readiness = observation
                                .fact
                                .readiness
                                .clone()
                                .context("deployment has no readiness identity")?;
                            let secret = self
                                .delivered_secrets
                                .get(&Digest::of(&observation.fact.secret)?)
                                .context("deployment has no delivered secret")?
                                .clone();
                            self.prepared_secrets.insert(readiness, secret);
                        }
                        if let ReleaseEffectResult::Observed(observation) = &result
                            && matches!(
                                observation.outcome,
                                ReleaseObserved::Deployment { ready: true, .. }
                            )
                            && after.phase == ReleasePhase::DeploymentReady
                        {
                            self.delivered_readbacks.insert((
                                observation.fact.execution.clone(),
                                observation
                                    .fact
                                    .readiness
                                    .clone()
                                    .context("readback has no readiness identity")?,
                            ));
                        }
                        Ok("release_settled".into())
                    }
                    Err(error)
                        if expected_fence(
                            path,
                            &pending.lease,
                            Some(&result),
                            now,
                            &error,
                            false,
                        )? =>
                    {
                        Ok("release_fenced".into())
                    }
                    Err(error) => Err(error),
                }
            }
            Action::ReleaseSecret {
                build,
                enabled,
                access,
                ready,
                delay,
            } => {
                self.provider.set_secret(
                    super::releases::secret(&plans[build as usize], build as usize)?,
                    now,
                    delay,
                    enabled,
                    access,
                    ready,
                )?;
                Ok("release_secret_changed".into())
            }
            Action::ReleaseUncertain { build, uncertain } => {
                let Some((release, _)) = releases.approval(build as usize) else {
                    return Ok("release_missing_approval".into());
                };
                self.provider.uncertain_absence(&release, uncertain)?;
                Ok("release_absence_authority_changed".into())
            }
            Action::ReleaseDeliverSecret { build } => {
                let plan = &plans[build as usize];
                let reference = super::releases::secret(plan, build as usize)?;
                let Some(metadata) = self.provider.visible_secret(&reference, now)? else {
                    return Ok("release_secret_not_visible".into());
                };
                if metadata.provider_state.barrier().is_none() {
                    return Ok("release_secret_unqualified".into());
                }
                let target = super::releases::target(plan)?;
                let mut journal = Journal::open(path)?;
                let current = journal.release_secret_metadata(&target, &reference)?;
                if current.as_ref().is_some_and(|(_, old)| {
                    metadata
                        .provider_state
                        .revision()
                        .relation(old.provider_state.revision())
                        != RevisionRelation::Newer
                }) {
                    return Ok("release_secret_unchanged".into());
                }
                journal.observe_release_secret(
                    &target,
                    &name(&format!(
                        "watcher_{}_{}",
                        build,
                        Digest::of(&metadata)?
                            .as_str()
                            .trim_start_matches("sha256:")
                    ))?,
                    current.map(|(revision, _)| revision).unwrap_or(0),
                    &metadata,
                )?;
                self.delivered_secrets
                    .insert(Digest::of(&reference)?, metadata);
                Ok("release_secret_delivered".into())
            }
            _ => anyhow::bail!("unknown release workflow action"),
        }
    }

    fn observe_activation(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        releases: &mut Releases,
        before: &[ReleaseState],
        after: &[ReleaseState],
        now: u64,
    ) -> Result<()> {
        let evidence = self.provider.evidence()?;
        for (previous, current) in before.iter().zip(after) {
            if previous.active == current.active {
                continue;
            }
            let receipt = current
                .active
                .as_ref()
                .context("workflow removed incumbent")?;
            ensure!(
                !self.activations.contains(receipt),
                "workflow restored historical activation"
            );
            let snapshot = self
                .executions
                .iter()
                .map(|(id, index)| self.host(path, &plans[*index], 0).inspect(id))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .find(|snapshot| snapshot.plan.release == receipt.release)
                .context("activation without workflow")?;
            ensure!(
                snapshot.phase == ReleasePhase::Active
                    && snapshot.terminal == Some(ReleaseTerminal::Activated)
                    && previous.desired.as_ref() == Some(&receipt.release)
                    && previous.generation == receipt.generation,
                "activation outside eligible workflow"
            );
            let secret = self
                .prepared_secrets
                .get(&receipt.readiness)
                .context("activation without prepared secret observation")?;
            ensure!(
                secret.enabled && secret.access_granted && secret.projection_ready,
                "activation without observed secret readiness"
            );
            let delivered = self
                .delivered_secrets
                .get(&Digest::of(&receipt.secret)?)
                .context("activation without delivered provider secret")?;
            ensure!(
                delivered == secret,
                "activation without current delivered secret revision"
            );
            ensure!(
                evidence
                    .resources
                    .iter()
                    .any(|resource| resource.fact.execution == snapshot.id
                        && resource.operation == ReleaseOperation::PrepareDeployment
                        && resource.fact.readiness.as_ref() == Some(&receipt.readiness)
                        && resource.visible_at <= now)
                    && self
                        .delivered_readbacks
                        .contains(&(snapshot.id.clone(), receipt.readiness.clone())),
                "activation without exact prepared deployment readback"
            );
            releases.record_workflow_activation(receipt)?;
            self.activations.push(receipt.clone());
        }
        Ok(())
    }

    fn check_provider_facts(&self, path: &Path, plans: &[BuildPlan]) -> Result<()> {
        let evidence = self.provider.evidence()?;
        let journal = Journal::open(path)?;
        let catalog: BTreeMap<_, _> = self
            .executions
            .iter()
            .map(|(id, build)| {
                Ok((
                    id.clone(),
                    (
                        self.host(path, &plans[*build], 0).inspect(id)?,
                        journal.release_execution_approval(id)?,
                    ),
                ))
            })
            .collect::<Result<_>>()?;
        let mut mutations = BTreeSet::new();
        for resource in &evidence.mutations {
            ensure!(
                mutations.insert(resource.fact.effect.clone()),
                "duplicate release provider mutation"
            );
        }
        for fact in evidence
            .resources
            .iter()
            .map(|resource| &resource.fact)
            .chain(
                evidence
                    .observations
                    .iter()
                    .map(|observation| &observation.fact),
            )
        {
            let (snapshot, approval) = catalog
                .get(&fact.execution)
                .context("provider fact for unknown release")?;
            ensure!(
                fact.release == snapshot.plan.release
                    && fact.plan == snapshot.plan.fingerprint()?
                    && fact.target == approval.target
                    && fact.artifact == approval.artifact
                    && fact.secret == approval.secret
                    && (fact.binding == snapshot.plan.resources
                        || fact.binding == snapshot.plan.deployment),
                "cross scoped release provider fact"
            );
        }
        Ok(())
    }

    pub fn drain_complete(&self, path: &Path, plans: &[BuildPlan]) -> Result<bool> {
        Ok(self
            .evidence(path, plans)?
            .executions
            .iter()
            .all(|snapshot| snapshot.terminal.is_some()))
    }

    pub fn finish(
        &mut self,
        path: &Path,
        plans: &[BuildPlan],
        releases: &Releases,
        now: u64,
    ) -> Result<()> {
        let evidence = self.evidence(path, plans)?;
        for snapshot in evidence.executions {
            let disposition = if let Some(terminal) = snapshot.terminal {
                justify_terminal(
                    terminal,
                    releases.eligible(&snapshot.plan.release)?,
                    self.activations.iter().any(|receipt| {
                        receipt.release == snapshot.plan.release
                            && receipt.target == snapshot.target
                    }),
                )?;
                Disposition::Terminal {
                    execution: snapshot.id,
                    terminal,
                }
            } else {
                let approval = Journal::open(path)?.release_execution_approval(&snapshot.id)?;
                match snapshot.waiting {
                    Some(
                        reason @ (ReleaseWait::SecretMetadata
                        | ReleaseWait::SecretDisabled
                        | ReleaseWait::SecretAccess
                        | ReleaseWait::SecretProjection),
                    ) => {
                        let metadata = self.provider.visible_secret(&approval.secret, now)?;
                        let blocked = match reason {
                            ReleaseWait::SecretMetadata => metadata.as_ref().is_none_or(|value| value.provider_state.barrier().is_none())
                                || crate::release::ready_secret(&Journal::open(path)?.connection, &approval)
                                    .err().is_some_and(|error| error.downcast_ref::<crate::release::ReleaseNotReady>() == Some(&crate::release::ReleaseNotReady::AwaitingSecretMetadata)),
                            ReleaseWait::SecretDisabled => {
                                metadata.is_some_and(|value| !value.enabled)
                            }
                            ReleaseWait::SecretAccess => {
                                metadata.is_some_and(|value| !value.access_granted)
                            }
                            ReleaseWait::SecretProjection => {
                                metadata.is_some_and(|value| !value.projection_ready)
                            }
                            _ => false,
                        };
                        ensure!(blocked, "eligible release did not converge");
                        Disposition::WaitingPrerequisite {
                            execution: snapshot.id,
                            reason,
                        }
                    }
                    Some(ReleaseWait::Reconciliation)
                        if evidence
                            .provider
                            .unknown_absence
                            .contains(&snapshot.plan.release) =>
                    {
                        justify_reconciliation(path, &snapshot, &evidence.provider)?;
                        Disposition::NeedsIntervention {
                            execution: snapshot.id,
                        }
                    }
                    _ => anyhow::bail!("release fair drain exhausted"),
                }
            };
            self.dispositions.push(disposition);
        }
        Ok(())
    }
}

fn justify_reconciliation(
    path: &Path,
    snapshot: &ReleaseSnapshot,
    provider: &release_provider::Evidence,
) -> Result<()> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let row = connection.query_row(
        "SELECT s.id,s.request,s.status,s.epoch,s.owner,s.lease_until,s.recovery,s.started,
                s.result,json_extract(w.body,'$.readiness')
         FROM release_steps s JOIN release_workflows w ON w.id=s.execution
         WHERE s.execution=?1 AND s.ordinal=?2",
        rusqlite::params![snapshot.id.as_str(), i64::try_from(snapshot.next_step)?],
        |row| {
            Ok(ReconciliationRow {
                effect: row.get(0)?,
                request: row.get(1)?,
                status: row.get(2)?,
                epoch: row.get(3)?,
                owner: row.get(4)?,
                until: row.get(5)?,
                recovery: row.get(6)?,
                started: row.get(7)?,
                result: row.get(8)?,
                readiness: row.get(9)?,
            })
        },
    )?;
    let effect = Digest::try_from(row.effect)?;
    let request: StepRequest = serde_json::from_str(&row.request)?;
    let family = match request.operation {
        ReleaseOperation::PrepareDependency => "dependency",
        ReleaseOperation::PrepareDeployment => "deployment",
        _ => anyhow::bail!("intervention is not an uncertain mutation"),
    };
    ensure!(
        request.ordinal == snapshot.next_step
            && effect
                == Digest::of(&(
                    "day2-release-step-v1",
                    &snapshot.id,
                    &snapshot.plan.recipe,
                    &request.name,
                    request.ordinal,
                ))?
            && row.status == "ambiguous"
            && row.recovery
            && row.started
            && row.until == 0
            && row.result.is_none(),
        "intervention without durable ambiguous dispatch"
    );

    // Worker slots and leases disappear on restart or reuse. The latest exact
    // claim, dispatch and deferred result must instead justify intervention.
    let (claim_sequence, claim_body) =
        reconciliation_event(&connection, &snapshot.id, &effect, "workflow_claimed")?;
    let (claimed_execution, (claimed_effect, claimed_step, epoch, owner, until, reconcile)): (
        Digest,
        (Digest, StepRequest, u64, Name, u64, bool),
    ) = serde_json::from_str(&claim_body)?;
    ensure!(
        claimed_execution == snapshot.id
            && claimed_effect == effect
            && claimed_step == request
            && epoch == u64::try_from(row.epoch)?
            && owner.as_str() == row.owner
            && until > 0
            && reconcile,
        "intervention claim identity mismatch"
    );
    let (dispatch_sequence, dispatch_body) = reconciliation_event(
        &connection,
        &snapshot.id,
        &effect,
        "workflow_provider_dispatch",
    )?;
    let (dispatched_execution, (dispatched_effect, dispatched_epoch, reconciled)): (
        Digest,
        (Digest, u64, bool),
    ) = serde_json::from_str(&dispatch_body)?;
    let (settlement_sequence, settlement_body) =
        reconciliation_event(&connection, &snapshot.id, &effect, "workflow_settlement")?;
    let (settled_execution, (settled_effect, result)): (Digest, (Digest, ReleaseEffectResult)) =
        serde_json::from_str(&settlement_body)?;
    ensure!(
        dispatched_execution == snapshot.id
            && dispatched_effect == effect
            && dispatched_epoch == epoch
            && reconciled
            && settled_execution == snapshot.id
            && settled_effect == effect
            && matches!(result, ReleaseEffectResult::Ambiguous {})
            && claim_sequence < dispatch_sequence
            && dispatch_sequence < settlement_sequence,
        "intervention lacks exact reconciled ambiguous outcome"
    );
    let readiness = if family == "deployment" {
        Some(Digest::try_from(
            row.readiness
                .context("deployment ambiguity lacks readiness")?,
        )?)
    } else {
        None
    };
    let resource = Digest::of(&("day2-release-resource-v1", &snapshot.id, family))?;
    ensure!(
        provider.unknown_absence.contains(&snapshot.plan.release)
            && !provider
                .resources
                .iter()
                .any(|item| { item.fact.resource == resource && item.fact.readiness == readiness }),
        "intervention despite provider receipt or qualified absence"
    );
    Ok(())
}

struct ReconciliationRow {
    effect: String,
    request: String,
    status: String,
    epoch: i64,
    owner: String,
    until: i64,
    recovery: bool,
    started: bool,
    result: Option<String>,
    readiness: Option<String>,
}

fn reconciliation_event(
    connection: &rusqlite::Connection,
    execution: &Digest,
    effect: &Digest,
    kind: &str,
) -> Result<(i64, String)> {
    Ok(connection.query_row(
        "SELECT sequence,body FROM release_events
         WHERE kind=?1 AND json_extract(body,'$[0]')=?2
           AND json_extract(body,'$[1][0]')=?3
         ORDER BY sequence DESC LIMIT 1",
        rusqlite::params![kind, execution.as_str(), effect.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

fn justify_terminal(terminal: ReleaseTerminal, eligible: bool, activated: bool) -> Result<()> {
    ensure!(
        match terminal {
            ReleaseTerminal::Activated => activated,
            ReleaseTerminal::AuthorityLost => !eligible,
            ReleaseTerminal::Intervention => false,
        },
        "unjustified release terminal state"
    );
    Ok(())
}

fn expected_fence(
    path: &Path,
    lease: &ReleaseLease,
    result: Option<&ReleaseEffectResult>,
    now: u64,
    error: &anyhow::Error,
    perform: bool,
) -> Result<bool> {
    let Some(reason) = error.downcast_ref::<ReleaseRejection>() else {
        return Ok(false);
    };
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (status, epoch, owner, until, previous, dispatched): (
        String,
        i64,
        String,
        i64,
        Option<String>,
        bool,
    ) = connection.query_row(
        "SELECT status,epoch,owner,lease_until,result,started FROM release_steps WHERE id=?1",
        [lease.effect.as_str()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    Ok(match reason {
        ReleaseRejection::FencedLease => {
            status != "running"
                || u64::try_from(epoch)? != lease.epoch
                || owner != lease.owner.as_str()
                || u64::try_from(until)? <= now
                || (perform && dispatched)
        }
        ReleaseRejection::ConflictingCompletion => {
            status == "complete"
                && result.is_some_and(|result| {
                    previous.as_ref().is_some_and(|body| {
                        serde_json::to_string(result).is_ok_and(|encoded| encoded != *body)
                    })
                })
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_reports_require_independent_outcomes_or_lost_authority() {
        assert!(justify_terminal(ReleaseTerminal::AuthorityLost, true, false).is_err());
        assert!(justify_terminal(ReleaseTerminal::Activated, true, false).is_err());
        assert!(justify_terminal(ReleaseTerminal::Intervention, false, false).is_err());
        assert!(justify_terminal(ReleaseTerminal::AuthorityLost, false, false).is_ok());
        assert!(justify_terminal(ReleaseTerminal::Activated, false, true).is_ok());
    }
}
