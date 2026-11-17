//! Durable runtime handoff and operator-observed deployment DATA. Kubernetes
//! and load-balancer collection belongs to the native operator adapter; these
//! records are neither pod attestation nor a substitute for current authority.
use super::*;
use crate::runtime_generation;
use rusqlite::Connection;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceIdentity {
    pub name: String,
    pub uid: String,
}

fn name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')),
        "runtime_pair_resource_name_invalid"
    );
    Ok(())
}

fn uid(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "runtime_pair_resource_uid_invalid"
    );
    Ok(())
}

impl ResourceIdentity {
    pub fn validate(&self) -> Result<()> {
        name(&self.name)?;
        uid(&self.uid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub project: String,
    pub service: String,
    pub id: String,
    pub neg: String,
    pub zone: String,
    pub health_check: String,
    pub configuration: String,
    pub port: u16,
    pub drain_seconds: u16,
}

impl Backend {
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.project,
            &self.service,
            &self.neg,
            &self.zone,
            &self.health_check,
        ] {
            name(value)?;
        }
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 32
                && self.id.bytes().all(|b| b.is_ascii_digit()),
            "runtime_pair_backend_id_invalid"
        );
        day2_assets::hash_part(&self.configuration)?;
        ensure!(
            self.port > 0 && (1..=300).contains(&self.drain_seconds),
            "runtime_pair_backend_bounds_invalid"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub service: ResourceIdentity,
    pub candidate_controller: ResourceIdentity,
    pub selection: ResourceIdentity,
    pub source_template: String,
    pub target_template: String,
    pub backend: Backend,
}

impl Binding {
    pub fn validate(&self) -> Result<()> {
        self.service.validate()?;
        self.candidate_controller.validate()?;
        self.selection.validate()?;
        day2_assets::hash_part(&self.source_template)?;
        day2_assets::hash_part(&self.target_template)?;
        self.backend.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.ip.parse::<std::net::Ipv4Addr>().is_ok() && self.port > 0,
            "runtime_pair_endpoint_invalid"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodObservation {
    pub pod: ResourceIdentity,
    pub replicaset_uid: String,
    pub owner_uid: String,
    pub node: String,
    pub pvc_uid: String,
    pub image: String,
    pub image_id: String,
    pub endpoint: Endpoint,
}

impl PodObservation {
    fn validate(&self, release: &Release, binding: &Binding, target: bool) -> Result<()> {
        self.pod.validate()?;
        uid(&self.replicaset_uid)?;
        uid(&self.owner_uid)?;
        self.endpoint.validate()?;
        let placement = release
            .placement
            .as_ref()
            .context("runtime_pair_placement_required")?;
        let software = if target {
            &release.target
        } else {
            &release.source
        };
        let digest = software
            .image
            .rsplit_once('@')
            .context("runtime_pair_image_changed")?
            .1;
        ensure!(
            self.node == placement.node
                && self.pvc_uid == placement.pvc_uid
                && self.image == software.image
                && self.image_id.ends_with(&format!("@{digest}"))
                && self.endpoint.port == binding.backend.port,
            "runtime_pair_pod_binding_changed"
        );
        ensure!(
            if target {
                self.replicaset_uid == binding.candidate_controller.uid
                    && (self.owner_uid == binding.selection.uid
                        || self.owner_uid == placement.controller_uid)
            } else {
                self.owner_uid == placement.controller_uid
                    && self.replicaset_uid != binding.candidate_controller.uid
            },
            "runtime_pair_pod_owner_changed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthObservation {
    pub round: u64,
    pub authority: authority_state::AuthorityStamp,
    pub service: ResourceIdentity,
    pub backend: Backend,
    pub target: PodObservation,
    pub source: Option<PodObservation>,
    pub healthy: Vec<Endpoint>,
}

impl HealthObservation {
    fn validate(&self, release: &Release, binding: &Binding) -> Result<()> {
        ensure!(
            self.round > 0 && self.service == binding.service && self.backend == binding.backend,
            "runtime_pair_backend_binding_changed"
        );
        self.target.validate(release, binding, true)?;
        if let Some(source) = &self.source {
            source.validate(release, binding, false)?;
            ensure!(
                source.endpoint != self.target.endpoint && source.pod.uid != self.target.pod.uid,
                "runtime_pair_endpoint_role_changed"
            );
        }
        ensure!(self.healthy.len() <= 256, "runtime_pair_endpoint_budget");
        let mut unique = BTreeSet::new();
        for endpoint in &self.healthy {
            endpoint.validate()?;
            ensure!(unique.insert(endpoint), "runtime_pair_duplicate_endpoint");
        }
        ensure!(
            unique.contains(&self.target.endpoint),
            "runtime_pair_target_lb_unhealthy"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainObservation {
    pub health: HealthObservation,
    pub absent: Vec<Endpoint>,
    pub elapsed_ms: u64,
    pub source_inflight: u64,
    pub source_streams: u64,
    pub source_stopped: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionObservation {
    pub health: HealthObservation,
    pub controller: ResourceIdentity,
    pub template: String,
    pub source_pods: u64,
    pub source_inflight: u64,
    pub source_streams: u64,
    pub source_stopped: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Stage {
    Bound,
    Promoted,
    Withdrawing {
        health: Box<HealthObservation>,
    },
    Quiesced {
        health: Box<HealthObservation>,
        drain: Box<DrainObservation>,
    },
    Complete {
        health: Box<HealthObservation>,
        drain: Box<DrainObservation>,
        adoption: Box<AdoptionObservation>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handoff {
    pub binding: Binding,
    pub round: u64,
    pub stage: Stage,
}

impl Handoff {
    pub(crate) fn validate(&self, release: &Release) -> Result<()> {
        self.binding.validate()?;
        let phase = match &self.stage {
            Stage::Bound => Phase::Prepared,
            Stage::Promoted => Phase::Serving,
            Stage::Withdrawing { health } => {
                health.validate(release, &self.binding)?;
                Phase::Draining
            }
            Stage::Quiesced { health, drain } | Stage::Complete { health, drain, .. } => {
                health.validate(release, &self.binding)?;
                drain.health.validate(release, &self.binding)?;
                self.require_drain(health, drain)?;
                if let Stage::Complete { adoption, .. } = &self.stage {
                    self.require_adoption(release, adoption)?;
                    Phase::Complete
                } else {
                    Phase::Draining
                }
            }
        };
        ensure!(
            release.phase == phase || (release.phase == Phase::Aborted && phase == Phase::Prepared),
            "runtime_pair_handoff_phase_changed"
        );
        ensure!(
            match &release.kind {
                ReleaseKind::RuntimePair {
                    execution: Execution::Admitted { check, .. },
                    ..
                } => phase == Phase::Prepared || check.is_some(),
                _ => false,
            },
            "runtime_pair_check_required"
        );
        Ok(())
    }

    fn require_drain(&self, withdrawn: &HealthObservation, drain: &DrainObservation) -> Result<()> {
        ensure!(
            drain.elapsed_ms >= u64::from(self.binding.backend.drain_seconds) * 1000
                && drain.absent.len() <= 256,
            "runtime_pair_lb_drain_incomplete"
        );
        let absent: BTreeSet<_> = drain.absent.iter().collect();
        ensure!(
            absent.len() == drain.absent.len(),
            "runtime_pair_duplicate_endpoint"
        );
        for endpoint in &drain.absent {
            endpoint.validate()?;
        }
        if let Some(source) = &withdrawn.source {
            ensure!(
                absent.contains(&source.endpoint),
                "runtime_pair_source_endpoint_not_removed"
            );
        }
        ensure!(
            !absent.contains(&drain.health.target.endpoint),
            "runtime_pair_target_endpoint_removed"
        );
        ensure!(
            drain
                .health
                .healthy
                .iter()
                .all(|endpoint| !absent.contains(endpoint)),
            "runtime_pair_contradictory_endpoint_observation"
        );
        Ok(())
    }

    fn require_adoption(&self, release: &Release, observation: &AdoptionObservation) -> Result<()> {
        observation.health.validate(release, &self.binding)?;
        observation.controller.validate()?;
        let placement = release
            .placement
            .as_ref()
            .context("runtime_pair_placement_required")?;
        ensure!(
            observation.controller.uid == placement.controller_uid
                && observation.template == self.binding.target_template
                && observation.source_pods == 0
                && observation.health.source.is_none()
                && observation.source_inflight == 0
                && observation.source_streams == 0
                && observation.source_stopped
                && observation.health.target.owner_uid == placement.controller_uid,
            "runtime_pair_controller_adoption_incomplete"
        );
        Ok(())
    }
}

pub(crate) fn handoff(release: &Release) -> Result<&Handoff> {
    match &release.kind {
        ReleaseKind::RuntimePair {
            execution:
                Execution::Admitted {
                    handoff: Some(value),
                    ..
                },
            ..
        } => Ok(value),
        _ => anyhow::bail!("runtime_pair_handoff_required"),
    }
}

pub(crate) fn retained_source(runtime: &Runtime, db: &Connection) -> Result<Option<String>> {
    let Some(release) = rollout::state(db)? else {
        return Ok(None);
    };
    if !matches!(release.kind, ReleaseKind::RuntimePair { .. })
        || !matches!(release.phase, Phase::Serving | Phase::Draining)
    {
        return Ok(None);
    }
    runtime.check_binding(db)?;
    let current = authority_state::current(db)?;
    ensure!(
        release.scope == runtime.scope()
            && release.source.artifact == runtime.artifact().id()
            && release.source.instance_digest == runtime.instance_digest()
            && release.target.instance_digest == runtime.instance_digest()
            && current.artifact_id == release.target.artifact
            && current.stamp == release.authority,
        "runtime_pair_authority_changed"
    );
    let ReleaseKind::RuntimePair {
        execution: Execution::Admitted {
            source, candidate, ..
        },
        ..
    } = &release.kind
    else {
        anyhow::bail!("runtime_pair_executor_not_admitted")
    };
    runtime_generation::require_active(db, candidate)?;
    runtime_generation::require_expected(db, runtime.scope(), source, &release.source.runtime)?;
    Ok(Some(source.clone()))
}

pub(crate) fn require_root_admission(
    runtime: &Runtime,
    db: &Connection,
    generation: &str,
) -> Result<()> {
    if let Some(source) = retained_source(runtime, db)?
        && source == generation
    {
        let release = rollout::state(db)?.context("runtime_pair_not_prepared")?;
        ensure!(
            !matches!(
                handoff(&release)?.stage,
                Stage::Quiesced { .. } | Stage::Complete { .. }
            ),
            "runtime_pair_source_quiesced"
        );
    }
    Ok(())
}

pub(crate) fn serving_ready(
    runtime: &Runtime,
    db: &Connection,
    release: &Release,
    candidate: bool,
) -> Result<bool> {
    let generation = runtime_generation::selected(runtime, db)?;
    ready_for_generation(release, &generation, candidate)
}

pub(super) fn ready_for_generation(
    release: &Release,
    generation: &str,
    candidate: bool,
) -> Result<bool> {
    if let ReleaseKind::RuntimePair {
        execution: Execution::Unadmitted,
        ..
    } = &release.kind
    {
        return Ok(matches!(release.phase, Phase::Prepared | Phase::Aborted)
            && generation
                == runtime_generation::expected_id(&release.scope, &release.source.runtime)?);
    }
    let ReleaseKind::RuntimePair {
        execution:
            Execution::Admitted {
                source,
                candidate: target,
                ..
            },
        ..
    } = &release.kind
    else {
        return Ok(false);
    };
    if generation == source {
        return Ok(matches!(
            release.phase,
            Phase::Prepared | Phase::Serving | Phase::Aborted
        ));
    }
    Ok(generation == target
        && matches!(
            release.phase,
            Phase::Serving | Phase::Draining | Phase::Complete
        )
        && (candidate
            || release
                .probe
                .as_ref()
                .is_some_and(|p| p.status == rollout::ProbeStatus::Verified)))
}

pub(crate) fn source_quiesced(runtime: &Runtime, db: &Connection) -> Result<bool> {
    let Some(source) = retained_source(runtime, db)? else {
        return Ok(false);
    };
    if runtime_generation::selected(runtime, db)? != source {
        return Ok(false);
    }
    let release = rollout::state(db)?.context("runtime_pair_not_prepared")?;
    Ok(matches!(handoff(&release)?.stage, Stage::Quiesced { .. }))
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationAction {
    Bind,
    Withdraw,
    Quiesce,
    Stopped,
    Complete,
}

pub fn apply_observation(
    runtime: &Runtime,
    id: &str,
    action: ObservationAction,
    path: &std::path::Path,
    operator: &LocalOperator,
) -> Result<Release> {
    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        crate::json::decode(bytes).map_err(|_| anyhow::anyhow!("runtime_pair_observation_invalid"))
    }
    let bytes = super::executor::input_bytes(path)?;
    match action {
        ObservationAction::Bind => bind_handoff(runtime, id, decode(&bytes)?, operator),
        ObservationAction::Withdraw => withdraw_source(runtime, id, decode(&bytes)?, operator),
        ObservationAction::Quiesce => quiesce_source(runtime, id, decode(&bytes)?, operator),
        ObservationAction::Stopped => {
            acknowledge_source_stop(runtime, id, decode(&bytes)?, operator)
        }
        ObservationAction::Complete => complete_handoff(runtime, id, decode(&bytes)?, operator),
    }
}

pub fn inspect_source_pending(
    runtime: &Runtime,
    id: &str,
    operator: &LocalOperator,
) -> Result<u64> {
    rollout::operator(runtime, operator)?;
    runtime.sql_read(|db| {
        let release = super::executor::bound(runtime, db, false)?;
        ensure!(release.id == id, "runtime_pair_binding_changed");
        source_pending(db, &release)
    })
}

/// Cleanup permission for a never-public candidate only. Policy may have
/// advanced since preparation, so use current operator authority and prove the
/// original Source is still the active native execution before returning DATA.
pub fn inspect_aborted(runtime: &Runtime, id: &str, operator: &LocalOperator) -> Result<Release> {
    ensure!(
        runtime.rolling() && !runtime.uses_native_storage(),
        "ordinary_rolling_profile_required"
    );
    rollout::operator(runtime, operator)?;
    let _operation = crate::deployment::OperationLease::acquire(
        runtime.db().parent().context("state root")?,
        runtime.app(),
    )?;
    let _release = rollout::release_lock(runtime)?;
    runtime.sql_read(|db| {
        ensure!(
            runtime.operators()?.contains(operator.name())
                || authority_state::current(db)?
                    .policy()?
                    .admins
                    .contains(operator.name()),
            "rollout_operator_required"
        );
        runtime.check_binding(db)?;
        let release = rollout::state(db)?.context("runtime_pair_not_prepared")?;
        ensure!(
            release.id == id
                && release.scope == runtime.scope()
                && release.source.artifact == runtime.artifact().id()
                && release.phase == Phase::Aborted
                && matches!(release.kind, ReleaseKind::RuntimePair { .. }),
            "runtime_pair_abort_cleanup_refused"
        );
        let source = runtime_generation::expected_id(&release.scope, &release.source.runtime)?;
        runtime_generation::require_expected(db, &release.scope, &source, &release.source.runtime)?;
        runtime_generation::require_active(db, &source)?;
        Ok(release)
    })
}

fn update(
    runtime: &Runtime,
    id: &str,
    operator: &LocalOperator,
    action: impl FnOnce(&Connection, &mut Release) -> Result<()>,
) -> Result<Release> {
    rollout::operator(runtime, operator)?;
    let _operation = crate::deployment::OperationLease::acquire(
        runtime.db().parent().context("state root")?,
        runtime.app(),
    )?;
    let _release = rollout::release_lock(runtime)?;
    super::local_stores(runtime)?;
    let expected = super::expected_storage(runtime)?;
    runtime.sql_write(|db| {
        ensure!(
            runtime.operators()?.contains(operator.name())
                || authority_state::current(db)?
                    .policy()?
                    .admins
                    .contains(operator.name()),
            "rollout_operator_required"
        );
        ensure!(
            rollout::storage_shape(runtime, db)? == expected.shape,
            "runtime_pair_store_shape_changed"
        );
        crate::store::require_no_managed_credential_restore_state(db)?;
        let mut release = super::executor::bound(runtime, db, false)?;
        ensure!(release.id == id, "runtime_pair_binding_changed");
        action(db, &mut release)?;
        let ReleaseKind::RuntimePair { execution, .. } = &release.kind else {
            unreachable!()
        };
        execution.validate(&release)?;
        rollout::write(db, &release)?;
        Ok(release)
    })
}

fn handoff_mut(release: &mut Release) -> Result<&mut Handoff> {
    match &mut release.kind {
        ReleaseKind::RuntimePair {
            execution:
                Execution::Admitted {
                    handoff: Some(value),
                    ..
                },
            ..
        } => Ok(value),
        _ => anyhow::bail!("runtime_pair_handoff_required"),
    }
}

pub fn bind_handoff(
    runtime: &Runtime,
    id: &str,
    binding: Binding,
    operator: &LocalOperator,
) -> Result<Release> {
    binding.validate()?;
    update(runtime, id, operator, |_, release| {
        let ReleaseKind::RuntimePair {
            execution: Execution::Admitted { handoff, .. },
            ..
        } = &mut release.kind
        else {
            anyhow::bail!("runtime_pair_executor_not_admitted")
        };
        if let Some(previous) = handoff {
            ensure!(
                previous.binding == binding,
                "runtime_pair_handoff_binding_changed"
            );
        } else {
            ensure!(
                release.phase == Phase::Prepared,
                "runtime_pair_not_prepared"
            );
            *handoff = Some(Box::new(Handoff {
                binding,
                round: 0,
                stage: Stage::Bound,
            }));
        }
        Ok(())
    })
}

pub fn promote_handoff(runtime: &Runtime, id: &str, operator: &LocalOperator) -> Result<Release> {
    update(runtime, id, operator, promote_in)
}

pub(super) fn promote_in(db: &Connection, release: &mut Release) -> Result<()> {
    let ReleaseKind::RuntimePair {
        execution:
            Execution::Admitted {
                source,
                candidate,
                check,
                ..
            },
        ..
    } = &release.kind
    else {
        anyhow::bail!("runtime_pair_executor_not_admitted")
    };
    runtime_generation::require_expected(db, &release.scope, source, &release.source.runtime)?;
    runtime_generation::require_expected(db, &release.scope, candidate, &release.target.runtime)?;
    if release.phase != Phase::Prepared {
        ensure!(
            matches!(
                release.phase,
                Phase::Serving | Phase::Draining | Phase::Complete
            ),
            "runtime_pair_promotion_refused"
        );
        runtime_generation::require_active(db, candidate)?;
        return Ok(());
    }
    ensure!(
        check.is_some() && matches!(handoff(release)?.stage, Stage::Bound),
        "runtime_pair_check_required"
    );
    runtime_generation::select_pair_target(db, source, candidate)?;
    handoff_mut(release)?.stage = Stage::Promoted;
    release.phase = Phase::Serving;
    Ok(())
}

/// A new provider observation is bound to one current authority and round.
/// Old observations cannot authorize a later transition after a competing read.
pub fn next_observation(runtime: &Runtime, id: &str, operator: &LocalOperator) -> Result<Release> {
    update(runtime, id, operator, |_, release| {
        ensure!(
            matches!(release.phase, Phase::Serving | Phase::Draining),
            "runtime_pair_public_admission_required"
        );
        let handoff = handoff_mut(release)?;
        handoff.round = handoff
            .round
            .checked_add(1)
            .context("runtime_pair_observation_exhausted")?;
        Ok(())
    })
}

fn current_observation(release: &Release, observation: &HealthObservation) -> Result<()> {
    let handoff = handoff(release)?;
    ensure!(
        observation.round == handoff.round && observation.authority == release.authority,
        "runtime_pair_observation_stale"
    );
    observation.validate(release, &handoff.binding)
}

pub fn withdraw_source(
    runtime: &Runtime,
    id: &str,
    observation: HealthObservation,
    operator: &LocalOperator,
) -> Result<Release> {
    update(runtime, id, operator, |_, release| {
        withdraw_in(release, observation)
    })
}

pub(super) fn withdraw_in(release: &mut Release, observation: HealthObservation) -> Result<()> {
    if let Stage::Withdrawing { health }
    | Stage::Quiesced { health, .. }
    | Stage::Complete { health, .. } = &handoff(release)?.stage
        && **health == observation
    {
        return Ok(());
    }
    current_observation(release, &observation)?;
    ensure!(
        release.phase == Phase::Serving
            && matches!(handoff(release)?.stage, Stage::Promoted)
            && release
                .probe
                .as_ref()
                .is_some_and(|probe| probe.status == rollout::ProbeStatus::Verified),
        "runtime_pair_probe_required"
    );
    handoff_mut(release)?.stage = Stage::Withdrawing {
        health: Box::new(observation),
    };
    release.phase = Phase::Draining;
    Ok(())
}

pub fn quiesce_source(
    runtime: &Runtime,
    id: &str,
    observation: DrainObservation,
    operator: &LocalOperator,
) -> Result<Release> {
    update(runtime, id, operator, |_, release| {
        quiesce_in(release, observation)
    })
}

pub(super) fn quiesce_in(release: &mut Release, observation: DrainObservation) -> Result<()> {
    let handoff = handoff(release)?;
    if let Stage::Quiesced { drain, .. } | Stage::Complete { drain, .. } = &handoff.stage
        && **drain == observation
    {
        return Ok(());
    }
    current_observation(release, &observation.health)?;
    let Stage::Withdrawing { health } = &handoff.stage else {
        anyhow::bail!("runtime_pair_withdrawal_required")
    };
    handoff.require_drain(health, &observation)?;
    ensure!(
        observation.source_inflight == 0
            && observation.source_streams == 0
            && observation.health.source == health.source,
        "runtime_pair_source_requests_not_drained"
    );
    let health = health.clone();
    handoff_mut(release)?.stage = Stage::Quiesced {
        health,
        drain: Box::new(observation),
    };
    Ok(())
}

/// Persist the observed graceful transport stop before the source Pod can be
/// retired. Deleted Pods alone cannot prove completion of in-flight responses.
pub fn acknowledge_source_stop(
    runtime: &Runtime,
    id: &str,
    observation: DrainObservation,
    operator: &LocalOperator,
) -> Result<Release> {
    update(runtime, id, operator, |_, release| {
        acknowledge_stop_in(release, observation)
    })
}

pub(super) fn acknowledge_stop_in(
    release: &mut Release,
    observation: DrainObservation,
) -> Result<()> {
    current_observation(release, &observation.health)?;
    let handoff = handoff(release)?;
    let Stage::Quiesced { health, drain } = &handoff.stage else {
        anyhow::bail!("runtime_pair_source_quiesce_required")
    };
    handoff.require_drain(health, &observation)?;
    ensure!(
        observation.source_stopped
            && observation.source_inflight == 0
            && observation.source_streams == 0
            && health
                .source
                .as_ref()
                .is_some_and(|original| observation.health.source.as_ref() == Some(original)),
        "runtime_pair_source_transport_stop_required"
    );
    if drain.source_stopped {
        return Ok(());
    }
    let health = health.clone();
    handoff_mut(release)?.stage = Stage::Quiesced {
        health,
        drain: Box::new(observation),
    };
    Ok(())
}

pub(crate) fn source_pending(db: &Connection, release: &Release) -> Result<u64> {
    runtime_generation::require_queue(db)?;
    let ReleaseKind::RuntimePair {
        execution: Execution::Admitted { source, .. },
        ..
    } = &release.kind
    else {
        anyhow::bail!("runtime_pair_executor_not_admitted")
    };
    // Revoked/restore-fenced work remains recorded under its original owner,
    // but cannot force a retired executable to acquire replacement authority.
    let pending: i64 = db.query_row(
        "SELECT count(*) FROM day2_invocation_runtime r
        JOIN day2_invocations i ON i.id=r.invocation
        LEFT JOIN day2_invocation_authority a ON a.invocation=i.id
        WHERE r.generation=?1 AND i.status NOT IN ('success','failure')
        AND (a.invocation IS NULL OR (a.epoch=?2 AND a.revision=?3))
        AND NOT EXISTS(SELECT 1 FROM day2_authority_blocks b WHERE b.invocation=i.id)",
        rusqlite::params![
            source,
            release.authority.epoch,
            i64::try_from(release.authority.revision)
                .context("runtime_pair_authority_revision_invalid")?
        ],
        |row| row.get(0),
    )?;
    u64::try_from(pending).context("runtime_pair_pending_count_invalid")
}

pub fn complete_handoff(
    runtime: &Runtime,
    id: &str,
    observation: AdoptionObservation,
    operator: &LocalOperator,
) -> Result<Release> {
    update(runtime, id, operator, |db, release| {
        complete_in(db, release, observation)?;
        rollout::record_runtime_release(runtime, db, release)
    })
}

pub(super) fn complete_in(
    db: &Connection,
    release: &mut Release,
    observation: AdoptionObservation,
) -> Result<()> {
    let handoff = handoff(release)?;
    if let Stage::Complete { adoption, .. } = &handoff.stage {
        ensure!(
            **adoption == observation,
            "runtime_pair_completion_conflict"
        );
        return Ok(());
    }
    current_observation(release, &observation.health)?;
    handoff.require_adoption(release, &observation)?;
    ensure!(
        source_pending(db, release)? == 0,
        "runtime_pair_source_work_pending"
    );
    let Stage::Quiesced { health, drain } = &handoff.stage else {
        anyhow::bail!("runtime_pair_source_quiesce_required")
    };
    ensure!(
        drain.source_stopped && drain.source_inflight == 0 && drain.source_streams == 0,
        "runtime_pair_source_transport_stop_required"
    );
    let next = Stage::Complete {
        health: health.clone(),
        drain: drain.clone(),
        adoption: Box::new(observation),
    };
    handoff_mut(release)?.stage = next;
    release.phase = Phase::Complete;
    Ok(())
}
