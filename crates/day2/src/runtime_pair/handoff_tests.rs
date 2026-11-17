use super::*;
use crate::runtime_pair::handoff::{self, *};

#[test]
fn helper_preflight_refuses_non_rwo_selection_without_opening_a_store() -> Result<()> {
    let world = World::new()?;
    let mut instance: serde_json::Value =
        serde_json::from_slice(&std::fs::read(world.runtime.instance_path())?)?;
    crate::runtime_pair::validate_instance(&serde_json::to_vec(&instance)?, "app")?;
    instance["apps"]["app"]["runtime"]["kind"] = serde_json::json!("linux_sqlite_single_v1");
    assert!(
        crate::runtime_pair::validate_instance(&serde_json::to_vec(&instance)?, "app").is_err()
    );
    assert!(
        crate::runtime_pair::validate_instance(&serde_json::to_vec(&instance)?, "another_app")
            .is_err()
    );
    assert!(crate::runtime_pair::validate_instance(&vec![b'x'; 1_048_577], "app").is_err());
    Ok(())
}

#[test]
fn aborted_cleanup_requires_current_operator_exact_release_and_active_original_source() -> Result<()>
{
    let world = bound_world()?;
    let operator = LocalOperator::assert_local("operator")?;
    assert!(handoff::inspect_aborted(&world.runtime, &world.release.id, &operator).is_err());
    let mut release = rollout::state(&world.db)?.unwrap();
    release.phase = Phase::Aborted;
    rollout::write(&world.db, &release)?;
    assert_eq!(
        handoff::inspect_aborted(&world.runtime, &release.id, &operator)?,
        release
    );
    assert!(handoff::inspect_aborted(&world.runtime, "another-release", &operator).is_err());
    assert!(
        handoff::inspect_aborted(
            &world.runtime,
            &release.id,
            &LocalOperator::assert_local("stranger")?
        )
        .is_err()
    );
    let source = runtime_generation::expected_id(world.runtime.scope(), &release.source.runtime)?;
    let target = runtime_generation::expected_id(world.runtime.scope(), &release.target.runtime)?;
    runtime_generation::select_pair_target(&world.db, &source, &target)?;
    assert!(handoff::inspect_aborted(&world.runtime, &release.id, &operator).is_err());
    Ok(())
}

#[test]
fn source_readiness_survives_preparation_and_target_waits_for_its_probe() -> Result<()> {
    let mut world = World::new()?;
    let source =
        runtime_generation::expected_id(world.runtime.scope(), &world.release.source.runtime)?;
    let target =
        runtime_generation::expected_id(world.runtime.scope(), &world.release.target.runtime)?;
    assert!(handoff::ready_for_generation(
        &world.release,
        &source,
        false
    )?);
    assert!(!handoff::ready_for_generation(
        &world.release,
        &target,
        false
    )?);
    world.admit()?;
    let mut release = rollout::state(&world.db)?.unwrap();
    assert!(handoff::ready_for_generation(&release, &source, false)?);
    release.phase = Phase::Serving;
    assert!(handoff::ready_for_generation(&release, &source, false)?);
    assert!(!handoff::ready_for_generation(&release, &target, false)?);
    assert!(handoff::ready_for_generation(&release, &target, true)?);
    verified_probe(&mut release);
    assert!(handoff::ready_for_generation(&release, &target, false)?);
    release.phase = Phase::Draining;
    assert!(!handoff::ready_for_generation(&release, &source, false)?);
    assert!(handoff::ready_for_generation(&release, &target, false)?);
    Ok(())
}

// Real SQLite, synthetic Linux qualification and deployment observations.
// These tests prove journal/owner guards, not a native pair or cloud rollout.
fn binding() -> Binding {
    Binding {
        service: ResourceIdentity {
            name: "app".into(),
            uid: "service-one".into(),
        },
        candidate_controller: ResourceIdentity {
            name: "pair-target".into(),
            uid: "target-rs-one".into(),
        },
        selection: ResourceIdentity {
            name: "pair-selection".into(),
            uid: "selection-one".into(),
        },
        source_template: crate::digest(b"source template"),
        target_template: crate::digest(b"target template"),
        backend: Backend {
            project: "example-project".into(),
            service: "app-backend".into(),
            id: "123456".into(),
            neg: "app-neg".into(),
            zone: "us-central1-a".into(),
            health_check: "app-health".into(),
            configuration: crate::digest(b"backend configuration"),
            port: 8080,
            drain_seconds: 30,
        },
    }
}

fn bound_world() -> Result<World> {
    let mut world = World::new()?;
    world.admit()?;
    let selection = world.selection(ExecutorRole::Candidate);
    let code = world.code(ExecutorRole::Candidate)?;
    let (release, generation, attempt) = begin_check(&world.runtime, &world.db, &selection, &code)?;
    finish_check(
        &world.runtime,
        &world.db,
        &selection,
        &code,
        &release,
        &check(generation, attempt),
    )?;
    let mut release = rollout::state(&world.db)?.unwrap();
    let ReleaseKind::RuntimePair {
        execution: Execution::Admitted { handoff, .. },
        ..
    } = &mut release.kind
    else {
        unreachable!()
    };
    *handoff = Some(Box::new(Handoff {
        binding: binding(),
        round: 0,
        stage: Stage::Bound,
    }));
    rollout::write(&world.db, &release)?;
    Ok(world)
}

fn round(release: &mut Release, n: u64) {
    let ReleaseKind::RuntimePair {
        execution: Execution::Admitted {
            handoff: Some(h), ..
        },
        ..
    } = &mut release.kind
    else {
        unreachable!()
    };
    h.round = n;
}

fn pod(world: &World, target: bool) -> PodObservation {
    let generation = if target {
        &world.release.target
    } else {
        &world.release.source
    };
    PodObservation {
        pod: ResourceIdentity {
            name: if target { "target-pod" } else { "source-pod" }.into(),
            uid: if target {
                "target-pod-one"
            } else {
                "source-pod-one"
            }
            .into(),
        },
        replicaset_uid: if target {
            "target-rs-one"
        } else {
            "source-rs-one"
        }
        .into(),
        owner_uid: if target {
            "selection-one"
        } else {
            "controller-one"
        }
        .into(),
        node: "node-one".into(),
        pvc_uid: "pvc-one".into(),
        image: generation.image.clone(),
        image_id: format!("docker-pullable://{}", generation.image),
        endpoint: Endpoint {
            ip: if target { "10.0.0.2" } else { "10.0.0.1" }.into(),
            port: 8080,
        },
    }
}

fn healthy(world: &World, n: u64) -> HealthObservation {
    let target = pod(world, true);
    let source = pod(world, false);
    HealthObservation {
        round: n,
        authority: world.release.authority.clone(),
        service: binding().service,
        backend: binding().backend,
        healthy: vec![source.endpoint.clone(), target.endpoint.clone()],
        source: Some(source),
        target,
    }
}

fn verified_probe(release: &mut Release) {
    release.probe = Some(rollout::Probe {
        definition: rollout::ProbeDefinition {
            actor: "alice".into(),
            command: "run".into(),
            input: json!({}),
            query: "read".into(),
            query_input: json!({}),
            expected: json!({}),
        },
        status: rollout::ProbeStatus::Verified,
    });
}

fn promoted(world: &mut World) -> Result<Release> {
    let mut release = rollout::state(&world.db)?.unwrap();
    let tx = world.db.transaction()?;
    handoff::promote_in(&tx, &mut release)?;
    rollout::write(&tx, &release)?;
    tx.commit()?;
    Ok(release)
}

#[test]
fn promotion_is_atomic_and_retains_exact_source_without_transferring_work() -> Result<()> {
    let mut world = bound_world()?;
    let before = rollout::state(&world.db)?.unwrap();
    let source = runtime_generation::expected_id(world.runtime.scope(), &before.source.runtime)?;
    let target = runtime_generation::expected_id(world.runtime.scope(), &before.target.runtime)?;
    {
        let tx = world.db.transaction()?;
        let mut rolled_back = before.clone();
        handoff::promote_in(&tx, &mut rolled_back)?;
        rollout::write(&tx, &rolled_back)?;
        runtime_generation::require_active(&tx, &target)?;
    }
    runtime_generation::require_active(&world.db, &source)?;
    assert_eq!(rollout::state(&world.db)?.unwrap(), before);
    let mut release = promoted(&mut world)?;
    runtime_generation::require_active(&world.db, &target)?;
    assert_eq!(
        handoff::retained_source(&world.runtime, &world.db)?,
        Some(source.clone())
    );
    require_executor(
        &world.runtime,
        &world.db,
        &world.selection(ExecutorRole::Source),
        &world.code(ExecutorRole::Source)?,
    )?;
    require_executor(
        &world.runtime,
        &world.db,
        &world.selection(ExecutorRole::Candidate),
        &world.code(ExecutorRole::Candidate)?,
    )?;
    assert!(
        runtime_generation::selected(&world.runtime, &world.db).is_err(),
        "synthetic qualification cannot admit this actual process"
    );
    handoff::promote_in(&world.db, &mut release)?;
    assert_eq!(handoff::source_pending(&world.db, &release)?, 2);
    let foreign: bool = world.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM day2_invocation_runtime WHERE generation!=?1)",
        [&source],
        |r| r.get(0),
    )?;
    assert!(!foreign);
    assert!(
        rollout::transition(
            &world.runtime,
            &release.id,
            Phase::Serving,
            Phase::Aborted,
            &LocalOperator::assert_local("operator")?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn withdrawal_requires_probe_and_exact_fresh_backend_target_observation() -> Result<()> {
    let mut world = bound_world()?;
    let mut release = promoted(&mut world)?;
    round(&mut release, 1);
    let observation = healthy(&world, 1);
    assert!(handoff::withdraw_in(&mut release, observation.clone()).is_err());
    verified_probe(&mut release);
    for field in [
        "round",
        "authority",
        "service",
        "backend",
        "target",
        "healthy",
    ] {
        let mut bad = serde_json::to_value(&observation)?;
        match field {
            "round" => bad["round"] = json!(2),
            "authority" => bad["authority"]["revision"] = json!(2),
            "service" => bad["service"]["uid"] = json!("other-service"),
            "backend" => bad["backend"]["id"] = json!("9999"),
            "target" => {
                bad["target"]["image_id"] =
                    json!(format!("docker-pullable://{}", world.release.source.image))
            }
            "healthy" => bad["healthy"] = json!([]),
            _ => unreachable!(),
        }
        let before = release.clone();
        assert!(
            handoff::withdraw_in(
                &mut release,
                crate::json::decode(&serde_json::to_vec(&bad)?)?
            )
            .is_err(),
            "{field}"
        );
        assert_eq!(release, before);
    }
    handoff::withdraw_in(&mut release, observation.clone())?;
    let after = release.clone();
    handoff::withdraw_in(&mut release, observation)?;
    assert_eq!(release, after);
    assert_eq!(release.phase, Phase::Draining);
    Ok(())
}

#[test]
fn source_quiescence_and_retirement_wait_for_lb_drain_and_only_source_backlog() -> Result<()> {
    let mut world = bound_world()?;
    let mut release = promoted(&mut world)?;
    verified_probe(&mut release);
    round(&mut release, 1);
    handoff::withdraw_in(&mut release, healthy(&world, 1))?;
    rollout::write(&world.db, &release)?;
    let source = runtime_generation::expected_id(world.runtime.scope(), &release.source.runtime)?;
    handoff::require_root_admission(&world.runtime, &world.db, &source)?;
    round(&mut release, 2);
    let mut drain = DrainObservation {
        health: healthy(&world, 2),
        absent: vec![pod(&world, false).endpoint],
        elapsed_ms: 29_999,
        source_inflight: 1,
        source_streams: 0,
        source_stopped: false,
    };
    drain.health.healthy = vec![drain.health.target.endpoint.clone()];
    assert!(handoff::quiesce_in(&mut release, drain.clone()).is_err());
    drain.elapsed_ms = 30_000;
    assert!(handoff::quiesce_in(&mut release, drain.clone()).is_err());
    drain.source_inflight = 0;
    let mut missing = drain.clone();
    missing.absent.clear();
    assert!(handoff::quiesce_in(&mut release, missing).is_err());
    handoff::quiesce_in(&mut release, drain)?;
    rollout::write(&world.db, &release)?;
    assert!(handoff::require_root_admission(&world.runtime, &world.db, &source).is_err());
    require_executor(
        &world.runtime,
        &world.db,
        &world.selection(ExecutorRole::Source),
        &world.code(ExecutorRole::Source)?,
    )?;
    round(&mut release, 3);
    let mut stopped = match &handoff::handoff(&release)?.stage {
        HandoffStage::Quiesced { drain, .. } => (**drain).clone(),
        _ => anyhow::bail!("missing quiescence"),
    };
    stopped.health = healthy(&world, 3);
    stopped.health.healthy = vec![stopped.health.target.endpoint.clone()];
    stopped.source_stopped = true;
    stopped.source_inflight = 0;
    stopped.source_streams = 0;
    handoff::acknowledge_stop_in(&mut release, stopped)?;
    let mut health = healthy(&world, 3);
    health.target.owner_uid = "controller-one".into();
    health.source = None;
    let adoption = AdoptionObservation {
        health,
        controller: ResourceIdentity {
            name: "app".into(),
            uid: "controller-one".into(),
        },
        template: binding().target_template,
        source_pods: 0,
        source_inflight: 0,
        source_streams: 0,
        source_stopped: true,
    };
    assert!(handoff::complete_in(&world.db, &mut release, adoption.clone()).is_err());
    world.db.execute(
        "UPDATE day2_invocations SET status='success' WHERE id IN ('parent','child')",
        [],
    )?;
    let target = runtime_generation::expected_id(world.runtime.scope(), &release.target.runtime)?;
    let tx = world.db.transaction()?;
    tx.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES('target-new','run','alice','{}',?1,1,'pending')",[world.runtime.artifact().id()])?;
    authority_state::pin_invocation(&tx, "target-new", &release.authority)?;
    tx.execute(
        "INSERT INTO day2_invocation_runtime VALUES('target-new',?1)",
        [&target],
    )?;
    tx.commit()?;
    handoff::complete_in(&world.db, &mut release, adoption.clone())?;
    handoff::complete_in(&world.db, &mut release, adoption)?;
    rollout::write(&world.db, &release)?;
    assert_eq!(release.phase, Phase::Complete);
    runtime_generation::require_active(&world.db, &target)?;
    assert_eq!(handoff::retained_source(&world.runtime, &world.db)?, None);
    assert!(
        require_executor(
            &world.runtime,
            &world.db,
            &world.selection(ExecutorRole::Source),
            &world.code(ExecutorRole::Source)?
        )
        .is_err()
    );
    require_executor(
        &world.runtime,
        &world.db,
        &world.selection(ExecutorRole::Candidate),
        &world.code(ExecutorRole::Candidate)?,
    )?;
    let owners: Vec<String> = world
        .db
        .prepare(
            "SELECT generation FROM day2_invocation_runtime WHERE invocation IN ('parent','child')",
        )?
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    assert_eq!(owners, vec![source.clone(), source]);
    Ok(())
}

#[test]
fn policy_revision_fences_old_work_without_discarding_promoted_executors() -> Result<()> {
    let mut world = bound_world()?;
    let mut release = promoted(&mut world)?;
    let before = authority_state::current(&world.db)?;
    let tx = world.db.transaction()?;
    tx.execute("UPDATE day2_authority SET revision=2", [])?;
    let next = authority_state::current(&tx)?;
    rollout::authority_changed(&tx, Some(&before), &next)?;
    tx.commit()?;
    release.authority.revision = 2;
    assert_eq!(rollout::state(&world.db)?.unwrap(), release);
    assert_eq!(handoff::source_pending(&world.db, &release)?, 0);
    assert!(handoff::retained_source(&world.runtime, &world.db)?.is_some());
    world.db.execute(
        "DELETE FROM day2_invocation_authority WHERE invocation='parent'",
        [],
    )?;
    assert_eq!(
        handoff::source_pending(&world.db, &release)?,
        1,
        "missing stamps are not known revoked work"
    );
    world.db.execute(
        "DELETE FROM day2_invocation_runtime WHERE invocation='parent'",
        [],
    )?;
    assert!(handoff::source_pending(&world.db, &release).is_err());
    Ok(())
}

#[test]
fn unadmitted_or_mismatched_handoff_journals_never_become_public_admission() -> Result<()> {
    let world = bound_world()?;
    let mut release = rollout::state(&world.db)?.unwrap();
    release.phase = Phase::Serving;
    rollout::write(&world.db, &release)?;
    assert!(rollout::state(&world.db).is_err());
    release.phase = Phase::Prepared;
    release.kind = ReleaseKind::RuntimePair {
        admission: Box::new(super::super::super::tests::review(
            &super::super::super::tests::receipt(),
            &super::super::super::tests::receipt().source,
        )?),
        execution: Execution::Unadmitted,
    };
    release.phase = Phase::Serving;
    rollout::write(&world.db, &release)?;
    assert!(rollout::state(&world.db).is_err());
    world.db.execute("DELETE FROM day2_rollout", [])?;
    assert!(handoff::retained_source(&world.runtime, &world.db)?.is_none());
    Ok(())
}

#[test]
fn identical_code_image_pair_preserves_source_restart_choice_and_explicit_target_role() -> Result<()>
{
    let world = bound_world()?;
    let mut release = rollout::state(&world.db)?.unwrap();
    let source_code = release.source.runtime.code()?;
    let Some(crate::security_admission::Containment::LinuxQualifiedV1 { evidence }) =
        &mut release.target.runtime.containment
    else {
        unreachable!()
    };
    evidence.runtime_supervisor = source_code.supervisor.clone();
    evidence.runtime_sandbox = source_code.sandbox.clone().unwrap();
    let ReleaseKind::RuntimePair { admission, .. } = &mut release.kind else {
        unreachable!()
    };
    let mut receipt = admission.receipt.clone();
    receipt.target.runtime = release.target.runtime.clone();
    **admission = crate::runtime_pair::tests::review(&receipt, &receipt.source)?;
    let target = runtime_generation::register_expected(
        &world.db,
        world.runtime.scope(),
        &release.target.runtime,
    )?;
    let ReleaseKind::RuntimePair {
        execution:
            Execution::Admitted {
                candidate,
                check: Some(check),
                ..
            },
        ..
    } = &mut release.kind
    else {
        unreachable!()
    };
    *candidate = target.clone();
    check.generation = target.clone();
    handoff::promote_in(&world.db, &mut release)?;
    rollout::write(&world.db, &release)?;
    let source = runtime_generation::expected_id(world.runtime.scope(), &release.source.runtime)?;
    assert_eq!(
        runtime_generation::choice_for_test(&world.runtime, &world.db, &source_code)?,
        source
    );
    let (_, selected) = require_executor(
        &world.runtime,
        &world.db,
        &world.selection(ExecutorRole::Candidate),
        &source_code,
    )?;
    assert_eq!(selected, target);
    assert!(
        runtime_generation::bind_admitted(&world.runtime, &world.db, &target).is_err(),
        "data cannot bind this real process to synthetic Linux code"
    );
    Ok(())
}

#[test]
fn helper_loss_cannot_release_a_pending_runtime_handoff_to_backup_or_offline_activation()
-> Result<()> {
    let mut world = bound_world()?;
    let instance = world.runtime.instance_path();
    // The keeper is gone: an ordinary kernel loan is available, but canonical
    // pending admission still excludes a fresh snapshot/maintenance operation.
    drop(crate::deployment::OperationLease::acquire(
        world.runtime.db().parent().unwrap(),
        "app",
    )?);
    assert!(crate::deployment::OperationLease::for_instance(instance, "app").is_err());
    assert!(crate::deployment::require_no_runtime_handoff(instance, "app").is_err());
    let mut release = promoted(&mut world)?;
    rollout::write(&world.db, &release)?;
    assert!(
        crate::deployment::OperationLease::for_instance(world.runtime.instance_path(), "app")
            .is_err()
    );
    // Bad or oversized journal data refuses instead of appearing absent.
    world.db.execute(
        "UPDATE day2_rollout SET release=?1",
        ["x".repeat(2_097_153)],
    )?;
    assert!(
        crate::deployment::OperationLease::for_instance(world.runtime.instance_path(), "app")
            .is_err()
    );
    release.phase = Phase::Prepared;
    if let ReleaseKind::RuntimePair {
        execution: Execution::Admitted {
            handoff: Some(h), ..
        },
        ..
    } = &mut release.kind
    {
        h.stage = Stage::Bound;
    }
    release.phase = Phase::Aborted;
    rollout::write(&world.db, &release)?;
    drop(crate::deployment::OperationLease::for_instance(
        world.runtime.instance_path(),
        "app",
    )?);
    Ok(())
}

#[test]
fn graceful_stop_acknowledgement_is_durable_exact_and_cannot_precede_quiescence() -> Result<()> {
    let mut world = bound_world()?;
    let mut release = promoted(&mut world)?;
    verified_probe(&mut release);
    round(&mut release, 1);
    let mut health = healthy(&world, 1);
    health.healthy = vec![health.target.endpoint.clone()];
    let mut stop = DrainObservation {
        health: health.clone(),
        absent: vec![pod(&world, false).endpoint],
        elapsed_ms: 30_000,
        source_inflight: 0,
        source_streams: 0,
        source_stopped: true,
    };
    assert!(handoff::acknowledge_stop_in(&mut release, stop.clone()).is_err());
    handoff::withdraw_in(&mut release, health)?;
    let mut drain = stop.clone();
    drain.source_stopped = false;
    handoff::quiesce_in(&mut release, drain)?;
    let original = release.clone();
    for invalid in 0..4 {
        let mut value = stop.clone();
        match invalid {
            0 => value.source_stopped = false,
            1 => value.source_inflight = 1,
            2 => value.health.source.as_mut().unwrap().pod.uid = "replacement".into(),
            _ => value.health.round += 1,
        }
        assert!(handoff::acknowledge_stop_in(&mut release, value).is_err());
        assert_eq!(release, original);
    }
    handoff::acknowledge_stop_in(&mut release, stop.clone())?;
    rollout::write(&world.db, &release)?;
    let mut reopened = Connection::open(world.runtime.db())?;
    let tx = reopened.transaction()?;
    let mut restored = rollout::state(&tx)?.unwrap();
    assert!(
        matches!(&handoff::handoff(&restored)?.stage,Stage::Quiesced {drain,..} if drain.source_stopped)
    );
    round(&mut restored, 2);
    stop.health.round = 2;
    handoff::acknowledge_stop_in(&mut restored, stop)?;
    tx.rollback()?;
    Ok(())
}
