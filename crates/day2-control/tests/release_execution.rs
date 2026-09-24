#[path = "support/release.rs"]
mod support;

use anyhow::{Result, ensure};
use day2_control::journal::{Journal, RecoveryMode};
use day2_control::provider_evidence::{ReadBarrier, RevisionToken, StateEvidence};
use day2_control::release::{ReleaseApproval, SecretObservation};
use day2_control::release_execution::{
    Capabilities, LEASE_MILLIS, Recipe, ReleaseClaim, ReleaseEffectResult, ReleaseExecutionHost,
    ReleaseExecutionPlan, ReleaseLease, ReleaseObservation, ReleaseObserved, ReleaseOperation,
    ReleasePhase, ReleaseRejection, ReleaseTerminal,
};
use day2_control::release_recipe::CompiledReleaseRecipe;
use day2_control::{BindingRef, Digest};
use rusqlite::Connection;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use support::*;

struct Provider {
    plan: ReleaseExecutionPlan,
    approval: ReleaseApproval,
    secret: Mutex<Option<SecretObservation>>,
    resources: Mutex<BTreeMap<Digest, Option<Digest>>>,
    preparations: Mutex<BTreeMap<Digest, Digest>>,
    writes: Mutex<Vec<Digest>>,
    retry_deployment: AtomicBool,
    unknown_mutation: AtomicBool,
    denied: AtomicBool,
}

impl Capabilities for Provider {
    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        ensure!(!self.denied.load(Ordering::SeqCst), "test provider revoked");
        ensure!(
            plan == &self.plan && approval == &self.approval,
            "test provider scope mismatch"
        );
        Ok(())
    }

    fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult> {
        let fact = lease.fact(Digest::new(b"qualified-test-metadata"))?;
        let outcome = match lease.step.operation {
            ReleaseOperation::PrepareDependency | ReleaseOperation::PrepareDeployment => {
                if self.unknown_mutation.swap(false, Ordering::SeqCst) {
                    return Ok(ReleaseEffectResult::Ambiguous {});
                }
                if lease.step.operation == ReleaseOperation::PrepareDeployment
                    && self.retry_deployment.swap(false, Ordering::SeqCst)
                {
                    return Ok(ReleaseEffectResult::RetryNotApplied {});
                }
                let mut resources = self.resources.lock().unwrap();
                if lease.recovery == RecoveryMode::Reconcile {
                    if resources.get(&fact.resource) != Some(&fact.readiness) {
                        return Ok(ReleaseEffectResult::ReconciledAbsent {
                            fact: Box::new(fact),
                        });
                    }
                } else {
                    resources.insert(fact.resource.clone(), fact.readiness.clone());
                    self.writes.lock().unwrap().push(lease.effect.clone());
                    if lease.step.operation == ReleaseOperation::PrepareDeployment {
                        self.preparations
                            .lock()
                            .unwrap()
                            .insert(fact.resource.clone(), lease.effect.clone());
                    }
                }
                if lease.step.operation == ReleaseOperation::PrepareDependency {
                    ReleaseObserved::DependencyPrepared {}
                } else {
                    ReleaseObserved::DeploymentPrepared {
                        incarnation: incarnation(&lease.effect),
                    }
                }
            }
            ReleaseOperation::ObserveSecret => ReleaseObserved::Secret {
                metadata: self.secret.lock().unwrap().clone(),
            },
            ReleaseOperation::ObserveDeployment => ReleaseObserved::Deployment {
                ready: self.resources.lock().unwrap().get(&fact.resource) == Some(&fact.readiness),
                evidence: StateEvidence::Qualified {
                    revision: RevisionToken::Ordered {
                        stream: fact.resource.clone(),
                        sequence: 1_u64.try_into().unwrap(),
                    },
                    barrier: ReadBarrier {
                        authority: lease.execution.plan.deployment.clone(),
                        resource: fact.resource.clone(),
                        after_effect: self
                            .preparations
                            .lock()
                            .unwrap()
                            .get(&fact.resource)
                            .cloned(),
                        receipt: Digest::new(b"qualified-deployment-read"),
                    },
                },
            },
            ReleaseOperation::Activate => anyhow::bail!("activation must never reach provider"),
        };
        Ok(ReleaseEffectResult::Observed(Box::new(
            ReleaseObservation { fact, outcome },
        )))
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    host: ReleaseExecutionHost,
    recipe: Arc<CompiledReleaseRecipe>,
    provider: Arc<Provider>,
    id: Digest,
}

impl Fixture {
    fn new(secret_ready: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("release.sqlite");
        let mut journal = Journal::open(&path).unwrap();
        configure(&mut journal, &target("alpha"), &plan("alpha", 1));
        let approval = approval(&mut journal, "alpha", 1, 0);
        let approved = journal.approve_release(&approval).unwrap();
        let recipe = Arc::new(CompiledReleaseRecipe::installed().unwrap());
        let plan = ReleaseExecutionPlan {
            release: approved.id().to_owned(),
            recipe: recipe.revision().unwrap(),
            durability: plan("alpha", 1).profile.durability,
            resources: approval.secret.binding.clone(),
            deployment: BindingRef::pin(name("deployment"), &"synthetic-runtime-v1").unwrap(),
        };
        let provider = Arc::new(Provider {
            plan: plan.clone(),
            approval: approval.clone(),
            secret: Mutex::new(secret_ready.then(|| observation(&approval, 1))),
            resources: Mutex::new(BTreeMap::new()),
            preparations: Mutex::new(BTreeMap::new()),
            writes: Mutex::new(vec![]),
            retry_deployment: AtomicBool::new(false),
            unknown_mutation: AtomicBool::new(false),
            denied: AtomicBool::new(false),
        });
        let host = ReleaseExecutionHost::new(
            path.clone(),
            name("alpha"),
            name("host"),
            plan.durability.clone(),
            provider.clone(),
            recipe.clone(),
        );
        let id = host.accept(&plan).unwrap();
        Self {
            _directory: directory,
            path,
            host,
            recipe,
            provider,
            id,
        }
    }

    fn lease(&self, now: u64) -> ReleaseLease {
        let snapshot = self.host.inspect(&self.id).unwrap();
        let request = self.recipe.choose(&snapshot).unwrap();
        match self.host.claim_at(&self.id, &request, now).unwrap() {
            ReleaseClaim::Acquired(lease) => *lease,
            other => panic!("expected lease, got {other:?}"),
        }
    }

    fn until(&self, phase: ReleasePhase, now: &mut u64) {
        for _ in 0..16 {
            if self.host.inspect(&self.id).unwrap().phase == phase {
                return;
            }
            self.host.advance_at(&self.id, *now).unwrap();
            *now += 1;
        }
        panic!("workflow failed to reach {phase:?}");
    }
}

#[test]
fn weak_secret_reads_are_durable_waits_and_cannot_poison_later_qualified_readiness() {
    let fixture = Fixture::new(false);
    fixture.host.advance_at(&fixture.id, 0).unwrap();
    for (index, revision) in [
        RevisionToken::Opaque {
            token: "opaque-weak-read".to_owned().try_into().unwrap(),
        },
        RevisionToken::Ordered {
            stream: Digest::of(&fixture.provider.approval.secret).unwrap(),
            sequence: 999_u64.try_into().unwrap(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let mut weak = observation(&fixture.provider.approval, 999);
        weak.provider_state = StateEvidence::Observed { revision };
        *fixture.provider.secret.lock().unwrap() = Some(weak);
        fixture
            .host
            .advance_at(&fixture.id, index as u64 + 1)
            .unwrap();
        assert_eq!(
            fixture.host.inspect(&fixture.id).unwrap().phase,
            ReleasePhase::WaitingSecret
        );
        let journal = Journal::open(&fixture.path).unwrap();
        assert!(
            journal
                .release_secret_metadata(
                    &fixture.provider.approval.target,
                    &fixture.provider.approval.secret
                )
                .unwrap()
                .is_none()
        );
        assert!(
            journal
                .release_state(&fixture.provider.approval.target)
                .unwrap()
                .active
                .is_none()
        );
    }
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    let weak_records: i64 = Connection::open(&fixture.path).unwrap().query_row(
        "SELECT count(*) FROM release_steps WHERE status='complete' AND json_extract(result,'$.outcome.metadata.provider_state.kind')='observed'",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(weak_records, 2);
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 1));
    fixture.until(ReleasePhase::Active, &mut 3);
}

#[test]
fn contradictory_qualified_secret_invalidates_queued_activation_until_fresh_preparation() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    let writes = fixture.provider.writes.lock().unwrap().len();
    let approval = &fixture.provider.approval;
    let mut conflicting = observation(approval, 1);
    conflicting.enabled = false;
    let mut journal = Journal::open(&fixture.path).unwrap();
    assert!(
        journal
            .observe_release_secret(&approval.target, &name("contradictory"), 1, &conflicting)
            .is_err()
    );
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingSecret
    );
    assert!(
        journal
            .release_state(&approval.target)
            .unwrap()
            .active
            .is_none()
    );
    *fixture.provider.secret.lock().unwrap() = Some(observation(approval, 2));
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), writes + 1);
    fixture.until(ReleasePhase::Active, &mut now);
}

#[test]
fn deployment_readback_requires_qualified_exact_prepared_effect_not_weak_state() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::WaitingDeployment, &mut now);
    let lease = fixture.lease(now);
    let original = fixture.host.perform_at(&lease, now).unwrap();
    let ReleaseEffectResult::Observed(mut weak) = original else {
        panic!("expected deployment read")
    };
    let ReleaseObserved::Deployment { evidence, .. } = &mut weak.outcome else {
        panic!("expected deployment read")
    };
    *evidence = StateEvidence::Observed {
        revision: RevisionToken::Opaque {
            token: "weak-ready".to_owned().try_into().unwrap(),
        },
    };
    fixture
        .host
        .settle_at(&lease, ReleaseEffectResult::Observed(weak), now)
        .unwrap();
    now += 1;
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingDeployment
    );
    let lease = fixture.lease(now);
    let original = fixture.host.perform_at(&lease, now).unwrap();
    for field in 0..3 {
        let ReleaseEffectResult::Observed(mut wrong) = original.clone() else {
            panic!("expected deployment read")
        };
        let ReleaseObserved::Deployment {
            evidence: StateEvidence::Qualified { barrier, .. },
            ..
        } = &mut wrong.outcome
        else {
            panic!("expected qualified deployment read")
        };
        match field {
            0 => barrier.after_effect = Some(Digest::new(b"other-deployment-effect")),
            1 => barrier.resource = Digest::new(b"other-resource"),
            _ => barrier.authority.revision = Digest::new(b"other-authority"),
        }
        let before = fixture.host.inspect(&fixture.id).unwrap();
        let journal = Journal::open(&fixture.path).unwrap();
        let audit = journal
            .release_event_count(&fixture.provider.approval.target)
            .unwrap();
        assert!(
            fixture
                .host
                .settle_at(&lease, ReleaseEffectResult::Observed(wrong), now)
                .is_err()
        );
        assert_eq!(fixture.host.inspect(&fixture.id).unwrap(), before);
        assert_eq!(
            journal
                .release_event_count(&fixture.provider.approval.target)
                .unwrap(),
            audit
        );
    }
    fixture.host.settle_at(&lease, original, now).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::DeploymentReady
    );
    fixture.until(ReleasePhase::Active, &mut (now + 1));
}

#[test]
fn compiled_recipe_waits_reopens_and_uses_distinct_read_steps_before_atomic_activation() {
    let fixture = Fixture::new(false);
    fixture.host.advance_at(&fixture.id, 0).unwrap();
    for now in 1..=3 {
        fixture.host.advance_at(&fixture.id, now).unwrap();
    }
    let snapshot = fixture.host.inspect(&fixture.id).unwrap();
    assert_eq!(snapshot.phase, ReleasePhase::WaitingSecret);
    assert_eq!(snapshot.next_step, 4);
    let connection = Connection::open(&fixture.path).unwrap();
    let (steps, identities): (i64, i64) = connection
        .query_row(
            "SELECT count(*),count(DISTINCT id) FROM release_steps
        WHERE json_extract(request,'$.operation')='observe_secret'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((steps, identities), (3, 3));
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 1));
    let restored = ReleaseExecutionHost::new(
        fixture.path.clone(),
        name("alpha"),
        name("restored"),
        fixture.provider.plan.durability.clone(),
        fixture.provider.clone(),
        Arc::new(CompiledReleaseRecipe::installed().unwrap()),
    );
    assert_eq!(restored.inspect(&fixture.id).unwrap(), snapshot);
    for now in 4..=7 {
        restored.advance_at(&fixture.id, now).unwrap();
    }
    assert_eq!(
        restored.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::Activated)
    );
    let journal = Journal::open(&fixture.path).unwrap();
    assert_eq!(
        journal
            .release_state(&fixture.provider.approval.target)
            .unwrap()
            .active
            .unwrap()
            .artifact,
        fixture.provider.approval.artifact
    );
    let (activation, completion): (i64, i64) = connection
        .query_row(
            "SELECT
        (SELECT count(*) FROM release_events WHERE kind='activated'),
        (SELECT count(*) FROM release_events WHERE kind='workflow_completed_step'
            AND json_extract(body,'$[1][2].terminal')='activated')",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((activation, completion), (1, 1));
}

#[test]
fn lost_ack_reconciles_same_step_and_forged_recovery_or_expired_dispatch_is_fenced() {
    let fixture = Fixture::new(true);
    let old = fixture.lease(0);
    let result = fixture.host.perform_at(&old, 1).unwrap();
    assert!(fixture.host.perform_at(&old, 2).is_err());
    assert!(
        fixture
            .host
            .settle_at(&old, result.clone(), LEASE_MILLIS)
            .is_err()
    );
    let recovered = fixture.lease(LEASE_MILLIS);
    assert_eq!(recovered.effect, old.effect);
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    let mut forged = recovered.clone();
    forged.recovery = RecoveryMode::Execute;
    assert_eq!(
        fixture
            .host
            .perform_at(&forged, LEASE_MILLIS + 1)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
    let actual = fixture
        .host
        .perform_at(&recovered, LEASE_MILLIS + 1)
        .unwrap();
    assert_eq!(
        fixture
            .host
            .settle_at(
                &forged,
                ReleaseEffectResult::RetryNotApplied {},
                LEASE_MILLIS + 2
            )
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
    assert_eq!(
        fixture
            .host
            .settle_at(
                &recovered,
                ReleaseEffectResult::RetryNotApplied {},
                LEASE_MILLIS + 2
            )
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::UncertainMutation)
    );
    fixture
        .host
        .settle_at(&recovered, actual, LEASE_MILLIS + 2)
        .unwrap();
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    let expired = fixture.lease(LEASE_MILLIS + 3);
    assert_eq!(
        fixture
            .host
            .perform_at(&expired, expired.until)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
}

#[test]
fn crash_before_dispatch_is_proven_unapplied_and_reclaims_execute_without_blind_reconciliation() {
    let fixture = Fixture::new(true);
    let old = fixture.lease(0);
    let restored = fixture.lease(LEASE_MILLIS);
    assert_eq!(restored.effect, old.effect);
    assert_eq!(restored.recovery, RecoveryMode::Execute);
    assert_eq!(
        fixture
            .host
            .perform_at(&old, LEASE_MILLIS + 1)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::FencedLease)
    );
    let result = fixture
        .host
        .perform_at(&restored, LEASE_MILLIS + 1)
        .unwrap();
    fixture
        .host
        .settle_at(&restored, result, LEASE_MILLIS + 2)
        .unwrap();
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
}

#[test]
fn wrong_provider_facts_never_advance_and_binding_revocation_does_not_erase_inflight_receipt() {
    let fixture = Fixture::new(true);
    let lease = fixture.lease(0);
    let ReleaseEffectResult::Observed(valid) = fixture.host.perform_at(&lease, 1).unwrap() else {
        panic!("observation")
    };
    for field in 0..8 {
        let mut invalid = valid.clone();
        match field {
            0 => invalid.fact.target.company = name("beta"),
            1 => invalid.fact.artifact = Digest::new(b"wrong"),
            2 => invalid.fact.binding.revision = Digest::new(b"wrong"),
            3 => invalid.fact.secret.version = 2.try_into().unwrap(),
            4 => invalid.fact.resource = Digest::new(b"wrong"),
            5 => invalid.fact.plan = Digest::new(b"wrong"),
            6 => invalid.fact.effect = Digest::new(b"wrong"),
            _ => invalid.fact.readiness = Some(Digest::new(b"wrong")),
        }
        assert_eq!(
            fixture
                .host
                .settle_at(&lease, ReleaseEffectResult::Observed(invalid), 2)
                .unwrap_err()
                .downcast_ref::<ReleaseRejection>(),
            Some(&ReleaseRejection::InvalidFact)
        );
    }
    fixture.provider.denied.store(true, Ordering::SeqCst);
    fixture
        .host
        .settle_at(&lease, ReleaseEffectResult::Observed(valid), 2)
        .unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingSecret
    );
}

#[test]
fn superseded_provider_read_is_recorded_then_stopped_without_a_new_mutation() {
    let fixture = Fixture::new(true);
    fixture.host.advance_at(&fixture.id, 0).unwrap();
    let read = fixture.lease(1);
    let result = fixture.host.perform_at(&read, 2).unwrap();
    let mut journal = Journal::open(&fixture.path).unwrap();
    let successor = approval(&mut journal, "alpha", 2, 1);
    journal.approve_release(&successor).unwrap();
    let mut wrong_reference = result.clone();
    if let ReleaseEffectResult::Observed(observation) = &mut wrong_reference
        && let ReleaseObserved::Secret {
            metadata: Some(metadata),
        } = &mut observation.outcome
    {
        metadata.reference.version = 2.try_into().unwrap();
    } else {
        panic!("expected secret metadata");
    }
    assert_eq!(
        fixture
            .host
            .settle_at(&read, wrong_reference, 3)
            .unwrap_err()
            .downcast_ref::<ReleaseRejection>(),
        Some(&ReleaseRejection::InvalidFact)
    );
    fixture.host.settle_at(&read, result, 3).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::AuthorityLost)
    );
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    assert_eq!(
        journal.release_state(&successor.target).unwrap().active,
        None
    );
    let connection = Connection::open(&fixture.path).unwrap();
    let complete: i64 = connection
        .query_row(
            "SELECT count(*) FROM release_steps WHERE status='complete'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(complete, 2);
}

#[test]
fn changed_guard_between_claim_and_dispatch_never_calls_provider() {
    let fixture = Fixture::new(true);
    let lease = fixture.lease(0);
    let mut journal = Journal::open(&fixture.path).unwrap();
    let approved = journal
        .load_approved_release(&fixture.provider.plan.release)
        .unwrap();
    journal
        .revoke_release(&approved, &actor("reviewer"))
        .unwrap();
    let result = fixture.host.perform_at(&lease, 1).unwrap();
    assert_eq!(result, ReleaseEffectResult::GuardChanged {});
    fixture.host.settle_at(&lease, result, 2).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::AuthorityLost)
    );
    assert!(fixture.provider.writes.lock().unwrap().is_empty());
}

#[test]
fn secret_invalidation_retires_unapplied_step_then_requires_fresh_deployment_generation() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::SecretReady, &mut now);
    fixture
        .provider
        .retry_deployment
        .store(true, Ordering::SeqCst);
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    let old_ordinal = fixture.host.inspect(&fixture.id).unwrap().next_step;
    let mut journal = Journal::open(&fixture.path).unwrap();
    let mut disabled = observation(&fixture.provider.approval, 2);
    disabled.enabled = false;
    journal
        .observe_release_secret(
            &fixture.provider.approval.target,
            &name("disabled"),
            1,
            &disabled,
        )
        .unwrap();
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    let waiting = fixture.host.inspect(&fixture.id).unwrap();
    assert_eq!(waiting.phase, ReleasePhase::WaitingSecret);
    assert_eq!(waiting.next_step, old_ordinal + 1);
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 3));
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    let prior_preparation = fixture.provider.resources.lock().unwrap().clone();
    let mut disabled = observation(&fixture.provider.approval, 4);
    disabled.access_granted = false;
    journal
        .observe_release_secret(
            &fixture.provider.approval.target,
            &name("access-lost"),
            3,
            &disabled,
        )
        .unwrap();
    fixture.host.advance_at(&fixture.id, now).unwrap();
    now += 1;
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::WaitingSecret
    );
    *fixture.provider.secret.lock().unwrap() = Some(observation(&fixture.provider.approval, 5));
    fixture.until(ReleasePhase::Active, &mut now);
    assert_ne!(
        *fixture.provider.resources.lock().unwrap(),
        prior_preparation
    );
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 3);
}

#[test]
fn enrolled_release_cannot_bypass_deployment_and_activation_failure_rolls_back_workflow_together() {
    let fixture = Fixture::new(true);
    let mut now = 0;
    fixture.until(ReleasePhase::DeploymentReady, &mut now);
    let mut journal = Journal::open(&fixture.path).unwrap();
    let approved = journal
        .load_approved_release(&fixture.provider.plan.release)
        .unwrap();
    let ready = journal.prepare_release(&approved).unwrap();
    assert!(journal.activate_release(&ready).is_err());
    let lease = fixture.lease(now);
    let result = fixture.host.perform_at(&lease, now + 1).unwrap();
    let connection = Connection::open(&fixture.path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_workflow_completion BEFORE INSERT ON release_events
        WHEN NEW.kind='workflow_completed_step' BEGIN SELECT RAISE(ABORT,'test workflow audit outage'); END;").unwrap();
    assert!(
        fixture
            .host
            .settle_at(&lease, result.clone(), now + 2)
            .is_err()
    );
    assert_eq!(
        journal
            .release_state(&fixture.provider.approval.target)
            .unwrap()
            .active,
        None
    );
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().phase,
        ReleasePhase::DeploymentReady
    );
    connection
        .execute_batch("DROP TRIGGER fail_workflow_completion;")
        .unwrap();
    fixture.host.settle_at(&lease, result, now + 2).unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::Activated)
    );
    assert!(journal.activate_release(&ready).is_err());
}

#[test]
fn strict_provider_result_contract_rejects_payload_on_empty_variants() {
    for kind in [
        "retry_not_applied",
        "ambiguous",
        "activate",
        "guard_changed",
    ] {
        assert!(
            serde_json::from_value::<ReleaseEffectResult>(
                serde_json::json!({"kind":kind,"unexpected":true})
            )
            .is_err()
        );
    }
    for kind in ["dependency_prepared", "deployment_prepared"] {
        assert!(
            serde_json::from_value::<ReleaseObserved>(
                serde_json::json!({"kind":kind,"unexpected":true})
            )
            .is_err()
        );
    }
}

#[test]
fn contradictory_persisted_phase_or_success_without_authority_receipt_is_rejected() {
    let fixture = Fixture::new(true);
    let connection = Connection::open(&fixture.path).unwrap();
    let original: String = connection
        .query_row(
            "SELECT body FROM release_workflows WHERE id=?1",
            [fixture.id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    for field in 0..4 {
        let mut body: serde_json::Value = serde_json::from_str(&original).unwrap();
        match field {
            0 => body["snapshot"]["terminal"] = serde_json::json!("activated"),
            1 => body["snapshot"]["phase"] = serde_json::json!("deployment_ready"),
            2 => body["snapshot"]["phase"] = serde_json::json!("stopped"),
            _ => body["snapshot"]["phase"] = serde_json::json!("secret_ready"),
        }
        connection
            .execute(
                "UPDATE release_workflows SET body=?1 WHERE id=?2",
                rusqlite::params![serde_json::to_string(&body).unwrap(), fixture.id.as_str()],
            )
            .unwrap();
        assert!(fixture.host.inspect(&fixture.id).is_err());
    }
    connection
        .execute(
            "UPDATE release_workflows SET body=?1 WHERE id=?2",
            rusqlite::params![original, fixture.id.as_str()],
        )
        .unwrap();
    let mut now = 0;
    fixture.until(ReleasePhase::Active, &mut now);
    let (mut body, original): (serde_json::Value, String) = {
        let original: String = connection
            .query_row(
                "SELECT body FROM release_workflows WHERE id=?1",
                [fixture.id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        (serde_json::from_str(&original).unwrap(), original)
    };
    body["activation"]["artifact"] = serde_json::to_value(Digest::new(b"forged-artifact")).unwrap();
    connection
        .execute(
            "UPDATE release_workflows SET body=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&body).unwrap(), fixture.id.as_str()],
        )
        .unwrap();
    assert!(fixture.host.inspect(&fixture.id).is_err());
    connection
        .execute(
            "UPDATE release_workflows SET body=?1 WHERE id=?2",
            rusqlite::params![original, fixture.id.as_str()],
        )
        .unwrap();
    assert_eq!(
        fixture.host.inspect(&fixture.id).unwrap().terminal,
        Some(ReleaseTerminal::Activated)
    );
}

#[test]
fn explicit_absence_evidence_is_durable_before_an_uncertain_mutation_can_execute_again() {
    let fixture = Fixture::new(true);
    fixture
        .provider
        .unknown_mutation
        .store(true, Ordering::SeqCst);
    let first = fixture.lease(0);
    let ambiguous = fixture.host.perform_at(&first, 1).unwrap();
    assert_eq!(ambiguous, ReleaseEffectResult::Ambiguous {});
    fixture.host.settle_at(&first, ambiguous, 2).unwrap();
    let restored = ReleaseExecutionHost::new(
        fixture.path.clone(),
        name("alpha"),
        name("restored"),
        fixture.provider.plan.durability.clone(),
        fixture.provider.clone(),
        Arc::new(CompiledReleaseRecipe::installed().unwrap()),
    );
    let snapshot = restored.inspect(&fixture.id).unwrap();
    let request = fixture.recipe.choose(&snapshot).unwrap();
    let ReleaseClaim::Acquired(reconcile) = restored.claim_at(&fixture.id, &request, 3).unwrap()
    else {
        panic!("reconcile")
    };
    assert_eq!(reconcile.recovery, RecoveryMode::Reconcile);
    let absence = restored.perform_at(&reconcile, 4).unwrap();
    assert!(matches!(
        absence,
        ReleaseEffectResult::ReconciledAbsent { .. }
    ));
    let connection = Connection::open(&fixture.path).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_absence_audit BEFORE INSERT ON release_events
        WHEN NEW.kind='workflow_settlement' AND json_extract(NEW.body,'$[1][1].kind')='reconciled_absent'
        BEGIN SELECT RAISE(ABORT,'test audit unavailable'); END;").unwrap();
    assert!(restored.settle_at(&reconcile, absence.clone(), 5).is_err());
    assert!(matches!(
        restored.claim_at(&fixture.id, &request, 6).unwrap(),
        ReleaseClaim::Busy
    ));
    assert!(fixture.provider.writes.lock().unwrap().is_empty());
    connection
        .execute_batch("DROP TRIGGER reject_absence_audit;")
        .unwrap();
    restored.settle_at(&reconcile, absence.clone(), 7).unwrap();
    let (sequence, body): (i64, String) = connection
        .query_row(
            "SELECT sequence,body FROM release_events
        WHERE kind='workflow_settlement' AND json_extract(body,'$[1][1].kind')='reconciled_absent'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    let persisted: ReleaseEffectResult = serde_json::from_value(body[1][1].clone()).unwrap();
    assert_eq!(persisted, absence);
    let ReleaseClaim::Acquired(retry) = restored.claim_at(&fixture.id, &request, 8).unwrap() else {
        panic!("retry")
    };
    assert_eq!(retry.recovery, RecoveryMode::Execute);
    assert_eq!(retry.effect, first.effect);
    let completed = restored.perform_at(&retry, 9).unwrap();
    restored.settle_at(&retry, completed, 10).unwrap();
    assert_eq!(fixture.provider.writes.lock().unwrap().len(), 1);
    let dispatch: i64 = connection
        .query_row(
            "SELECT max(sequence) FROM release_events WHERE kind='workflow_provider_dispatch'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(sequence < dispatch);
}
