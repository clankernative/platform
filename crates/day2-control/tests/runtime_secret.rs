#[path = "support/release.rs"]
mod support;

use anyhow::{Result, ensure};
use day2_control::{
    BindingRef, Digest,
    journal::Journal,
    provider_evidence::{DeploymentIncarnation, ReadBarrier, RevisionToken, StateEvidence},
    release::{GitApproval, ReleaseApproval},
    release_execution::{
        Capabilities, ReleaseEffectResult, ReleaseExecutionHost, ReleaseExecutionPlan,
        ReleaseLease, ReleaseObservation, ReleaseObserved, ReleaseOperation, ReleaseProviderFact,
    },
    release_recipe::CompiledReleaseRecipe,
    runtime_secret::{
        ConsumerDrainObservation, ConsumerQuiescenceProof, ConsumerQuiescenceSubject,
        ConsumerStage, ProviderResource, QuiescenceAuthorityDecision, QuiescenceCoverage,
        ResourceScope, RuntimeSecretRejection, SecretVersionKey, VersionState,
    },
    secret_retirement::RetirementPlan,
};
use rusqlite::Connection;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Barrier, Mutex},
};
use support::*;

fn resource(company: &str) -> ProviderResource {
    ProviderResource {
        provider: name("gcp"),
        account: name(&format!("{company}-project")),
        secret: name("shared-runtime-credential"),
    }
}

fn candidate(
    journal: &mut Journal,
    company: &str,
    app: &str,
    revision: u8,
    version: u64,
) -> ReleaseApproval {
    let mut build = plan(company, revision);
    build.app = name(app);
    let mut target = target(company);
    target.app = name(app);
    configure(journal, &target, &build);
    let (artifact, evidence) = succeed(journal, &build);
    let generation = journal.release_state(&target).unwrap().generation;
    let policy = authority(&build).policy;
    let approval = ReleaseApproval {
        target,
        request: name(&format!("release-{revision}")),
        expected_generation: generation,
        build_execution: build.execution_id().unwrap(),
        artifact,
        evidence,
        git: GitApproval {
            source: build.profile.source.clone(),
            commit: build.commit,
            policy,
            receipt: Digest::of(&(company, app, revision)).unwrap(),
            actor: actor("reviewer"),
        },
        secret: day2_control::release::ImmutableSecretRef {
            binding: BindingRef::pin(name(&format!("{app}-secrets")), &(company, app)).unwrap(),
            secret: name(&format!("{app}-password")),
            version: version.try_into().unwrap(),
        },
    };
    journal
        .register_runtime_secret(
            &approval.target,
            &approval.secret,
            &resource(company),
            &actor("operator"),
        )
        .unwrap();
    approval
}

fn retirement(journal: &mut Journal, approval: &ReleaseApproval) -> RetirementPlan {
    let key = journal
        .runtime_secret_binding(&approval.target, &approval.secret)
        .unwrap()
        .key()
        .clone();
    let scope = ResourceScope::from(&approval.target);
    let policy = Digest::new(b"explicit-retirement-policy");
    let authority = journal
        .observe_runtime_secret_authority(
            &key.resource,
            &scope,
            &name("retirement-policy"),
            0,
            &policy,
            &actor("operator"),
        )
        .unwrap();
    RetirementPlan {
        key,
        scope,
        request: name("retire-version"),
        authority_revision: authority.revision,
        policy,
        actor: actor("operator"),
        approval: Digest::new(b"approved-retirement"),
        resources: BindingRef::pin(name("retirement-provider"), &"qualified-test-provider")
            .unwrap(),
        durability: BindingRef::pin(name("temporal"), &"retirement-queue").unwrap(),
        recipe: Digest::new(b"native-retirement-journal-test"),
    }
}

#[derive(Default)]
struct Provider {
    plans: Mutex<BTreeMap<Digest, (ReleaseExecutionPlan, ReleaseApproval)>>,
    deployments: Mutex<BTreeMap<Digest, ReleaseProviderFact>>,
    fenced: Mutex<BTreeSet<Digest>>,
}

fn incarnation(deployment: &ReleaseProviderFact) -> DeploymentIncarnation {
    DeploymentIncarnation {
        controller: deployment.resource.as_str().to_owned().try_into().unwrap(),
        generation: deployment.effect.as_str().to_owned().try_into().unwrap(),
    }
}

impl Provider {
    fn drain(
        &self,
        journal: &mut Journal,
        release: &Digest,
        successor: &Digest,
        key: SecretVersionKey,
    ) -> ConsumerDrainObservation {
        let execution = Digest::of(&("day2-release-workflow-v1", release)).unwrap();
        let deployment = self
            .deployments
            .lock()
            .unwrap()
            .remove(&execution)
            .expect("existing deployment must actually drain");
        // This synthetic provider owns exactly this controller and its one
        // deployment, with no delegated work. Fence before issuing its attestation.
        self.fenced
            .lock()
            .unwrap()
            .insert(deployment.resource.clone());
        let authority = journal
            .observe_quiescence_authority(
                &deployment,
                &name("synthetic-qualification"),
                0,
                &QuiescenceAuthorityDecision::QualifiedTerminatedAndFenced {
                    review: Digest::new(b"synthetic-closed-world-provider-not-cloud-qualification"),
                },
                &actor("fixture-reviewer"),
            )
            .unwrap();
        let subject = ConsumerQuiescenceSubject {
            release: release.clone(),
            key: key.clone(),
            successor: successor.clone(),
            deployment: Digest::of(&deployment).unwrap(),
        };
        let proof = ConsumerQuiescenceProof::TerminatedAndFenced {
            subject: Box::new(subject),
            incarnation: incarnation(&deployment),
            authority,
            fence: "synthetic-no-recreation-fence"
                .to_owned()
                .try_into()
                .unwrap(),
            coverage: QuiescenceCoverage::CompleteDescendantsAndDelegatedWork,
            receipt: Digest::of(&("terminated-and-fenced", release, successor)).unwrap(),
        };
        ConsumerDrainObservation {
            release: release.clone(),
            key,
            successor: successor.clone(),
            deployment,
            proof,
        }
    }
}

impl Capabilities for Provider {
    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        ensure!(
            self.plans.lock().unwrap().get(&plan.execution_id()?)
                == Some(&(plan.clone(), approval.clone())),
            "test provider binding mismatch"
        );
        Ok(())
    }

    fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult> {
        let fact = lease.fact(Digest::new(b"test-provider-readback"))?;
        let outcome = match lease.step.operation {
            ReleaseOperation::PrepareDependency => ReleaseObserved::DependencyPrepared {},
            ReleaseOperation::ObserveSecret => ReleaseObserved::Secret {
                metadata: Some(observation(&lease.approval, 1)),
            },
            ReleaseOperation::PrepareDeployment => {
                ensure!(
                    !self.fenced.lock().unwrap().contains(&fact.resource),
                    "synthetic deployment controller is fenced"
                );
                self.deployments
                    .lock()
                    .unwrap()
                    .insert(lease.execution.id.clone(), fact.clone());
                ReleaseObserved::DeploymentPrepared {
                    incarnation: incarnation(&fact),
                }
            }
            ReleaseOperation::ObserveDeployment => {
                let deployments = self.deployments.lock().unwrap();
                let prepared = deployments.get(&lease.execution.id);
                ReleaseObserved::Deployment {
                    ready: prepared.is_some_and(|prepared| prepared.readiness == fact.readiness),
                    incarnation: incarnation(prepared.expect("prepared deployment")),
                    evidence: StateEvidence::Qualified {
                        revision: RevisionToken::Ordered {
                            stream: fact.resource.clone(),
                            sequence: 1.try_into().unwrap(),
                        },
                        barrier: ReadBarrier {
                            authority: fact.binding.clone(),
                            resource: fact.resource.clone(),
                            after_effect: prepared.map(|prepared| prepared.effect.clone()),
                            receipt: Digest::new(b"synthetic-deployment-readback"),
                        },
                    },
                }
            }
            ReleaseOperation::Activate => anyhow::bail!("activation is a native commit"),
        };
        Ok(ReleaseEffectResult::Observed(Box::new(
            ReleaseObservation { fact, outcome },
        )))
    }
}

fn enroll(
    path: &Path,
    approval: &ReleaseApproval,
    provider: Arc<Provider>,
) -> (ReleaseExecutionHost, Digest, Digest) {
    let mut journal = Journal::open(path).unwrap();
    let approved = journal.approve_release(approval).unwrap();
    let recipe = Arc::new(CompiledReleaseRecipe::installed().unwrap());
    let plan = ReleaseExecutionPlan {
        release: approved.id().clone(),
        recipe: recipe.identity().unwrap(),
        durability: BindingRef::pin(name("temporal"), &"deployment-queue").unwrap(),
        resources: approval.secret.binding.clone(),
        deployment: BindingRef::pin(name("deployment"), &"test-deployment-binding").unwrap(),
        deployment_input: None,
    };
    provider.plans.lock().unwrap().insert(
        plan.execution_id().unwrap(),
        (plan.clone(), approval.clone()),
    );
    let host = ReleaseExecutionHost::new(
        path.to_owned(),
        approval.target.company.clone(),
        name("worker"),
        plan.durability.clone(),
        provider,
        recipe,
    );
    let id = host.accept(&plan).unwrap();
    (host, id, approved.id().clone())
}

fn activate(path: &Path, approval: &ReleaseApproval, provider: Arc<Provider>) -> Digest {
    let (host, id, release) = enroll(path, approval, provider);
    for now in 0..5 {
        host.advance_at(&id, now).unwrap();
    }
    assert_eq!(
        Journal::open(path)
            .unwrap()
            .release_state(&approval.target)
            .unwrap()
            .active
            .unwrap()
            .release,
        release
    );
    release
}

struct DrainFixture {
    directory: tempfile::TempDir,
    journal: Journal,
    approval: ReleaseApproval,
    proof: ConsumerDrainObservation,
}

fn drain_fixture() -> DrainFixture {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let provider = Arc::new(Provider::default());
    let first = candidate(&mut journal, "alpha", "reports", 1, 1);
    let first_release = activate(&path, &first, provider.clone());
    let second = candidate(&mut journal, "alpha", "reports", 2, 2);
    let successor = activate(&path, &second, provider.clone());
    let key = journal.runtime_secret_consumer(&first_release).unwrap().key;
    let proof = provider.drain(&mut journal, &first_release, &successor, key);
    DrainFixture {
        directory,
        journal,
        approval: first,
        proof,
    }
}

fn free_drained_consumer(fixture: &mut DrainFixture) {
    fixture
        .journal
        .observe_runtime_secret_drain(&fixture.proof, &actor("watcher"))
        .unwrap();
    fixture
        .journal
        .release_runtime_secret_rollback(
            &fixture.proof.release,
            &fixture.proof.successor,
            &actor("operator"),
        )
        .unwrap();
    assert_eq!(
        fixture
            .journal
            .runtime_secret_consumer_counts(&fixture.proof.key)
            .unwrap()
            .total(),
        0
    );
}

#[test]
fn observation_only_and_transplanted_quiescence_proofs_cannot_free_consumers() {
    let mut fixture = drain_fixture();
    let mut weak = fixture.proof.clone();
    weak.proof = ConsumerQuiescenceProof::ObservationOnly {
        incarnation: incarnation(&weak.deployment),
        evidence: Digest::new(b"zero-pods-and-api-absence-do-not-prove-quiescence"),
    };
    let mut forged = Vec::from([weak]);
    for field in 0..6 {
        let mut value = fixture.proof.clone();
        let ConsumerQuiescenceProof::TerminatedAndFenced {
            subject,
            incarnation,
            ..
        } = &mut value.proof
        else {
            unreachable!()
        };
        match field {
            0 => subject.release = Digest::new(b"other-release"),
            1 => subject.key.version = 2.try_into().unwrap(),
            2 => subject.successor = Digest::new(b"other-successor"),
            3 => subject.deployment = Digest::new(b"other-deployment"),
            4 => incarnation.controller = "different-controller".to_owned().try_into().unwrap(),
            5 => incarnation.generation = "different-generation".to_owned().try_into().unwrap(),
            _ => unreachable!(),
        }
        forged.push(value);
    }
    for value in forged {
        assert_eq!(
            fixture
                .journal
                .observe_runtime_secret_drain(&value, &actor("watcher"))
                .unwrap_err()
                .downcast_ref::<RuntimeSecretRejection>(),
            Some(&RuntimeSecretRejection::QuiescenceUnproven)
        );
    }
    let mut partial = serde_json::to_value(&fixture.proof).unwrap();
    partial["proof"]["coverage"] = serde_json::json!("visible_pods_only");
    assert!(serde_json::from_value::<ConsumerDrainObservation>(partial).is_err());
    let protected = fixture
        .journal
        .runtime_secret_consumer(&fixture.proof.release)
        .unwrap();
    assert_eq!(protected.stage, ConsumerStage::Draining);
    assert!(protected.rollback_protected);
    free_drained_consumer(&mut fixture);
}

#[test]
fn revocation_reprotects_freed_history_and_replaying_an_old_grant_cannot_restore_it() {
    let mut fixture = drain_fixture();
    free_drained_consumer(&mut fixture);
    let revoked = fixture
        .journal
        .observe_quiescence_authority(
            &fixture.proof.deployment,
            &name("revoke-qualification"),
            1,
            &QuiescenceAuthorityDecision::Revoked,
            &actor("fixture-reviewer"),
        )
        .unwrap();
    assert_eq!(revoked.revision().get(), 2);
    let prior = fixture
        .journal
        .observe_quiescence_authority(
            &fixture.proof.deployment,
            &name("synthetic-qualification"),
            0,
            &QuiescenceAuthorityDecision::QualifiedTerminatedAndFenced {
                review: Digest::new(b"synthetic-closed-world-provider-not-cloud-qualification"),
            },
            &actor("fixture-reviewer"),
        )
        .unwrap();
    assert_eq!(prior.revision().get(), 1);
    assert_eq!(
        fixture
            .journal
            .quiescence_authority(&fixture.proof.deployment)
            .unwrap(),
        Some(revoked)
    );
    let counts = fixture
        .journal
        .runtime_secret_consumer_counts(&fixture.proof.key)
        .unwrap();
    assert_eq!(counts.unproven, 1);
    assert_eq!(counts.total(), 1);
    assert_eq!(
        fixture
            .journal
            .runtime_secret_consumer(&fixture.proof.release)
            .unwrap()
            .stage,
        ConsumerStage::Drained
    );
    assert_eq!(
        fixture
            .journal
            .observe_runtime_secret_drain(&fixture.proof, &actor("watcher"))
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::QuiescenceUnproven)
    );
    assert_eq!(
        fixture
            .journal
            .release_runtime_secret_rollback(
                &fixture.proof.release,
                &fixture.proof.successor,
                &actor("operator")
            )
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::QuiescenceUnproven)
    );

    let connection = Connection::open(fixture.directory.path().join("control.sqlite")).unwrap();
    for sql in [
        "DELETE FROM runtime_secret_quiescence_requests",
        "UPDATE runtime_secret_quiescence_requests SET revision=3",
        "DELETE FROM runtime_secret_deployment_history",
        "UPDATE runtime_secret_deployment_history SET incarnation='forged'",
    ] {
        assert!(connection.execute(sql, []).is_err());
    }
    connection.execute("UPDATE runtime_secret_quiescence_authorities SET body=(SELECT body FROM runtime_secret_quiescence_requests WHERE revision=1)", []).unwrap();
    assert!(
        fixture
            .journal
            .runtime_secret_consumer_counts(&fixture.proof.key)
            .unwrap_err()
            .to_string()
            .contains("revision corruption")
    );
}

#[test]
fn changed_controller_generation_reprotects_consumers_and_stale_identity_cannot_restore_proof() {
    let mut fixture = drain_fixture();
    free_drained_consumer(&mut fixture);
    let original = fixture
        .journal
        .deployment_incarnation(&fixture.proof.deployment)
        .unwrap();
    let replacement = DeploymentIncarnation {
        controller: original.controller.clone(),
        generation: "new-physical-generation".to_owned().try_into().unwrap(),
    };
    fixture
        .journal
        .observe_deployment_incarnation(&fixture.proof.deployment, &replacement, &actor("watcher"))
        .unwrap();
    assert_eq!(
        fixture
            .journal
            .runtime_secret_consumer_counts(&fixture.proof.key)
            .unwrap()
            .unproven,
        1
    );
    assert_eq!(
        fixture
            .journal
            .observe_deployment_incarnation(
                &fixture.proof.deployment,
                &original,
                &actor("stale-watcher")
            )
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::StaleDrain)
    );
    fixture
        .journal
        .observe_quiescence_authority(
            &fixture.proof.deployment,
            &name("new-generation-review"),
            0,
            &QuiescenceAuthorityDecision::QualifiedTerminatedAndFenced {
                review: Digest::new(b"new-synthetic-review"),
            },
            &actor("fixture-reviewer"),
        )
        .unwrap();
    assert_eq!(
        fixture
            .journal
            .runtime_secret_consumer_counts(&fixture.proof.key)
            .unwrap()
            .total(),
        1
    );
    assert_eq!(
        fixture
            .journal
            .observe_runtime_secret_drain(&fixture.proof, &actor("watcher"))
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::QuiescenceUnproven)
    );
    let mut wrong_deployment = fixture.proof.deployment.clone();
    wrong_deployment.binding =
        BindingRef::pin(name("other-provider"), &"different-binding").unwrap();
    assert_eq!(
        fixture
            .journal
            .observe_quiescence_authority(
                &wrong_deployment,
                &name("forged-scope"),
                0,
                &QuiescenceAuthorityDecision::Revoked,
                &actor("fixture-reviewer")
            )
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::StaleDrain)
    );

    let connection = Connection::open(fixture.directory.path().join("control.sqlite")).unwrap();
    connection.execute("UPDATE runtime_secret_deployments SET body=(SELECT body FROM runtime_secret_deployment_history WHERE release=runtime_secret_deployments.release ORDER BY sequence LIMIT 1) WHERE release=?1", [fixture.proof.release.as_str()]).unwrap();
    assert!(
        fixture
            .journal
            .runtime_secret_consumer_counts(&fixture.proof.key)
            .unwrap_err()
            .to_string()
            .contains("incarnation history corruption")
    );
}

#[test]
fn legacy_evidence_schema_is_never_promoted_to_qualified_proof() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let approval = candidate(&mut journal, "alpha", "reports", 1, 1);
    journal.approve_release(&approval).unwrap();
    drop(journal);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("UPDATE runtime_secret_meta SET version=1", [])
        .unwrap();
    assert!(
        Journal::open(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("explicit evidence migration required")
    );
    assert_eq!(
        connection
            .query_row("SELECT version FROM runtime_secret_meta", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM runtime_secret_consumers", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        1
    );
}

#[test]
fn lost_quiescence_after_disable_preserves_physical_result_without_success() {
    use day2_control::{
        provider_evidence::EffectAcknowledgement,
        secret_retirement::{
            Capabilities, Recipe, RetirementEffectResult, RetirementExecutionHost, RetirementLease,
            RetirementObservation, RetirementObserved, RetirementOperation, RetirementPhase,
            RetirementTerminal,
        },
        secret_retirement_recipe::CompiledSecretRetirementRecipe,
    };

    struct RetirementProvider {
        plan: RetirementPlan,
        applied: Mutex<Option<Digest>>,
    }
    impl Capabilities for RetirementProvider {
        fn validate(&self, plan: &RetirementPlan) -> Result<()> {
            ensure!(*plan == self.plan, "test retirement scope mismatch");
            Ok(())
        }
        fn perform(&self, lease: &RetirementLease) -> Result<RetirementEffectResult> {
            let fact = lease.fact(Digest::new(b"physical-disable-readback"))?;
            let revision = RevisionToken::Ordered {
                stream: Digest::of(&self.plan.key)?,
                sequence: 1.try_into()?,
            };
            let outcome = match lease.step.operation {
                RetirementOperation::DisableVersion => {
                    let mut applied = self.applied.lock().unwrap();
                    ensure!(applied.is_none(), "duplicate disable mutation");
                    *applied = Some(lease.effect.clone());
                    RetirementObserved::DisableAcknowledged {
                        acknowledgement: EffectAcknowledgement {
                            effect: lease.effect.clone(),
                            revision,
                            receipt: Digest::new(b"acknowledged-disable"),
                        },
                    }
                }
                RetirementOperation::ObserveDisabled => {
                    let applied = self.applied.lock().unwrap().clone();
                    RetirementObserved::Disabled {
                        disabled: applied.is_some(),
                        evidence: StateEvidence::Qualified {
                            revision,
                            barrier: ReadBarrier {
                                authority: self.plan.resources.clone(),
                                resource: Digest::of(&self.plan.key)?,
                                after_effect: applied,
                                receipt: Digest::new(b"qualified-disabled-state"),
                            },
                        },
                    }
                }
                _ => anyhow::bail!("native step reached provider"),
            };
            Ok(RetirementEffectResult::Observed(RetirementObservation {
                fact,
                outcome,
            }))
        }
    }

    let mut fixture = drain_fixture();
    free_drained_consumer(&mut fixture);
    let recipe = Arc::new(CompiledSecretRetirementRecipe::installed().unwrap());
    let mut plan = retirement(&mut fixture.journal, &fixture.approval);
    plan.recipe = recipe.revision().unwrap();
    let provider = Arc::new(RetirementProvider {
        plan: plan.clone(),
        applied: Mutex::new(None),
    });
    let host = RetirementExecutionHost::new(
        fixture.directory.path().join("control.sqlite"),
        plan.scope.company.clone(),
        name("retirement-worker"),
        plan.durability.clone(),
        provider.clone(),
        recipe,
    );
    let id = host.accept(&plan).unwrap();
    host.advance_at(&id, 0).unwrap();
    host.advance_at(&id, 1).unwrap();
    assert_eq!(
        host.inspect(&id).unwrap().phase,
        RetirementPhase::WaitingDisabled
    );
    assert!(provider.applied.lock().unwrap().is_some());
    fixture
        .journal
        .observe_quiescence_authority(
            &fixture.proof.deployment,
            &name("revoke-after-dispatch"),
            1,
            &QuiescenceAuthorityDecision::Revoked,
            &actor("fixture-reviewer"),
        )
        .unwrap();
    host.advance_at(&id, 2).unwrap();
    host.advance_at(&id, 3).unwrap();
    assert_eq!(
        fixture.journal.runtime_secret_version(&plan.key).unwrap(),
        VersionState::Disabled
    );
    assert_eq!(host.inspect(&id).unwrap().phase, RetirementPhase::Stopped);
    assert_eq!(
        host.inspect(&id).unwrap().terminal,
        Some(RetirementTerminal::AuthorityLost)
    );
    assert_eq!(
        fixture
            .journal
            .runtime_secret_consumer_counts(&plan.key)
            .unwrap()
            .unproven,
        1
    );
}

#[test]
fn two_app_aliases_share_one_physical_version_and_cannot_cross_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let first = candidate(&mut journal, "alpha", "reports", 1, 1);
    let second = candidate(&mut journal, "alpha", "workspace", 1, 1);
    let first_key = journal
        .runtime_secret_binding(&first.target, &first.secret)
        .unwrap()
        .key()
        .clone();
    assert_eq!(
        *journal
            .runtime_secret_binding(&second.target, &second.secret)
            .unwrap()
            .key(),
        first_key
    );
    let mut other = second.target.clone();
    other.company = name("beta");
    assert_eq!(
        journal
            .register_runtime_secret(
                &other,
                &second.secret,
                &first_key.resource,
                &actor("operator")
            )
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::WrongOwner)
    );
    other = second.target.clone();
    other.environment = name("staging");
    assert_eq!(
        journal
            .register_runtime_secret(
                &other,
                &second.secret,
                &first_key.resource,
                &actor("operator")
            )
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::WrongOwner)
    );
    assert_eq!(
        journal
            .register_runtime_secret(
                &first.target,
                &first.secret,
                &ProviderResource {
                    secret: name("different-physical-secret"),
                    ..first_key.resource.clone()
                },
                &actor("operator")
            )
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::BindingConflict)
    );
    assert_eq!(
        Journal::open(&path)
            .unwrap()
            .runtime_secret_binding(&first.target, &first.secret)
            .unwrap()
            .key(),
        &first_key
    );
}

#[test]
fn retirement_barrier_blocks_new_aliases_and_approvals_but_preserves_both_consumers() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("control.sqlite")).unwrap();
    let first = candidate(&mut journal, "alpha", "reports", 1, 1);
    let second = candidate(&mut journal, "alpha", "workspace", 1, 1);
    journal.approve_release(&first).unwrap();
    journal.approve_release(&second).unwrap();
    let later = candidate(&mut journal, "alpha", "reports", 2, 1);
    let plan = retirement(&mut journal, &first);
    journal.accept_secret_retirement(&plan).unwrap();
    assert_eq!(
        journal.runtime_secret_version(&plan.key).unwrap(),
        VersionState::Retiring
    );
    assert_eq!(
        journal
            .runtime_secret_consumer_counts(&plan.key)
            .unwrap()
            .pending,
        2
    );
    assert_eq!(
        journal
            .approve_release(&later)
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::VersionUnavailable)
    );
    let mut alias = first.secret.clone();
    alias.secret = name("another-alias");
    assert_eq!(
        journal
            .register_runtime_secret(
                &first.target,
                &alias,
                &plan.key.resource,
                &actor("operator")
            )
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::VersionUnavailable)
    );
    assert_eq!(
        journal
            .runtime_secret_consumer_counts(&plan.key)
            .unwrap()
            .total(),
        2
    );
}

#[test]
fn admission_and_retirement_race_cannot_lose_a_protected_consumer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let approval = candidate(&mut journal, "alpha", "reports", 1, 1);
    let retirement = retirement(&mut journal, &approval);
    let barrier = Arc::new(Barrier::new(2));
    let first = barrier.clone();
    let first_path = path.clone();
    let admitted = std::thread::spawn(move || {
        let mut journal = Journal::open(&first_path).unwrap();
        first.wait();
        journal.approve_release(&approval)
    });
    let key = retirement.key.clone();
    let retired = std::thread::spawn(move || {
        let mut journal = Journal::open(&path).unwrap();
        barrier.wait();
        journal.accept_secret_retirement(&retirement)
    });
    let admitted = admitted.join().unwrap();
    retired.join().unwrap().unwrap();
    let count = journal
        .runtime_secret_consumer_counts(&key)
        .unwrap()
        .total();
    assert_eq!(count, u64::from(admitted.is_ok()));
    if let Err(error) = admitted {
        assert_eq!(
            error.downcast_ref::<RuntimeSecretRejection>(),
            Some(&RuntimeSecretRejection::VersionUnavailable)
        );
    }
    assert_eq!(
        journal.runtime_secret_version(&key).unwrap(),
        VersionState::Retiring
    );
}

#[test]
fn deployed_consumers_need_exact_drain_and_explicit_rollback_release() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let provider = Arc::new(Provider::default());
    let first = candidate(&mut journal, "alpha", "reports", 1, 1);
    let first_release = activate(&path, &first, provider.clone());
    let second = candidate(&mut journal, "alpha", "reports", 2, 2);
    let second_release = activate(&path, &second, provider.clone());
    let old = journal.runtime_secret_consumer(&first_release).unwrap();
    assert_eq!(old.stage, ConsumerStage::Draining);
    assert!(old.rollback_protected);
    assert_eq!(
        journal
            .release_runtime_secret_rollback(&first_release, &second_release, &actor("operator"))
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::StaleDrain)
    );
    let proof = provider.drain(
        &mut journal,
        &first_release,
        &second_release,
        old.key.clone(),
    );
    let mut forged = proof.clone();
    forged.key.version = 2.try_into().unwrap();
    assert_eq!(
        journal
            .observe_runtime_secret_drain(&forged, &actor("watcher"))
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::StaleDrain)
    );
    let connection = Connection::open(&path).unwrap();
    let execution = Digest::of(&("day2-release-workflow-v1", &first_release)).unwrap();
    connection.execute("UPDATE release_steps SET status='ambiguous',started=1,recovery=1 WHERE execution=?1 AND ordinal=0", [execution.as_str()]).unwrap();
    assert_eq!(
        journal
            .observe_runtime_secret_drain(&proof, &actor("watcher"))
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::UnsettledEffects)
    );
    connection.execute("UPDATE release_steps SET status='complete',recovery=0 WHERE execution=?1 AND ordinal=0", [execution.as_str()]).unwrap();
    journal
        .observe_runtime_secret_drain(&proof, &actor("watcher"))
        .unwrap();
    assert_eq!(
        journal
            .runtime_secret_consumer_counts(&old.key)
            .unwrap()
            .rollback,
        1
    );
    journal
        .release_runtime_secret_rollback(&first_release, &second_release, &actor("operator"))
        .unwrap();
    assert_eq!(
        journal
            .runtime_secret_consumer_counts(&old.key)
            .unwrap()
            .total(),
        0
    );
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM runtime_secret_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    journal
        .observe_runtime_secret_drain(&proof, &actor("watcher"))
        .unwrap();
    journal
        .release_runtime_secret_rollback(&first_release, &second_release, &actor("operator"))
        .unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM runtime_secret_events", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        count
    );
    forged = proof;
    forged.release = second_release.clone();
    assert!(
        journal
            .observe_runtime_secret_drain(&forged, &actor("watcher"))
            .is_err()
    );
    assert_eq!(
        journal
            .runtime_secret_consumer(&second_release)
            .unwrap()
            .stage,
        ConsumerStage::Active
    );
}

#[test]
fn zero_counter_does_not_hide_an_active_consumer_without_immutable_release_proof() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let first = candidate(&mut journal, "alpha", "reports", 1, 1);
    let release = activate(&path, &first, Arc::new(Provider::default()));
    let mut consumer = journal.runtime_secret_consumer(&release).unwrap();
    consumer.stage = ConsumerStage::Abandoned;
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE runtime_secret_consumers SET stage='abandoned',body=?2 WHERE release=?1",
            rusqlite::params![release.as_str(), serde_json::to_string(&consumer).unwrap()],
        )
        .unwrap();
    assert!(
        journal
            .runtime_secret_consumer_counts(&consumer.key)
            .is_err()
    );
}

#[test]
fn readiness_invalidation_cannot_erase_historical_deployment_protection() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let approval = candidate(&mut journal, "alpha", "reports", 1, 1);
    let provider = Arc::new(Provider::default());
    let (host, id, release) = enroll(&path, &approval, provider.clone());
    for now in 0..3 {
        host.advance_at(&id, now).unwrap();
    }
    assert!(journal.release_deployment_fact(&release).unwrap().is_some());
    let mut disabled = observation(&approval, 2);
    disabled.enabled = false;
    journal
        .observe_release_secret(&approval.target, &name("disabled"), 1, &disabled)
        .unwrap();
    host.advance_at(&id, 3).unwrap();
    assert!(journal.release_deployment_fact(&release).unwrap().is_none());
    assert!(provider.deployments.lock().unwrap().contains_key(&id));
    let approved = journal.load_approved_release(&release).unwrap();
    journal
        .cancel_release(&approved, &actor("operator"))
        .unwrap();
    assert_eq!(
        journal
            .abandon_runtime_secret_consumer(&release, &actor("operator"))
            .unwrap_err()
            .downcast_ref::<RuntimeSecretRejection>(),
        Some(&RuntimeSecretRejection::UnsettledEffects)
    );
    assert_eq!(
        journal.runtime_secret_consumer(&release).unwrap().stage,
        ConsumerStage::Pending
    );
}

#[test]
fn audit_is_append_only_and_admission_rolls_back_when_audit_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let approval = candidate(&mut journal, "alpha", "reports", 1, 1);
    let connection = Connection::open(&path).unwrap();
    for sql in [
        "UPDATE runtime_secret_events SET kind='forged'",
        "DELETE FROM runtime_secret_events",
        "INSERT OR REPLACE INTO runtime_secret_events SELECT sequence,resource,'forged',body FROM runtime_secret_events LIMIT 1",
    ] {
        assert!(connection.execute(sql, []).is_err());
    }
    connection.execute_batch("CREATE TRIGGER reject_consumer_audit BEFORE INSERT ON runtime_secret_events WHEN NEW.kind='consumer_reserved' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;").unwrap();
    assert!(journal.approve_release(&approval).is_err());
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM runtime_secret_consumers", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM release_approvals", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn unknown_schema_version_fails_closed_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    drop(Journal::open(&path).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE runtime_secret_meta SET version=999", [])
        .unwrap();
    assert!(Journal::open(&path).is_err());
}

#[test]
fn existing_approvals_without_consumer_registry_require_explicit_migration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let approval = candidate(&mut journal, "alpha", "reports", 1, 1);
    journal.approve_release(&approval).unwrap();
    drop(journal);
    let row: (String, String, String, String) = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT id,target,fingerprint,body FROM release_approvals",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let legacy = directory.path().join("legacy.sqlite");
    let connection = Connection::open(&legacy).unwrap();
    connection.execute_batch("CREATE TABLE release_approvals(id TEXT PRIMARY KEY,target TEXT NOT NULL,fingerprint TEXT NOT NULL,body TEXT NOT NULL);").unwrap();
    connection
        .execute(
            "INSERT INTO release_approvals VALUES(?1,?2,?3,?4)",
            rusqlite::params![row.0, row.1, row.2, row.3],
        )
        .unwrap();
    drop(connection);
    let error = Journal::open(&legacy)
        .err()
        .expect("untracked legacy release must fail closed");
    assert!(
        error
            .to_string()
            .contains("explicit runtime secret consumer migration")
    );
}

#[test]
fn protected_consumer_identity_cannot_be_moved_replaced_or_deleted() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let first = candidate(&mut journal, "alpha", "reports", 1, 1);
    let first_release = activate(&path, &first, Arc::new(Provider::default()));
    let second = candidate(&mut journal, "alpha", "workspace", 1, 2);
    let second_key = journal
        .runtime_secret_binding(&second.target, &second.secret)
        .unwrap()
        .key()
        .clone();
    let first_key = journal.runtime_secret_consumer(&first_release).unwrap().key;
    let connection = Connection::open(&path).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE runtime_secret_consumers SET version=?2 WHERE release=?1",
                rusqlite::params![first_release.as_str(), second_key.id().unwrap().as_str()]
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "UPDATE runtime_secret_consumers SET release=?2 WHERE release=?1",
                rusqlite::params![
                    first_release.as_str(),
                    Digest::new(b"forged-release").as_str()
                ]
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM runtime_secret_consumers WHERE release=?1",
                [first_release.as_str()]
            )
            .is_err()
    );
    assert!(connection.execute("INSERT OR REPLACE INTO runtime_secret_consumers SELECT release,version,stage,rollback,body FROM runtime_secret_consumers WHERE release=?1", [first_release.as_str()]).is_err());
    assert_eq!(
        journal
            .runtime_secret_consumer_counts(&first_key)
            .unwrap()
            .active,
        1
    );
    assert_eq!(
        journal
            .runtime_secret_consumer(&first_release)
            .unwrap()
            .stage,
        ConsumerStage::Active
    );
}

#[test]
fn changing_the_cached_version_flag_cannot_bypass_a_retirement_barrier() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let approval = candidate(&mut journal, "alpha", "reports", 1, 1);
    let plan = retirement(&mut journal, &approval);
    journal.accept_secret_retirement(&plan).unwrap();
    let forged = serde_json::json!({ "key": plan.key, "state": "available", "retirement": null });
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE runtime_secret_versions SET state='available',body=?2 WHERE id=?1",
            rusqlite::params![
                plan.key.id().unwrap().as_str(),
                serde_json::to_string(&forged).unwrap()
            ],
        )
        .unwrap();
    assert!(journal.approve_release(&approval).is_err());
    assert!(journal.runtime_secret_version(&plan.key).is_err());
}
