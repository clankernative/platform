use anyhow::Result;
use day2_control::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    contracts::BuildProfile,
    engine::{Capabilities, EffectResult, ExecutionHost, check_publication},
    journal::{
        Claim, CompletionRejection, HostFault, Journal, Lease, RecoveryMode, RetryDisposition,
    },
    kernel::{
        BuildFailureEvidence, EffectKind, FailureCode, Observation, State, VerificationEvidence,
    },
    source::CheckConclusion,
};
use durable_temporal::{AdvanceBackend, BackendError, RuntimeConfig, StepOutcome};
use rusqlite::{Connection, params};
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

fn plan() -> BuildPlan {
    BuildPlan {
        version: 1,
        company: name("example"),
        app: name("links"),
        request: name("guard-regression"),
        commit: GitOid::try_from("1234567890abcdef1234567890abcdef12345678".to_owned()).unwrap(),
        profile: BuildProfile {
            source: BindingRef::pin(name("source"), &"repository-v1").unwrap(),
            builder: BindingRef::pin(name("builder"), &"runner-v1").unwrap(),
            durability: BindingRef::pin(name("temporal"), &"namespace-v1").unwrap(),
            platform: Digest::new(b"platform"),
            recipe: Digest::new(b"recipe"),
        },
    }
}

fn claim(journal: &mut Journal, id: &Digest, now: u64) -> Result<Lease> {
    match journal.claim(id, name("worker"), now, 100)? {
        Claim::Acquired(lease) => Ok(*lease),
        other => anyhow::bail!("expected a lease, got {other:?}"),
    }
}

#[test]
fn acceptance_actor_is_atomic_and_cannot_be_reassigned_by_duplicate_request() -> Result<()> {
    use day2_control::journal::AcceptanceProvenance;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch("CREATE TRIGGER reject_provenance BEFORE INSERT ON execution_acceptance BEGIN SELECT RAISE(ABORT,'injected_failure'); END;")?;
    let plan = plan();
    assert!(journal.accept_as(&plan, "alice@example.com").is_err());
    for table in ["executions", "outbox", "events", "execution_acceptance"] {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        assert_eq!(count, 0);
    }
    connection.execute_batch("DROP TRIGGER reject_provenance")?;
    let id = journal.accept_as(&plan, "alice@example.com")?.id;
    assert_eq!(journal.accept_as(&plan, "alice@example.com")?.id, id);
    assert!(journal.accept_as(&plan, "bob@example.com").is_err());
    assert!(journal.accept(&plan).is_err());
    assert_eq!(journal.event_count(&id)?, 1);
    assert!(
        matches!(journal.accepted_by(&id)?, AcceptanceProvenance::Operator { actor } if actor.as_str() == "alice@example.com")
    );
    connection.execute(
        "DELETE FROM execution_acceptance WHERE execution=?1",
        [id.as_str()],
    )?;
    assert!(journal.accept_as(&plan, "alice@example.com").is_err());
    assert!(journal.accepted_by(&id).is_err());
    Ok(())
}

#[test]
fn platform_host_acceptance_is_explicit_and_actor_input_is_bounded() -> Result<()> {
    use day2_control::journal::AcceptanceProvenance;
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::open(&directory.path().join("journal.sqlite"))?;
    let plan = plan();
    for actor in ["", " ", "bad\nactor"] {
        assert!(journal.accept_as(&plan, actor).is_err());
    }
    let id = journal.accept(&plan)?.id;
    assert_eq!(
        journal.accepted_by(&id)?,
        AcceptanceProvenance::PlatformHost
    );
    assert_eq!(journal.accept(&plan)?.id, id);
    Ok(())
}

#[test]
fn mutable_lease_fields_cannot_erase_persisted_publication_ambiguity() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::open(&directory.path().join("journal.sqlite"))?;
    let plan = plan();
    let id = journal.accept(&plan)?.id;
    let source = Digest::new(b"source-bytes");
    let fetched = claim(&mut journal, &id, 0)?;
    journal.complete(
        &fetched,
        &Observation::Source {
            source: source.clone(),
        },
        1,
    )?;
    let verified = claim(&mut journal, &id, 2)?;
    let evidence = VerificationEvidence {
        plan: plan.fingerprint()?,
        source,
        platform: plan.profile.platform.clone(),
        recipe: plan.profile.recipe.clone(),
        builder: plan.profile.builder.clone(),
        artifact: Digest::new(b"artifact"),
        checks: Digest::new(b"checks"),
    };
    journal.complete(&verified, &Observation::Verified { evidence }, 3)?;
    let first_publish = claim(&mut journal, &id, 4)?;
    journal.defer(&first_publish, RetryDisposition::Ambiguous, 5)?;
    let recovered = claim(&mut journal, &id, 6)?;
    assert_eq!(recovered.kind, EffectKind::PublishCheck);
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    let State::Verified { evidence, .. } = journal.get(&id)?.state else {
        panic!("expected verified state");
    };
    let observed_receipt = Observation::Published {
        evidence,
        publication: Digest::new(b"receipt"),
    };
    let count = journal.event_count(&id)?;
    for mutation in 0..5 {
        let mut forged = recovered.clone();
        match mutation {
            0 => forged.kind = EffectKind::FetchSource,
            1 => forged.recovery = RecoveryMode::Execute,
            2 => {
                forged.kind = EffectKind::FetchSource;
                forged.recovery = RecoveryMode::Execute;
            }
            3 => forged.epoch += 1,
            _ => forged.owner = name("another-worker"),
        }
        assert!(
            journal
                .defer(&forged, RetryDisposition::NotApplied, 7)
                .is_err()
        );
        assert!(journal.complete(&forged, &observed_receipt, 7).is_err());
        assert_eq!(journal.event_count(&id)?, count);
        assert_eq!(journal.get(&id)?.revision, 2);
    }
    assert!(
        journal
            .complete(
                &recovered,
                &Observation::Rejected {
                    code: FailureCode::Permanent
                },
                7
            )
            .is_err(),
        "unknown remote outcome cannot be downgraded to a definitive rejection"
    );
    assert_eq!(journal.event_count(&id)?, count);
    assert!(matches!(
        journal.complete(&recovered, &observed_receipt, 7)?,
        State::Succeeded { .. }
    ));
    Ok(())
}

#[test]
fn journal_reads_and_claims_reject_corrupted_pinned_metadata_with_unchanged_identity() -> Result<()>
{
    for field in 0..6 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let mut journal = Journal::open(&path)?;
        let original = plan();
        let id = journal.accept(&original)?.id;
        let mut changed = original.clone();
        match field {
            0 => {
                changed.commit =
                    GitOid::try_from("abcdef1234567890abcdef1234567890abcdef12".to_owned())?
            }
            1 => changed.profile.source.revision = Digest::new(b"new-source-binding"),
            2 => changed.profile.builder.revision = Digest::new(b"new-builder-binding"),
            3 => changed.profile.durability.revision = Digest::new(b"new-durability-binding"),
            4 => changed.profile.platform = Digest::new(b"new-platform"),
            _ => changed.profile.recipe = Digest::new(b"new-recipe"),
        }
        assert_eq!(
            changed.execution_id()?,
            id,
            "this regression must exercise fingerprint validation, not identity validation"
        );
        assert_ne!(changed.fingerprint()?, original.fingerprint()?);
        let count = journal.event_count(&id)?;
        Connection::open(&path)?.execute(
            "UPDATE executions SET plan=?2 WHERE id=?1",
            params![id.as_str(), serde_json::to_string(&changed)?],
        )?;
        assert!(journal.get(&id).is_err());
        assert!(journal.claim(&id, name("worker"), 0, 100).is_err());
        assert!(journal.accept(&original).is_err());
        assert_eq!(journal.event_count(&id)?, count);
    }
    Ok(())
}

#[test]
fn legacy_journal_layout_is_not_silently_upgraded() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    drop(Journal::open(&path)?);
    Connection::open(&path)?.execute("UPDATE control_meta SET version=1 WHERE singleton=1", [])?;
    assert!(Journal::open(&path).is_err());
    let version: i64 = Connection::open(&path)?.query_row(
        "SELECT version FROM control_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 1);
    Ok(())
}

struct FaultCapabilities {
    mode: u8,
    calls: AtomicUsize,
}

impl Capabilities for FaultCapabilities {
    fn validate(&self, _plan: &BuildPlan) -> Result<()> {
        if self.mode == 0 {
            anyhow::bail!("sensitive-provider-token-in-validation-error");
        }
        Ok(())
    }

    fn perform(&self, _lease: &Lease) -> Result<EffectResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            3 => anyhow::bail!("sensitive-provider-token-in-transport-error"),
            4 => Ok(EffectResult::Completed(Observation::Published {
                evidence: Digest::new(b"not-verified"),
                publication: Digest::new(b"not-published"),
            })),
            _ => Ok(EffectResult::Completed(Observation::Source {
                source: Digest::new(b"source"),
            })),
        }
    }
}

fn runtime() -> RuntimeConfig {
    RuntimeConfig {
        endpoint: "http://127.0.0.1:12345".to_owned(),
        namespace: "unit-test-only".to_owned(),
        task_queue: "unit-test-only".to_owned(),
        workflow_contract_version: 1,
        sdk_version: "1.0.0".to_owned(),
        execution_timeout_seconds: 3600,
        activity_timeout_seconds: 900,
    }
}

#[test]
fn host_faults_are_redacted_bounded_and_preserve_uncertain_leases() -> Result<()> {
    let cases = [
        HostFault::CapabilityBinding,
        HostFault::Clock,
        HostFault::Claim,
        HostFault::Capability,
        HostFault::Completion,
        HostFault::Clock,
    ];
    for (mode, expected) in cases.into_iter().enumerate() {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let mut plan = plan();
        plan.profile.durability = BindingRef::pin(name("temporal"), &runtime())?;
        let id = Journal::open(&path)?.accept(&plan)?.id;
        let capabilities = Arc::new(FaultCapabilities {
            mode: mode as u8,
            calls: AtomicUsize::new(0),
        });
        let host = ExecutionHost::new(
            path.clone(),
            plan.company.clone(),
            name("worker"),
            plan.profile.durability.clone(),
            capabilities.clone(),
        );
        let reads = Cell::new(0);
        let error = host
            .advance_with_clock(&id, || {
                let read = reads.get();
                reads.set(read + 1);
                match mode {
                    1 => anyhow::bail!("sensitive-provider-token-in-clock-error"),
                    2 => Ok(u64::MAX),
                    5 if read > 0 => anyhow::bail!("sensitive-provider-token-after-effect"),
                    _ => Ok(0),
                }
            })
            .unwrap_err();
        assert_eq!(error.downcast_ref::<HostFault>(), Some(&expected));
        assert!(!format!("{error:#}").contains("sensitive-provider-token"));
        let mut journal = Journal::open(&path)?;
        let before_repeated_faults = journal.event_count(&id)?;
        for _ in 0..32 {
            journal.record_fault(&id, expected)?;
        }
        assert_eq!(journal.event_count(&id)?, before_repeated_faults);
        let (count, body): (i64, String) = Connection::open(&path)?.query_row(
            "SELECT COUNT(*), body FROM events WHERE execution=?1 AND kind='host_fault'",
            [id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(count, 1);
        assert_eq!(serde_json::from_str::<HostFault>(&body)?, expected);
        assert!(!body.contains("sensitive-provider-token"));
        assert!(matches!(journal.get(&id)?.state, State::Accepted));
        assert_eq!(journal.get(&id)?.revision, 0);
        if mode >= 3 {
            assert_eq!(capabilities.calls.load(Ordering::SeqCst), 1);
            let recovered = claim(&mut journal, &id, 1_200_001)?;
            assert_eq!(
                recovered.recovery,
                RecoveryMode::Reconcile,
                "host failure must not pretend the attempted effect was unapplied"
            );
        } else {
            assert_eq!(capabilities.calls.load(Ordering::SeqCst), 0);
        }
    }
    Ok(())
}

#[test]
fn backend_rejection_cannot_emit_cross_company_or_wrong_runtime_diagnostics() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut plan = plan();
    plan.profile.durability = BindingRef::pin(name("temporal"), &runtime())?;
    let id = Journal::open(&path)?.accept(&plan)?.id;
    let capabilities = Arc::new(FaultCapabilities {
        mode: 0,
        calls: AtomicUsize::new(0),
    });
    let wrong_company = ExecutionHost::new(
        path.clone(),
        name("another-company"),
        name("worker"),
        plan.profile.durability.clone(),
        capabilities.clone(),
    );
    assert_eq!(
        wrong_company.advance(id.as_str(), &runtime()),
        Err(BackendError::Rejected)
    );
    let host = ExecutionHost::new(
        path.clone(),
        plan.company.clone(),
        name("worker"),
        plan.profile.durability.clone(),
        capabilities,
    );
    let mut changed = runtime();
    changed.namespace = "other-namespace".to_owned();
    assert_eq!(
        host.advance(id.as_str(), &changed),
        Err(BackendError::Rejected)
    );
    assert_eq!(Journal::open(&path)?.event_count(&id)?, 1);
    assert_eq!(
        host.advance(id.as_str(), &runtime()),
        Err(BackendError::Rejected)
    );
    assert_eq!(
        Journal::open(&path)?.event_count(&id)?,
        2,
        "an authorized execution records the capability validation failure"
    );
    let other_plan = BuildPlan {
        request: name("unavailable-provider"),
        ..plan.clone()
    };
    let other_id = Journal::open(&path)?.accept(&other_plan)?.id;
    let failing = ExecutionHost::new(
        path.clone(),
        plan.company,
        name("worker"),
        plan.profile.durability,
        Arc::new(FaultCapabilities {
            mode: 3,
            calls: AtomicUsize::new(0),
        }),
    );
    assert_eq!(
        failing.advance(other_id.as_str(), &runtime()),
        Err(BackendError::Retryable)
    );
    assert!(matches!(
        Journal::open(&path)?.get(&other_id)?.state,
        State::Accepted
    ));
    Ok(())
}

#[test]
fn separately_scheduled_boundaries_match_the_live_driver() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let plan = plan();
    let mut outcomes = Vec::new();
    for split in [false, true] {
        let path = directory.path().join(format!("journal-{split}.sqlite"));
        let id = Journal::open(&path)?.accept(&plan)?.id;
        let host = ExecutionHost::new(
            path.clone(),
            plan.company.clone(),
            name("worker"),
            plan.profile.durability.clone(),
            Arc::new(FaultCapabilities {
                mode: 1,
                calls: AtomicUsize::new(0),
            }),
        );
        let progress = if split {
            let Claim::Acquired(lease) = host.claim_at(&id, 10)? else {
                anyhow::bail!("expected first claim");
            };
            assert!(matches!(
                Journal::open(&path)?.get(&id)?.state,
                State::Accepted
            ));
            let result = host.perform(&lease)?;
            assert!(matches!(
                Journal::open(&path)?.get(&id)?.state,
                State::Accepted
            ));
            host.settle_at(&lease, result, 10)?
        } else {
            host.advance_at(&id, 10)?
        };
        assert_eq!(progress, StepOutcome::Continue);
        let journal = Journal::open(&path)?;
        outcomes.push((
            serde_json::to_string(&journal.get(&id)?)?,
            journal.event_count(&id)?,
        ));
    }
    assert_eq!(outcomes[0], outcomes[1]);
    Ok(())
}

#[test]
fn fenced_completion_retains_only_a_typed_redacted_rejection() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let plan = plan();
    let id = Journal::open(&path)?.accept(&plan)?.id;
    let host = ExecutionHost::new(
        path.clone(),
        plan.company.clone(),
        name("worker"),
        plan.profile.durability.clone(),
        Arc::new(FaultCapabilities {
            mode: 1,
            calls: AtomicUsize::new(0),
        }),
    );
    let Claim::Acquired(lease) = host.claim_at(&id, 0)? else {
        anyhow::bail!("expected claim");
    };
    let outcome = host.perform(&lease)?;
    let error = host.settle_at(&lease, outcome, lease.until).unwrap_err();
    assert_eq!(
        error.downcast_ref::<HostFault>(),
        Some(&HostFault::Completion)
    );
    assert_eq!(
        error.downcast_ref::<CompletionRejection>(),
        Some(&CompletionRejection::FencedLease)
    );
    assert!(matches!(
        Journal::open(&path)?.get(&id)?.state,
        State::Accepted
    ));
    Ok(())
}

struct RevocableCapabilities {
    allowed: AtomicBool,
    calls: AtomicUsize,
}

impl Capabilities for RevocableCapabilities {
    fn validate(&self, _plan: &BuildPlan) -> Result<()> {
        anyhow::ensure!(self.allowed.load(Ordering::SeqCst), "binding revoked");
        Ok(())
    }

    fn perform(&self, _lease: &Lease) -> Result<EffectResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(EffectResult::Completed(Observation::Source {
            source: Digest::new(b"source"),
        }))
    }
}

#[test]
fn revoked_binding_blocks_new_provider_work_but_not_recording_an_inflight_outcome() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let plan = plan();
    let id = Journal::open(&path)?.accept(&plan)?.id;
    let capabilities = Arc::new(RevocableCapabilities {
        allowed: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let host = ExecutionHost::new(
        path.clone(),
        plan.company.clone(),
        name("worker"),
        plan.profile.durability.clone(),
        capabilities.clone(),
    );
    let Claim::Acquired(lease) = host.claim_at(&id, 0)? else {
        anyhow::bail!("expected first claim");
    };
    capabilities.allowed.store(false, Ordering::SeqCst);
    assert!(host.perform(&lease).is_err());
    assert_eq!(capabilities.calls.load(Ordering::SeqCst), 0);
    capabilities.allowed.store(true, Ordering::SeqCst);
    let outcome = host.perform(&lease)?;
    capabilities.allowed.store(false, Ordering::SeqCst);
    assert_eq!(host.settle_at(&lease, outcome, 1)?, StepOutcome::Continue);
    assert!(host.claim_at(&id, 2).is_err());
    assert!(matches!(
        Journal::open(&path)?.get(&id)?.state,
        State::SourceReady { .. }
    ));

    let other = ExecutionHost::new(
        path.clone(),
        name("other-company"),
        name("worker"),
        plan.profile.durability.clone(),
        capabilities,
    );
    let event_count = Journal::open(&path)?.event_count(&id)?;
    assert!(other.claim_at(&id, 2).is_err());
    assert!(other.perform(&lease).is_err());
    assert!(other.settle_at(&lease, EffectResult::Ambiguous, 2).is_err());
    assert_eq!(Journal::open(&path)?.event_count(&id)?, event_count);
    Ok(())
}

fn failed_evidence(plan: &BuildPlan, source: &Digest) -> Result<BuildFailureEvidence> {
    Ok(BuildFailureEvidence {
        plan: plan.fingerprint()?,
        source: source.clone(),
        platform: plan.profile.platform.clone(),
        recipe: plan.profile.recipe.clone(),
        builder: plan.profile.builder.clone(),
        checks: Digest::new(b"bound-failed-build-report"),
        code: FailureCode::Contract,
    })
}

#[test]
fn failed_build_evidence_is_bound_and_publication_survives_ambiguity() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path)?;
    let plan = plan();
    let id = journal.accept(&plan)?.id;
    let source = Digest::new(b"source");
    let fetch = claim(&mut journal, &id, 0)?;
    assert!(check_publication(&fetch).is_err());
    journal.complete(
        &fetch,
        &Observation::Source {
            source: source.clone(),
        },
        1,
    )?;
    let verify = claim(&mut journal, &id, 2)?;
    let evidence = failed_evidence(&plan, &source)?;
    for field in 0..5 {
        let mut changed = evidence.clone();
        match field {
            0 => changed.plan = Digest::new(b"other-plan"),
            1 => changed.source = Digest::new(b"other-source"),
            2 => changed.platform = Digest::new(b"other-platform"),
            3 => changed.recipe = Digest::new(b"other-recipe"),
            _ => changed.builder.revision = Digest::new(b"other-builder"),
        }
        assert!(
            journal
                .complete(
                    &verify,
                    &Observation::BuildRejected { evidence: changed },
                    3
                )
                .is_err()
        );
        assert_eq!(journal.get(&id)?.revision, 1);
    }
    let state = journal.complete(&verify, &Observation::BuildRejected { evidence }, 3)?;
    assert!(matches!(
        state,
        State::VerificationFailed {
            code: FailureCode::Contract,
            ..
        }
    ));
    assert_eq!(state.next_effect(), Some(EffectKind::PublishCheck));
    assert_eq!(
        journal.pending_for(&plan.company, &plan.profile.durability, 8)?,
        vec![id.clone()],
        "a lost start acknowledgement must not hide pending failure publication"
    );
    let publish = claim(&mut journal, &id, 4)?;
    let expected = check_publication(&publish)?;
    assert_eq!(expected.conclusion, CheckConclusion::Failure);
    assert_eq!(expected.commit, plan.commit);
    assert_eq!(expected.effect_id, publish.effect);
    assert!(
        journal
            .complete(
                &publish,
                &Observation::Published {
                    evidence: Digest::new(b"other-evidence"),
                    publication: Digest::new(b"receipt"),
                },
                5
            )
            .is_err()
    );
    journal.defer(&publish, RetryDisposition::Ambiguous, 5)?;
    drop(journal);
    let mut journal = Journal::open(&path)?;
    let recovered = claim(&mut journal, &id, 6)?;
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    assert_eq!(check_publication(&recovered)?, expected);
    assert!(
        journal
            .defer(&recovered, RetryDisposition::NotApplied, 7)
            .is_err()
    );
    let state = journal.complete(
        &recovered,
        &Observation::Published {
            evidence: expected.evidence,
            publication: Digest::new(b"receipt"),
        },
        7,
    )?;
    assert_eq!(
        state,
        State::Failed {
            code: FailureCode::Contract
        }
    );
    assert_eq!(state.next_effect(), None);
    assert_eq!(journal.get(&id)?.revision, 3);
    Ok(())
}

struct FailedBuildProvider;

impl Capabilities for FailedBuildProvider {
    fn validate(&self, plan: &BuildPlan) -> Result<()> {
        plan.validate()
    }

    fn perform(&self, lease: &Lease) -> Result<EffectResult> {
        Ok(EffectResult::Completed(match &lease.execution.state {
            State::Accepted => Observation::Source {
                source: Digest::new(b"source"),
            },
            State::SourceReady { source } => Observation::BuildRejected {
                evidence: failed_evidence(&lease.execution.plan, source)?,
            },
            State::VerificationFailed { .. } => {
                let publication = check_publication(lease)?;
                assert_eq!(publication.conclusion, CheckConclusion::Failure);
                Observation::Published {
                    evidence: publication.evidence,
                    publication: Digest::of(&"fake-failure-check")?,
                }
            }
            state => anyhow::bail!("unexpected failed-build fixture state: {state:?}"),
        }))
    }
}

#[test]
fn execution_host_reports_failed_only_after_publishing_failed_build_check() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("journal.sqlite");
    let plan = plan();
    let host = ExecutionHost::new(
        path.clone(),
        plan.company.clone(),
        name("worker"),
        plan.profile.durability.clone(),
        Arc::new(FailedBuildProvider),
    );
    let id = host.accept(&plan)?;
    assert_eq!(host.advance_at(&id, 0)?, StepOutcome::Continue);
    assert_eq!(host.advance_at(&id, 1)?, StepOutcome::Continue);
    assert!(matches!(
        Journal::open(&path)?.get(&id)?.state,
        State::VerificationFailed { .. }
    ));
    assert_eq!(host.advance_at(&id, 2)?, StepOutcome::Failed);
    assert_eq!(
        Journal::open(&path)?.get(&id)?.state,
        State::Failed {
            code: FailureCode::Contract
        }
    );
    Ok(())
}
