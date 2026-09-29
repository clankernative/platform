use day2_control::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    contracts::{BuildProfile, Instance},
    journal::{Claim, Journal, RecoveryMode, RetryDisposition},
    kernel::{FailureCode, Observation, State, VerificationEvidence},
};
use proptest::prelude::*;

fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

fn plan(company: &str, request: &str) -> BuildPlan {
    BuildPlan {
        version: 1,
        company: name(company),
        app: name("links"),
        request: name(request),
        commit: GitOid::try_from("1234567890abcdef1234567890abcdef12345678".to_owned()).unwrap(),
        profile: BuildProfile {
            source: BindingRef::pin(name("github"), &"repository-42").unwrap(),
            builder: BindingRef::pin(name("hosted"), &"runner-v1").unwrap(),
            durability: BindingRef::pin(name("temporal"), &"namespace-one").unwrap(),
            platform: Digest::new(b"platform"),
            recipe: Digest::new(b"recipe"),
        },
    }
}

fn lease(journal: &mut Journal, plan: &BuildPlan, now: u64) -> day2_control::journal::Lease {
    match journal
        .claim(&plan.execution_id().unwrap(), name("worker"), now, 100)
        .unwrap()
    {
        Claim::Acquired(lease) => *lease,
        other => panic!("expected lease, got {other:?}"),
    }
}

fn observation(plan: &BuildPlan, state: &State) -> Observation {
    match state {
        State::Accepted => Observation::Source {
            source: Digest::new(b"source"),
        },
        State::SourceReady { source } => Observation::Verified {
            evidence: VerificationEvidence {
                plan: plan.fingerprint().unwrap(),
                source: source.clone(),
                platform: plan.profile.platform.clone(),
                recipe: plan.profile.recipe.clone(),
                builder: plan.profile.builder.clone(),
                artifact: Digest::new(b"artifact"),
                checks: Digest::new(b"checks"),
                credential_presence: day2_control::kernel::CredentialPresence::Absent,
            },
        },
        State::Verified { evidence, .. } => Observation::Published {
            evidence: evidence.clone(),
            publication: Digest::new(b"check"),
        },
        _ => panic!("terminal state"),
    }
}

#[test]
fn acceptance_outbox_and_receipt_survive_reopen_with_tenant_scoped_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    let first = plan("example", "change-1");
    let second = plan("exampleco", "change-1");
    let id = first.execution_id().unwrap();
    let mut journal = Journal::open(&path).unwrap();
    journal.accept(&first).unwrap();
    journal.accept(&first).unwrap();
    journal.accept(&second).unwrap();
    assert_eq!(journal.event_count(&id).unwrap(), 1);
    assert_eq!(journal.pending_dispatches(32).unwrap().len(), 2);
    let mut changed = first.clone();
    changed.profile.source.revision = Digest::new(b"new-default");
    assert!(journal.accept(&changed).is_err());
    drop(journal);
    let mut journal = Journal::open(&path).unwrap();
    assert_eq!(journal.get(&id).unwrap().plan, first);
    journal.dispatched(&id, "workflow-1", "run-1").unwrap();
    journal.dispatched(&id, "workflow-1", "run-2").unwrap();
    assert!(
        journal
            .dispatched(&id, "different-workflow", "run-3")
            .is_err()
    );
    assert_eq!(
        journal.pending_dispatches(32).unwrap(),
        vec![second.execution_id().unwrap()]
    );
}

#[test]
fn expired_worker_is_fenced_and_completion_is_atomic_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    let plan = plan("example", "change-1");
    let id = plan.execution_id().unwrap();
    journal.accept(&plan).unwrap();
    let old = lease(&mut journal, &plan, 0);
    assert!(matches!(
        journal.claim(&id, name("other"), 99, 100).unwrap(),
        Claim::Busy
    ));
    let new = lease(&mut journal, &plan, 100);
    assert_eq!(new.recovery, RecoveryMode::Reconcile);
    let result = observation(&plan, &old.execution.state);
    assert!(journal.complete(&old, &result, 101).is_err());
    journal.complete(&new, &result, 101).unwrap();
    let count = journal.event_count(&id).unwrap();
    journal.complete(&new, &result, 102).unwrap();
    assert_eq!(count, journal.event_count(&id).unwrap());
    assert!(
        journal
            .complete(
                &new,
                &Observation::Source {
                    source: Digest::new(b"different")
                },
                102
            )
            .is_err()
    );
    assert_eq!(journal.get(&id).unwrap().revision, 1);
}

#[test]
fn stale_or_untrusted_verification_evidence_cannot_advance() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    let plan = plan("example", "change-1");
    journal.accept(&plan).unwrap();
    let first = lease(&mut journal, &plan, 0);
    journal
        .complete(&first, &observation(&plan, &first.execution.state), 1)
        .unwrap();
    let second = lease(&mut journal, &plan, 2);
    let Observation::Verified { evidence } = observation(&plan, &second.execution.state) else {
        unreachable!()
    };
    for field in 0..5 {
        let mut bad = evidence.clone();
        match field {
            0 => bad.plan = Digest::new(b"stale"),
            1 => bad.source = Digest::new(b"stale"),
            2 => bad.platform = Digest::new(b"stale"),
            3 => bad.recipe = Digest::new(b"stale"),
            _ => bad.builder.revision = Digest::new(b"untrusted"),
        }
        assert!(
            journal
                .complete(&second, &Observation::Verified { evidence: bad }, 3)
                .is_err()
        );
        assert_eq!(
            journal.get(&plan.execution_id().unwrap()).unwrap().revision,
            1
        );
    }
    journal
        .complete(&second, &Observation::Verified { evidence }, 3)
        .unwrap();
}

#[test]
fn ambiguous_mutation_never_becomes_a_blind_retry_even_after_cancellation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    let mut journal = Journal::open(&path).unwrap();
    let plan = plan("example", "change-1");
    let id = plan.execution_id().unwrap();
    journal.accept(&plan).unwrap();
    for now in [0, 2] {
        let lease = lease(&mut journal, &plan, now);
        journal
            .complete(&lease, &observation(&plan, &lease.execution.state), now + 1)
            .unwrap();
    }
    let publish = lease(&mut journal, &plan, 4);
    journal
        .defer(&publish, RetryDisposition::Ambiguous, 5)
        .unwrap();
    journal.request_cancel(&id).unwrap();
    drop(journal);
    let mut journal = Journal::open(&path).unwrap();
    let recovery = lease(&mut journal, &plan, 6);
    assert_eq!(recovery.recovery, RecoveryMode::Reconcile);
    assert!(
        journal
            .defer(&recovery, RetryDisposition::NotApplied, 7)
            .is_err()
    );
    journal
        .complete(&recovery, &observation(&plan, &recovery.execution.state), 7)
        .unwrap();
    assert!(matches!(
        journal.get(&id).unwrap().state,
        State::Succeeded { .. }
    ));
}

#[test]
fn cancellation_before_effect_and_rejection_are_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    let first = plan("example", "change-1");
    journal.accept(&first).unwrap();
    journal
        .request_cancel(&first.execution_id().unwrap())
        .unwrap();
    assert!(matches!(
        journal
            .claim(&first.execution_id().unwrap(), name("worker"), 0, 100)
            .unwrap(),
        Claim::Terminal(State::Cancelled)
    ));
    let second = plan("example", "change-2");
    journal.accept(&second).unwrap();
    let claim = lease(&mut journal, &second, 0);
    journal
        .complete(
            &claim,
            &Observation::Rejected {
                code: FailureCode::Denied,
            },
            1,
        )
        .unwrap();
    assert!(matches!(
        journal
            .claim(&second.execution_id().unwrap(), name("worker"), 2, 100)
            .unwrap(),
        Claim::Terminal(State::Failed {
            code: FailureCode::Denied
        })
    ));
}

#[test]
fn instance_selection_is_closed_and_pins_existing_execution() {
    let original = plan("example", "change-1");
    let mut instance = Instance {
        version: 1,
        company: name("example"),
        build_profiles: [(name("default"), original.profile.clone())].into(),
    };
    let accepted = instance
        .plan(
            &name("default"),
            name("links"),
            name("change-1"),
            original.commit.clone(),
        )
        .unwrap();
    instance
        .build_profiles
        .get_mut(&name("default"))
        .unwrap()
        .source
        .revision = Digest::new(b"new-provider");
    assert_eq!(accepted, original);
    assert!(
        instance
            .plan(&name("absent"), name("links"), name("x"), original.commit)
            .is_err()
    );
    let mut json = serde_json::to_value(&instance).unwrap();
    json["arbitrary_command"] = "curl secret".into();
    assert!(serde_json::from_value::<Instance>(json).is_err());
    assert!(serde_json::from_str::<Digest>("\"latest\"").is_err());
    assert!(serde_json::from_str::<Name>("\"../other-company\"").is_err());
    assert!(serde_json::from_str::<GitOid>("\"main\"").is_err());
}

#[test]
fn company_catalog_supports_the_existing_fleet_and_rejects_unbounded_profiles() {
    let profile = plan("example", "fleet").profile;
    let mut instance = Instance {
        version: 1,
        company: name("example"),
        build_profiles: (0..46)
            .map(|index| (name(&format!("app-{index}")), profile.clone()))
            .collect(),
    };
    instance.validate().unwrap();
    for index in 46..1025 {
        instance
            .build_profiles
            .insert(name(&format!("app-{index}")), profile.clone());
    }
    assert!(instance.validate().is_err());
}

#[test]
fn injected_acceptance_and_completion_failures_never_leave_partial_records() {
    for table in ["executions", "outbox", "events"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite");
        let mut journal = Journal::open(&path).unwrap();
        let fault = rusqlite::Connection::open(&path).unwrap();
        fault.execute_batch(&format!("CREATE TRIGGER fault BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        let plan = plan("example", "atomic-accept");
        assert!(journal.accept(&plan).is_err());
        assert!(journal.get(&plan.execution_id().unwrap()).is_err());
        assert!(journal.pending_dispatches(32).unwrap().is_empty());
        assert_eq!(
            journal.event_count(&plan.execution_id().unwrap()).unwrap(),
            0
        );
    }
    for (table, operation) in [
        ("effects", "UPDATE"),
        ("executions", "UPDATE"),
        ("events", "INSERT"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite");
        let mut journal = Journal::open(&path).unwrap();
        let plan = plan("example", "atomic-complete");
        let id = plan.execution_id().unwrap();
        journal.accept(&plan).unwrap();
        let lease = lease(&mut journal, &plan, 0);
        let fault = rusqlite::Connection::open(&path).unwrap();
        fault.execute_batch(&format!("CREATE TRIGGER fault BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'injected'); END;")).unwrap();
        let observation = observation(&plan, &lease.execution.state);
        assert!(journal.complete(&lease, &observation, 1).is_err());
        assert_eq!(journal.get(&id).unwrap().state, State::Accepted);
        assert_eq!(journal.event_count(&id).unwrap(), 2);
        fault.execute_batch("DROP TRIGGER fault").unwrap();
        journal.complete(&lease, &observation, 2).unwrap();
        assert_eq!(journal.get(&id).unwrap().revision, 1);
    }
}

#[test]
fn concurrent_supervisors_share_one_effect_claim() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.sqlite");
    let plan = plan("example", "concurrent");
    let id = plan.execution_id().unwrap();
    Journal::open(&path).unwrap().accept(&plan).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let handles = (0..4)
        .map(|index| {
            let path = path.clone();
            let id = id.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut journal = Journal::open(&path).unwrap();
                barrier.wait();
                matches!(
                    journal
                        .claim(&id, name(&format!("worker-{index}")), 0, 100)
                        .unwrap(),
                    Claim::Acquired(_)
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn outbox_selection_cannot_be_starved_or_redirected_by_another_instance() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = Journal::open(&directory.path().join("journal.sqlite")).unwrap();
    let first = plan("example", "first");
    let mut second = plan("exampleco", "second");
    second.profile.durability.revision = Digest::new(b"other-namespace");
    journal.accept(&first).unwrap();
    journal.accept(&second).unwrap();
    assert_eq!(
        journal
            .pending_for(&first.company, &first.profile.durability, 1)
            .unwrap(),
        vec![first.execution_id().unwrap()]
    );
    assert_eq!(
        journal
            .pending_for(&second.company, &second.profile.durability, 1)
            .unwrap(),
        vec![second.execution_id().unwrap()]
    );
    assert!(
        journal
            .pending_for(&first.company, &second.profile.durability, 1)
            .unwrap()
            .is_empty()
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        rng_seed: proptest::test_runner::RngSeed::Fixed(0xDA72_C101),
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct(concat!(env!("CARGO_MANIFEST_DIR"), "/../../artifacts/control-journal-regressions.txt")))),
        .. ProptestConfig::default()
    })]
    #[test]
    fn seeded_crash_and_duplicate_schedules_preserve_the_reference_transition_order(schedule in prop::collection::vec(0u8..4, 1..40)) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.sqlite");
        let plan = plan("example", "property-run");
        let id = plan.execution_id().unwrap();
        Journal::open(&path).unwrap().accept(&plan).unwrap();
        let mut reference_stage = 0;
        let mut now = 0;
        for action in schedule.into_iter().chain([0, 0, 0]) {
            let mut journal = Journal::open(&path).unwrap();
            prop_assert_eq!(journal.get(&id).unwrap().revision, reference_stage);
            journal.accept(&plan).unwrap();
            match journal.claim(&id, name("worker"), now, 10).unwrap() {
                Claim::Terminal(State::Succeeded { .. }) => { prop_assert_eq!(reference_stage, 3); break; }
                Claim::Acquired(claim) => {
                    if action != 1 {
                        let observation = observation(&plan, &claim.execution.state);
                        journal.complete(&claim, &observation, now + 1).unwrap();
                        reference_stage += 1;
                        if action == 2 { journal.complete(&claim, &observation, now + 2).unwrap(); }
                        prop_assert_eq!(journal.get(&id).unwrap().revision, reference_stage);
                    }
                }
                other => prop_assert!(false, "unexpected {other:?}"),
            }
            now += 20;
        }
        let journal = Journal::open(&path).unwrap();
        prop_assert!(matches!(journal.get(&id).unwrap().state, State::Succeeded { .. }), "expected terminal verified release");
        prop_assert_eq!(journal.get(&id).unwrap().revision, 3);
    }
}
