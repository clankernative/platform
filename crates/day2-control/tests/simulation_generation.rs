use anyhow::Result;
use day2_control::simulation::{
    self, Fault, ReadSelection, ReadStrength,
    coverage::{Coverage, Transition},
    generation::{
        self, BuildId, Intent, InvalidAttempt, Program, ScheduleChoice, SecretVersionId, TenantId,
        WorkerId,
    },
    shrink::{FailureFingerprint, ShrinkBudget, check_and_persist, minimize},
};
use proptest::{prelude::*, test_runner::RngSeed};
use std::{cell::Cell, path::Path};

#[test]
fn generated_eight_profiles_witness_required_transitions_before_recovery() -> Result<()> {
    let mut campaign = Coverage::default();
    for case in 0..8 {
        let scenario = generation::generated(3_664_912_422, case)?;
        let directory = tempfile::tempdir()?;
        let trace = simulation::run(&scenario, directory.path())?;
        trace.require_success()?;
        let coverage = Coverage::from_trace(&trace)?;
        let required: &[Transition] = match case {
            2 => &[
                Transition::StaleProviderRead,
                Transition::OpaqueProviderRead,
            ],
            3 => &[
                Transition::QueuedRetirementReconciliation,
                Transition::OriginalRequestDelivered,
            ],
            6 => &[
                Transition::ExternalDisableUnattributed,
                Transition::UnqualifiedDrainRefused,
                Transition::ControllerRecreated,
                Transition::FencedRecreationRefused,
            ],
            _ => &[],
        };
        for &transition in required {
            assert!(
                coverage.scheduled.observed(transition) > 0,
                "generated profile {case} did not witness {transition:?} before recovery"
            );
        }
        campaign.merge(&coverage)?;
    }
    campaign.require_campaign()?;
    Ok(())
}

fn goal(code: &str, action: &str) -> FailureFingerprint {
    FailureFingerprint {
        code: code.into(),
        action: Some(action.into()),
    }
}

#[test]
fn semantic_reduction_keeps_reference_dependencies_and_explicit_negative_intent() -> Result<()> {
    let first = BuildId::First;
    let second = BuildId::Second;
    let probe = Intent::Invalid {
        attempt: InvalidAttempt::WrongApproval {
            build: first,
            wrong_tenant: true,
        },
    };
    let program = Program {
        seed: 81,
        intents: vec![
            Intent::Submit { build: second },
            Intent::Approve { build: second },
            Intent::Submit { build: first },
            Intent::Approve { build: first },
            Intent::StartRelease { build: first },
            probe.clone(),
        ],
        schedule: vec![
            ScheduleChoice::Restart {},
            ScheduleChoice::Work {
                worker: WorkerId::Fourth,
                selection: 7,
                fault: Fault::LostAck,
            },
            ScheduleChoice::Tick { millis: 900 },
        ],
    };
    let report = minimize(&program, ShrinkBudget::new(512)?, |candidate| {
        let started = candidate
            .intents
            .contains(&Intent::StartRelease { build: first });
        let negative = candidate.intents.contains(&probe);
        let work = candidate
            .schedule
            .iter()
            .any(|choice| matches!(choice, ScheduleChoice::Work { .. }));
        if started {
            assert!(candidate.intents.contains(&Intent::Submit { build: first }));
            assert!(
                candidate
                    .intents
                    .contains(&Intent::Approve { build: first })
            );
        }
        Ok((started && negative && work).then(|| goal("synthetic_guard", "release_settle")))
    })?;
    assert!(report.fixed_point);
    assert!(!report.budget_exhausted);
    assert_eq!(report.program.seed, program.seed);
    assert_eq!(
        report.program.intents,
        vec![
            Intent::Submit { build: first },
            Intent::Approve { build: first },
            Intent::StartRelease { build: first },
            probe
        ]
    );
    assert_eq!(
        report.program.schedule,
        vec![ScheduleChoice::Work {
            worker: WorkerId::First,
            selection: 0,
            fault: Fault::None
        }]
    );
    assert_eq!(generation::compile(&report.program)?.format, 4);
    Ok(())
}

#[test]
fn shorter_different_failures_are_not_accepted_as_the_counterexample() -> Result<()> {
    let original = Program {
        seed: 4,
        intents: Vec::new(),
        schedule: vec![
            ScheduleChoice::Restart {},
            ScheduleChoice::Tick { millis: 10 },
        ],
    };
    let report = minimize(&original, ShrinkBudget::new(32)?, |candidate| {
        let restart = candidate.schedule.contains(&ScheduleChoice::Restart {});
        let tick = candidate
            .schedule
            .iter()
            .any(|choice| matches!(choice, ScheduleChoice::Tick { .. }));
        Ok(Some(match (restart, tick) {
            (true, true) => goal("stale_revision", "release_settle"),
            (true, false) => goal("stale_revision", "claim"),
            _ => goal("wrong_company", "release_settle"),
        }))
    })?;
    assert_eq!(report.fingerprint, goal("stale_revision", "release_settle"));
    assert_eq!(
        report.program.schedule,
        vec![
            ScheduleChoice::Restart {},
            ScheduleChoice::Tick { millis: 0 }
        ]
    );
    assert!(report.fixed_point);
    Ok(())
}

#[test]
fn reduction_budget_and_unclassified_evaluation_errors_are_not_hidden() -> Result<()> {
    let original = Program {
        seed: 8,
        intents: Vec::new(),
        schedule: vec![
            ScheduleChoice::Restart {},
            ScheduleChoice::Tick { millis: 12 },
        ],
    };
    let calls = Cell::new(0);
    let report = minimize(&original, ShrinkBudget::new(1)?, |_| {
        calls.set(calls.get() + 1);
        Ok(Some(goal("synthetic_guard", "restart")))
    })?;
    assert_eq!(calls.get(), 1);
    assert_eq!(report.evaluations, 1);
    assert_eq!(report.program, original);
    assert!(report.budget_exhausted);
    assert!(!report.fixed_point);
    let calls = Cell::new(0);
    assert!(
        minimize(&original, ShrinkBudget::new(10)?, |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok(Some(goal("synthetic_guard", "restart")))
            } else {
                anyhow::bail!("injected evaluator unavailable")
            }
        })
        .is_err()
    );
    assert!(ShrinkBudget::new(0).is_err());
    assert!(ShrinkBudget::new(4097).is_err());
    Ok(())
}

fn build() -> impl Strategy<Value = BuildId> {
    proptest::sample::select(BuildId::ALL.to_vec())
}
fn worker() -> impl Strategy<Value = WorkerId> {
    proptest::sample::select(WorkerId::ALL.to_vec())
}
fn version() -> impl Strategy<Value = SecretVersionId> {
    proptest::sample::select(SecretVersionId::ALL.to_vec())
}
fn tenant() -> impl Strategy<Value = TenantId> {
    proptest::sample::select(vec![TenantId::Primary, TenantId::Independent])
}
fn fault() -> impl Strategy<Value = Fault> {
    prop_oneof![8 => Just(Fault::None), 1 => Just(Fault::NotApplied), 1 => Just(Fault::LostAck), 1 => Just(Fault::Delayed), 1 => Just(Fault::Unavailable), 1 => Just(Fault::Reject)]
}

fn read_selection() -> impl Strategy<Value = ReadSelection> {
    proptest::sample::select(vec![
        ReadSelection::Current,
        ReadSelection::Previous,
        ReadSelection::Oldest,
    ])
}

fn read_strength() -> impl Strategy<Value = ReadStrength> {
    proptest::sample::select(vec![
        ReadStrength::Qualified,
        ReadStrength::Observed,
        ReadStrength::Opaque,
    ])
}

fn intent() -> impl Strategy<Value = Intent> {
    prop_oneof![
        4 => build().prop_map(|build| Intent::Submit { build }),
        2 => proptest::sample::select(vec![BuildId::Second,BuildId::SecondAppSecond,BuildId::Third]).prop_map(|build| Intent::SubmitReplacement { build }),
        5 => build().prop_map(|build| Intent::Approve { build }),
        5 => build().prop_map(|build| Intent::StartRelease { build }),
        5 => (build(), any::<bool>(), any::<bool>(), any::<bool>(), 0..=4_000_000u32).prop_map(|(build,enabled,access,ready,delay)| Intent::Secret { build,enabled,access,ready,delay }),
        3 => build().prop_map(|build| Intent::DeliverSecret { build }),
        1 => build().prop_map(|build| Intent::CancelBuild { build }),
        1 => build().prop_map(|build| Intent::CancelRelease { build }),
        1 => build().prop_map(|build| Intent::RevokeRelease { build }),
        1 => tenant().prop_map(|tenant| Intent::RevokeAuthority { tenant }),
        1 => (tenant(),any::<bool>()).prop_map(|(tenant,revoked)| Intent::Binding { tenant,revoked }),
        1 => (build(),any::<bool>()).prop_map(|(build,uncertain)| Intent::Uncertain { build,uncertain }),
        2 => version().prop_map(|version| Intent::Retire { version }),
        2 => build().prop_map(|build| Intent::Drain { build }),
        2 => build().prop_map(|build| Intent::ReleaseRollback { build }),
    ]
}

fn negative() -> impl Strategy<Value = Intent> {
    prop_oneof![
        (build(), any::<bool>()).prop_map(|(build, wrong_binding)| InvalidAttempt::Isolation {
            build,
            wrong_binding
        }),
        (build(), any::<bool>()).prop_map(|(build, wrong_tenant)| InvalidAttempt::WrongApproval {
            build,
            wrong_tenant
        }),
        build().prop_map(|build| InvalidAttempt::PrematureStart { build }),
        version().prop_map(|version| InvalidAttempt::PrematureRetirement { version }),
        build().prop_map(|build| InvalidAttempt::PrematureDrain { build }),
    ]
    .prop_map(|attempt| Intent::Invalid { attempt })
}

fn choice() -> impl Strategy<Value = ScheduleChoice> {
    prop_oneof![
        4 => any::<u8>().prop_map(|selection| ScheduleChoice::Admit { selection }),
        12 => (worker(),any::<u8>(),fault()).prop_map(|(worker,selection,fault)| ScheduleChoice::Work { worker,selection,fault }),
        6 => (version(),worker(),fault()).prop_map(|(version,worker,fault)| ScheduleChoice::RetirementWork { version,worker,fault }),
        2 => (version(),worker()).prop_map(|(version,worker)| ScheduleChoice::RetirementContend { version,worker }),
        3 => (build(),0..=4_000_000u32).prop_map(|(build,delay)| ScheduleChoice::QuiesceDeployment { build,delay }),
        3 => (version(),read_selection(),read_strength()).prop_map(|(version,selection,strength)| ScheduleChoice::SecretReadMode { version,selection,strength }),
        2 => version().prop_map(|version| ScheduleChoice::HoldRetirement { version }),
        2 => version().prop_map(|version| ScheduleChoice::DeliverRetirement { version }),
        2 => (version(),any::<bool>()).prop_map(|(version,enabled)| ScheduleChoice::ExternalSecretState { version,enabled }),
        2 => build().prop_map(|build| ScheduleChoice::ObserveStoppedDeployment { build }),
        2 => build().prop_map(|build| ScheduleChoice::ProbeDrain { build }),
        2 => build().prop_map(|build| ScheduleChoice::RecreateDeployment { build }),
        2 => (build(),worker()).prop_map(|(build,worker)| ScheduleChoice::Contend { build,worker }),
        2 => worker().prop_map(|worker| ScheduleChoice::DuplicateDelivery { worker }),
        2 => (0..=4_000_000u32).prop_map(|millis| ScheduleChoice::Tick { millis }),
        1 => Just(ScheduleChoice::Restart {}),
    ]
}

fn programs() -> impl Strategy<Value = Program> {
    (
        any::<u64>(),
        proptest::collection::vec(build(), 1..7),
        proptest::collection::vec(intent(), 4..25),
        proptest::collection::vec(negative(), 0..4),
        proptest::collection::vec(choice(), 64..129),
    )
        .prop_map(|(seed, submitted, mut intents, negative, schedule)| {
            intents.extend(submitted.into_iter().map(|build| Intent::Submit { build }));
            intents.extend(negative);
            Program {
                seed,
                intents,
                schedule,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 12,
        max_shrink_iters: 0,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(0xd25e_2026),
        ..ProptestConfig::default()
    })]
    #[test]
    fn generated_typed_histories_replay_and_recover(program in programs()) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/control-generation-regressions");
        let outcome = check_and_persist(&program,&root,ShrinkBudget::new(16).unwrap())
            .map_err(|_| TestCaseError::fail("counterexample persistence/evaluation infrastructure failed"))?;
        if let Some(failure) = outcome {
            return Err(TestCaseError::fail(format!("counterexample {:?}/{:?}; evidence {}",failure.summary.status,failure.summary.stage,failure.directory.display())));
        }
    }
}
