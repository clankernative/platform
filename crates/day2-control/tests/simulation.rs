use anyhow::Result;
use day2_control::{
    Digest,
    kernel::State,
    simulation::{self, Action, Disposition, Fault, Scenario},
};

fn run(actions: Vec<Action>) -> Result<simulation::Trace> {
    let directory = tempfile::tempdir()?;
    simulation::run(
        &Scenario {
            format: 1,
            seed: 7,
            actions,
        },
        directory.path(),
    )
}

#[test]
fn scenario_contract_rejects_unknown_actions_fields_indices_and_budgets() -> Result<()> {
    for body in [
        r#"{"format":1,"seed":1,"actions":[{"action":"cloud_mutation"}]}"#,
        r#"{"format":1,"seed":1,"actions":[{"action":"restart","ignored":true}]}"#,
        r#"{"format":1,"seed":1,"actions":[{"action":"heal","ignored":true}]}"#,
        r#"{"format":1,"seed":1,"actions":[],"extra":true}"#,
    ] {
        assert!(serde_json::from_str::<Scenario>(body).is_err());
    }
    for action in [
        Action::Claim { build: 3, slot: 0 },
        Action::Settle { slot: 4 },
        Action::Binding {
            tenant: 2,
            revoked: true,
        },
        Action::Tick { millis: 4_000_001 },
    ] {
        assert!(
            Scenario {
                format: 1,
                seed: 1,
                actions: vec![action]
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Scenario {
            format: 5,
            seed: 1,
            actions: vec![]
        }
        .validate()
        .is_err()
    );
    for action in [
        Action::HoldRetirement { version: 1 },
        Action::ObserveStoppedDeployment { build: 0 },
    ] {
        assert!(
            Scenario {
                format: 3,
                seed: 1,
                actions: vec![action]
            }
            .validate()
            .is_err()
        );
    }
    for action in [
        Action::HoldRetirement { version: 0 },
        Action::DeliverRetirement { version: 4 },
        Action::RecreateDeployment { build: 6 },
    ] {
        assert!(
            Scenario {
                format: 4,
                seed: 1,
                actions: vec![action]
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Scenario {
            format: 1,
            seed: 1,
            actions: vec![Action::Restart {}; simulation::MAX_ACTIONS + 1]
        }
        .validate()
        .is_err()
    );
    assert!(simulation::generated(1, 128).is_err());
    for workflow in [
        Action::ReleaseSecret {
            build: 0,
            enabled: true,
            access: true,
            ready: true,
            delay: 0,
        },
        Action::ReleaseDeliverSecret { build: 0 },
    ] {
        let legacy = Action::Secret {
            build: 0,
            enabled: true,
            access: true,
            ready: true,
        };
        for actions in [
            vec![legacy.clone(), workflow.clone()],
            vec![workflow.clone(), legacy.clone()],
        ] {
            assert!(
                Scenario {
                    format: 1,
                    seed: 1,
                    actions
                }
                .validate()
                .is_err()
            );
        }
    }
    Scenario {
        format: 1,
        seed: 1,
        actions: vec![
            Action::Secret {
                build: 0,
                enabled: true,
                access: true,
                ready: true,
            },
            Action::ReleaseSecret {
                build: 1,
                enabled: true,
                access: true,
                ready: true,
                delay: 0,
            },
        ],
    }
    .validate()?;
    assert_eq!(simulation::generated(1, 0)?, simulation::generated(1, 0)?);
    assert_ne!(simulation::generated(1, 0)?, simulation::generated(1, 1)?);
    Ok(())
}

#[test]
fn regression_corpus_replays_canonical_logical_state_in_fresh_directories() -> Result<()> {
    for scenario in simulation::regressions()? {
        let directory = tempfile::tempdir()?;
        let trace = simulation::run(&scenario, directory.path())?;
        trace.require_success()?;
        let replay = tempfile::tempdir()?;
        simulation::replay(&trace, replay.path())?;
        let encoded = serde_json::to_string(&trace)?;
        assert!(!encoded.contains(directory.path().to_str().unwrap()));
        assert!(!encoded.contains("SystemTime"));
        assert!(simulation::run(&scenario, directory.path()).is_err());
    }
    Ok(())
}

#[test]
fn stale_completions_are_fenced_and_revocation_does_not_erase_inflight_outcomes() -> Result<()> {
    let trace = run(vec![
        Action::Claim { build: 0, slot: 0 },
        Action::Perform {
            slot: 0,
            fault: Fault::None,
        },
        Action::Tick { millis: 1_200_001 },
        Action::Claim { build: 0, slot: 1 },
        Action::Settle { slot: 0 },
        Action::Binding {
            tenant: 0,
            revoked: true,
        },
        Action::Perform {
            slot: 1,
            fault: Fault::None,
        },
        Action::Binding {
            tenant: 0,
            revoked: false,
        },
        Action::Perform {
            slot: 1,
            fault: Fault::None,
        },
        Action::Binding {
            tenant: 0,
            revoked: true,
        },
        Action::Settle { slot: 1 },
    ])?;
    trace.require_success()?;
    assert_eq!(trace.events[4].outcome, "refused");
    assert_eq!(trace.events[6].outcome, "provider_refused");
    assert_eq!(trace.events[10].outcome, "accepted");
    assert!(trace.dispositions.iter().all(|item| matches!(
        item,
        Disposition::Terminal {
            state: State::Succeeded { .. },
            ..
        }
    )));
    Ok(())
}

#[test]
fn definite_nonapplication_and_rejection_do_not_create_publication_mutations() -> Result<()> {
    let mut actions = Vec::new();
    for _ in 0..2 {
        actions.extend([
            Action::Claim { build: 0, slot: 0 },
            Action::Perform {
                slot: 0,
                fault: Fault::None,
            },
            Action::Settle { slot: 0 },
        ]);
    }
    actions.extend([
        Action::Claim { build: 0, slot: 0 },
        Action::Perform {
            slot: 0,
            fault: Fault::NotApplied,
        },
        Action::Settle { slot: 0 },
        Action::Claim { build: 0, slot: 0 },
        Action::Perform {
            slot: 0,
            fault: Fault::Reject,
        },
        Action::Settle { slot: 0 },
    ]);
    let trace = run(actions)?;
    trace.require_success()?;
    assert!(matches!(
        trace.dispositions[0],
        Disposition::Terminal {
            state: State::Failed { .. },
            ..
        }
    ));
    assert_eq!(trace.publications.len(), 2);
    assert!(
        trace
            .publications
            .iter()
            .all(|record| record.commit != trace.plans[0].commit.as_str())
    );
    Ok(())
}

#[test]
fn trace_identity_provider_facts_and_terminal_results_cannot_be_forged() -> Result<()> {
    let trace = run(vec![])?;
    trace.require_success()?;
    let mut variants = Vec::new();
    let mut changed = trace.clone();
    changed.implementation = Digest::new(b"other implementation");
    variants.push(changed);
    let mut changed = trace.clone();
    changed.provider_records[0].company = "wrong_company".into();
    variants.push(changed);
    let mut changed = trace.clone();
    changed.publications[0].receipt = Digest::new(b"forged receipt");
    variants.push(changed);
    let mut changed = trace.clone();
    changed.dispositions[0] = Disposition::Terminal {
        build: 0,
        state: State::Cancelled,
    };
    variants.push(changed);
    let mut changed = trace;
    changed.events[0].now += 1;
    variants.push(changed);
    for variant in variants {
        let directory = tempfile::tempdir()?;
        assert!(simulation::replay(&variant, directory.path()).is_err());
    }
    Ok(())
}
