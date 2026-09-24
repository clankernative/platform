//! Outcome assertions complement the lab's per-step invariants. A simulator in
//! which every request is refused must not pass acceptance by doing nothing.
use anyhow::Result;
use day2_control::{
    kernel::State,
    simulation::{self, Action, Disposition, Fault, Scenario, Trace},
};

fn step(actions: &mut Vec<Action>, build: u8) {
    actions.extend([
        Action::Claim { build, slot: build },
        Action::Perform {
            slot: build,
            fault: Fault::None,
        },
        Action::Settle { slot: build },
    ]);
}

fn build(actions: &mut Vec<Action>, build: u8) {
    for _ in 0..3 {
        step(actions, build);
    }
}

fn approve(build: u8) -> Action {
    Action::Approve {
        build,
        wrong_commit: false,
        wrong_tenant: false,
    }
}

fn secret(build: u8, enabled: bool) -> Action {
    Action::Secret {
        build,
        enabled,
        access: true,
        ready: true,
    }
}

fn run(actions: Vec<Action>) -> Result<Trace> {
    let directory = tempfile::tempdir()?;
    let trace = simulation::run(
        &Scenario {
            format: 1,
            seed: 42,
            actions,
        },
        directory.path(),
    )?;
    trace.require_success()?;
    Ok(trace)
}

#[test]
fn secret_first_and_approval_first_both_reach_a_real_activation() -> Result<()> {
    for secret_first in [false, true] {
        let mut actions = Vec::new();
        if secret_first {
            actions.push(secret(0, true));
        }
        build(&mut actions, 0);
        actions.push(approve(0));
        if !secret_first {
            actions.push(Action::Prepare { build: 0 });
            actions.push(secret(0, true));
        }
        actions.extend([Action::Prepare { build: 0 }, Action::Activate { build: 0 }]);
        let trace = run(actions)?;
        let active = trace.releases[0]
            .active
            .as_ref()
            .expect("eligible release must activate");
        let Disposition::Terminal {
            state: State::Succeeded { artifact, .. },
            ..
        } = &trace.dispositions[0]
        else {
            panic!("eligible build must succeed");
        };
        assert_eq!(&active.artifact, artifact);
        assert_eq!(active.generation, 1);
        assert!(trace.releases[1].active.is_none());
    }
    Ok(())
}

#[test]
fn stale_readiness_preserves_incumbent_until_a_fresh_proof_is_prepared() -> Result<()> {
    let mut actions = Vec::new();
    build(&mut actions, 0);
    actions.extend([
        approve(0),
        secret(0, true),
        Action::Prepare { build: 0 },
        Action::Activate { build: 0 },
    ]);
    let incumbent = run(actions.clone())?.releases[0].active.clone().unwrap();
    build(&mut actions, 1);
    actions.extend([
        approve(1),
        secret(1, true),
        Action::Prepare { build: 1 },
        secret(1, false),
        Action::Activate { build: 1 },
    ]);
    let disabled = run(actions.clone())?;
    assert_eq!(disabled.releases[0].active.as_ref(), Some(&incumbent));
    assert_eq!(disabled.releases[0].generation, 2);

    actions.extend([secret(1, true), Action::Activate { build: 1 }]);
    assert_eq!(
        run(actions.clone())?.releases[0].active.as_ref(),
        Some(&incumbent)
    );
    actions.extend([Action::Prepare { build: 1 }, Action::Activate { build: 1 }]);
    let ready = run(actions)?;
    let active = ready.releases[0].active.as_ref().unwrap();
    assert_eq!(active.generation, 2);
    assert_ne!(active.artifact, incumbent.artifact);
    assert_eq!(active.secret.version.get(), 2);
    Ok(())
}

#[test]
fn unknown_publication_blocks_only_its_execution_without_a_second_mutation() -> Result<()> {
    let mut actions = Vec::new();
    step(&mut actions, 0);
    step(&mut actions, 0);
    actions.extend([Action::Claim { build: 0, slot: 0 }, Action::Restart {}]);
    let trace = run(actions)?;
    assert!(matches!(
        trace.dispositions[0],
        Disposition::NeedsInterventionUnknownPublication { build: 0, .. }
    ));
    for (index, disposition) in trace.dispositions.iter().enumerate().skip(1) {
        assert!(
            matches!(disposition, Disposition::Terminal { build, state: State::Succeeded { .. } } if usize::from(*build) == index)
        );
    }
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
fn an_accepted_publication_with_lost_acknowledgement_reconciles_to_one_receipt() -> Result<()> {
    let mut actions = Vec::new();
    step(&mut actions, 0);
    step(&mut actions, 0);
    actions.extend([
        Action::Claim { build: 0, slot: 0 },
        Action::Perform {
            slot: 0,
            fault: Fault::LostAck,
        },
        Action::Restart {},
    ]);
    let trace = run(actions)?;
    assert!(trace.dispositions.iter().all(|disposition| matches!(
        disposition,
        Disposition::Terminal {
            state: State::Succeeded { .. },
            ..
        }
    )));
    assert_eq!(trace.publications.len(), 3);
    let replay = tempfile::tempdir()?;
    simulation::replay(&trace, replay.path())?;
    let mut corrupted = trace;
    corrupted.events[0].outcome = "invented_success".into();
    let replay = tempfile::tempdir()?;
    assert!(simulation::replay(&corrupted, replay.path()).is_err());
    Ok(())
}
