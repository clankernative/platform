use anyhow::Result;
use day2_control::simulation::{self, Action, Scenario};

#[test]
fn generated_world_admits_only_requested_candidates_and_reconstructs_them() -> Result<()> {
    let scenario = Scenario {
        format: 2,
        seed: 17,
        actions: vec![
            Action::Claim { build: 0, slot: 0 },
            Action::Approve {
                build: 1,
                wrong_commit: false,
                wrong_tenant: false,
            },
            Action::Submit { build: 2 },
            Action::Submit { build: 0 },
            Action::Submit { build: 2 },
            Action::Restart {},
        ],
    };
    let directory = tempfile::tempdir()?;
    let trace = simulation::run(&scenario, directory.path())?;
    trace.require_success()?;
    assert_eq!(trace.events[0].outcome, "build_not_submitted");
    assert_eq!(trace.events[1].outcome, "build_not_submitted");
    assert_eq!(trace.events[4].outcome, "duplicate_submission");
    assert_eq!(trace.events[5].executions.len(), 2);
    assert_eq!(trace.dispositions.len(), 2);
    assert_eq!(trace.schedule_events as usize, scenario.actions.len());
    assert!(trace.events.len() > scenario.actions.len());
    let replay = tempfile::tempdir()?;
    simulation::replay(&trace, replay.path())?;

    let mut forged = trace.clone();
    forged.schedule_events = forged.events.len() as u32;
    assert!(forged.validate().is_err());
    let mut forged = trace.clone();
    forged.dispositions[1] = forged.dispositions[0].clone();
    assert!(forged.validate().is_err());
    let mut forged = trace;
    forged.scenario.actions.swap(2, 3);
    assert!(forged.validate().is_err());
    Ok(())
}

#[test]
fn empty_generated_world_cannot_borrow_coverage_from_recovery() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let trace = simulation::run(
        &Scenario {
            format: 2,
            seed: 3,
            actions: vec![],
        },
        directory.path(),
    )?;
    trace.require_success()?;
    assert!(trace.dispositions.is_empty());
    assert!(trace.workflow.executions.is_empty());
    let coverage = simulation::coverage::Coverage::from_trace(&trace)?;
    let mut campaign = simulation::coverage::Coverage::default();
    for _ in 0..8 {
        campaign.merge(&coverage)?;
    }
    assert!(campaign.require_campaign().is_err());
    Ok(())
}

#[test]
fn revoked_binding_refuses_new_admission_and_does_not_hide_missing_requests() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let trace = simulation::run(
        &Scenario {
            format: 2,
            seed: 19,
            actions: vec![
                Action::Binding {
                    tenant: 0,
                    revoked: true,
                },
                Action::Submit { build: 0 },
                Action::Claim { build: 0, slot: 0 },
                Action::Binding {
                    tenant: 0,
                    revoked: false,
                },
                Action::Submit { build: 0 },
            ],
        },
        directory.path(),
    )?;
    trace.require_success()?;
    assert_eq!(trace.events[1].outcome, "submission_refused");
    assert!(trace.events[1].executions.is_empty());
    assert_eq!(trace.events[2].outcome, "build_not_submitted");
    assert_eq!(trace.events[4].outcome, "submitted");
    assert_eq!(trace.dispositions.len(), 1);
    Ok(())
}
