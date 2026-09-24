use anyhow::{Context, Result};
use day2_control::{
    release_execution::{ReleaseOperation, ReleasePhase, ReleaseTerminal},
    simulation::{self, Action, Fault, Scenario, Trace},
};

fn build(actions: &mut Vec<Action>, build: u8) {
    for _ in 0..3 {
        actions.extend([
            Action::Claim { build, slot: build },
            Action::Perform {
                slot: build,
                fault: Fault::None,
            },
            Action::Settle { slot: build },
        ]);
    }
}
fn approve(build: u8) -> Action {
    Action::Approve {
        build,
        wrong_commit: false,
        wrong_tenant: false,
    }
}
fn secret(build: u8, enabled: bool, access: bool) -> Action {
    Action::ReleaseSecret {
        build,
        enabled,
        access,
        ready: true,
        delay: 0,
    }
}
fn step(actions: &mut Vec<Action>, build: u8) {
    actions.extend([
        Action::ReleaseClaim { build, slot: build },
        Action::ReleasePerform {
            slot: build,
            fault: Fault::None,
        },
        Action::ReleaseSettle { slot: build },
    ]);
}
fn start(actions: &mut Vec<Action>, build: u8) {
    actions.extend([approve(build), Action::ReleaseStart { build }]);
}
fn run(actions: Vec<Action>) -> Result<Trace> {
    let directory = tempfile::tempdir()?;
    let scenario = Scenario {
        format: 1,
        seed: 9,
        actions,
    };
    let trace = simulation::run(&scenario, directory.path())?;
    if trace.require_success().is_err() {
        use std::{io::Write, path::Path};
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/control-simulation/workflow-failures");
        std::fs::create_dir_all(&root)?;
        let identity = day2_control::Digest::of(&scenario)?;
        let prefix = identity.as_str().strip_prefix("sha256:").unwrap();
        for (suffix, bytes) in [
            ("scenario", serde_json::to_vec_pretty(&scenario)?),
            ("trace", serde_json::to_vec_pretty(&trace)?),
        ] {
            anyhow::ensure!(
                bytes.len() <= simulation::MAX_TRACE_BYTES,
                "failure evidence budget"
            );
            let mut file = tempfile::NamedTempFile::new_in(&root)?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist(root.join(format!("{prefix}.{suffix}.json")))?;
        }
        trace.require_success().with_context(|| {
            format!(
                "persisted workflow failure {prefix}; final action {:?}",
                trace.events.last().map(|event| &event.action)
            )
        })?;
    }
    Ok(trace)
}

#[test]
fn compiled_recipe_converges_newest_revision_and_other_tenant_for_both_arrival_orders() -> Result<()>
{
    for secret_first in [true, false] {
        let mut actions = Vec::new();
        for index in 0..3 {
            if secret_first {
                actions.push(secret(index, true, true));
            }
            build(&mut actions, index);
            start(&mut actions, index);
            if !secret_first {
                actions.push(secret(index, true, true));
            }
        }
        actions.push(Action::Restart {});
        let trace = run(actions)?;
        let active = trace.releases[0]
            .active
            .as_ref()
            .expect("alpha must activate newest candidate");
        assert_eq!(active.generation, 2);
        assert_eq!(active.secret.version.get(), 2);
        assert!(trace.releases[1].active.is_some());
        assert_eq!(trace.workflow.executions.len(), 3);
        assert_eq!(
            trace
                .workflow
                .executions
                .iter()
                .filter(|item| item.terminal == Some(ReleaseTerminal::Activated))
                .count(),
            2
        );
        assert_eq!(
            trace
                .workflow
                .executions
                .iter()
                .filter(|item| item.terminal == Some(ReleaseTerminal::AuthorityLost))
                .count(),
            1
        );
    }
    Ok(())
}

#[test]
fn lost_ack_and_crash_before_dispatch_reconstruct_process_without_duplicate_mutations() -> Result<()>
{
    for accepted in [true, false] {
        let mut actions = Vec::new();
        build(&mut actions, 0);
        start(&mut actions, 0);
        actions.push(secret(0, true, true));
        actions.push(Action::ReleaseClaim { build: 0, slot: 0 });
        if accepted {
            actions.push(Action::ReleasePerform {
                slot: 0,
                fault: Fault::LostAck,
            });
        }
        actions.push(Action::Restart {});
        let trace = run(actions)?;
        assert_eq!(trace.workflow.executions[0].phase, ReleasePhase::Active);
        assert_eq!(trace.workflow.provider.mutations.len(), 2);
        assert_eq!(
            trace
                .workflow
                .provider
                .mutations
                .iter()
                .filter(|item| item.operation == ReleaseOperation::PrepareDependency)
                .count(),
            1
        );
        let replay = tempfile::tempdir()?;
        simulation::replay(&trace, replay.path())?;
    }
    Ok(())
}

#[test]
fn observed_disable_and_reenable_require_fresh_preparation_and_preserve_incumbent() -> Result<()> {
    let mut actions = Vec::new();
    build(&mut actions, 0);
    start(&mut actions, 0);
    actions.push(secret(0, true, true));
    for _ in 0..5 {
        step(&mut actions, 0);
    }
    let incumbent = run(actions.clone())?.releases[0].active.clone().unwrap();
    build(&mut actions, 1);
    start(&mut actions, 1);
    actions.push(secret(1, true, true));
    for _ in 0..4 {
        step(&mut actions, 1);
    }
    actions.extend([
        Action::ReleaseClaim { build: 1, slot: 1 },
        secret(1, false, true),
        Action::ReleaseDeliverSecret { build: 1 },
        Action::ReleasePerform {
            slot: 1,
            fault: Fault::None,
        },
        Action::ReleaseSettle { slot: 1 },
    ]);
    let disabled = run(actions.clone())?;
    assert_eq!(disabled.releases[0].active.as_ref(), Some(&incumbent));
    assert!(
        disabled
            .workflow
            .executions
            .iter()
            .any(|item| item.phase == ReleasePhase::WaitingSecret)
    );
    actions.extend([
        secret(1, true, true),
        Action::ReleaseDeliverSecret { build: 1 },
        Action::Restart {},
    ]);
    let restored = run(actions)?;
    let active = restored.releases[0].active.as_ref().unwrap();
    assert_eq!(active.generation, 2);
    assert_ne!(active.artifact, incumbent.artifact);
    let deployments: Vec<_> = restored
        .workflow
        .provider
        .mutations
        .iter()
        .filter(|item| {
            item.operation == ReleaseOperation::PrepareDeployment
                && item.fact.secret.version.get() == 2
        })
        .collect();
    assert_eq!(deployments.len(), 2);
    assert_ne!(deployments[0].fact.readiness, deployments[1].fact.readiness);
    Ok(())
}

#[test]
fn delayed_iam_converges_but_missing_metadata_waits_without_displacing_incumbent() -> Result<()> {
    let mut actions = Vec::new();
    build(&mut actions, 0);
    start(&mut actions, 0);
    actions.push(secret(0, true, true));
    for _ in 0..5 {
        step(&mut actions, 0);
    }
    let incumbent = run(actions.clone())?.releases[0].active.clone().unwrap();
    build(&mut actions, 1);
    start(&mut actions, 1);
    assert_eq!(
        run(actions.clone())?.releases[0].active.as_ref(),
        Some(&incumbent)
    );
    actions.extend([
        secret(1, true, false),
        Action::ReleaseSecret {
            build: 1,
            enabled: true,
            access: true,
            ready: true,
            delay: 4_000_000,
        },
    ]);
    let trace = run(actions)?;
    assert_eq!(trace.releases[0].active.as_ref().unwrap().generation, 2);
    assert!(
        trace
            .workflow
            .executions
            .iter()
            .all(|item| item.terminal.is_some())
    );
    Ok(())
}

#[test]
fn true_ambiguity_is_explicit_and_does_not_starve_other_tenant() -> Result<()> {
    let mut actions = Vec::new();
    for index in [0, 2] {
        build(&mut actions, index);
        start(&mut actions, index);
        actions.push(secret(index, true, true));
    }
    actions.extend([
        Action::ReleaseUncertain {
            build: 0,
            uncertain: true,
        },
        Action::ReleaseClaim { build: 0, slot: 0 },
        Action::ReleasePerform {
            slot: 0,
            fault: Fault::Unavailable,
        },
        Action::Restart {},
        Action::Tick {
            millis: day2_control::release_execution::LEASE_MILLIS as u32 + 1,
        },
        Action::ReleaseClaim { build: 0, slot: 0 },
        Action::ReleasePerform {
            slot: 0,
            fault: Fault::None,
        },
        Action::ReleaseSettle { slot: 0 },
        Action::ReleaseClaim { build: 2, slot: 0 },
        Action::Restart {},
    ]);
    let trace = run(actions)?;
    assert!(trace.releases[0].active.is_none());
    assert!(trace.releases[1].active.is_some());
    assert_eq!(trace.workflow.provider.mutations.len(), 2);
    assert!(serde_json::to_string(&trace.workflow.dispositions)?.contains("needs_intervention"));
    Ok(())
}

#[test]
fn cancellation_retires_pending_recipe_and_never_removes_incumbent() -> Result<()> {
    let mut actions = Vec::new();
    build(&mut actions, 0);
    start(&mut actions, 0);
    actions.push(secret(0, true, true));
    for _ in 0..5 {
        step(&mut actions, 0);
    }
    let incumbent = run(actions.clone())?.releases[0].active.clone().unwrap();
    build(&mut actions, 1);
    start(&mut actions, 1);
    actions.push(secret(1, true, true));
    step(&mut actions, 1);
    actions.extend([Action::ReleaseCancel { build: 1 }, Action::Restart {}]);
    let trace = run(actions)?;
    assert_eq!(trace.releases[0].active.as_ref(), Some(&incumbent));
    assert!(
        trace
            .workflow
            .executions
            .iter()
            .any(|item| item.terminal == Some(ReleaseTerminal::AuthorityLost))
    );
    Ok(())
}

#[test]
fn completed_build_cancellation_is_not_release_cancellation() -> Result<()> {
    let mut actions = Vec::new();
    build(&mut actions, 0);
    start(&mut actions, 0);
    actions.push(secret(0, true, true));
    actions.push(Action::Cancel { build: 0 });
    let trace = run(actions)?;
    assert!(trace.releases[0].active.is_some());
    assert_eq!(
        trace.workflow.executions[0].terminal,
        Some(ReleaseTerminal::Activated)
    );
    Ok(())
}
