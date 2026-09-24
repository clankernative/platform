use anyhow::{Result, ensure};
use day2_control::{
    runtime_secret::VersionState,
    secret_retirement::{RetirementTerminal, RetirementWait},
    simulation::{self, Action, Fault, Scenario, coverage::Coverage},
};

#[test]
fn externally_disabled_material_requires_intervention_not_a_fabricated_effect() -> Result<()> {
    // Reduced from replayed property counterexample 2906789129048056144:
    // legacy material publication can disable a version just like the explicit
    // weak-provider environment action, but neither supplies our effect receipt.
    let scenario = Scenario {
        format: 4,
        seed: 2_906_789_129_048_056_144,
        actions: vec![
            Action::Submit { build: 4 },
            Action::ReleaseSecret {
                build: 4,
                enabled: false,
                access: true,
                ready: true,
                delay: 0,
            },
            Action::RetireSecret { version: 2 },
            Action::RetirementClaim {
                version: 2,
                slot: 0,
            },
            Action::RetirementPerform {
                slot: 0,
                fault: Fault::None,
            },
            Action::RetirementSettle { slot: 0 },
            Action::RetirementClaim {
                version: 2,
                slot: 0,
            },
            Action::RetirementPerform {
                slot: 0,
                fault: Fault::None,
            },
            Action::Restart {},
        ],
    };
    let directory = tempfile::tempdir()?;
    let trace = simulation::run(&scenario, directory.path())?;
    trace.require_success()?;
    ensure!(
        trace.retirement.provider.mutations.is_empty(),
        "external state fabricated an effect receipt"
    );
    ensure!(
        trace
            .retirement
            .snapshot
            .executions
            .iter()
            .any(
                |execution| execution.waiting == Some(RetirementWait::Reconciliation)
                    && execution.terminal.is_none()
            ),
        "unacknowledged external state was promoted to retirement success"
    );
    let replay = tempfile::tempdir()?;
    simulation::replay(&trace, replay.path())?;
    Ok(())
}

#[test]
fn generated_shared_rollover_protects_both_aliases_then_retires_once_and_replays() -> Result<()> {
    let scenario = simulation::generated(3_664_912_422, 0)?;
    let directory = tempfile::tempdir()?;
    let trace = simulation::run(&scenario, directory.path())?;
    trace.require_success()?;
    ensure!(
        trace.retirement.provider.mutations.len() == 1,
        "one shared version disable required"
    );
    let mutation = &trace.retirement.provider.mutations[0];
    ensure!(
        mutation.fact.key.version.get() == 1,
        "only incumbent version may retire"
    );
    ensure!(
        trace
            .retirement
            .snapshot
            .executions
            .iter()
            .any(|value| value.terminal == Some(RetirementTerminal::Disabled)),
        "retirement did not finish"
    );
    ensure!(
        trace
            .retirement
            .snapshot
            .versions
            .iter()
            .any(|value| value.key == mutation.fact.key && value.state == VersionState::Disabled),
        "disabled provider receipt was not settled"
    );
    ensure!(
        trace.events[..trace.schedule_events as usize]
            .iter()
            .any(|event| event
                .retirement
                .executions
                .iter()
                .any(|execution| execution.waiting == Some(RetirementWait::Consumers))),
        "generated schedule did not witness blocked retirement"
    );
    let active = trace
        .releases
        .iter()
        .filter_map(|state| state.active.as_ref())
        .collect::<Vec<_>>();
    ensure!(
        active
            .iter()
            .filter(|receipt| receipt.target.company.as_str() == "alpha"
                && receipt.secret.version.get() == 2)
            .count()
            == 2,
        "both apps must move to V2"
    );
    ensure!(
        active
            .iter()
            .any(|receipt| receipt.target.company.as_str() == "beta"
                && receipt.secret.version.get() == 3),
        "independent company must remain active"
    );
    ensure!(
        trace.retirement.provider.drains.len() == 2,
        "both old deployments need separate drain proofs"
    );
    let coverage = Coverage::from_trace(&trace)?;
    ensure!(
        coverage.meaningful_scheduled_cases == 1,
        "rollover coverage must be scheduled"
    );
    let encoded = serde_json::to_vec(&trace)?;
    let persisted: simulation::Trace = day2::json::decode_evidence(&encoded)?;
    ensure!(persisted == trace, "persisted rollover trace changed");
    let replay = tempfile::tempdir()?;
    simulation::replay(&persisted, replay.path())?;
    Ok(())
}
