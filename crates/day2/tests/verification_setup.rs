//! Native conformance for operation-owned verification setup.
use anyhow::{Context, Result, ensure};
use day2::{
    artifact::LoadedArtifact,
    automation,
    development::{self, Campaign, CampaignTime},
    store::{Fault, replay},
};
use serde_json::{Value, json};
use std::path::PathBuf;

fn row_data(row: &Value) -> Result<Value> {
    Ok(serde_json::from_str(
        row.get("data")
            .and_then(Value::as_str)
            .context("snapshot row data must be encoded JSON")?,
    )?)
}

#[test]
fn registered_setup_runs_as_checked_trace_steps_before_each_positive_case() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_VERIFICATION_SETUP_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_VERIFICATION_SETUP_ARTIFACT")?;
    let directory = tempfile::tempdir()?;
    let evidence =
        development::verify(&artifact, &directory.path().join("campaign"), 0x51_7A_9E, 1)?;

    ensure!(
        evidence.verification_complete,
        "verification campaign incomplete"
    );
    for operation in [
        "a_invalidate",
        "b_read",
        "configure_failure",
        "prepare_first",
        "prepare_second",
    ] {
        assert_eq!(
            evidence.obligations[&format!("verification_setup.{operation}")],
            1
        );
    }
    assert_eq!(evidence.setup_counts["verification_setup.prepare_first"], 2);
    assert_eq!(
        evidence.setup_counts["verification_setup.prepare_second"],
        1
    );
    assert_eq!(evidence.traces.len(), evidence.examples + 5 + 3);
    let admitted = LoadedArtifact::load(&artifact)?;
    for trace in &evidence.traces {
        replay(&admitted, trace)?;
    }

    let states = evidence
        .snapshot
        .get("actor_states")
        .and_then(serde_json::Value::as_array)
        .context("final actor states are missing")?;
    ensure!(
        states
            .iter()
            .any(|state| row_data(state).is_ok_and(|data| data["stage"] == 2)),
        "positive query did not preserve the fully prepared actor state"
    );
    for check in [
        "command-trace-replay",
        "duplicate-delivery",
        "schema-invalid-input-rejection",
        "properties-after-each-command-and-completion",
    ] {
        assert!(
            evidence.checks.contains(&check.to_owned()),
            "missing {check}"
        );
    }
    Ok(())
}

#[test]
fn failed_second_setup_preserves_stage_one_and_never_invokes_the_query() -> Result<()> {
    let artifact = std::env::var_os("DAY2_TEST_VERIFICATION_SETUP_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify or set DAY2_TEST_VERIFICATION_SETUP_ARTIFACT")?;
    let directory = tempfile::tempdir()?;
    let runtime = development::create_verification_for(
        &artifact,
        &directory.path().join("instance"),
        None,
        "developer",
    )?;
    let configured = runtime.invoke(
        "verification_setup.configure_failure",
        "developer",
        "configure-second-stage-failure",
        &json!({"fail_second": true}),
        1,
        Fault::None,
    )?;
    assert_eq!(configured.status, "success", "{configured:?}");
    let mut campaign = Campaign::for_actor(
        runtime,
        None,
        0x51_7A_9E,
        1,
        "developer",
        false,
        CampaignTime::Verification,
    )?;
    let runner = automation::runner()?;
    let result = automation::run(&runner, &["exercise", "", "1"], |request| {
        campaign.effect(request)
    });
    assert!(
        result.is_err(),
        "declared setup failure unexpectedly completed"
    );
    assert!(!campaign.is_complete());
    let snapshot = campaign.runtime.inspect()?;
    let states = snapshot
        .get("actor_states")
        .and_then(Value::as_array)
        .context("failure state table missing")?;
    assert!(states.iter().any(|state| {
        row_data(state).is_ok_and(|data| {
            data["actor"] == "developer" && data["stage"] == 1 && data["fail_second"] == true
        })
    }));
    assert!(campaign.evidence.traces.iter().any(|trace| {
        trace.request.operation == "verification_setup.prepare_second"
            && trace.outcome.status == "failure"
    }));
    assert!(
        !campaign
            .evidence
            .traces
            .iter()
            .any(|trace| trace.request.operation == "verification_setup.b_read")
    );
    Ok(())
}

#[test]
fn omitted_reordered_and_forged_setup_steps_cannot_complete_a_receipt() -> Result<()> {
    for mutation in ["omit", "reorder", "forge"] {
        let artifact = std::env::var_os("DAY2_TEST_VERIFICATION_SETUP_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_VERIFICATION_SETUP_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        let runtime = development::create_verification_for(
            &artifact,
            &directory.path().join("instance"),
            None,
            "developer",
        )?;
        let mut campaign = Campaign::for_actor(
            runtime,
            None,
            0x51_7A_9E,
            1,
            "developer",
            false,
            CampaignTime::Verification,
        )?;
        let runner = automation::runner()?;
        let mut changed_nonempty_plan = false;
        let result = automation::run(&runner, &["exercise", "", "1"], |request| {
            let is_setup_plan = request.action == "dev-setups";
            let mut response = campaign.effect(request)?;
            if is_setup_plan {
                let steps = response
                    .as_array_mut()
                    .context("native setup plan must be a step list")?;
                if steps.len() == 2 {
                    changed_nonempty_plan = true;
                    match mutation {
                        "omit" => steps.clear(),
                        "reorder" => steps.reverse(),
                        "forge" => {
                            steps[0]["operation"] = json!("a_invalidate");
                        }
                        _ => unreachable!(),
                    }
                }
            }
            Ok(response)
        });
        assert!(
            changed_nonempty_plan,
            "{mutation} did not reach the query setup plan"
        );
        assert!(result.is_err(), "{mutation} setup unexpectedly completed");
        assert!(!campaign.is_complete(), "{mutation} setup issued a receipt");
    }
    Ok(())
}
