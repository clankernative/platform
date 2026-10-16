//! Native app regressions use permissive read policy so actor isolation must
//! come from the actual Roc handler, and independent expectations stay in tests.
use crate::{
    artifact::Instance,
    store::{Fault, Runtime},
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs;

pub(crate) struct World {
    pub(crate) directory: tempfile::TempDir,
    pub(crate) runtime: Runtime,
}

impl World {
    pub(crate) fn new() -> Result<Self> {
        let artifact = std::env::var("DAY2_TEST_CHART_LIVE_ARTIFACT")
            .context("run xtask verify or set DAY2_TEST_CHART_LIVE_ARTIFACT")?;
        let actors = json!(["alice", "bob", "empty"]);
        let operations = json!({
            "chart_live.chart": {"actors":actors,"mode":{"kind":"read"},"models":{"chart_samples":{"read":true,"rows":{"kind":"all"}}}},
            "chart_live.append_sample": {"actors":actors,"mode":{"kind":"current_state"},"models":{"chart_samples":{"read":true,"create":true,"rows":{"kind":"all"}}}},
            "chart_live.update_sample": {"actors":actors,"mode":{"kind":"current_state"},"models":{"chart_samples":{"read":true,"update_fields":["value","missing"],"rows":{"kind":"all"}}}}
        });
        let instance: Instance = serde_json::from_value(json!({
            "installation":"chart_test", "environment":"test", "apps":{"chart":{
                "artifact":artifact,"readers":actors,"writers":actors,
                "authority":{"version":1,"operations":operations}
            }}
        }))?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "chart")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }

    pub(crate) fn append(&self, actor: &str, time: i64, value: i64, missing: bool) -> Result<()> {
        let result = self.runtime.invoke(
            "chart_live.append_sample",
            actor,
            &format!("{actor}-{time}"),
            &json!({"time":time,"value":value,"missing":missing}),
            100,
            Fault::None,
        )?;
        assert_eq!(result.status, "success", "{}", result.error);
        Ok(())
    }
}

fn check(
    runtime: &Runtime,
    operation: &str,
    actor: &str,
    input: &Value,
    before: &Value,
    output: &Value,
    after: &Value,
) -> Result<bool> {
    let contextual = |snapshot: &Value| {
        let mut snapshot = snapshot.clone();
        snapshot["verification"] = json!({"actor":actor,"input":input.to_string()});
        snapshot.to_string()
    };
    let request = format!(
        "verify:{}",
        json!({"action":"check","operation":operation,
        "snapshot":contextual(after),"before":contextual(before),"output":output.to_string(),"seed":0})
    );
    let reply: Value = serde_json::from_slice(&crate::properties::exchange_verification(
        runtime.artifact(),
        request.as_bytes(),
    )?)?;
    Ok(reply["error"] == "" && reply["value"] == "true")
}

#[test]
fn native_chart_ranges_use_the_dispatch_actor_and_reject_circular_oracles() -> Result<()> {
    let world = World::new()?;
    let start = 1_735_689_600_000i64;
    for (offset, value, missing) in [
        (-1, 8, false),
        (0, 0, false),
        (1, 72, false),
        (2, 0, true),
        (3, 91, false),
    ] {
        world.append("alice", start + offset, value, missing)?;
        world.append("bob", start + offset, 100 - value, !missing)?;
    }
    for (index, (actor, from, to, expected)) in [
        (
            "alice",
            start,
            start + 3,
            vec![
                (start, 0, false),
                (start + 1, 72, false),
                (start + 2, 0, true),
            ],
        ),
        ("bob", start, start + 1, vec![(start, 100, true)]),
        ("alice", start + 3, start + 4, vec![(start + 3, 91, false)]),
        ("empty", start, start + 4, vec![]),
        ("alice", start + 4, start + 5, vec![]),
        ("alice", 0, 1, vec![]),
        ("alice", 4_102_444_800_000, 4_102_444_800_001, vec![]),
    ]
    .into_iter()
    .enumerate()
    {
        let before = world.runtime.verification_snapshot()?;
        let input = json!({"start":from,"end":to});
        let result = world.runtime.invoke(
            "chart_live.chart",
            actor,
            &format!("range-{index}"),
            &input,
            100,
            Fault::None,
        )?;
        assert_eq!(result.status, "success", "{}", result.error);
        assert_eq!(result.result["actor"], actor);
        let actual: Vec<_> = result.result["chart"]["samples"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["time"].as_i64().unwrap(),
                    row["value"].as_i64().unwrap(),
                    row["missing"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
        let after = world.runtime.verification_snapshot()?;
        assert_eq!(before, after);
        assert!(check(
            &world.runtime,
            "chart_live.chart",
            actor,
            &input,
            &before,
            &result.result,
            &after
        )?);
        let mut forged = result.result.clone();
        forged["actor"] = json!("someone-else");
        forged["chart"]["samples"]["items"] = json!([]);
        assert!(!check(
            &world.runtime,
            "chart_live.chart",
            actor,
            &input,
            &before,
            &forged,
            &after
        )?);
        assert!(!check(
            &world.runtime,
            "chart_live.chart",
            "another-caller",
            &input,
            &before,
            &result.result,
            &after
        )?);
    }
    for (index, (start, end)) in [
        (-1i64, 1i64),
        (2, 2),
        (3, 2),
        (0, 2_678_400_001),
        (0, i64::MAX),
        (4_102_444_800_000, 4_102_444_800_002),
    ]
    .into_iter()
    .enumerate()
    {
        let before = world.runtime.verification_snapshot()?;
        let result = world.runtime.invoke(
            "chart_live.chart",
            "alice",
            &format!("invalid-{index}"),
            &json!({"start":start,"end":end}),
            100,
            Fault::None,
        )?;
        assert_ne!(result.status, "success");
        assert_eq!(world.runtime.verification_snapshot()?, before);
    }
    Ok(())
}

#[test]
fn native_chart_update_oracle_requires_exact_fields_version_and_unchanged_other_rows() -> Result<()>
{
    let world = World::new()?;
    let time = 1_735_689_600_000i64;
    world.append("alice", time, 0, false)?;
    world.append("bob", time, 99, true)?;
    world.append("alice", time + 1, 17, false)?;
    let before = world.runtime.verification_snapshot()?;
    let input = json!({"sample_time":time,"expected_version":1,"value":1,"missing":true});
    let result = world.runtime.invoke(
        "chart_live.update_sample",
        "alice",
        "update",
        &input,
        100,
        Fault::None,
    )?;
    assert_eq!(result.status, "success", "{}", result.error);
    assert_eq!(result.result, json!({"time":time,"version":2}));
    let after = world.runtime.verification_snapshot()?;
    assert!(check(
        &world.runtime,
        "chart_live.update_sample",
        "alice",
        &input,
        &before,
        &result.result,
        &after
    )?);
    let stale = world.runtime.invoke(
        "chart_live.update_sample",
        "alice",
        "stale",
        &input,
        101,
        Fault::None,
    )?;
    assert_ne!(stale.status, "success");
    assert_eq!(world.runtime.verification_snapshot()?, after);
    for actor in ["bob", "empty"] {
        assert!(!check(
            &world.runtime,
            "chart_live.update_sample",
            actor,
            &input,
            &before,
            &result.result,
            &after
        )?);
    }
    // A different valid update must not satisfy the original requested transition.
    let wrong_input = json!({"sample_time":time,"expected_version":1,"value":2,"missing":false});
    assert!(!check(
        &world.runtime,
        "chart_live.update_sample",
        "alice",
        &wrong_input,
        &before,
        &result.result,
        &after
    )?);
    let changed = world.runtime.invoke(
        "chart_live.update_sample",
        "bob",
        "other-row",
        &json!({"sample_time":time,"expected_version":1,"value":22,"missing":false}),
        100,
        Fault::None,
    )?;
    assert_eq!(changed.status, "success");
    assert!(!check(
        &world.runtime,
        "chart_live.update_sample",
        "alice",
        &input,
        &before,
        &result.result,
        &world.runtime.verification_snapshot()?
    )?);
    Ok(())
}
