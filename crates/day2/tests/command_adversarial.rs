#[path = "support/commands.rs"]
mod support;
use anyhow::Result;
use day2::{
    invocations,
    store::{Fault, replay},
};
use serde_json::{Value, json};
use support::World;

fn world() -> Result<World> {
    let world = World::artifact("DAY2_TEST_REPORTS_PROBE_ARTIFACT")?;
    world.change_policy(|p| {
        p.operations
            .get_mut("reports.submit")
            .unwrap()
            .models
            .get_mut("reports")
            .unwrap()
            .update_fields
            .insert("text".into());
    })?;
    Ok(world)
}
fn submit(world: &World, id: &str, title: &str, text: &str) -> Result<day2::protocol::Outcome> {
    world.runtime.invoke(
        "reports.submit",
        "alice",
        id,
        &json!({"title":title,"text":text}),
        100,
        Fault::None,
    )
}
fn changes(world: &World) -> Result<i64> {
    Ok(rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT count(*) FROM day2_audit_changes",
        [],
        |r| r.get(0),
    )?)
}

#[test]
fn forged_entity_does_not_authorize_a_child_command_without_current_transaction_observation()
-> Result<()> {
    let world = world()?;
    let seed = submit(&world, "seed", "Seed", "single line")?;
    let before = world.runtime.inspect()?;
    let count = changes(&world)?;
    let id = seed.result["id"].as_str().unwrap();
    let rejected = submit(&world, "forged", "forged", id)?;
    assert_eq!(rejected.status, "failure");
    assert_eq!(
        rejected.error,
        "command_target_requires_transaction_observation"
    );
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(changes(&world)?, count);
    assert!(invocations::children(&world.runtime, "forged")?.is_empty());
    assert_eq!(submit(&world, "forged", "forged", id)?, rejected);
    replay(world.runtime.artifact(), &world.runtime.trace("forged")?)?;
    Ok(())
}

#[test]
fn changing_a_target_after_child_acceptance_rolls_back_parent_data_intent_and_audit() -> Result<()>
{
    let world = world()?;
    let before = world.runtime.inspect()?;
    let rejected = submit(&world, "changed", "after_request", "original")?;
    assert_eq!(rejected.status, "failure");
    assert_eq!(rejected.error, "command_target_changed_after_request");
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(changes(&world)?, 0);
    assert!(invocations::children(&world.runtime, "changed")?.is_empty());
    assert_eq!(
        submit(&world, "changed", "after_request", "original")?,
        rejected
    );
    replay(world.runtime.artifact(), &world.runtime.trace("changed")?)?;
    Ok(())
}

#[test]
fn an_internal_edit_cannot_change_another_row_or_keep_its_earlier_write_on_failure() -> Result<()> {
    let world = world()?;
    let other = submit(&world, "other", "Other", "untouched")?;
    let id = other.result["id"].as_str().unwrap();
    submit(&world, "target", "Target", &format!("first\n{id}"))?;
    let child = world.child("target")?;
    let before = world.runtime.inspect()?;
    let count = changes(&world)?;
    let outcome = world.finish(&child)?;
    assert_eq!(outcome.status, "failure");
    assert!(matches!(
        outcome.error.as_str(),
        "forbidden" | "application_edit_target_forbidden"
    ));
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(changes(&world)?, count);
    assert!(invocations::children(&world.runtime, &child)?.is_empty());
    replay(world.runtime.artifact(), &world.runtime.trace(&child)?)?;
    assert_eq!(world.finish(&child)?, outcome);
    assert_eq!(world.finish(&world.child("other")?)?.status, "success");
    let detail = world.detail(&Value::String(id.into()), "unaffected")?;
    assert_eq!(detail["bytes"], 9);
    assert_eq!(detail["lines"], 1);
    assert_eq!(detail["version"], 2);
    Ok(())
}
