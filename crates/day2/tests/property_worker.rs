use anyhow::{Context, Result, ensure};
use day2::{identity::Id, properties, protocol::Row, store::Fault};
use serde_json::json;

#[test]
fn qualified_property_worker_evaluates_and_replays_ten_thousand_typed_rows() -> Result<()> {
    let world = crate::support::commands::World::new()?;
    let submitted = world.submit("capacity-seed", Fault::None)?;
    ensure!(
        submitted.status == "success",
        "seed command failed: {}",
        submitted.error
    );
    let seed_snapshot = world.runtime.application_snapshot()?;
    let seed = seed_snapshot.as_value()["reports"]
        .as_array()
        .and_then(|rows| rows.first())
        .context("typed seed report missing")?;
    let seed: Row = serde_json::from_value(seed.clone())?;
    let identity = world.runtime.artifact().contract().schema.models["reports"]
        .identity
        .as_ref()
        .context("Reports identity")?;

    let rows = (1_u64..=10_000)
        .map(|number| {
            Ok(serde_json::to_value(Row {
                id: Id::from_uuid(
                    &identity.prefix,
                    day2::identity::generate(&[23; 32], 200_000, &identity.key, number)?,
                )?,
                ..seed.clone()
            })?)
        })
        .collect::<Result<Vec<_>>>()?;
    let snapshot = json!({"reports":rows});
    ensure!(
        serde_json::to_vec(&snapshot)?.len() > 1_048_576,
        "capacity regression must cross the ordinary worker frame limit"
    );
    let evidence = properties::evaluate(world.runtime.artifact(), &snapshot)?;
    ensure!(
        evidence.checks.iter().all(|check| check.passed),
        "qualified properties rejected 10,000 valid typed rows"
    );
    ensure!(properties::replay(world.runtime.artifact(), &evidence)? == evidence);

    let mut over_limit = snapshot["reports"]
        .as_array()
        .context("report rows")?
        .clone();
    over_limit.push(serde_json::to_value(Row {
        id: Id::from_uuid(
            &identity.prefix,
            day2::identity::generate(&[23; 32], 200_000, &identity.key, 10_001)?,
        )?,
        ..seed
    })?);
    ensure!(
        properties::evaluate(world.runtime.artifact(), &json!({"reports":over_limit})).is_err(),
        "10,001 rows must fail closed before worker evaluation"
    );
    Ok(())
}
