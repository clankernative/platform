use anyhow::{Context, Result, ensure};
use day2::{identity::Id, properties, protocol::Row, store::Fault};
use serde_json::json;

#[test]
fn operation_campaign_checks_large_before_and_after_snapshots() -> Result<()> {
    use day2::{automation, development};
    use rusqlite::{Connection, params};
    use std::{collections::BTreeMap, path::PathBuf};

    let artifact = std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
        .map(PathBuf::from)
        .context("run xtask verify with compiled Reports")?;
    let directory = tempfile::tempdir()?;
    let runtime = development::create(&artifact, &directory.path().join("instance"), None)?;
    let identity = runtime.artifact().contract().schema.models["reports"]
        .identity
        .as_ref()
        .context("Reports identity")?;
    // Exercise nested JSON escaping as well as both lifecycle scopes. The real
    // operations still use small inputs and bounded pages; only verification
    // callbacks receive the complete state. Seed completed announcements so
    // sweep does not turn snapshot capacity into a large command fan-out.
    let text = "Quoted \"text\" and a backslash \\\n".repeat(128);
    let mut connection = Connection::open(runtime.db())?;
    let transaction = connection.transaction()?;
    for ordinal in 1..=512 {
        let id = day2::identity::generate(&[23; 32], 200_000, &identity.key, ordinal)?;
        transaction.execute(
            "INSERT INTO reports(id,version,created_at,deleted_at,title,text,owner,ready,announced,bytes,lines) \
             VALUES(?1,1,200000,?2,?3,?4,'developer',1,1,?5,?6)",
            params![
                id.as_slice(),
                if ordinal <= 16 { 200_001 } else { 0 },
                format!("Report {ordinal}"),
                text,
                (text.len() as u64).to_be_bytes().as_slice(),
                (text.split('\n').count() as u64).to_be_bytes().as_slice(),
            ],
        )?;
    }
    transaction.commit()?;
    runtime.validate_storage()?;
    let snapshot = serde_json::to_vec(&runtime.verification_snapshot()?)?;
    ensure!(
        snapshot.len() > 1_048_576
            && snapshot.len()
                < runtime
                    .artifact()
                    .contract()
                    .verification_limits
                    .snapshot_bytes,
        "campaign must exceed the ordinary frame limit within the verification budget"
    );

    let mut campaign = development::Campaign::for_actor(
        runtime,
        None,
        42,
        1,
        development::ACTOR,
        false,
        development::CampaignTime::Verification,
    )?;
    let mut completed = BTreeMap::<String, usize>::new();
    automation::run(&automation::runner()?, &["exercise", "", "1"], |request| {
        let action = request.action.clone();
        let result = campaign.effect(request)?;
        *completed.entry(action).or_default() += 1;
        Ok(result)
    })?;
    ensure!(campaign.is_complete() && campaign.evidence.verification_complete);
    ensure!(campaign.evidence.failure.is_none());
    let operations = campaign.runtime.artifact().contract().operations.len();
    ensure!(completed.get("dev-prepare-sample") == Some(&operations));
    ensure!(completed.get("dev-assert") == Some(&operations));
    ensure!(completed.get("dev-errors") == Some(&1));
    ensure!(
        campaign
            .evidence
            .obligations
            .values()
            .all(|count| *count == 1)
    );
    Ok(())
}

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
