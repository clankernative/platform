use crate::support::commands as support;
use anyhow::{Context, Result, ensure};
use day2::{authority_state, invocations, migration, store::Fault};
use std::{fs, process::Command};
use support::World;

#[test]
fn migration_and_activation_require_drain_at_acceptance_preparation_and_external_effect_boundaries()
-> Result<()> {
    for phase in 0..4 {
        let world = World::new()?;
        world.submit("submit", Fault::None)?;
        let analysis = world.child("submit")?;
        if phase == 1 {
            assert!(
                world
                    .runtime
                    .execute(&analysis, Fault::AfterPrepare)
                    .is_err()
            );
        }
        if phase >= 2 {
            assert_eq!(world.finish(&analysis)?.status, "success");
            let notify = world.child(&analysis)?;
            assert_eq!(
                world.runtime.execute(&notify, Fault::None)?.status,
                "pending"
            );
            if phase == 3 {
                assert!(
                    world
                        .runtime
                        .execute(&notify, Fault::AfterExternal(1))
                        .is_err()
                );
            }
        }
        let instance = std::fs::read(world.runtime.instance_path())?;
        let before = world.runtime.inspect()?;
        let plan = migration::plan(&world.runtime, world.runtime.artifact())?;
        assert_eq!(
            migration::apply(&world.runtime, world.runtime.artifact(), &plan)
                .unwrap_err()
                .to_string(),
            "migration_requires_drained_invocations"
        );
        assert!(migration::activate(&world.runtime, world.runtime.artifact()).is_err());
        assert_eq!(world.runtime.inspect()?, before);
        assert_eq!(std::fs::read(world.runtime.instance_path())?, instance);
        assert!(
            invocations::drain(&world.runtime, 16)?
                .iter()
                .all(|item| item.status == "success")
        );
        migration::apply(&world.runtime, world.runtime.artifact(), &plan)?;
        migration::activate(&world.runtime, world.runtime.artifact())?;
    }
    Ok(())
}

#[test]
fn replaying_a_migration_receipt_does_not_bypass_new_pending_commands() -> Result<()> {
    let world = World::new()?;
    let plan = migration::plan(&world.runtime, world.runtime.artifact())?;
    migration::apply(&world.runtime, world.runtime.artifact(), &plan)?;
    world.submit("late", Fault::None)?;
    assert_eq!(
        migration::apply(&world.runtime, world.runtime.artifact(), &plan)
            .unwrap_err()
            .to_string(),
        "migration_requires_drained_invocations"
    );
    invocations::drain(&world.runtime, 16)?;
    migration::apply(&world.runtime, world.runtime.artifact(), &plan)?;
    Ok(())
}

/// The in-pod commands `day2 platform maintain activate` rehearses before its
/// migration fence, on a copy of the store under the target instance:
/// migration plan and apply, activation, then `day2 admit`, which is the store
/// admission day2-serve runs at startup. `change` is SQL applied to the copy
/// first. Returns the copy and each command's output.
fn rehearse(
    world: &World,
    change: Option<&str>,
) -> Result<(tempfile::TempDir, Vec<(String, std::process::Output)>)> {
    let copy = tempfile::tempdir()?;
    let instance = copy.path().join("instance.json");
    fs::copy(world.runtime.instance_path(), &instance)?;
    fs::create_dir(copy.path().join(".state"))?;
    let store = copy.path().join(".state/reports.sqlite");
    rusqlite::Connection::open(world.runtime.db())?
        .execute("VACUUM INTO ?1", [store.to_str().context("store path")?])?;
    if let Some(change) = change {
        rusqlite::Connection::open(&store)?.execute_batch(change)?;
    }
    let artifact = world
        .runtime
        .artifact()
        .directory()
        .to_str()
        .context("artifact")?
        .to_owned();
    let instance = instance.to_str().context("instance")?.to_owned();
    let plan = copy
        .path()
        .join("plan.json")
        .to_str()
        .context("plan")?
        .to_owned();
    let mut outputs = Vec::new();
    for step in ["migration-plan", "migration-apply"] {
        outputs.push((
            step.to_owned(),
            day2(&[step, &instance, "reports", &artifact, &plan])?,
        ));
    }
    let expected = serde_json::to_string(
        &authority_state::current(&rusqlite::Connection::open(&store)?)?.stamp,
    )?;
    outputs.push((
        "activate".to_owned(),
        day2(&[
            "activate",
            &instance,
            "reports",
            &artifact,
            "alice",
            &expected,
            "rehearsal",
        ])?,
    ));
    outputs.push(("admit".to_owned(), day2(&["admit", &instance, "reports"])?));
    Ok((copy, outputs))
}

fn day2(arguments: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_day2"))
        .args(arguments)
        .output()?)
}

fn succeeded(outputs: &[(String, std::process::Output)]) -> Result<()> {
    for (step, output) in outputs {
        ensure!(
            output.status.success(),
            "{step}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Every table's rows, in a fixed order.
fn store_rows(store: &std::path::Path) -> Result<Vec<(String, Vec<String>)>> {
    let db = rusqlite::Connection::open(store)?;
    let tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut rows = Vec::new();
    for table in tables {
        let mut statement = db.prepare(&format!("SELECT * FROM \"{table}\" ORDER BY rowid"))?;
        let columns = statement.column_count();
        let values = statement
            .query_map([], |row| {
                (0..columns)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map(|values| format!("{values:?}"))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.push((table, values));
    }
    Ok(rows)
}

/// Replaces the store's credential unit with the version-1 unit builds before
/// the version-2 unit installed in every store, GoLinks' among them.
const VERSION_1_UNIT: &str = concat!(
    "DROP TABLE day2_credential_reveals; DROP TABLE day2_credential_revocations;
    DROP TABLE day2_credential_receipts; DROP TABLE day2_credential_deliveries;
    DROP TABLE day2_credential_material; DROP TABLE day2_credential_versions;
    DROP TABLE day2_credential_lineages; DROP TABLE day2_credential_confirmations;
    DROP TABLE day2_credential_browser; DROP TABLE day2_credential_origins;
    DROP TABLE day2_credential_schema_version;",
    include_str!("../fixtures/credential-schema-v1.sql")
);

#[test]
fn rehearsed_activation_admits_only_a_store_the_target_opens() -> Result<()> {
    let world = World::new()?;
    world.submit("submit", Fault::None)?;
    invocations::drain(&world.runtime, 16)?;
    let (_copy, admitted) = rehearse(&world, None)?;
    succeeded(&admitted)?;
    let receipt: serde_json::Value = serde_json::from_slice(&admitted[3].1.stdout)?;
    assert_eq!(receipt["admitted"], true);
    assert_eq!(receipt["artifact"], world.runtime.artifact().id());

    // GoLinks' persisted links are the one data migration AGENTS.md allows. A
    // store written before the version-2 credential unit holds an empty
    // version-1 unit beside its app rows: the target replaces that unit and
    // admits the store, and the app rows are untouched.
    let (copy, replaced) = rehearse(&world, Some(VERSION_1_UNIT))?;
    succeeded(&replaced)?;
    let store = copy.path().join(".state/reports.sqlite");
    let app = |store: &std::path::Path| -> Result<Vec<(String, Vec<String>)>> {
        Ok(store_rows(store)?
            .into_iter()
            .filter(|(table, _)| !table.starts_with("day2_"))
            .collect())
    };
    let reports = app(world.runtime.db())?;
    assert!(reports.iter().any(|(_, rows)| !rows.is_empty()));
    assert_eq!(app(&store)?, reports);
    let version: i64 = rusqlite::Connection::open(&store)?.query_row(
        "SELECT version FROM day2_credential_schema_version",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 2);
    // The replaced unit is current, so admitting the store again changes nothing.
    let before = store_rows(&store)?;
    let instance = copy.path().join("instance.json");
    let again = day2(&["admit", instance.to_str().context("instance")?, "reports"])?;
    succeeded(&[("admit".to_owned(), again)])?;
    assert_eq!(store_rows(&store)?, before);

    // A version-1 unit holding credential state, and any other unit version:
    // the migration and the activation succeed, and the store admission
    // refuses the store, exactly where day2-serve would after a real activation.
    let occupied = format!(
        "{VERSION_1_UNIT} INSERT INTO day2_credential_browser VALUES('invocation','attempt','{{}}',1);"
    );
    for (change, refusal) in [
        (occupied.as_str(), "holds credential state"),
        (
            "UPDATE day2_credential_schema_version SET version=3",
            "unsupported credential schema version",
        ),
    ] {
        let (_copy, refused) = rehearse(&world, Some(change))?;
        succeeded(&refused[..3])?;
        let (step, output) = &refused[3];
        assert_eq!(step, "admit");
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(refusal),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // The rehearsals changed only their copies.
    day2::deployment::admit_store(&world.runtime)?;
    Ok(())
}
