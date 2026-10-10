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
/// admission day2-serve runs at startup. Returns each command's output.
fn rehearse(
    world: &World,
    credential_version: Option<i64>,
) -> Result<Vec<(String, std::process::Output)>> {
    let copy = tempfile::tempdir()?;
    let instance = copy.path().join("instance.json");
    fs::copy(world.runtime.instance_path(), &instance)?;
    fs::create_dir(copy.path().join(".state"))?;
    let store = copy.path().join(".state/reports.sqlite");
    rusqlite::Connection::open(world.runtime.db())?
        .execute("VACUUM INTO ?1", [store.to_str().context("store path")?])?;
    if let Some(version) = credential_version {
        rusqlite::Connection::open(&store)?.execute(
            "UPDATE day2_credential_schema_version SET version=?1",
            [version],
        )?;
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
    let day2 = |arguments: &[&str]| -> Result<std::process::Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_day2"))
            .args(arguments)
            .output()?)
    };
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
    Ok(outputs)
}

#[test]
fn rehearsed_activation_admits_only_a_store_the_target_opens() -> Result<()> {
    let world = World::new()?;
    let admitted = rehearse(&world, None)?;
    for (step, output) in &admitted {
        ensure!(
            output.status.success(),
            "{step}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let receipt: serde_json::Value = serde_json::from_slice(&admitted[3].1.stdout)?;
    assert_eq!(receipt["admitted"], true);
    assert_eq!(receipt["artifact"], world.runtime.artifact().id());

    // A credential unit from before the current private schema: the migration
    // and the activation succeed, and the store admission refuses it, exactly
    // where day2-serve would after a real activation.
    let refused = rehearse(&world, Some(1))?;
    for (step, output) in &refused[..3] {
        ensure!(
            output.status.success(),
            "{step}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let (step, output) = &refused[3];
    assert_eq!(step, "admit");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported credential schema version"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The rehearsals changed only their copies.
    day2::deployment::admit_store(&world.runtime)?;
    Ok(())
}
