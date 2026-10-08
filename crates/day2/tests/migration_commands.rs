use crate::support::commands as support;
use anyhow::Result;
use day2::{invocations, migration, store::Fault};
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
