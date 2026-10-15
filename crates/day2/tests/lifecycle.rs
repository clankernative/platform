use anyhow::{Context, Result};
use day2::{
    artifact::Instance,
    properties,
    protocol::Outcome,
    store::{Fault, Runtime, replay},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

struct World {
    _directory: tempfile::TempDir,
    runtime: Runtime,
}

impl World {
    fn new() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_LIFECYCLE_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_LIFECYCLE_ARTIFACT")?;
        let actors = ["alice", "bob", "admin"];
        let mut operations = serde_json::Map::new();
        for name in [
            "create",
            "remove_child",
            "remove_parent",
            "restore_child",
            "restore_parent",
        ] {
            operations.insert(format!("lifecycle.{name}"), json!({
                "actors":actors,"mode":{"kind":"current_state"},
                "models":{
                    "parents":{"read":true,"create":true,"update_fields":["title"],"rows":{"kind":"owner_or_admin","field":"owner"}},
                    "children":{"read":true,"create":true,"update_fields":["title","parent_id"],"rows":{"kind":"owner_or_admin","field":"owner"}}
                }
            }));
        }
        let directory = tempfile::tempdir()?;
        let instance: Instance = serde_json::from_value(json!({
            "installation":"lifecycle_fixture","environment":"test",
            "apps":{"app":{"artifact":artifact,"readers":actors,"writers":actors,
                "authority":{"version":1,"admins":["admin"],"operations":operations}}}
        }))?;
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "app")?;
        runtime.initialize()?;
        Ok(Self {
            _directory: directory,
            runtime,
        })
    }

    fn invoke(
        &self,
        actor: &str,
        operation: &str,
        key: &str,
        input: Value,
        fault: Fault,
    ) -> Result<Outcome> {
        self.runtime.invoke(
            &format!("lifecycle.{operation}"),
            actor,
            key,
            &input,
            100,
            fault,
        )
    }

    fn create(&self, key: &str) -> Result<Value> {
        let outcome = self.invoke(
            "alice",
            "create",
            key,
            Self::create_input(json!(day2::identity::example("par")), false),
            Fault::None,
        )?;
        assert_eq!(outcome.status, "success", "{outcome:?}");
        Ok(outcome.result)
    }

    fn input(id_field: &str, id: &Value, version: i64) -> Value {
        let mut input = json!({id_field:id,"expected_version":version});
        if id_field == "child_id" {
            input["attempt_other"] = json!(false);
        }
        input
    }

    fn create_input(parent_id: Value, reuse_parent: bool) -> Value {
        json!({"parent_id":parent_id,"reuse_parent":reuse_parent,"parent_title":"Referenced parent","spare_title":"Spare","child_title":"Child"})
    }

    fn check(&self) -> Result<()> {
        let evidence =
            properties::require(&self.runtime, &self._directory.path().join("properties"))?;
        assert!(evidence.checks.iter().all(|check| check.passed));
        assert_eq!(
            properties::replay(self.runtime.artifact(), &evidence)?,
            evidence
        );
        self.runtime.validate_storage()
    }
}

#[test]
fn admitted_lifecycle_preserves_values_visibility_receipts_and_replay() -> Result<()> {
    let world = World::new()?;
    let created = world.create("create")?;
    let before = world.runtime.inspect()?;
    for (operation, field, id) in [
        ("remove_child", "child_id", &created["child_id"]),
        ("remove_parent", "parent_id", &created["spare_parent_id"]),
    ] {
        let input = World::input(field, id, 1);
        let removed = world.invoke("alice", operation, operation, input.clone(), Fault::None)?;
        assert_eq!(removed.status, "success", "{removed:?}");
        assert_eq!(removed.result["id"], *id);
        assert_eq!(removed.result["version"], 2);
        let retained = world.runtime.inspect()?;
        assert_eq!(
            world.invoke("alice", operation, operation, input, Fault::None)?,
            removed
        );
        assert_eq!(world.runtime.inspect()?, retained);
        replay(world.runtime.artifact(), &world.runtime.trace(operation)?)?;
        let repeated = world.invoke(
            "alice",
            operation,
            &format!("repeat-{operation}"),
            World::input(field, id, 2),
            Fault::None,
        )?;
        assert_eq!(repeated.error, "row_already_deleted");
        assert_eq!(world.runtime.inspect()?, retained);
        replay(
            world.runtime.artifact(),
            &world.runtime.trace(&format!("repeat-{operation}"))?,
        )?;
        world.check()?;
    }
    let live = world.runtime.application_snapshot()?;
    assert_eq!(live.as_value()["parents"].as_array().unwrap().len(), 1);
    assert!(live.as_value()["children"].as_array().unwrap().is_empty());
    let verification = world.runtime.verification_snapshot()?;
    assert_eq!(
        serde_json::from_str::<Value>(verification["live"].as_str().unwrap())?,
        live.as_value().clone()
    );
    let deleted: Value = serde_json::from_str(verification["deleted"].as_str().unwrap())?;
    assert_eq!(deleted["parents"][0]["id"], created["spare_parent_id"]);
    assert_eq!(deleted["children"][0]["id"], created["child_id"]);
    for (operation, field, id) in [
        ("restore_parent", "parent_id", &created["spare_parent_id"]),
        ("restore_child", "child_id", &created["child_id"]),
    ] {
        let restored = world.invoke(
            "alice",
            operation,
            operation,
            World::input(field, id, 2),
            Fault::None,
        )?;
        assert_eq!(restored.status, "success", "{restored:?}");
        assert_eq!(restored.result["version"], 3);
        replay(world.runtime.artifact(), &world.runtime.trace(operation)?)?;
        let repeated = world.invoke(
            "alice",
            operation,
            &format!("repeat-{operation}"),
            World::input(field, id, 3),
            Fault::None,
        )?;
        assert_eq!(repeated.error, "row_not_deleted");
        world.check()?;
    }
    let after = world.runtime.inspect()?;
    for table in ["parents", "children"] {
        for original in before[table].as_array().unwrap() {
            let restored = after[table]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == original["id"])
                .unwrap();
            assert_eq!(restored["data"], original["data"]);
            assert_eq!(restored["created_at"], original["created_at"]);
        }
    }
    Ok(())
}

#[test]
fn admitted_lifecycle_enforces_owner_versions_and_restrictive_relationships() -> Result<()> {
    let world = World::new()?;
    let created = world.create("create")?;
    let before = world.runtime.inspect()?;
    for (actor, operation, field, id, version, error) in [
        (
            "bob",
            "remove_child",
            "child_id",
            &created["child_id"],
            1,
            "forbidden",
        ),
        (
            "alice",
            "remove_child",
            "child_id",
            &created["child_id"],
            2,
            "conflict",
        ),
        (
            "alice",
            "remove_parent",
            "parent_id",
            &created["parent_id"],
            1,
            "live_reference_conflict",
        ),
    ] {
        let key = format!("reject-{actor}-{operation}-{version}");
        let outcome = world.invoke(
            actor,
            operation,
            &key,
            World::input(field, id, version),
            Fault::None,
        )?;
        assert_eq!(outcome.status, "failure");
        assert_eq!(outcome.error, error);
        assert_eq!(world.runtime.inspect()?, before);
        replay(world.runtime.artifact(), &world.runtime.trace(&key)?)?;
    }
    for (operation, field, id) in [
        ("remove_child", "child_id", &created["child_id"]),
        ("remove_parent", "parent_id", &created["parent_id"]),
    ] {
        let removed = world.invoke(
            "alice",
            operation,
            operation,
            World::input(field, id, 1),
            Fault::None,
        )?;
        assert_eq!(removed.status, "success", "{removed:?}");
    }
    let deleted = world.runtime.inspect()?;
    for (actor, error) in [("bob", "forbidden"), ("alice", "live_reference_conflict")] {
        let key = format!("restore-child-{actor}");
        let outcome = world.invoke(
            actor,
            "restore_child",
            &key,
            World::input("child_id", &created["child_id"], 2),
            Fault::None,
        )?;
        assert_eq!(outcome.error, error);
        assert_eq!(world.runtime.inspect()?, deleted);
        replay(world.runtime.artifact(), &world.runtime.trace(&key)?)?;
    }
    let parent = world.invoke(
        "alice",
        "restore_parent",
        "restore-parent",
        World::input("parent_id", &created["parent_id"], 2),
        Fault::None,
    )?;
    assert_eq!(parent.status, "success", "{parent:?}");
    let child = world.invoke(
        "alice",
        "restore_child",
        "restore-child",
        World::input("child_id", &created["child_id"], 2),
        Fault::None,
    )?;
    assert_eq!(child.status, "success", "{child:?}");
    world.check()
}

#[test]
fn admitted_lifecycle_rolls_back_interruptions_and_recovers_ambiguous_commits() -> Result<()> {
    let world = World::new()?;
    let created = world.create("create")?;
    let input = World::input("child_id", &created["child_id"], 1);
    let before = world.runtime.inspect()?;
    let failed = world.invoke(
        "alice",
        "remove_child",
        "failed",
        input.clone(),
        Fault::FailAfterWrite(1),
    )?;
    assert_eq!(failed.status, "failure");
    assert_eq!(world.runtime.inspect()?, before);
    replay(world.runtime.artifact(), &world.runtime.trace("failed")?)?;
    assert!(
        world
            .invoke(
                "alice",
                "remove_child",
                "interrupted",
                input.clone(),
                Fault::BeforeCommit
            )
            .is_err()
    );
    assert_eq!(world.runtime.inspect()?, before);
    let removed = world.invoke("alice", "remove_child", "interrupted", input, Fault::None)?;
    assert_eq!(removed.status, "success");
    let input = World::input("child_id", &created["child_id"], 2);
    assert!(
        world
            .invoke(
                "alice",
                "restore_child",
                "ambiguous",
                input.clone(),
                Fault::AfterCommit
            )
            .is_err()
    );
    let committed = world.runtime.inspect()?;
    let recovered = world.invoke("alice", "restore_child", "ambiguous", input, Fault::None)?;
    assert_eq!(recovered.status, "success", "{recovered:?}");
    assert_eq!(recovered.result["version"], 3);
    assert_eq!(world.runtime.inspect()?, committed);
    replay(world.runtime.artifact(), &world.runtime.trace("ambiguous")?)?;
    world.check()
}

#[test]
fn admitted_lifecycle_generators_restore_from_explicit_deleted_snapshots() -> Result<()> {
    let world = World::new()?;
    let directory = tempfile::tempdir()?;
    let evidence = day2::development::verify(
        world.runtime.artifact().directory(),
        &directory.path().join("campaign"),
        127,
        4,
    )?;
    assert!(evidence.verification_complete);
    for name in [
        "create",
        "remove_child",
        "remove_parent",
        "restore_child",
        "restore_parent",
    ] {
        assert_eq!(evidence.obligations[&format!("lifecycle.{name}")], 4);
    }
    assert_eq!(evidence.traces.len(), 20);
    for trace in &evidence.traces {
        replay(world.runtime.artifact(), trace)?;
    }
    Ok(())
}

#[test]
fn admitted_lifecycle_rejects_other_row_effects_and_new_references_to_tombstones() -> Result<()> {
    let world = World::new()?;
    let first = world.create("first")?;
    let second = world.create("second")?;
    let before = world.runtime.inspect()?;
    let mut input = World::input("child_id", &first["child_id"], 1);
    input["attempt_other"] = json!(true);
    let wrong = world.invoke(
        "alice",
        "remove_child",
        "wrong-delete-target",
        input,
        Fault::None,
    )?;
    assert_eq!(wrong.error, "application_edit_target_forbidden");
    assert_eq!(world.runtime.inspect()?, before);
    replay(
        world.runtime.artifact(),
        &world.runtime.trace("wrong-delete-target")?,
    )?;
    for (key, child) in [
        ("remove-first", &first["child_id"]),
        ("remove-second", &second["child_id"]),
    ] {
        assert_eq!(
            world
                .invoke(
                    "alice",
                    "remove_child",
                    key,
                    World::input("child_id", child, 1),
                    Fault::None
                )?
                .status,
            "success"
        );
    }
    let before = world.runtime.inspect()?;
    let mut input = World::input("child_id", &first["child_id"], 2);
    input["attempt_other"] = json!(true);
    let wrong = world.invoke(
        "alice",
        "restore_child",
        "wrong-restore-target",
        input,
        Fault::None,
    )?;
    assert_eq!(wrong.error, "application_edit_target_forbidden");
    assert_eq!(world.runtime.inspect()?, before);
    replay(
        world.runtime.artifact(),
        &world.runtime.trace("wrong-restore-target")?,
    )?;
    assert_eq!(
        world
            .invoke(
                "alice",
                "remove_parent",
                "remove-spare",
                World::input("parent_id", &first["spare_parent_id"], 1),
                Fault::None
            )?
            .status,
        "success"
    );
    let before = world.runtime.inspect()?;
    let refused = world.invoke(
        "alice",
        "create",
        "attach-to-deleted",
        World::create_input(first["spare_parent_id"].clone(), true),
        Fault::None,
    )?;
    assert_eq!(refused.error, "live_reference_conflict");
    assert_eq!(
        world.runtime.inspect()?,
        before,
        "a failed child attachment must roll back both earlier parent creations"
    );
    replay(
        world.runtime.artifact(),
        &world.runtime.trace("attach-to-deleted")?,
    )?;
    world.check()
}
