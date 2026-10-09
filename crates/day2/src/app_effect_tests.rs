//! Native SQLite authority tests; no worker-supplied observation grants creation authority.
use super::*;
use crate::app_contract::{Effect, Execution};
use std::collections::BTreeMap;

fn fixture(db: &Connection) -> Result<Schema> {
    db.execute_batch(PLATFORM_DDL)?;
    db.execute_batch("BEGIN IMMEDIATE")?;
    crate::audit::upgrade(db)?;
    let schema = Schema {
        models: ["parents", "children"]
            .map(|name| {
                (
                    name.into(),
                    Record {
                        fields: BTreeMap::from([
                            ("owner".into(), Kind::Text),
                            ("status".into(), Kind::Text),
                        ]),
                        roc_type: None,
                        identity: None,
                    },
                )
            })
            .into(),
        inputs: BTreeMap::new(),
        foreign_keys: vec![],
        rollups: Vec::new(),
        indexes: vec![],
        domains: BTreeMap::new(),
    };
    for ddl in schema.ddl()? {
        db.execute_batch(&ddl)?;
    }
    for invocation in ["current", "foreign"] {
        db.execute("INSERT INTO day2_invocations(id,operation,actor,input,artifact,now,status) VALUES(?1,'change','alice','{}','artifact',100,'pending')", [invocation])?;
    }
    db.execute_batch("COMMIT")?;
    Ok(schema)
}

fn request(invocation: &str) -> Request {
    Request {
        operation: "change".into(),
        input: json!({"id":"1", "version":1}).to_string(),
        context: Context {
            authentication: "request".into(),
            caller: Vec::new(),
            authenticated: String::new(),
            delegation_rule: String::new(),
            invocation_id: invocation.into(),
            actor: "alice".into(),
            now: 100,
        },
        observations: vec![],
    }
}

fn policy() -> Result<Policy> {
    let grant = json!({"read":true,"create":true,"update_fields":["status"],"rows":{"kind":"owner_or_admin","field":"owner"}});
    Ok(serde_json::from_value(
        json!({"version":1,"operations":{"change":{
            "actors":["alice"],"mode":{"kind":"current_state"},"models":{"parents":grant,"children":grant}
        }}}),
    )?)
}

fn declaration(kind: &str, model: &str, edit: bool) -> Execution {
    Execution {
        effects: vec![Effect {
            kind: kind.into(),
            model: model.into(),
            fields: vec!["status".into()],
            command: String::new(),
        }],
        model: if edit { "parents" } else { "" }.into(),
        id_field: if edit { "id" } else { "" }.into(),
        version_field: if edit { "version" } else { "" }.into(),
        ..Execution::default()
    }
}

fn create(db: &Connection, schema: &Schema, request: &mut Request, model: &str) -> Result<Row> {
    let instruction = Instruction {
        kind: "create".into(),
        model: model.into(),
        data: json!({"owner":"alice","status":"pending"}).to_string(),
        ..Instruction::default()
    };
    let result = effect(
        db,
        schema,
        request,
        &instruction,
        EffectContext {
            scope: "installation-a",
            policy: &policy()?,
            operation: "change",
            entropy: &crate::host_inputs::SecureEntropy,
        },
    )?;
    let row = serde_json::from_str(&result)?;
    request.observations.push(Observation {
        instruction,
        result,
        error: String::new(),
    });
    Ok(row)
}

fn update(model: &str, row: &Row) -> Instruction {
    Instruction {
        kind: "update".into(),
        model: model.into(),
        id: row.id,
        expected_version: row.version,
        data: json!({"owner":"alice","status":"complete"}).to_string(),
        ..Instruction::default()
    }
}

fn check(
    db: &Connection,
    schema: &Schema,
    execution: &Execution,
    request: &Request,
    instruction: &Instruction,
) -> Result<()> {
    check_app_effect(
        db,
        schema,
        execution,
        instruction,
        &serde_json::from_str(&request.input)?,
        &request.context.invocation_id,
    )
}

#[test]
fn created_update_requires_native_exact_origin_and_preserves_primary_edit_target() -> Result<()> {
    let db = Connection::open_in_memory()?;
    let schema = fixture(&db)?;
    db.execute_batch("BEGIN IMMEDIATE")?;
    let mut current = request("current");
    let mut foreign = request("foreign");
    let own = create(&db, &schema, &mut current, "children")?;
    let other = create(&db, &schema, &mut foreign, "children")?;
    let primary_other = create(&db, &schema, &mut current, "parents")?;
    for edit in [false, true] {
        let declared = declaration("update_created", "children", edit);
        check(&db, &schema, &declared, &current, &update("children", &own))?;
        // A forged successful observation is not a creation receipt in this invocation.
        let mut forged = current.clone();
        forged.observations.extend(foreign.observations.clone());
        assert_eq!(
            check(
                &db,
                &schema,
                &declared,
                &forged,
                &update("children", &other)
            )
            .unwrap_err()
            .to_string(),
            "application_created_update_forbidden"
        );
    }
    assert_eq!(
        check(
            &db,
            &schema,
            &declaration("update", "children", true),
            &current,
            &update("children", &own)
        )
        .unwrap_err()
        .to_string(),
        "application_edit_target_forbidden"
    );
    assert_eq!(
        check(
            &db,
            &schema,
            &declaration("update_created", "parents", true),
            &current,
            &update("parents", &primary_other)
        )
        .unwrap_err()
        .to_string(),
        "application_edit_target_forbidden"
    );
    let mut primary_input = current.clone();
    primary_input.input = json!({"id":primary_other.id.to_string(),"version":1}).to_string();
    check(
        &db,
        &schema,
        &declaration("update_created", "parents", true),
        &primary_input,
        &update("parents", &primary_other),
    )?;
    // Same numeric ID in another model, or a version-one legacy row without native audit, grants nothing.
    for (id, model) in [(own.id, "parents"), (17.into(), "children")] {
        db.execute(
            &format!("INSERT INTO {model}(id,version,created_at,owner,status) VALUES(?1,1,100,'alice','pending')"),
            [id.sql(None)?],
        )?;
        let row = get(&db, model, &schema.models[model], id)?;
        assert_eq!(
            check(
                &db,
                &schema,
                &declaration("update_created", model, false),
                &current,
                &update(model, &row)
            )
            .unwrap_err()
            .to_string(),
            "application_created_update_forbidden"
        );
    }
    // Updating a preexisting row creates an audit entry, but never a creation proof.
    let preexisting = get(&db, "children", &schema.models["children"], 17.into())?;
    effect(
        &db,
        &schema,
        &current,
        &update("children", &preexisting),
        EffectContext {
            scope: "installation-a",
            policy: &policy()?,
            operation: "change",
            entropy: &crate::host_inputs::SecureEntropy,
        },
    )?;
    assert!(!crate::audit::created_by_invocation(
        &db,
        "current",
        "children",
        preexisting.id
    )?);
    let mut forbidden_field = update("children", &own);
    forbidden_field.data = json!({"owner":"bob","status":"complete"}).to_string();
    assert_eq!(
        check(
            &db,
            &schema,
            &declaration("update_created", "children", true),
            &current,
            &forbidden_field
        )
        .unwrap_err()
        .to_string(),
        "undeclared_application_update_field"
    );
    db.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn created_update_survives_reopen_but_not_rollback_or_another_installation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("app.sqlite");
    let db = Connection::open(&path)?;
    let schema = fixture(&db)?;
    let mut current = request("current");
    db.execute_batch("BEGIN IMMEDIATE")?;
    let own = create(&db, &schema, &mut current, "children")?;
    db.execute_batch("COMMIT")?;
    drop(db);
    let db = Connection::open(&path)?;
    db.execute_batch("BEGIN IMMEDIATE")?;
    let declared = declaration("update_created", "children", true);
    let instruction = update("children", &own);
    check(&db, &schema, &declared, &current, &instruction)?;
    effect(
        &db,
        &schema,
        &current,
        &instruction,
        EffectContext {
            scope: "installation-a",
            policy: &policy()?,
            operation: "change",
            entropy: &crate::host_inputs::SecureEntropy,
        },
    )?;
    db.execute_batch("ROLLBACK; BEGIN IMMEDIATE")?;
    assert_eq!(
        get(&db, "children", &schema.models["children"], own.id)?.version,
        1
    );
    check(&db, &schema, &declared, &current, &instruction)?;
    let result = effect(
        &db,
        &schema,
        &current,
        &instruction,
        EffectContext {
            scope: "installation-a",
            policy: &policy()?,
            operation: "change",
            entropy: &crate::host_inputs::SecureEntropy,
        },
    )?;
    current.observations.push(Observation {
        instruction,
        result,
        error: String::new(),
    });
    db.execute_batch("COMMIT; BEGIN IMMEDIATE")?;
    let rolled_back = create(&db, &schema, &mut current, "parents")?;
    assert!(crate::audit::created_by_invocation(
        &db,
        "current",
        "parents",
        rolled_back.id
    )?);
    db.execute_batch("ROLLBACK; BEGIN IMMEDIATE")?;
    assert!(!crate::audit::created_by_invocation(
        &db,
        "current",
        "parents",
        rolled_back.id
    )?);
    db.execute_batch("ROLLBACK")?;
    assert!(crate::audit::created_by_invocation(&db, "current", "children", own.id).is_err());
    let other_installation = Connection::open_in_memory()?;
    fixture(&other_installation)?;
    other_installation.execute_batch("BEGIN IMMEDIATE")?;
    assert!(!crate::audit::created_by_invocation(
        &other_installation,
        "current",
        "children",
        own.id
    )?);
    Ok(())
}

#[test]
fn created_origin_does_not_refresh_cas_or_override_current_operator_authority() -> Result<()> {
    let db = Connection::open_in_memory()?;
    let schema = fixture(&db)?;
    db.execute_batch("BEGIN IMMEDIATE")?;
    let mut current = request("current");
    let own = create(&db, &schema, &mut current, "children")?;
    let instruction = update("children", &own);
    let declared = declaration("update_created", "children", true);
    check(&db, &schema, &declared, &current, &instruction)?;
    let foreign = request("foreign");
    effect(
        &db,
        &schema,
        &foreign,
        &instruction,
        EffectContext {
            scope: "installation-a",
            policy: &policy()?,
            operation: "change",
            entropy: &crate::host_inputs::SecureEntropy,
        },
    )?;
    check(&db, &schema, &declared, &current, &instruction)?;
    let conflict = effect(
        &db,
        &schema,
        &current,
        &instruction,
        EffectContext {
            scope: "installation-a",
            policy: &policy()?,
            operation: "change",
            entropy: &crate::host_inputs::SecureEntropy,
        },
    )
    .unwrap_err();
    assert_eq!(crate::error::observation_code(&conflict), "conflict");
    let fresh = get(&db, "children", &schema.models["children"], own.id)?;
    let instruction = update("children", &fresh);
    for mode in [
        crate::authority::Mode::Read,
        crate::authority::Mode::Edit {
            model: "parents".into(),
            id_field: "id".into(),
            version_field: "version".into(),
        },
    ] {
        let mut restricted = policy()?;
        restricted.operations.get_mut("change").unwrap().mode = mode;
        assert!(
            effect(
                &db,
                &schema,
                &current,
                &instruction,
                EffectContext {
                    scope: "installation-a",
                    policy: &restricted,
                    operation: "change",
                    entropy: &crate::host_inputs::SecureEntropy,
                },
            )
            .is_err()
        );
        assert!(
            restricted
                .check_create(
                    "change",
                    "children",
                    "alice",
                    &json!({"owner":"alice","status":"pending"})
                )
                .is_err()
        );
    }
    let mut revoked = policy()?;
    revoked.operations.get_mut("change").unwrap().actors.clear();
    assert!(
        effect(
            &db,
            &schema,
            &current,
            &instruction,
            EffectContext {
                scope: "installation-a",
                policy: &revoked,
                operation: "change",
                entropy: &crate::host_inputs::SecureEntropy,
            },
        )
        .is_err()
    );
    let mut fields_revoked = policy()?;
    fields_revoked
        .operations
        .get_mut("change")
        .unwrap()
        .models
        .get_mut("children")
        .unwrap()
        .update_fields
        .clear();
    assert!(
        effect(
            &db,
            &schema,
            &current,
            &instruction,
            EffectContext {
                scope: "installation-a",
                policy: &fields_revoked,
                operation: "change",
                entropy: &crate::host_inputs::SecureEntropy,
            },
        )
        .is_err()
    );
    let mut wrong_owner = current.clone();
    wrong_owner.context.actor = "bob".into();
    let mut owner_policy = policy()?;
    owner_policy
        .operations
        .get_mut("change")
        .unwrap()
        .actors
        .insert("bob".into());
    assert!(
        effect(
            &db,
            &schema,
            &wrong_owner,
            &instruction,
            EffectContext {
                scope: "installation-a",
                policy: &owner_policy,
                operation: "change",
                entropy: &crate::host_inputs::SecureEntropy,
            },
        )
        .is_err()
    );
    // A fresh read may update after another writer, but still uses its observed revision.
    check(&db, &schema, &declared, &current, &instruction)?;
    effect(
        &db,
        &schema,
        &current,
        &instruction,
        EffectContext {
            scope: "installation-a",
            policy: &policy()?,
            operation: "change",
            entropy: &crate::host_inputs::SecureEntropy,
        },
    )?;
    Ok(())
}

/// Deletion is a state the row is in, not a row that stopped existing.
///
/// The whole point of the platform's stance is that an application cannot lose
/// a record: the strongest thing it can say is "hide this", and the executor
/// has to make that hiding total (no read path still returns it) and total
/// undo (a restore puts it back exactly, same id, same data). Both halves are
/// here because either one alone is a different, worse product — hiding
/// without undo is deletion with extra steps, undo without hiding is a flag
/// nobody honours.
#[test]
fn a_soft_deleted_row_leaves_every_read_until_a_restore_brings_it_back() -> Result<()> {
    let db = Connection::open_in_memory()?;
    let schema = fixture(&db)?;
    db.execute_batch("BEGIN IMMEDIATE")?;
    let mut current = request("current");
    let row = create(&db, &schema, &mut current, "children")?;
    let record = &schema.models["children"];

    let change = |kind: &str, version: i64| Instruction {
        kind: kind.into(),
        model: "children".into(),
        id: row.id,
        expected_version: version,
        ..Instruction::default()
    };
    // Each attempt records its observation, successful or not, exactly as the
    // runtime does — otherwise two writes in one invocation collide on the
    // audit ordinal and the test would be measuring that instead.
    let run = |request: &mut Request, instruction: &Instruction| -> Result<String> {
        let result = effect(
            &db,
            &schema,
            request,
            instruction,
            EffectContext {
                scope: "installation-a",
                policy: &policy()?,
                operation: "change",
                entropy: &crate::host_inputs::SecureEntropy,
            },
        );
        request.observations.push(Observation {
            instruction: instruction.clone(),
            result: result.as_deref().unwrap_or_default().into(),
            error: result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default(),
        });
        result
    };

    // Declaring the delete is enough to declare the undo, and an operation
    // that declared neither cannot reach either.
    let declared = declaration("soft_delete", "children", false);
    check(&db, &schema, &declared, &current, &change("soft_delete", 1))?;
    check(&db, &schema, &declared, &current, &change("restore", 1))?;
    for kind in ["soft_delete", "restore"] {
        assert_eq!(
            check(
                &db,
                &schema,
                &declaration("update", "children", false),
                &current,
                &change(kind, 1),
            )
            .unwrap_err()
            .to_string(),
            "undeclared_application_effect",
            "{kind} slipped through on an update declaration"
        );
    }

    let deleted: Row = serde_json::from_str(&run(&mut current, &change("soft_delete", 1))?)?;
    assert_eq!(
        (deleted.id, deleted.version, &deleted.data),
        (row.id, 2, &row.data),
        "deleting changed something other than the row's visibility"
    );

    // Gone from every read an application has: by id, and by selection.
    assert_eq!(
        crate::error::observation_code(&get(&db, "children", record, row.id).unwrap_err()),
        "not_found"
    );
    let live: i64 = db.query_row(
        "SELECT count(*) FROM children WHERE deleted_at=0",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(live, 0, "the row is still live in the table");
    // And an update cannot resurrect it as a side effect of editing it.
    assert_eq!(
        crate::error::observation_code(
            &run(&mut current, &update("children", &deleted)).unwrap_err()
        ),
        "not_found",
        "a deleted row is still editable"
    );
    // Deleting twice is a caller working from a stale view, not a no-op.
    assert_eq!(
        run(&mut current, &change("soft_delete", 2))
            .unwrap_err()
            .to_string(),
        "row_already_deleted"
    );

    let restored: Row = serde_json::from_str(&run(&mut current, &change("restore", 2))?)?;
    assert_eq!(
        (restored.id, restored.version, &restored.data),
        (row.id, 3, &row.data),
        "the restored row is not the row that was deleted"
    );
    assert_eq!(get(&db, "children", record, row.id)?, restored);
    assert_eq!(
        run(&mut current, &change("restore", 3))
            .unwrap_err()
            .to_string(),
        "row_not_deleted"
    );
    // A stale version loses to the version check like any other write.
    assert_eq!(
        crate::error::observation_code(&run(&mut current, &change("soft_delete", 1)).unwrap_err()),
        "version_conflict"
    );
    Ok(())
}
