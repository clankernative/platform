use anyhow::Result;
use day2::{
    artifact::Operation,
    authority::{Change, Policy, RowFilter},
    protocol::Row,
    schema::Schema,
};
use proptest::{
    prelude::*,
    test_runner::{Config, RngSeed, TestRunner},
};
use serde_json::{Value, json};

fn contracts() -> Result<(Vec<Operation>, Schema)> {
    Ok((
        serde_json::from_value(json!([
            {"name":"links.list","kind":"query","input_type":"list"},
            {"name":"links.create","kind":"command","input_type":"create"},
            {"name":"links.edit","kind":"command","input_type":"edit"},
            {"name":"links.current","kind":"command","input_type":"edit"},
            {"name":"admin.salaries","kind":"query","input_type":"list"}
        ]))?,
        serde_json::from_value(json!({
            "models": {
                "links":{"fields":{"owner":"text","title":{"text_domain":{"roc_type":"Title"}},"archived":"boolean"}},
                "secrets":{"fields":{"content":"text"}}
            },
            "inputs": {
                "list":{"fields":{}},
                "create":{"fields":{"title":{"text_domain":{"roc_type":"Title"}}}},
                "edit":{"fields":{"link_id":{"reference":{"target":"links"}},"expected_version":"integer","title":{"text_domain":{"roc_type":"Title"}}}}
            },
            "foreign_keys":[]
        }))?,
    ))
}

fn policy_json() -> Value {
    let readers = json!({"actors":["alice","bob","admin"],"mode":{"kind":"read"},"models":{"links":{"read":true,"rows":{"kind":"owner_or_admin","field":"owner"}}}});
    let edit = json!({"actors":["alice","bob","admin"],"mode":{"kind":"edit","model":"links","id_field":"link_id","version_field":"expected_version"},"models":{"links":{"read":true,"update_fields":["title"],"rows":{"kind":"owner_or_admin","field":"owner"}}}});
    let mut current = edit.clone();
    current["mode"] = json!({"kind":"current_state"});
    json!({
        "version":1,
        "admins":["admin"],
        "operations": {
            "links.list":readers,
            "links.create":{"actors":["alice","bob","admin"],"mode":{"kind":"current_state"},"models":{"links":{"read":true,"create":true,"rows":{"kind":"owner_or_admin","field":"owner"}}}},
            "links.edit":edit,
            "links.current":current,
            "admin.salaries":{"actors":[],"mode":{"kind":"read"},"models":{}}
        },
        "constraints":{"links":{"title":{"nonempty":true,"max_bytes":200}}}
    })
}

fn policy() -> Result<Policy> {
    let policy: Policy = serde_json::from_value(policy_json())?;
    let (operations, schema) = contracts()?;
    policy.validate(&operations, &schema)?;
    Ok(policy)
}

fn value(owner: &str, title: &str) -> Value {
    json!({"owner":owner,"title":title,"archived":false})
}

fn input(version: i64) -> Value {
    json!({"link_id":"42","expected_version":version,"title":"Next"})
}

#[test]
fn operation_grants_are_explicit_and_admin_is_not_a_superuser() -> Result<()> {
    let policy = policy()?;
    policy.authorize("links.edit", "alice")?;
    for actor in ["alice", "admin", "unknown"] {
        assert!(policy.authorize("admin.salaries", actor).is_err());
        assert!(policy.authorize("unregistered.command", actor).is_err());
    }
    assert!(policy.authorize("links.edit", "unknown").is_err());
    assert!(
        policy
            .check_read(
                "links.list",
                "secrets",
                "admin",
                &json!({"content":"secret"})
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn owner_scope_applies_to_reads_and_is_available_before_pagination() -> Result<()> {
    let policy = policy()?;
    assert_eq!(
        policy.read_scope("links.list", "links", "alice")?,
        RowFilter::Owner {
            field: "owner".into(),
            actor: "alice".into()
        }
    );
    assert_eq!(
        policy.read_scope("links.list", "links", "admin")?,
        RowFilter::All
    );
    policy.check_read("links.list", "links", "alice", &value("alice", "Mine"))?;
    policy.check_read("links.list", "links", "admin", &value("bob", "Another"))?;
    assert!(
        policy
            .check_read("links.list", "links", "alice", &value("bob", "Another"))
            .is_err()
    );
    assert!(
        policy
            .read_scope("admin.salaries", "links", "alice")
            .is_err()
    );
    Ok(())
}

#[test]
fn owner_assignment_and_field_writes_are_host_guarded() -> Result<()> {
    let policy = policy()?;
    for actor in ["alice", "admin"] {
        policy.check_create("links.create", "links", actor, &value(actor, "Initial"))?;
        assert!(
            policy
                .check_create("links.create", "links", actor, &value("bob", "Initial"))
                .is_err()
        );
        let before = value("alice", "Initial");
        let next = value("alice", "Next");
        policy.check_update(
            "links.edit",
            "links",
            actor,
            &input(1),
            &Change {
                id: 42.into(),
                before: &before,
                after: &next,
            },
        )?;
        for after in [
            value("bob", "Next"),
            json!({"owner":"alice","title":"Next","archived":true}),
        ] {
            assert!(
                policy
                    .check_update(
                        "links.edit",
                        "links",
                        actor,
                        &input(1),
                        &Change {
                            id: 42.into(),
                            before: &before,
                            after: &after
                        }
                    )
                    .is_err()
            );
        }
    }
    let before = value("bob", "Initial");
    let next = value("bob", "Next");
    assert!(
        policy
            .check_update(
                "links.edit",
                "links",
                "alice",
                &input(1),
                &Change {
                    id: 42.into(),
                    before: &before,
                    after: &next
                }
            )
            .is_err()
    );
    assert!(
        policy
            .check_create("links.edit", "links", "alice", &value("alice", "Initial"))
            .is_err()
    );
    Ok(())
}

#[test]
fn model_ownership_remains_immutable_through_broader_operation_grants() -> Result<()> {
    let (operations, schema) = contracts()?;
    let mut raw = policy_json();
    for operation in ["links.create", "links.edit", "links.current"] {
        raw["operations"][operation]["models"]["links"]["rows"] = json!({"kind":"all"});
    }
    let policy: Policy = serde_json::from_value(raw.clone())?;
    policy.validate(&operations, &schema)?;
    assert_eq!(
        policy.read_scope("links.current", "links", "alice")?,
        RowFilter::All
    );
    let before = value("bob", "Initial");
    let unchanged_owner = value("bob", "Next");
    for actor in ["alice", "admin"] {
        policy.check_create("links.create", "links", actor, &value(actor, "Initial"))?;
        assert!(
            policy
                .check_create("links.create", "links", actor, &value("bob", "Initial"))
                .is_err()
        );
        policy.check_update(
            "links.current",
            "links",
            actor,
            &input(1),
            &Change {
                id: 42.into(),
                before: &before,
                after: &unchanged_owner,
            },
        )?;
    }
    raw["operations"]["links.current"]["models"]["links"]["update_fields"] =
        json!(["title", "owner"]);
    let forged: Policy = serde_json::from_value(raw)?;
    let error = forged.validate(&operations, &schema).unwrap_err();
    assert!(error.to_string().contains("immutable across all grants"));
    let transferred = value("alice", "Next");
    for actor in ["alice", "admin"] {
        assert!(
            forged
                .check_update(
                    "links.current",
                    "links",
                    actor,
                    &input(1),
                    &Change {
                        id: 42.into(),
                        before: &before,
                        after: &transferred
                    }
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn every_owner_scoped_operation_must_agree_on_the_models_owner_field() -> Result<()> {
    let (operations, schema) = contracts()?;
    let mut raw = policy_json();
    raw["operations"]["links.list"]["models"]["links"]["rows"]["field"] = json!("title");
    let policy: Policy = serde_json::from_value(raw)?;
    let error = policy.validate(&operations, &schema).unwrap_err();
    assert!(error.to_string().contains("conflicting owner fields"));
    assert!(
        policy
            .check_create("links.create", "links", "alice", &value("alice", "Title"))
            .is_err()
    );
    Ok(())
}

#[test]
fn caller_version_is_checked_independently_of_the_handler_and_effect_version() -> Result<()> {
    let policy = policy()?;
    let mut row = Row {
        id: 42.into(),
        version: 1,
        created_at: 0,
        data: value("alice", "Initial").to_string(),
    };
    policy.check_edit("links.edit", "alice", &input(1), &row)?;
    row.version = 2;
    assert_eq!(
        policy
            .check_edit("links.edit", "alice", &input(1), &row)
            .unwrap_err()
            .to_string(),
        "conflict"
    );
    policy.check_edit("links.edit", "alice", &input(2), &row)?;
    assert_eq!(
        policy
            .check_edit("links.edit", "bob", &input(1), &row)
            .unwrap_err()
            .to_string(),
        "forbidden"
    );
    let before = value("alice", "Initial");
    let next = value("alice", "Next");
    assert!(
        policy
            .check_update(
                "links.edit",
                "links",
                "alice",
                &input(1),
                &Change {
                    id: 43.into(),
                    before: &before,
                    after: &next
                }
            )
            .is_err()
    );
    assert!(policy.edit_target("links.current", &input(1))?.is_none());
    policy.check_update(
        "links.current",
        "links",
        "alice",
        &input(1),
        &Change {
            id: 43.into(),
            before: &before,
            after: &next,
        },
    )?;
    for invalid in [
        json!({}),
        json!({"link_id":42,"expected_version":1}),
        json!({"link_id":"042","expected_version":1}),
        json!({"link_id":"42","expected_version":0}),
        json!({"link_id":"42","expected_version":1.0}),
        json!({"link_id":"42","expected_version":i64::MAX}),
    ] {
        assert!(policy.edit_target("links.edit", &invalid).is_err());
    }
    Ok(())
}

#[test]
fn forged_plain_text_handles_do_not_bypass_host_constraints() -> Result<()> {
    let policy = policy()?;
    let before = value("alice", "Initial");
    for title in [
        "".to_string(),
        " \t\n\u{2003}".to_string(),
        "x".repeat(201),
        "\u{1f600}".repeat(51),
    ] {
        let after = value("alice", &title);
        assert!(
            policy
                .check_create("links.create", "links", "alice", &after)
                .is_err()
        );
        assert!(
            policy
                .check_update(
                    "links.edit",
                    "links",
                    "alice",
                    &input(1),
                    &Change {
                        id: 42.into(),
                        before: &before,
                        after: &after
                    }
                )
                .is_err()
        );
    }
    policy.check_create(
        "links.create",
        "links",
        "alice",
        &value("alice", &"x".repeat(200)),
    )?;
    Ok(())
}

#[test]
fn policy_admission_rejects_drift_and_unsafe_combinations() -> Result<()> {
    let (operations, schema) = contracts()?;
    let mut mutations = Vec::new();
    let mut missing = policy_json();
    missing["operations"]
        .as_object_mut()
        .unwrap()
        .remove("links.edit");
    mutations.push(missing);
    for (pointer, replacement) in [
        ("/version", json!(2)),
        ("/operations/links.edit/mode/id_field", json!("title")),
        ("/operations/links.edit/mode/version_field", json!("title")),
        ("/operations/links.edit/models/links/create", json!(true)),
        ("/operations/links.create/models/links/read", json!(false)),
        ("/operations/links.edit/models/links/read", json!(false)),
        (
            "/operations/links.edit/models/links/update_fields",
            json!(["owner"]),
        ),
        (
            "/operations/links.edit/models/links/update_fields",
            json!(["unknown"]),
        ),
        (
            "/operations/links.edit/models/links/rows/field",
            json!("archived"),
        ),
        ("/operations/links.list/models/links/create", json!(true)),
        ("/constraints/links/title/max_bytes", json!(16_385)),
        ("/constraints/links/title/max_bytes", json!(0)),
        ("/constraints", json!({})),
    ] {
        let mut malformed = policy_json();
        if let Some(target) = malformed.pointer_mut(pointer) {
            *target = replacement;
        } else {
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            malformed.pointer_mut(parent).unwrap()[key] = replacement;
        }
        mutations.push(malformed);
    }
    for mutation in mutations {
        let policy: Policy = serde_json::from_value(mutation)?;
        assert!(policy.validate(&operations, &schema).is_err());
    }
    let mut other_model = policy_json();
    other_model["operations"]["links.edit"]["models"]["secrets"] =
        json!({"read":true,"update_fields":["content"],"rows":{"kind":"all"}});
    assert!(
        serde_json::from_value::<Policy>(other_model)?
            .validate(&operations, &schema)
            .is_err()
    );
    let mut unknown_model = policy_json();
    unknown_model["operations"]["links.list"]["models"]["unknown"] =
        json!({"read":true,"rows":{"kind":"all"}});
    assert!(
        serde_json::from_value::<Policy>(unknown_model)?
            .validate(&operations, &schema)
            .is_err()
    );
    let mut invalid_actor = policy_json();
    invalid_actor["admins"] = json!(["admin\n"]);
    assert!(
        serde_json::from_value::<Policy>(invalid_actor)?
            .validate(&operations, &schema)
            .is_err()
    );
    let mut unknown = policy_json();
    unknown["operations"]["links.edit"]["mode"]["ignored"] = json!(true);
    assert!(serde_json::from_value::<Policy>(unknown).is_err());
    Ok(())
}

#[test]
fn seeded_text_constraint_property_matches_unicode_and_byte_rules() -> Result<()> {
    let policy = policy()?;
    let mut runner = TestRunner::new(Config {
        cases: 256,
        rng_seed: RngSeed::Fixed(0x6175_7468_6f72_6974),
        ..Config::default()
    });
    runner.run(&proptest::collection::vec(any::<char>(), 0..240), |chars| {
        let title: String = chars.into_iter().collect();
        let expected = !title.trim().is_empty() && title.len() <= 200;
        prop_assert_eq!(
            policy
                .check_create("links.create", "links", "alice", &value("alice", &title))
                .is_ok(),
            expected
        );
        Ok(())
    })?;
    Ok(())
}

#[test]
fn a_domain_entry_grants_operations_but_never_ownership_or_administration() -> Result<()> {
    let (operations, schema) = contracts()?;
    let mut document = policy_json();
    for name in ["links.list", "links.create", "links.edit"] {
        document["operations"][name]["actors"] = json!(["domain:wonderly.com", "admin"]);
    }
    let policy: Policy = serde_json::from_value(document.clone())?;
    policy.validate(&operations, &schema)?;
    policy.validate_domains(Some("wonderly.com"))?;
    // Validation binds the entry to the installation's verified domain.
    assert!(policy.validate_domains(None).is_err());
    assert!(policy.validate_domains(Some("example.com")).is_err());

    let hire = "newhire@wonderly.com";
    policy.authorize("links.edit", hire)?;
    for outsider in [
        "newhire@evil-wonderly.com",
        "newhire@sub.wonderly.com",
        "NewHire@wonderly.com",
        "alice",
        "svc:links@wonderly.com",
        "domain:wonderly.com",
    ] {
        assert!(
            policy.authorize("links.edit", outsider).is_err(),
            "{outsider}"
        );
    }
    assert!(policy.authorize("admin.salaries", hire).is_err());
    // Row authority is unchanged: members of the domain see their own rows,
    // under their own address, and only the named admin sees everyone's.
    assert_eq!(
        policy.read_scope("links.list", "links", hire)?,
        RowFilter::Owner {
            field: "owner".into(),
            actor: hire.into()
        }
    );
    assert_eq!(
        policy.read_scope("links.list", "links", "admin")?,
        RowFilter::All
    );
    assert!(
        policy
            .read_scope("links.list", "links", "eve@evil-wonderly.com")
            .is_err()
    );
    policy.check_read("links.list", "links", hire, &value(hire, "Mine"))?;
    assert!(
        policy
            .check_read(
                "links.list",
                "links",
                hire,
                &value("bob@wonderly.com", "Theirs")
            )
            .is_err()
    );
    policy.check_create("links.create", "links", hire, &value(hire, "Initial"))?;
    // A row owned by the entry is not a row anybody owns.
    assert!(
        policy
            .check_create(
                "links.create",
                "links",
                hire,
                &value("domain:wonderly.com", "Initial")
            )
            .is_err()
    );

    // Administrators and both sides of a delegation stay named people.
    let mut admins = document.clone();
    admins["admins"] = json!(["domain:wonderly.com"]);
    let mut authenticated = document.clone();
    authenticated["delegations"] = json!({"support":{"authenticated":["domain:wonderly.com"],
        "may_act_as":{"kind":"any_human"},"paths":["request"]}});
    let mut targets = document.clone();
    targets["delegations"] = json!({"support":{"authenticated":["support@wonderly.com"],
        "may_act_as":{"kind":"actors","actors":["domain:wonderly.com"]},"paths":["request"]}});
    let mut malformed = document;
    malformed["operations"]["links.list"]["actors"] = json!(["domain:Wonderly.com"]);
    for (name, refused) in [
        ("admins", admins),
        ("delegation authenticated", authenticated),
        ("delegation targets", targets),
        ("malformed domain", malformed),
    ] {
        assert!(
            serde_json::from_value::<Policy>(refused)?
                .validate(&operations, &schema)
                .is_err(),
            "{name}"
        );
    }
    Ok(())
}
