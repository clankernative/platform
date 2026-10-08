use crate::support::commands as support;
use anyhow::{Context, Result};
use day2::{authority_state, resource_admin};
use serde_json::{Value, json};
use support::World;

fn configured() -> Result<World> {
    let world = World::new()?;
    let path = world.runtime.instance_path();
    let root = path.parent().context("instance parent")?;
    let mut instance: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    instance["control"] = json!({"version":1,"state_directory":root.join("control"),"operators":["it"],
        "sources":{"repo":{"kind":"local_git","repository":root.join("repo")}},
        "apps":{world.runtime.app():{"source":"repo"}}});
    std::fs::write(path, serde_json::to_vec(&instance)?)?;
    Ok(world)
}

#[test]
fn administrator_reduces_company_capacity_with_explicit_return_and_verified_activation_proof()
-> Result<()> {
    use day2::{
        authority_state::{ApplyAuthority, LocalOperator},
        budget,
    };
    use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope, VersionRef};
    let world = configured()?;
    let path = world.runtime.instance_path();
    let app = world.runtime.app();
    let operator = LocalOperator::assert_local("it")?;
    let mut db = rusqlite::Connection::open(world.runtime.db())?;
    let mut active = authority_state::current(&db)?;
    let original = BudgetDefinition {
        revision: 1,
        scope: BudgetScope::Installation,
        period_seconds: 3600,
        limits: BudgetLimits {
            calls: Some(10),
            ..BudgetLimits::default()
        },
    };
    active
        .document
        .resources
        .budgets
        .insert("company".into(), original.clone());
    for grant in active
        .document
        .resources
        .operations
        .values_mut()
        .flat_map(|slots| slots.values_mut())
    {
        grant.budgets.push(VersionRef {
            id: "company".into(),
            revision: 1,
        });
    }
    authority_state::apply(
        &world.runtime,
        &operator,
        &ApplyAuthority {
            request_id: "meter".into(),
            expected: Some(active.stamp),
            document: active.document,
        },
    )?;
    resource_admin::setup_company_budget(path, "it")?;
    resource_admin::allocate(
        path,
        app,
        "it",
        &resource_admin::Allocate {
            id: "first".into(),
            budget: "company".into(),
            limits: original.limits.clone(),
        },
    )?;
    assert!(resource_admin::company_budget(path, "app-actor").is_err());
    let state = resource_admin::company_budget(path, "it")?;
    let ledger = state["apps"][app]["usage"]["ledger_id"]
        .as_str()
        .context("ledger")?
        .to_string();
    let now = resource_admin::now_ms()? / 1000;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    budget::reserve_in(
        &tx,
        &budget::ReservationRequest {
            id: "unresolved".into(),
            binding: "reviewed-physical-attempt".into(),
            context: budget::BudgetContext {
                app: app.into(),
                actor: "alice".into(),
                connection: "mailbox".into(),
                invocation_root: "root".into(),
                now,
            },
            budgets: std::collections::BTreeMap::from([("company".into(), original.clone())]),
            quote: budget::Consumption {
                calls: 2,
                ..Default::default()
            },
        },
    )?;
    tx.commit()?;
    let mut lower = original.clone();
    lower.revision = 2;
    lower.limits.calls = Some(6);
    let change = budget::PoolReductionRequest {
        id: "reduce-company".into(),
        budget_id: "company".into(),
        expected: original,
        definition: lower.clone(),
        effective_window: now - now.rem_euclid(3600),
        returns: vec![budget::CapacityReturn {
            ledger_id: ledger.clone(),
            window_start: now - now.rem_euclid(3600),
            unit: "calls".into(),
            amount: 4,
        }],
        reason: "Retain two unresolved calls and four units for later use".into(),
    };
    resource_admin::propose_pool_reduction(path, "it", &change)?;
    assert!(
        resource_admin::return_company_capacity(
            path,
            app,
            "it",
            &resource_admin::ReturnCompanyCapacity {
                reduction: change.id.clone(),
                ledger_id: "different-ledger".into()
            }
        )
        .is_err()
    );
    let returned = resource_admin::ReturnCompanyCapacity {
        reduction: change.id.clone(),
        ledger_id: ledger,
    };
    resource_admin::return_company_capacity(path, app, "it", &returned)?;
    resource_admin::return_company_capacity(path, app, "it", &returned)?;
    resource_admin::decide_pool_reduction(
        path,
        "it",
        &resource_admin::DecidePoolReduction {
            reduction: change.id.clone(),
            complete: true,
        },
    )?;
    let pool = resource_admin::company_budget(path, "it")?;
    assert_eq!(pool["pool"]["accounts"][0]["limit"], 6);
    assert_eq!(pool["apps"][app]["usage"]["accounts"][0]["reserved"], 2);
    assert_eq!(pool["apps"][app]["usage"]["accounts"][0]["limit"], 6);
    let mut active = authority_state::current(&db)?;
    active
        .document
        .resources
        .budgets
        .insert("company".into(), lower);
    for grant in active
        .document
        .resources
        .operations
        .values_mut()
        .flat_map(|slots| slots.values_mut())
    {
        grant.budgets = vec![VersionRef {
            id: "company".into(),
            revision: 2,
        }];
    }
    let apply = ApplyAuthority {
        request_id: "activate-lower".into(),
        expected: Some(active.stamp),
        document: active.document,
    };
    assert!(
        authority_state::apply(&world.runtime, &operator, &apply)
            .unwrap_err()
            .to_string()
            .contains("proof_required")
    );
    resource_admin::import_pool_reduction(
        path,
        app,
        "it",
        &resource_admin::ImportPoolReduction {
            reduction: change.id,
        },
    )?;
    authority_state::apply(&world.runtime, &operator, &apply)?;
    assert_eq!(
        authority_state::current(&db)?.document.resources.budgets["company"].revision,
        2
    );
    Ok(())
}

#[test]
fn review_approval_is_durable_atomic_and_does_not_change_memberships_or_business_policy()
-> Result<()> {
    let world = configured()?;
    let path = world.runtime.instance_path();
    let app = world.runtime.app();
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let before = authority_state::current(&db)?;
    assert!(
        !before.document.resources.is_empty(),
        "test fixture must explicitly grant notification resources"
    );
    let mut authoring = resource_admin::authoring(path, "it")?;
    authoring.bindings.insert(app.into(), json!([]));
    let saved = resource_admin::save(path, "it", &authoring)?;
    assert_eq!(authority_state::current(&db)?, before);
    let preview = resource_admin::preview(path, app, "it")?;
    assert_eq!(preview["changed"], true);
    let proposal = resource_admin::Proposal {
        id: "remove-notifications".into(),
        expected: before.stamp.clone(),
        authoring_revision: saved.revision,
        note: "Retire the notification workflow".into(),
    };
    resource_admin::propose(path, app, "it", &proposal)?;
    resource_admin::propose(path, app, "it", &proposal)?;
    assert_eq!(authority_state::current(&db)?, before);
    let mut decision = resource_admin::Decision {
        review: proposal.id,
        decision: "approve".into(),
        reason: "No external delivery is required".into(),
        reviewed_data_movement: false,
    };
    assert!(resource_admin::decide(path, app, "it", &decision).is_err());
    assert_eq!(authority_state::current(&db)?, before);
    decision.reviewed_data_movement = true;
    let receipt = resource_admin::decide(path, app, "it", &decision)?;
    assert_eq!(resource_admin::decide(path, app, "it", &decision)?, receipt);
    let after = authority_state::current(&db)?;
    assert_eq!(after.stamp.revision, before.stamp.revision + 1);
    assert!(after.document.resources.is_empty());
    assert_eq!(after.document.policy, before.document.policy);
    assert_eq!(after.document.writers, before.document.writers);
    assert_eq!(after.artifact_id, before.artifact_id);
    assert_eq!(
        resource_admin::reviews(path, app, "it")?["reviews"][0]["decision"],
        "approve"
    );
    assert!(
        db.execute("DELETE FROM day2_resource_review_decisions", [])
            .is_err()
    );
    Ok(())
}

#[test]
fn stale_review_cannot_activate_after_an_independent_authority_change() -> Result<()> {
    let world = configured()?;
    let path = world.runtime.instance_path();
    let app = world.runtime.app();
    let preview = resource_admin::preview(path, app, "it")?;
    let proposal = resource_admin::Proposal {
        id: "stale-review".into(),
        expected: serde_json::from_value(preview["expected"].clone())?,
        authoring_revision: preview["authoring_revision"]
            .as_str()
            .context("revision")?
            .into(),
        note: "Validate review race".into(),
    };
    resource_admin::propose(path, app, "it", &proposal)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let mut active = authority_state::current(&db)?;
    active.document.enabled = false;
    authority_state::apply(
        &world.runtime,
        &authority_state::LocalOperator::assert_local("it")?,
        &authority_state::ApplyAuthority {
            request_id: "independent-disable".into(),
            expected: Some(active.stamp),
            document: active.document,
        },
    )?;
    let decision = resource_admin::Decision {
        review: proposal.id,
        decision: "approve".into(),
        reason: "A stale approval must fail".into(),
        reviewed_data_movement: true,
    };
    assert!(resource_admin::decide(path, app, "it", &decision).is_err());
    assert!(!authority_state::current(&db)?.document.enabled);
    assert!(resource_admin::reviews(path, app, "it")?["reviews"][0]["decision"].is_null());
    let denied = resource_admin::Decision {
        decision: "deny".into(),
        reason: "Superseded by disablement".into(),
        ..decision
    };
    resource_admin::decide(path, app, "it", &denied)?;
    Ok(())
}

#[test]
fn mixed_policy_owners_can_request_their_own_changes_but_only_it_can_activate_them() -> Result<()> {
    let world = configured()?;
    let path = world.runtime.instance_path();
    let app = world.runtime.app();
    let mut authoring = resource_admin::authoring(path, "it")?;
    let bindings = authoring
        .bindings
        .get_mut(app)
        .unwrap()
        .as_array_mut()
        .unwrap();
    for attachment in bindings {
        let id = attachment["policy"]["id"].as_str().unwrap().to_string();
        authoring.catalog["policies"][&id]["owner"] =
            json!(if attachment["operation"] == "reports.notify" {
                "owner-a"
            } else {
                "owner-b"
            });
        authoring.catalog["policies"][&id]["revision"] = json!(2);
        attachment["policy"]["revision"] = json!(2);
    }
    resource_admin::save(path, "it", &authoring)?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    let expected = authority_state::current(&db)?.stamp;
    authority_state::apply_desired(
        &world.runtime,
        &authority_state::LocalOperator::assert_local("it")?,
        "establish-owners",
        Some(expected),
    )?;
    let visible = resource_admin::authoring(path, "owner-a")?;
    assert_eq!(visible.bindings[app].as_array().unwrap().len(), 1);
    let preview = resource_admin::preview(path, app, "owner-a")?;
    assert_eq!(preview["review_requires_administrator"], true);
    assert!(preview["active"]["operations"]["reports.detail"].is_null());
    let saved = resource_admin::attach(
        path,
        app,
        "owner-a",
        &resource_admin::Attach {
            revision: visible.revision,
            bindings: vec![],
        },
    )?;
    let staged = day2::artifact::Instance::load(path)?;
    assert_eq!(staged.apps[app].resource_policies.len(), 1);
    assert_eq!(
        staged.apps[app].resource_policies[0].operation,
        "reports.detail"
    );
    let proposal = resource_admin::Proposal {
        id: "owner-removal".into(),
        expected: serde_json::from_value(preview["expected"].clone())?,
        authoring_revision: saved.revision,
        note: "Retire my delivery binding".into(),
    };
    resource_admin::propose(path, app, "owner-a", &proposal)?;
    let review = resource_admin::reviews(path, app, "owner-a")?;
    assert_eq!(review["reviews"][0]["requires_administrator"], true);
    assert!(review["reviews"][0]["resources"]["operations"]["reports.detail"].is_null());
    let decision = resource_admin::Decision {
        review: proposal.id,
        decision: "approve".into(),
        reason: "Reviewed mixed ownership and retained read grant".into(),
        reviewed_data_movement: true,
    };
    assert!(resource_admin::decide(path, app, "owner-a", &decision).is_err());
    resource_admin::decide(path, app, "it", &decision)?;
    let active = authority_state::current(&db)?;
    assert!(
        !active
            .document
            .resources
            .operations
            .contains_key("reports.notify")
    );
    assert!(
        active
            .document
            .resources
            .operations
            .contains_key("reports.detail")
    );
    Ok(())
}

#[test]
fn stale_desired_pins_do_not_prevent_inspecting_or_repairing_active_bindings() -> Result<()> {
    let world = configured()?;
    let path = world.runtime.instance_path();
    let app = world.runtime.app();
    let mut authoring = resource_admin::authoring(path, "it")?;
    for policy in authoring.catalog["policies"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        policy["revision"] = json!(2);
    }
    resource_admin::save(path, "it", &authoring)?;
    let preview = resource_admin::preview(path, app, "it")?;
    assert!(preview["validation_error"].is_string());
    assert!(
        !preview["active"]["operations"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert!(!preview["operations"].as_array().unwrap().is_empty());
    let fresh = resource_admin::authoring(path, "it")?;
    let mut bindings = fresh.bindings[app].clone();
    for attachment in bindings.as_array_mut().unwrap() {
        attachment["policy"]["revision"] = json!(2);
    }
    resource_admin::attach(
        path,
        app,
        "it",
        &resource_admin::Attach {
            revision: fresh.revision,
            bindings: serde_json::from_value(bindings)?,
        },
    )?;
    assert!(resource_admin::preview(path, app, "it")?["validation_error"].is_null());
    Ok(())
}
