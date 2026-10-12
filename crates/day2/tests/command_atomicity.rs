use crate::support::commands as support;
use anyhow::{Context, Result};
use day2::{
    invocations,
    store::{Fault, replay},
};
use serde_json::json;

#[test]
fn a_changed_authority_snapshot_blocks_a_child_without_business_execution() -> Result<()> {
    let world = World::new()?;
    world.submit("pinned", Fault::None)?;
    let child = world.child("pinned")?;
    world.change_policy(|policy| {
        policy
            .operations
            .get_mut("reports.detail")
            .unwrap()
            .actors
            .insert("another_reader".into());
    })?;
    let refused = world.finish(&child)?;
    assert_eq!(refused.status, "blocked");
    assert_eq!(refused.error, "authority_policy_changed");
    assert!(world.runtime.trace(&child).is_err());
    let receipt = serde_json::to_value(invocations::status(&world.runtime, &child, "alice")?)?;
    assert_eq!(receipt["status"], "blocked");
    assert!(receipt["result"].is_null());
    assert_eq!(receipt["error"], "authority_policy_changed");
    let artifact = world.runtime.artifact();
    let document = day2::openapi::Catalog::from_artifact(artifact.contract())?.document(
        artifact.contract(),
        world.runtime.app(),
        artifact.id(),
        "test-cookie",
        "http://127.0.0.1",
    );
    assert!(
        document["components"]["schemas"]["Invocation"]["properties"]["status"]["enum"]
            .as_array()
            .context("receipt status schema")?
            .contains(&receipt["status"])
    );
    let children = serde_json::to_value(invocations::children(&world.runtime, "pinned")?)?;
    assert_eq!(children[0]["status"], "blocked");
    assert!(
        document["components"]["schemas"]["Invocation"]["properties"]["children"]["items"]
            ["properties"]["status"]["enum"]
            .as_array()
            .context("child status schema")?
            .contains(&children[0]["status"])
    );
    assert_eq!(world.runtime.inspect()?["reports"][0]["version"], 1);
    Ok(())
}
use support::World;
#[test]
fn uuid_ids_roundtrip_binary_storage_retries_and_model_checked_pagination() -> Result<()> {
    use std::collections::BTreeSet;
    let world = World::new()?;
    let first = world.submit("same-request", Fault::None)?;
    assert_eq!(first.status, "success");
    let id = first.result["id"].as_str().context("public ID")?;
    assert!(day2::identity::valid_for(id, "rep"));
    assert_eq!(id.len(), 30);
    assert_eq!(
        world.submit("same-request", Fault::None)?.result,
        first.result
    );
    let other_installation = World::new()?;
    assert_ne!(
        other_installation
            .submit("same-request", Fault::None)?
            .result["id"],
        first.result["id"]
    );
    let mut expected = BTreeSet::from([id.to_string()]);
    for index in 0..4 {
        let saved = world.submit(&format!("row-{index}"), Fault::None)?;
        expected.insert(
            saved.result["id"]
                .as_str()
                .context("public ID")?
                .to_string(),
        );
    }
    assert_eq!(expected.len(), 5);
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    let mut stored = connection.prepare("SELECT id,typeof(id),length(id) FROM reports")?;
    let mut rows = stored.query([])?;
    let mut decoded = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        assert_eq!(row.get::<_, String>(1)?, "blob");
        assert_eq!(row.get::<_, i64>(2)?, 16);
        decoded
            .insert(day2::identity::Id::from_uuid("rep", bytes.try_into().unwrap())?.to_string());
    }
    assert_eq!(decoded, expected);
    let mut after = String::new();
    let mut seen = Vec::new();
    for page in 0..3 {
        let result = world.runtime.invoke(
            "reports.list",
            "alice",
            &format!("page-{page}"),
            &json!({"after":after,"limit":2}),
            101,
            Fault::None,
        )?;
        assert_eq!(result.status, "success", "{}", result.error);
        let items = result.result["items"].as_array().context("page items")?;
        assert_eq!(items.len(), if page < 2 { 2 } else { 1 });
        assert_eq!(result.result["has_more"], page < 2);
        after = result.result["next_after"]
            .as_str()
            .context("cursor")?
            .to_string();
        seen.extend(
            items
                .iter()
                .map(|row| row["id"].as_str().unwrap().to_string()),
        );
        replay(
            world.runtime.artifact(),
            &world.runtime.trace(&format!("page-{page}"))?,
        )?;
    }
    assert_eq!(seen, expected.into_iter().collect::<Vec<_>>());
    for invalid in [
        "1".to_string(),
        id.replace("rep_", "cus_"),
        id.to_uppercase(),
    ] {
        assert!(
            world
                .runtime
                .accept(
                    "reports.detail",
                    "alice",
                    "invalid-id",
                    &json!({"report_id":invalid}),
                    102
                )
                .is_err()
        );
    }
    let wrong_cursor = world.runtime.invoke(
        "reports.list",
        "alice",
        "wrong-cursor",
        &json!({"after":id.replace("rep_","cus_"),"limit":2}),
        102,
        Fault::None,
    );
    assert!(wrong_cursor.is_err() || wrong_cursor?.status == "failure");
    Ok(())
}

#[test]
fn every_mutation_boundary_rolls_back_child_acceptance_with_data_and_ack_loss_reuses_receipt()
-> Result<()> {
    for index in 1..=2 {
        let world = World::new()?;
        let failed = world.submit("failed", Fault::FailAfterWrite(index))?;
        assert_eq!(failed.status, "failure");
        assert!(invocations::children(&world.runtime, "failed")?.is_empty());
        assert!(
            world.runtime.inspect()?["reports"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        replay(world.runtime.artifact(), &world.runtime.trace("failed")?)?;
        assert!(
            world
                .submit("interrupted", Fault::InterruptAfterWrite(index))
                .is_err()
        );
        assert!(invocations::children(&world.runtime, "interrupted")?.is_empty());
        assert!(
            world.runtime.inspect()?["reports"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(world.finish("interrupted")?.status, "success");
        assert_eq!(
            invocations::children(&world.runtime, "interrupted")?.len(),
            1
        );
    }
    let world = World::new()?;
    assert!(world.submit("ambiguous", Fault::AfterCommit).is_err());
    let child = world.child("ambiguous")?;
    assert_eq!(world.submit("ambiguous", Fault::None)?.status, "success");
    assert_eq!(world.child("ambiguous")?, child);
    Ok(())
}

#[test]
fn private_commands_and_cross_actor_receipts_are_not_public_rpc() -> Result<()> {
    let world = World::new()?;
    let saved = world.submit("private", Fault::None)?;
    for operation in [
        "reports.analyze",
        "reports.notify",
        "jobs.reports.analyze.complete",
        "$job.work.reports.analyze",
    ] {
        assert!(
            world
                .runtime
                .invoke(
                    operation,
                    "alice",
                    "hostile",
                    &json!({"report_id":saved.result["id"],"expected_version":1,"text":"fake"}),
                    100,
                    Fault::None
                )
                .is_err()
        );
    }
    assert!(
        serde_json::to_value(world.runtime.artifact().contract())?
            .get("jobs")
            .is_none()
    );
    let catalog =
        day2::operation_catalog::Catalog::from_artifact(world.runtime.artifact().contract())?;
    assert_eq!(catalog.endpoints.len(), 4);
    assert!(invocations::status(&world.runtime, "private", "bob").is_err());
    let receipt = invocations::status(&world.runtime, "private", "alice")?;
    assert_eq!(receipt.children.len(), 1);
    assert!(!serde_json::to_string(&receipt)?.contains("first line"));
    Ok(())
}

#[test]
fn explicit_request_grants_and_fresh_execution_authority_are_required() -> Result<()> {
    let world = World::new()?;
    world.change_policy(|p| {
        p.operations
            .get_mut("reports.submit")
            .unwrap()
            .commands
            .clear();
    })?;
    let outcome = world.submit("denied", Fault::None)?;
    assert_eq!(outcome.status, "failure");
    assert_eq!(outcome.error, "command_request_forbidden");
    assert!(
        world.runtime.inspect()?["reports"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(invocations::children(&world.runtime, "denied")?.is_empty());
    let world = World::new()?;
    world.submit("revoked", Fault::None)?;
    let child = world.child("revoked")?;
    world.change_policy(|p| {
        p.operations
            .get_mut("reports.analyze")
            .unwrap()
            .actors
            .remove("alice");
    })?;
    assert_eq!(
        world.runtime.execute(&child, Fault::None)?.status,
        "blocked"
    );
    assert_eq!(world.runtime.inspect()?["reports"][0]["version"], 1);
    Ok(())
}

#[test]
fn stale_captured_analysis_cannot_overwrite_edits_and_properties_hold_at_each_boundary()
-> Result<()> {
    let world = World::new()?;
    world.properties()?;
    let saved = world.submit("original", Fault::None)?;
    let old = world.child("original")?;
    assert!(world.runtime.execute(&old, Fault::AfterPrepare).is_err());
    world.properties()?;
    let revised = world.runtime.invoke(
        "reports.revise",
        "alice",
        "revision",
        &json!({"report_id":saved.result["id"],"expected_version":1,"text":"é\n東京"}),
        101,
        Fault::None,
    )?;
    assert_eq!(revised.status, "success", "{}", revised.error);
    world.properties()?;
    let stale = world.finish(&old)?;
    assert_eq!(stale.status, "failure");
    assert_eq!(stale.error, "conflict");
    assert_eq!(world.runtime.inspect()?["reports"][0]["version"], 2);
    replay(world.runtime.artifact(), &world.runtime.trace(&old)?)?;
    let new = world.child("revision")?;
    assert_eq!(world.finish(&new)?.status, "success");
    world.properties()?;
    let row = world.runtime.inspect()?["reports"][0].clone();
    assert_eq!(row["version"], 3);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(row["data"].as_str().unwrap())?["bytes"],
        9
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(row["data"].as_str().unwrap())?["lines"],
        2
    );
    assert_eq!(world.finish(&world.child(&new)?)?.status, "success");
    world.properties()?;
    Ok(())
}

#[test]
fn analysis_receipt_child_request_and_mandatory_audit_commit_together() -> Result<()> {
    let world = World::new()?;
    world.submit("audit", Fault::None)?;
    let child = world.child("audit")?;
    let db = rusqlite::Connection::open(world.runtime.db())?;
    db.execute_batch("DROP TRIGGER day2_receipt_event")?;
    assert!(world.finish(&child).is_err());
    assert_eq!(world.runtime.inspect()?["reports"][0]["version"], 1);
    assert!(invocations::children(&world.runtime, &child)?.is_empty());
    assert_eq!(
        db.query_row("SELECT count(*) FROM day2_audit", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn submit_analyze_notify_are_independently_replayable_and_receipts_are_idempotent() -> Result<()> {
    let world = World::new()?;
    world.submit("replay", Fault::None)?;
    let analyze = world.child("replay")?;
    assert_eq!(world.finish(&analyze)?.status, "success");
    let notify = world.child(&analyze)?;
    assert_eq!(world.finish(&notify)?.status, "success");
    for id in ["replay", analyze.as_str(), notify.as_str()] {
        replay(world.runtime.artifact(), &world.runtime.trace(id)?)?;
    }
    let before = world.runtime.inspect()?;
    assert_eq!(world.finish(&notify)?.status, "success");
    assert_eq!(world.runtime.inspect()?, before);
    let db = rusqlite::Connection::open(world.runtime.db())?;
    assert_eq!(
        db.query_row("SELECT count(*) FROM day2_audit", [], |r| r
            .get::<_, i64>(0))?,
        3
    );
    let events = world.runtime.audit_events("admin", 0)?;
    assert!(!serde_json::to_string(&events)?.contains("first line"));
    assert!(
        events
            .iter()
            .any(|event| event.identity == notify && event.outcome == "success")
    );
    Ok(())
}
