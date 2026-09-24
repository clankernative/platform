use anyhow::{Context, Result};
use day2::{
    artifact::Instance,
    protocol::{Outcome, Trace},
    store::{Fault, Runtime, replay},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn policy(edit_mode: Value, private_reads: bool) -> Value {
    let owned = json!({"kind":"owner_or_admin", "field":"owner"});
    let reads = if private_reads {
        owned.clone()
    } else {
        json!({"kind":"all"})
    };
    let mut operations = serde_json::Map::new();
    for name in ["links.list", "links.detail"] {
        operations.insert(
            name.into(),
            json!({
                "actors":["alice","bob","admin","viewer"], "mode":{"kind":"read"},
                "models":{"links":{"read":true,"rows":reads}}
            }),
        );
    }
    operations.insert(
        "links.create".into(),
        json!({
            "actors":["alice","bob","admin"], "mode":{"kind":"current_state"},
            "models":{"links":{"read":true,"create":true,"rows":owned}}
        }),
    );
    operations.insert(
        "links.edit".into(),
        json!({
            "actors":["alice","bob","admin"], "mode":edit_mode,
            "models":{"links":{"read":true,"update_fields":["title"],"rows":owned}}
        }),
    );
    json!({"version":1,"admins":["admin"],"operations":operations,
        "constraints":{"links":{"title":{"nonempty":true,"max_bytes":200}}}})
}

fn edit_mode() -> Value {
    json!({"kind":"edit","model":"links","id_field":"link_id","version_field":"expected_version"})
}

struct World {
    directory: tempfile::TempDir,
    runtime: Runtime,
}

impl World {
    fn new() -> Result<Self> {
        Self::configured(edit_mode(), false)
    }

    fn configured(mode: Value, private_reads: bool) -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_OWNED_PROBE_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_OWNED_PROBE_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        let instance: Instance = serde_json::from_value(json!({
            "installation":"owned_runtimeco", "environment":"test", "apps":{"owned":{
                "artifact":artifact,"readers":["viewer"],"writers":["alice","bob","admin"],
                "auditors":["alice","admin"],"authority":policy(mode, private_reads)
            }}
        }))?;
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "owned")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }

    fn invoke(&self, actor: &str, operation: &str, id: &str, input: Value) -> Result<Outcome> {
        self.runtime
            .invoke(operation, actor, id, &input, 100, Fault::None)
    }

    fn create(&self, actor: &str, id: &str) -> Result<String> {
        let outcome = self.invoke(
            actor,
            "links.create",
            id,
            json!({
                "title":format!("{actor} {id}"), "destination":"https://example.com/handbook"
            }),
        )?;
        assert_eq!(outcome.status, "success", "{}", outcome.error);
        Ok(outcome.result["id"].as_str().context("created id")?.into())
    }

    fn edit(
        &self,
        actor: &str,
        invocation: &str,
        id: &str,
        version: i64,
        title: &str,
    ) -> Result<Outcome> {
        self.invoke(
            actor,
            "links.edit",
            invocation,
            json!({"link_id":id,"expected_version":version,"title":title}),
        )
    }

    fn query(&self, actor: &str, id: &str) -> Result<Outcome> {
        self.invoke(actor, "links.list", id, json!({"after":"","limit":20}))
    }

    fn changes(&self) -> Result<i64> {
        Ok(rusqlite::Connection::open(self.runtime.db())?.query_row(
            "SELECT count(*) FROM day2_audit_changes",
            [],
            |row| row.get(0),
        )?)
    }

    fn update_policy(&self, change: impl FnOnce(&mut day2::authority::Policy)) -> Result<()> {
        let mut instance = Instance::load(self.runtime.instance_path())?;
        let policy = instance
            .apps
            .get_mut("owned")
            .context("owned binding")?
            .authority
            .as_mut()
            .context("authority policy")?;
        change(policy);
        policy.validate(
            &self.runtime.artifact().contract().operations,
            &self.runtime.artifact().contract().schema,
        )?;
        fs::write(self.runtime.instance_path(), serde_json::to_vec(&instance)?)?;
        let active =
            day2::authority_state::current(&rusqlite::Connection::open(self.runtime.db())?)?;
        day2::authority_state::apply_desired(
            &self.runtime,
            &day2::authority_state::LocalOperator::assert_local("test-operator")?,
            &format!("test-policy-{}", active.stamp.revision + 1),
            Some(active.stamp),
        )?;
        Ok(())
    }

    fn receipt(&self, id: &str) -> Result<Value> {
        let connection = rusqlite::Connection::open(self.runtime.db())?;
        let (status, outcome, trace): (String, Option<String>, Option<String>) = connection
            .query_row(
                "SELECT status,outcome,trace FROM day2_invocations WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        let audits: i64 = connection.query_row(
            "SELECT count(*) FROM day2_audit WHERE invocation=?1",
            [id],
            |row| row.get(0),
        )?;
        Ok(json!({"status":status,"outcome":outcome,"trace":trace,"audits":audits}))
    }

    fn audited(&self, id: &str, error: &str) -> Result<Trace> {
        let trace = self.runtime.trace(id)?;
        assert_eq!(trace.outcome.status, "failure");
        assert_eq!(trace.outcome.error, error);
        let count: i64 = rusqlite::Connection::open(self.runtime.db())?.query_row(
            "SELECT count(*) FROM day2_audit WHERE invocation=?1 AND status='failure'",
            [id],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1);
        replay(self.runtime.artifact(), &trace)?;
        Ok(trace)
    }
}

#[test]
fn hostile_edit_effects_cannot_escape_target_fields_or_commit_a_partial_write() -> Result<()> {
    let world = World::new()?;
    let target = world.create("alice", "target")?;
    world.create("alice", "other-owner-row")?;
    world.create("bob", "bob-row")?;
    let before = world.runtime.inspect()?;
    let visible = world.query("alice", "before-query")?;
    assert_eq!(visible.status, "success");
    let cases = [
        ("alice", "empty", "constraint_violation"),
        ("alice", "owner", "forbidden"),
        ("admin", "owner", "forbidden"),
        ("alice", "destination", "forbidden"),
        ("admin", "destination", "forbidden"),
        ("alice", "other-row", "application_edit_target_forbidden"),
        ("alice", "late-denial", "forbidden"),
    ];
    for (index, (actor, branch, error)) in cases.into_iter().enumerate() {
        let invocation = format!("attack-{index}");
        let outcome = world.edit(actor, &invocation, &target, 1, branch)?;
        assert_eq!(outcome.error, error, "{actor}/{branch}");
        let trace = world.audited(&invocation, error)?;
        assert!(trace.guard.as_ref().context("guard")?.error.is_empty());
        assert!(!trace.request.observations.is_empty());
        if branch == "late-denial" {
            assert!(
                trace
                    .request
                    .observations
                    .iter()
                    .any(|observation| observation.instruction.kind == "update"
                        && observation.error.is_empty())
            );
            assert_eq!(
                trace
                    .request
                    .observations
                    .last()
                    .context("denied effect")?
                    .error,
                "forbidden"
            );
        }
        assert_eq!(world.runtime.inspect()?, before, "rollback: {branch}");
        assert_eq!(world.changes()?, 3, "audit rollback: {branch}");
        let after = world.query("alice", &format!("query-after-{index}"))?;
        assert_eq!(after.result, visible.result);
        let retried = world.edit(actor, &invocation, &target, 1, branch)?;
        assert_eq!(retried, outcome);
        assert_eq!(world.changes()?, 3);
    }
    day2::properties::require(
        world.runtime.artifact(),
        &world.runtime.inspect()?,
        &world.directory.path().join("properties"),
    )?;
    Ok(())
}

#[test]
fn permissive_domain_constructor_and_admin_do_not_bypass_creation_rules() -> Result<()> {
    let world = World::new()?;
    let before = world.runtime.inspect()?;
    for (index, (actor, title, error)) in [
        ("alice", "", "constraint_violation"),
        ("alice", "   ", "constraint_violation"),
        ("alice", "spoof-owner", "forbidden"),
        ("admin", "spoof-owner", "forbidden"),
    ]
    .into_iter()
    .enumerate()
    {
        let invocation = format!("create-attack-{index}");
        let outcome = world.invoke(
            actor,
            "links.create",
            &invocation,
            json!({
                "title":title,"destination":"https://example.com/handbook"
            }),
        )?;
        assert_eq!(outcome.error, error);
        let trace = world.audited(&invocation, error)?;
        assert!(
            trace
                .request
                .observations
                .iter()
                .any(|observation| observation.instruction.kind == "create")
        );
        assert_eq!(world.runtime.inspect()?, before);
        assert_eq!(world.changes()?, 0);
    }
    Ok(())
}

#[test]
fn stale_edit_is_denied_even_when_the_worker_would_do_nothing() -> Result<()> {
    let world = World::new()?;
    let target = world.create("alice", "target")?;
    let edited = world.edit("alice", "first-edit", &target, 1, "Committed title")?;
    assert_eq!(edited.status, "success");
    assert_eq!(edited.result["version"], 2);
    let before = world.runtime.inspect()?;
    let outcome = world.edit("alice", "stale-noop", &target, 1, "noop")?;
    assert_eq!(outcome.error, "conflict");
    let trace = world.audited("stale-noop", "conflict")?;
    assert_eq!(trace.guard.as_ref().context("guard")?.error, "conflict");
    assert!(trace.request.observations.is_empty());
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 2);
    let fresh = world.edit("alice", "fresh-noop", &target, 2, "noop")?;
    assert_eq!(fresh.status, "success");
    assert_eq!(fresh.result["version"], 2);
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 2);
    replay(
        world.runtime.artifact(),
        &world.runtime.trace("fresh-noop")?,
    )?;
    Ok(())
}

#[test]
fn current_state_policy_cannot_disable_the_app_revision_guard() -> Result<()> {
    let world = World::configured(json!({"kind":"current_state"}), false)?;
    let target = world.create("alice", "target")?;
    assert_eq!(
        world
            .edit("alice", "first-edit", &target, 1, "First title")?
            .status,
        "success"
    );
    let stale_input = world.edit(
        "alice",
        "current-state-edit",
        &target,
        1,
        "Latest-state title",
    )?;
    assert_eq!(stale_input.status, "failure");
    assert_eq!(stale_input.error, "conflict");
    let trace = world.runtime.trace("current-state-edit")?;
    assert!(
        trace
            .guard
            .as_ref()
            .context("guard")?
            .precondition_row
            .is_some()
    );
    replay(world.runtime.artifact(), &trace)?;
    let before = world.runtime.inspect()?;
    assert_eq!(
        world
            .edit("bob", "wrong-owner", &target, 1, "Bob title")?
            .error,
        "forbidden"
    );
    assert_eq!(
        world
            .edit("admin", "admin-owner-transfer", &target, 2, "owner")?
            .error,
        "forbidden"
    );
    world.audited("wrong-owner", "forbidden")?;
    world.audited("admin-owner-transfer", "forbidden")?;
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 2);
    Ok(())
}

#[test]
fn owner_scoped_queries_filter_before_pagination_and_guard_direct_get() -> Result<()> {
    let world = World::configured(edit_mode(), true)?;
    let alice_id = world.create("alice", "alice-row")?;
    world.create("bob", "bob-row")?;
    let before = world.runtime.inspect()?;
    for actor in ["alice", "bob"] {
        let outcome = world.invoke(
            actor,
            "links.list",
            &format!("{actor}-page"),
            json!({"after":"","limit":1}),
        )?;
        assert_eq!(outcome.status, "success");
        let items = outcome.result["items"].as_array().context("query items")?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["owner"], actor);
        assert_eq!(outcome.result["has_more"], false);
        replay(
            world.runtime.artifact(),
            &world.runtime.trace(&format!("{actor}-page"))?,
        )?;
    }
    let admin = world.query("admin", "admin-query")?;
    assert_eq!(
        admin.result["items"]
            .as_array()
            .context("admin rows")?
            .len(),
        2
    );
    let denied = world.invoke(
        "bob",
        "links.detail",
        "direct-other-owner",
        json!({"link_id":alice_id}),
    )?;
    assert_eq!(denied.error, "forbidden");
    world.audited("direct-other-owner", "forbidden")?;
    let empty = world.query("viewer", "viewer-query")?;
    assert_eq!(empty.status, "success");
    assert_eq!(empty.result["items"], json!([]));
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 2);
    Ok(())
}

#[test]
fn completed_query_receipt_does_not_restore_revoked_admin_visibility() -> Result<()> {
    let world = World::configured(edit_mode(), true)?;
    world.create("alice", "alice-row")?;
    world.create("bob", "bob-row")?;
    let original = world.query("admin", "private-query")?;
    assert_eq!(original.status, "success");
    assert_eq!(
        original.result["items"].as_array().context("items")?.len(),
        2
    );
    let receipt = world.receipt("private-query")?;
    let before = world.runtime.inspect()?;

    world.update_policy(|policy| {
        policy.admins.remove("admin");
    })?;
    assert_eq!(
        world
            .query("admin", "private-query")
            .unwrap_err()
            .to_string(),
        "receipt_policy_changed"
    );
    assert_eq!(world.receipt("private-query")?, receipt);
    assert_eq!(receipt["audits"], 1);
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 2);

    // The actor still has operation access, just no longer cross-owner visibility.
    let fresh = world.query("admin", "fresh-private-query")?;
    assert_eq!(fresh.status, "success");
    assert_eq!(fresh.result["items"], json!([]));
    Ok(())
}

#[test]
fn completed_edit_receipt_policy_mismatch_never_reexecutes_or_overwrites() -> Result<()> {
    let world = World::new()?;
    let target = world.create("alice", "target")?;
    let original = world.edit("alice", "committed-edit", &target, 1, "Original edit")?;
    assert_eq!(original.status, "success");
    assert_eq!(original.result["version"], 2);
    let receipt = world.receipt("committed-edit")?;
    let before = world.runtime.inspect()?;

    world.update_policy(|policy| {
        policy
            .constraints
            .get_mut("links")
            .unwrap()
            .get_mut("title")
            .unwrap()
            .max_bytes = 199;
    })?;
    assert_eq!(
        world
            .edit("alice", "committed-edit", &target, 1, "Original edit")
            .unwrap_err()
            .to_string(),
        "receipt_policy_changed"
    );
    assert_eq!(world.receipt("committed-edit")?, receipt);
    assert_eq!(receipt["audits"], 1);
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 2);

    let fresh = world.edit("alice", "new-policy-edit", &target, 2, "New policy edit")?;
    assert_eq!(fresh.status, "success");
    assert_eq!(fresh.result["version"], 3);
    assert_eq!(world.receipt("committed-edit")?, receipt);
    Ok(())
}

#[test]
fn same_policy_retry_returns_original_receipt_after_later_row_versions() -> Result<()> {
    let world = World::new()?;
    let target = world.create("alice", "target")?;
    let first = world.edit("alice", "first-edit", &target, 1, "First edit")?;
    assert_eq!(first.status, "success");
    assert_eq!(first.result["version"], 2);
    let receipt = world.receipt("first-edit")?;
    let later = world.edit("alice", "later-edit", &target, 2, "Later edit")?;
    assert_eq!(later.status, "success");
    assert_eq!(later.result["version"], 3);
    let before = world.runtime.inspect()?;

    let retry = world.edit("alice", "first-edit", &target, 1, "First edit")?;
    assert_eq!(retry, first);
    assert_eq!(retry.result["version"], 2);
    assert_eq!(world.receipt("first-edit")?, receipt);
    assert_eq!(receipt["audits"], 1);
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 3);
    Ok(())
}

#[test]
fn accepted_edit_rechecks_revoked_operation_access_before_execution() -> Result<()> {
    let world = World::new()?;
    let target = world.create("alice", "target")?;
    world.runtime.accept(
        "links.edit",
        "alice",
        "accepted-edit",
        &json!({"link_id":target,"expected_version":1,"title":"Pending edit"}),
        100,
    )?;
    let receipt = world.receipt("accepted-edit")?;
    let before = world.runtime.inspect()?;
    assert_eq!(receipt["status"], "pending");
    assert_eq!(receipt["audits"], 0);
    world.update_policy(|policy| {
        policy
            .operations
            .get_mut("links.edit")
            .unwrap()
            .actors
            .remove("alice");
    })?;

    let blocked = world.runtime.execute("accepted-edit", Fault::None)?;
    assert_eq!(blocked.status, "blocked");
    assert_eq!(blocked.error, "authority_policy_changed");
    assert_eq!(world.receipt("accepted-edit")?, receipt);
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 1);
    Ok(())
}

#[test]
fn completed_receipts_without_authority_evidence_are_not_reexecuted() -> Result<()> {
    let world = World::new()?;
    let target = world.create("alice", "target")?;
    let original = world.edit("alice", "committed-edit", &target, 1, "Committed edit")?;
    assert_eq!(original.status, "success");
    let receipt = world.receipt("committed-edit")?;
    let original_trace = receipt["trace"].as_str().context("stored trace")?;
    let mut legacy: Value = serde_json::from_str(original_trace)?;
    legacy["format"] = json!(1);
    legacy
        .as_object_mut()
        .context("trace object")?
        .remove("guard");
    let mut missing_guard = legacy.clone();
    missing_guard["format"] = json!(2);
    let before = world.runtime.inspect()?;
    let connection = rusqlite::Connection::open(world.runtime.db())?;
    for trace in [
        None,
        Some(legacy.to_string()),
        Some(missing_guard.to_string()),
    ] {
        connection.execute(
            "UPDATE day2_invocations SET trace=?1 WHERE id='committed-edit'",
            [trace],
        )?;
        let unavailable = world.receipt("committed-edit")?;
        assert_eq!(
            world
                .edit("alice", "committed-edit", &target, 1, "Committed edit")
                .unwrap_err()
                .to_string(),
            "receipt_authority_unavailable"
        );
        assert_eq!(world.receipt("committed-edit")?, unavailable);
        assert_eq!(world.runtime.inspect()?, before);
        assert_eq!(world.changes()?, 2);
        assert_eq!(unavailable["audits"], 1);
    }
    connection.execute(
        "UPDATE day2_invocations SET trace=?1 WHERE id='committed-edit'",
        [original_trace],
    )?;
    assert_eq!(
        world.edit("alice", "committed-edit", &target, 1, "Committed edit")?,
        original
    );
    assert_eq!(world.receipt("committed-edit")?, receipt);
    Ok(())
}

#[test]
fn owned_edit_faults_preserve_atomicity_and_exactly_one_completion() -> Result<()> {
    for (name, fault, first_error, committed) in [
        ("failure", Fault::FailAfterWrite(1), None, false),
        (
            "interrupt",
            Fault::InterruptAfterWrite(1),
            Some("simulated_process_loss"),
            false,
        ),
        (
            "before_commit",
            Fault::BeforeCommit,
            Some("simulated_process_loss"),
            false,
        ),
        (
            "after_commit",
            Fault::AfterCommit,
            Some("ambiguous_after_commit"),
            true,
        ),
    ] {
        let world = World::new()?;
        let target = world.create("alice", "target")?;
        let before = world.runtime.inspect()?;
        let input = json!({
            "link_id":target,"expected_version":1,"title":"Fault-tested edit"
        });
        let first = world
            .runtime
            .invoke("links.edit", "alice", name, &input, 100, fault);
        if let Some(error) = first_error {
            assert_eq!(first.unwrap_err().to_string(), error, "{name}");
        } else {
            let outcome = first?;
            assert_eq!(outcome.status, "failure", "{name}");
            assert_eq!(outcome.error, "injected_failure", "{name}");
        }
        let initial_receipt = world.receipt(name)?;
        let failed = matches!(fault, Fault::FailAfterWrite(_));
        let complete = failed || committed;
        assert_eq!(
            initial_receipt["status"],
            if failed {
                "failure"
            } else if committed {
                "success"
            } else {
                "pending"
            },
            "{name}"
        );
        assert_eq!(initial_receipt["audits"], i64::from(complete), "{name}");
        assert_eq!(world.changes()?, if committed { 2 } else { 1 }, "{name}");
        if committed {
            assert_eq!(world.runtime.inspect()?["links"][0]["version"], 2, "{name}");
        } else {
            assert_eq!(world.runtime.inspect()?, before, "{name}");
        }
        if !complete {
            assert!(initial_receipt["outcome"].is_null(), "{name}");
            assert!(initial_receipt["trace"].is_null(), "{name}");
        }

        let retry = world
            .runtime
            .invoke("links.edit", "alice", name, &input, 100, Fault::None)?;
        if failed {
            assert_eq!(retry.status, "failure", "{name}");
            assert_eq!(retry.error, "injected_failure", "{name}");
            assert_eq!(world.runtime.inspect()?, before, "{name}");
            assert_eq!(world.changes()?, 1, "{name}");
        } else {
            assert_eq!(retry.status, "success", "{name}");
            assert_eq!(retry.result["version"], 2, "{name}");
            assert_eq!(world.runtime.inspect()?["links"][0]["version"], 2, "{name}");
            assert_eq!(world.changes()?, 2, "{name}");
        }
        let receipt = world.receipt(name)?;
        assert_eq!(receipt["audits"], 1, "{name}");
        if complete {
            assert_eq!(
                receipt, initial_receipt,
                "completed receipt changed: {name}"
            );
        }
        let state = world.runtime.inspect()?;
        assert_eq!(
            world
                .runtime
                .invoke("links.edit", "alice", name, &input, 100, Fault::None)?,
            retry,
            "{name}"
        );
        assert_eq!(
            world.runtime.inspect()?,
            state,
            "duplicate mutation: {name}"
        );
        assert_eq!(
            world.receipt(name)?,
            receipt,
            "duplicate completion: {name}"
        );
        replay(world.runtime.artifact(), &world.runtime.trace(name)?)?;
    }
    Ok(())
}

#[test]
fn missing_authority_rejects_new_and_already_accepted_invocations() -> Result<()> {
    let world = World::new()?;
    let target = world.create("alice", "target")?;
    let input = json!({"link_id":target,"expected_version":1,"title":"Pending edit"});
    world
        .runtime
        .accept("links.edit", "alice", "pending-edit", &input, 100)?;
    let pending = world.receipt("pending-edit")?;
    let before = world.runtime.inspect()?;
    let mut instance = Instance::load(world.runtime.instance_path())?;
    instance
        .apps
        .get_mut("owned")
        .context("owned binding")?
        .authority = None;
    fs::write(
        world.runtime.instance_path(),
        serde_json::to_vec(&instance)?,
    )?;
    let active = day2::authority_state::current(&rusqlite::Connection::open(world.runtime.db())?)?;
    day2::authority_state::apply_desired(
        &world.runtime,
        &day2::authority_state::LocalOperator::assert_local("test-operator")?,
        "remove-policy",
        Some(active.stamp),
    )?;

    assert_eq!(
        world
            .runtime
            .invoke("links.edit", "alice", "new-edit", &input, 100, Fault::None)
            .unwrap_err()
            .to_string(),
        "missing_authority_policy"
    );
    assert_eq!(
        world.runtime.execute("pending-edit", Fault::None)?.status,
        "blocked"
    );
    let new_invocations: i64 = rusqlite::Connection::open(world.runtime.db())?.query_row(
        "SELECT count(*) FROM day2_invocations WHERE id='new-edit'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(new_invocations, 0);
    assert_eq!(world.receipt("pending-edit")?, pending);
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["audits"], 0);
    assert_eq!(world.runtime.inspect()?, before);
    assert_eq!(world.changes()?, 1);
    Ok(())
}
