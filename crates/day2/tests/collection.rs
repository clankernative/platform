//! Complete collection behavior through compiled Roc, native SQLite and authority.
use anyhow::{Context, Result, ensure};
use day2::{
    artifact::Instance,
    protocol::{Outcome, Trace},
    store::{Fault, Runtime, replay},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, time::Duration};

#[path = "support/compiler.rs"]
mod compiler;
#[path = "support/evidence.rs"]
mod evidence;

struct World {
    runtime: Runtime,
    directory: PathBuf,
}

impl World {
    fn new() -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_COLLECTION_ARTIFACT")
            .map(PathBuf::from)
            .context(
                "build fixtures/collection-conformance and set DAY2_TEST_COLLECTION_ARTIFACT",
            )?;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/collection-conformance");
        fs::create_dir_all(&root)?;
        let directory = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(root)?
            .keep();
        let owned = json!({"kind":"owner_or_admin","field":"owner"});
        let policy = json!({"version":1,"admins":["admin"],"constraints":{},"operations":{
            "collections.insert":{"actors":["alice","bob","admin"],"mode":{"kind":"current_state"},
                "models":{"entries":{"read":true,"create":true,"rows":owned}}},
            "collections.collect":{"actors":["alice","bob","admin","viewer"],"mode":{"kind":"read"},
                "models":{"entries":{"read":true,"rows":owned}}},
            "collections.update_collect":{"actors":["alice","bob","admin"],"mode":{"kind":"current_state"},
                "models":{"entries":{"read":true,"update_fields":["note"],"rows":owned}}}
        }});
        let instance = json!({"installation":"collectiontest","environment":"test","apps":{"collections":{
            "artifact":artifact,"readers":["alice","bob","admin","viewer"],
            "writers":["alice","bob","admin"],"auditors":["admin"],"authority":policy
        }}});
        let path = directory.join("instance.json");
        fs::write(&path, serde_json::to_vec_pretty(&instance)?)?;
        let runtime = Runtime::load(&path, "collections")?;
        runtime.initialize()?;
        Ok(Self { runtime, directory })
    }

    fn invoke(&self, operation: &str, actor: &str, id: &str, input: Value) -> Result<Outcome> {
        self.runtime
            .invoke(operation, actor, id, &input, 100, Fault::None)
    }

    fn insert(&self, actor: &str, bucket: &str, rank: i64) -> Result<Value> {
        let id = format!("insert-{actor}-{bucket}-{rank}");
        let outcome = self.invoke(
            "collections.insert",
            actor,
            &id,
            json!({"bucket":bucket,"rank":rank}),
        )?;
        ensure!(outcome.status == "success", "insert {id}: {outcome:?}");
        // Only identity comes from the app. Every business value is independent.
        Ok(json!({"id":outcome.result["id"],"version":1,"owner":actor,
            "bucket":bucket,"rank":rank,"note":"before"}))
    }

    fn collect(
        &self,
        actor: &str,
        id: &str,
        bucket: &str,
        maximum: u64,
        after: &str,
    ) -> Result<Outcome> {
        self.invoke(
            "collections.collect",
            actor,
            id,
            json!({"bucket":bucket,"maximum_rows":maximum,"after":after}),
        )
    }

    fn update_collect(&self, id: &str, row: &Value, maximum: u64, note: &str) -> Result<Outcome> {
        self.invoke("collections.update_collect", "alice", id,
            json!({"row_id":row["id"],"bucket":"keep","maximum_rows":maximum,"after":"","note":note}))
    }

    fn changes(&self) -> Result<i64> {
        Ok(rusqlite::Connection::open(self.runtime.db())?.query_row(
            "SELECT count(*) FROM day2_audit_changes",
            [],
            |row| row.get(0),
        )?)
    }

    fn snapshot(&self) -> Result<Value> {
        // This fixture intentionally exceeds the ordinary inspection budget.
        // Read every native column in one consistent, explicitly bounded snapshot;
        // retain the primary key as exact hex bytes without using app projection code.
        let mut db = rusqlite::Connection::open_with_flags(
            self.runtime.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let transaction = db.transaction()?;
        let rows = transaction
            .prepare("SELECT hex(id),version,created_at,bucket,note,owner,rank FROM entries ORDER BY id LIMIT 513")?
            .query_map([], |row| Ok(json!({
                "id_hex":row.get::<_, String>(0)?, "version":row.get::<_, i64>(1)?,
                "created_at":row.get::<_, i64>(2)?, "bucket":row.get::<_, String>(3)?,
                "note":row.get::<_, String>(4)?, "owner":row.get::<_, String>(5)?,
                "rank":row.get::<_, i64>(6)?
            })))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            rows.len() <= 512,
            "complete collection fixture snapshot overflow"
        );
        transaction.commit()?;
        Ok(json!({"entries":rows}))
    }

    fn audit(&self, id: &str, expected: &str) -> Result<Trace> {
        let trace = self.runtime.trace(id)?;
        let status: String = rusqlite::Connection::open(self.runtime.db())?.query_row(
            "SELECT status FROM day2_audit WHERE invocation=?1",
            [id],
            |row| row.get(0),
        )?;
        ensure!(
            status == expected,
            "mandatory audit status for {id}: {status}"
        );
        replay(self.runtime.artifact(), &trace)?;
        Ok(trace)
    }

    fn revoke_collection_read(&self) -> Result<()> {
        let mut instance = Instance::load(self.runtime.instance_path())?;
        instance
            .apps
            .get_mut("collections")
            .context("collection app")?
            .authority
            .as_mut()
            .context("authority")?
            .operations
            .get_mut("collections.collect")
            .context("collect operation")?
            .models
            .get_mut("entries")
            .context("entry permission")?
            .read = false;
        fs::write(self.runtime.instance_path(), serde_json::to_vec(&instance)?)?;
        let active =
            day2::authority_state::current(&rusqlite::Connection::open(self.runtime.db())?)?;
        day2::authority_state::apply_desired(
            &self.runtime,
            &day2::authority_state::LocalOperator::assert_local("collection-operator")?,
            "revoke-collection-read",
            Some(active.stamp),
        )?;
        Ok(())
    }
}

fn expected_order(rows: &[Value], actor: &str, bucket: &str) -> Vec<Value> {
    let mut selected: Vec<_> = rows
        .iter()
        .filter(|row| row["bucket"] == bucket && (actor == "admin" || row["owner"] == actor))
        .cloned()
        .collect();
    selected.sort_by_key(|row| std::cmp::Reverse(row["rank"].as_i64().unwrap()));
    selected
}

fn assert_collection(outcome: &Outcome, expected: &[Value]) -> Result<()> {
    ensure!(outcome.status == "success", "collection: {outcome:?}");
    ensure!(
        outcome.result["count"] == json!(expected.len()),
        "complete collection count"
    );
    let sequence: Vec<String> = serde_json::from_str(
        outcome.result["sequence"]
            .as_str()
            .context("native collection sequence")?,
    )?;
    // Fixture values never contain the delimiter; compact tokens retain every
    // field while keeping the 256-row result within the native Str byte bound.
    let expected_sequence: Vec<_> = expected
        .iter()
        .map(|row| {
            format!(
                "{}|{}|{}|{}|{}|{}",
                row["id"].as_str().unwrap(),
                row["version"],
                row["owner"].as_str().unwrap(),
                row["bucket"].as_str().unwrap(),
                row["rank"],
                row["note"].as_str().unwrap()
            )
        })
        .collect();
    ensure!(
        sequence == expected_sequence,
        "complete ordered collection differs from independent state"
    );
    Ok(())
}

#[test]
fn complete_collections_preserve_authority_order_bounds_and_atomic_rollback() -> Result<()> {
    let world = World::new()?;
    let mut evidence = evidence::Evidence::start(
        &world.directory.join("evidence"),
        json!({
            "artifact":world.runtime.artifact().id(),"instance":world.runtime.instance_path(),
            "scenario":"Complete collections over mixed owners and predicates; transaction overflow rolls back",
            "alice_initial_keep":205,"bob_keep":110,"alice_other":7,"alice_final_keep":257
        }),
    )?;
    evidence.run(|evidence| {
        let mut rows = Vec::new();
        assert_collection(&world.collect("alice", "empty", "keep", 1, "")?, &[])?;
        world.audit("empty", "success")?;
        for maximum in [0, 257, u64::MAX] {
            let id = format!("invalid-{maximum}");
            let outcome = world.collect("alice", &id, "keep", maximum, "")?;
            ensure!(
                outcome.status == "failure" && outcome.error == "invalid_collection_bound",
                "{outcome:?}"
            );
            let trace = world.audit(&id, "failure")?;
            ensure!(
                trace
                    .request
                    .observations
                    .iter()
                    .all(|item| item.instruction.kind != "select_page"),
                "invalid bound must not start paging"
            );
        }
        evidence.event(json!({"phase":"empty-and-invalid-bounds","snapshot":world.snapshot()?}))?;

        // Deliberately unrelated insertion order, hidden higher ranks and nonmatching buckets.
        for index in 0..205 {
            rows.push(world.insert("alice", "keep", (index * 73) % 205)?);
        }
        for index in 0..110 {
            rows.push(world.insert("bob", "keep", 1000 + index)?);
        }
        for index in 0..7 {
            rows.push(world.insert("alice", "other", 2000 + index)?);
        }
        let before = world.snapshot()?;
        let changes = world.changes()?;
        evidence.event(json!({"phase":"seeded","expected":rows,"snapshot":before}))?;

        let expected = expected_order(&rows, "alice", "keep");
        let full = world.collect("alice", "full", "keep", 205, "")?;
        assert_collection(&full, &expected)?;
        let trace = world.audit("full", "success")?;
        let pages: Vec<_> = trace
            .request
            .observations
            .iter()
            .filter(|item| item.instruction.kind == "select_page")
            .collect();
        ensure!(
            pages.len() == 3,
            "205 matching rows require three maximum-size pages"
        );
        let mut cursor = String::new();
        for (index, page) in pages.iter().enumerate() {
            let request: Value = serde_json::from_str(&page.instruction.data)?;
            let result: Value = serde_json::from_str(&page.result)?;
            ensure!(
                request["limit"] == 100,
                "collect must replace the supplied one-row page size"
            );
            ensure!(
                request["after"] == cursor,
                "pages must follow the native continuation"
            );
            ensure!(
                result["items"].as_array().context("page rows")?.len()
                    == if index < 2 { 100 } else { 5 },
                "unexpected native page length"
            );
            cursor = result["next_after"].as_str().context("page cursor")?.into();
        }
        let first: Value = serde_json::from_str(&pages[0].result)?;
        let prior_cursor = first["next_after"].as_str().context("first real cursor")?;
        ensure!(
            !prior_cursor.is_empty(),
            "multiple-page positive control must expose a cursor"
        );
        assert_collection(
            &world.collect("alice", "restart-cursor", "keep", 205, prior_cursor)?,
            &expected,
        )?;
        assert_collection(
            &world.collect("bob", "bob-view", "keep", 110, "")?,
            &expected_order(&rows, "bob", "keep"),
        )?;
        assert_collection(
            &world.collect("viewer", "viewer-empty", "keep", 1, "")?,
            &[],
        )?;
        assert_collection(
            &world.collect("alice", "other-filter", "other", 7, "")?,
            &expected_order(&rows, "alice", "other"),
        )?;
        let overflow = world.collect("alice", "query-overflow", "keep", 204, "")?;
        ensure!(
            overflow.status == "failure" && overflow.error == "collection_limit_exceeded",
            "{overflow:?}"
        );
        world.audit("query-overflow", "failure")?;
        let admin = world.collect("admin", "admin-overflow", "keep", 256, "")?;
        ensure!(
            admin.error == "collection_limit_exceeded",
            "administrator must count every visible row"
        );
        ensure!(
            world.snapshot()? == before && world.changes()? == changes,
            "queries changed business state"
        );
        evidence.event(json!({"phase":"complete-query","trace":trace,"expected":expected}))?;

        let target = expected[0].clone();
        for maximum in [204, 0, 257] {
            let id = format!("update-fails-{maximum}");
            let outcome = world.update_collect(&id, &target, maximum, "must roll back")?;
            let error = if maximum == 204 {
                "collection_limit_exceeded"
            } else {
                "invalid_collection_bound"
            };
            ensure!(
                outcome.status == "failure" && outcome.error == error,
                "{outcome:?}"
            );
            let trace = world.audit(&id, "failure")?;
            ensure!(
                trace
                    .request
                    .observations
                    .iter()
                    .any(|item| item.instruction.kind == "update" && item.error.is_empty()),
                "positive control: the transaction must perform its write before collect fails"
            );
            ensure!(
                world.snapshot()? == before && world.changes()? == changes,
                "collection failure committed its preceding write"
            );
            ensure!(
                world.update_collect(&id, &target, maximum, "must roll back")? == outcome,
                "failed receipt retry changed outcome"
            );
            evidence.event(json!({"phase":"atomic-rollback","maximum":maximum,"trace":trace}))?;
        }
        let success = world.update_collect("update-succeeds", &target, 205, "committed")?;
        let saved = rows
            .iter_mut()
            .find(|row| row["id"] == target["id"])
            .context("expected target")?;
        saved["note"] = json!("committed");
        saved["version"] = json!(2);
        assert_collection(&success, &expected_order(&rows, "alice", "keep"))?;
        ensure!(
            world.changes()? == changes + 1,
            "successful transaction must commit exactly one audited change"
        );
        world.audit("update-succeeds", "success")?;

        for rank in 205..256 {
            rows.push(world.insert("alice", "keep", rank)?);
        }
        assert_collection(
            &world.collect("alice", "maximum-exact", "keep", 256, "")?,
            &expected_order(&rows, "alice", "keep"),
        )?;
        rows.push(world.insert("alice", "keep", 256)?);
        let maximum_overflow = world.collect("alice", "maximum-overflow", "keep", 256, "")?;
        ensure!(
            maximum_overflow.error == "collection_limit_exceeded",
            "257 rows must not truncate to 256"
        );
        world.audit("maximum-overflow", "failure")?;
        evidence
            .event(json!({"phase":"maximum-bound","expected":rows,"snapshot":world.snapshot()?}))?;

        world.revoke_collection_read()?;
        let denied = world.collect("alice", "revoked-read", "keep", 256, "")?;
        ensure!(
            denied.status == "failure" && denied.error == "forbidden",
            "{denied:?}"
        );
        world.audit("revoked-read", "failure")?;
        let stale = world.collect("alice", "full", "keep", 205, "").unwrap_err();
        ensure!(
            stale.to_string().contains("receipt_policy_changed"),
            "old collection receipt bypassed new authority: {stale:#}"
        );
        evidence.event(
            json!({"phase":"revoked-authority","denied":denied,"snapshot":world.snapshot()?}),
        )?;
        Ok(())
    })
}

#[test]
fn compiler_keeps_collect_read_only_and_rejects_transaction_composition() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let directory = tempfile::tempdir_in(root.join("artifacts"))?;
    let stage = directory.path();
    fs::create_dir(stage.join("app"))?;
    day2::sdk::stage(&root.join("sdk"), &stage.join("sdk"))?;
    fs::write(stage.join("sdk/main.roc"), day2::sdk::app_platform())?;
    let header = r#"app [step] { pf: platform "../sdk/main.roc" }
import pf.Query
import pf.Tx
import pf.Model
import pf.Selection
subject : Selection(Str) -> Query(List(Model.Entity(Str)))
"#;
    for (name, body, allowed) in [
        (
            "TypedCollect",
            "subject = |selection| Query.collect(selection, 256)",
            true,
        ),
        (
            "WriteFromCollect",
            "subject = |selection| Query.collect(selection, 256).and_then(|rows| Tx.succeed(rows))",
            false,
        ),
    ] {
        let file = stage.join(format!("app/{name}.roc"));
        fs::write(
            &file,
            format!(
                "{header}{body}\nstep : Str -> Str\nstep = |_| {{ _ = subject\n \"checked\" }}\n"
            ),
        )?;
        let mut command = day2::sandbox::compiler(
            &root,
            stage,
            &root.join("../.toolchains/roc").canonicalize()?,
        )?;
        command.args(["check", "--no-cache"]).arg(&file);
        let output = compiler::output(&mut command, Duration::from_secs(45))?;
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(output.status.success() == allowed, "{name}: {diagnostic}");
        ensure!(
            allowed || diagnostic.to_ascii_lowercase().contains("type mismatch"),
            "wrong rejection: {diagnostic}"
        );
    }
    Ok(())
}
