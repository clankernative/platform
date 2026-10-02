//! The operator path: a declaration in the instance, read by someone entitled
//! to make it, acting on the app's real database.
//!
//! The eligibility rules themselves are unit-tested next to the code that
//! enforces them. What is tested here is the part that only exists once the
//! pieces are wired together: that the declaration is the operator's and not
//! the app's, that a model nobody declared is not touched, and that a sweep
//! reaches the database the app actually writes to.
use anyhow::{Context, Result};
use day2::{
    artifact::{AppBinding, Instance},
    retention::{self, Rule},
    store::Runtime,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

struct World {
    directory: tempfile::TempDir,
    runtime: Runtime,
}

impl World {
    fn new(retention: BTreeMap<String, Rule>) -> Result<Self> {
        let artifact = std::env::var_os("DAY2_TEST_HTTP_ARTIFACT")
            .map(PathBuf::from)
            .context("run xtask verify or set DAY2_TEST_HTTP_ARTIFACT")?;
        let directory = tempfile::tempdir()?;
        let instance = Instance {
            installation: "retentionco".into(),
            environment: "test".into(),
            branding: None,
            control: Some(serde_json::from_value(json!({
                "version": 1,
                "state_directory": directory.path().join("control"),
                "operators": ["it"],
                "sources": {},
                "apps": {},
            }))?),
            resources: None,
            apps: BTreeMap::from([(
                "links".into(),
                AppBinding {
                    security: None,
                    resource_policies: Vec::new(),
                    credential_families: Default::default(),
                    oauth_connections: Default::default(),
                    schedules: Default::default(),
                    ingress: Default::default(),
                    runtime: None,
                    retention,
                    journal: None,
                    authority: Some(serde_json::from_str(include_str!(
                        "../../../fixtures/authority-policies/owned-links.json"
                    ))?),
                    artifact: artifact.to_string_lossy().into(),
                    readers: BTreeSet::from(["viewer".into()]),
                    writers: BTreeSet::from(["alice".into()]),
                    edge: None,
                },
            )]),
            identity: None,
            security_shell: None,
            oauth_shell_transport: None,
            oauth_clients: None,
        };
        let path = directory.path().join("instance.json");
        fs::write(&path, serde_json::to_vec(&instance)?)?;
        let runtime = Runtime::load(&path, "links")?;
        runtime.initialize()?;
        Ok(Self { directory, runtime })
    }

    fn instance(&self) -> PathBuf {
        self.directory.path().join("instance.json")
    }

    fn db(&self) -> Result<rusqlite::Connection> {
        Ok(rusqlite::Connection::open(self.runtime.db())?)
    }

    /// Rows straight into the app's table: this test is about the operator
    /// path, and the app has no deletion of its own to drive.
    ///
    /// The columns are read from the table rather than written out here, so
    /// the test says what it means — a row exists, and it is deleted or it is
    /// not — instead of restating a fixture's fields and breaking when they
    /// change.
    fn seed(&self, rows: &[(i64, i64)]) -> Result<()> {
        let db = self.db()?;
        let columns: Vec<(String, String)> = db
            .prepare("SELECT name,type FROM pragma_table_info('links')")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, deleted_at) in rows {
            let mut names = Vec::new();
            let mut values: Vec<rusqlite::types::Value> = Vec::new();
            for (name, kind) in &columns {
                names.push(format!("\"{name}\""));
                values.push(match name.as_str() {
                    // A uuid model stores sixteen bytes; the numeric id in the
                    // test is just a way to tell the rows apart.
                    "id" if kind == "BLOB" => {
                        // A uuid model stores sixteen bytes, and the platform
                        // reads the version and variant back out of them, so a
                        // seeded row has to be a real v7 and not sixteen zeroes.
                        let mut bytes = [0u8; 16];
                        bytes[6] = 0x70;
                        bytes[8] = 0x80;
                        bytes[15] = u8::try_from(*id)?;
                        bytes.to_vec().into()
                    }
                    "id" => (*id).into(),
                    "version" => 1.into(),
                    "created_at" => 100.into(),
                    "deleted_at" => (*deleted_at).into(),
                    _ if kind == "INTEGER" => 0.into(),
                    _ if kind == "BLOB" => vec![0u8; 16].into(),
                    _ => "https://example.com/x".to_string().into(),
                });
            }
            let placeholders = (1..=values.len())
                .map(|n| format!("?{n}"))
                .collect::<Vec<_>>()
                .join(",");
            db.execute(
                &format!(
                    "INSERT INTO links({}) VALUES({placeholders})",
                    names.join(",")
                ),
                rusqlite::params_from_iter(values),
            )?;
        }
        Ok(())
    }

    /// Which seeded rows are still there, by the number they were given.
    fn ids(&self) -> Result<Vec<i64>> {
        Ok(self
            .db()?
            .prepare(
                "SELECT CASE WHEN typeof(id)='blob' THEN unicode(substr(id,16,1))
                 ELSE id END FROM links ORDER BY id",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }
}

fn rule(after_days: u32) -> BTreeMap<String, Rule> {
    BTreeMap::from([(
        "links".to_string(),
        Rule {
            after_days,
            reason: "retired links are kept for a quarter".into(),
        },
    )])
}

/// Removal is the operator's decision, and only theirs.
#[test]
fn only_an_installation_administrator_can_plan_or_sweep() -> Result<()> {
    let world = World::new(rule(10))?;
    world.seed(&[(1, 0), (2, 50_000)])?;
    let now = 1_000_000;

    let plan = retention::plan(&world.instance(), "links", "it", now)?;
    assert_eq!(plan.models[0].eligible, 1);

    for outsider in ["alice", "viewer", ""] {
        assert!(
            retention::plan(&world.instance(), "links", outsider, now).is_err(),
            "{outsider} read a retention plan"
        );
        assert!(
            retention::sweep(&world.instance(), "links", outsider, now, &plan).is_err(),
            "{outsider} ran a sweep"
        );
    }
    assert_eq!(world.ids()?, vec![1, 2], "a refused sweep removed a row");
    Ok(())
}

/// An instance that declares nothing removes nothing.
///
/// The default, and the reason the field is a map that starts empty rather than
/// a window with a sensible value. A platform whose retention had a default
/// would be deleting data on behalf of operators who never asked.
#[test]
fn an_app_with_no_declaration_keeps_everything_forever() -> Result<()> {
    let world = World::new(BTreeMap::new())?;
    world.seed(&[(1, 0), (2, 1), (3, 2)])?;
    let now = i64::from(u32::MAX);

    let plan = retention::plan(&world.instance(), "links", "it", now)?;
    assert!(plan.models.is_empty(), "a model was swept without a rule");
    let swept = retention::sweep(&world.instance(), "links", "it", now, &plan)?;
    assert_eq!(swept.removed, 0);
    assert_eq!(
        world.ids()?,
        vec![1, 2, 3],
        "rows deleted at the dawn of time were removed with no policy at all"
    );
    Ok(())
}

/// A policy that could not mean what it says is refused when the instance loads.
///
/// At load, not at the sweep: an instance whose retention is nonsense should
/// fail to start, in front of whoever is deploying it, rather than at 3am on
/// the night someone finally runs a sweep against it.
#[test]
fn an_instance_declaring_an_impossible_policy_does_not_load() -> Result<()> {
    let world = World::new(rule(10))?;
    let mut instance: serde_json::Value = serde_json::from_slice(&fs::read(world.instance())?)?;
    let good = instance["apps"]["links"]["retention"]["links"].clone();
    assert_eq!(good["after_days"], 10);

    for (label, broken) in [
        ("no window", json!({"after_days": 0, "reason": "because"})),
        ("no reason", json!({"after_days": 30, "reason": "   "})),
    ] {
        instance["apps"]["links"]["retention"]["links"] = broken;
        assert!(
            Instance::from_bytes(&serde_json::to_vec(&instance)?).is_err(),
            "an instance with {label} loaded"
        );
    }

    // A model name that is not an identifier cannot reach a SQL statement.
    instance["apps"]["links"]["retention"] = json!({"links; DROP TABLE links": good});
    assert!(Instance::from_bytes(&serde_json::to_vec(&instance)?).is_err());
    Ok(())
}

/// A sweep reaches the database the app writes to, and leaves the rest of it.
#[test]
fn a_sweep_removes_the_declared_rows_and_records_each_one() -> Result<()> {
    let world = World::new(rule(10))?;
    world.seed(&[(1, 0), (2, 990_000), (3, 50_000), (4, 60_000)])?;
    let now = 1_000_000;

    let plan = retention::plan(&world.instance(), "links", "it", now)?;
    assert_eq!(plan.models[0].eligible, 2);
    let swept = retention::sweep(&world.instance(), "links", "it", now, &plan)?;
    assert_eq!(swept.removed, 2);
    assert_eq!(
        world.ids()?,
        vec![1, 2],
        "the live row or the recent deletion did not survive"
    );

    let recorded: Vec<(String, String)> = world
        .db()?
        .prepare("SELECT model,record_id FROM day2_retention_removals ORDER BY record_id")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    // The recorded id is the one the application, the audit log and every
    // screen use. A uuid model stores raw bytes; a record holding sixteen bytes
    // of hex would be a record nobody could match to anything.
    assert_eq!(recorded.len(), 2);
    assert!(
        recorded
            .iter()
            .all(|(model, id)| model == "links" && id.starts_with("lin_")),
        "removals were not recorded under the application's own ids: {recorded:?}"
    );
    assert_ne!(recorded[0].1, recorded[1].1);

    // The removal is in the operator's audit stream, with the installation's
    // scope on it like every other event.
    let scoped: i64 = world.db()?.query_row(
        "SELECT count(*) FROM day2_audit_events WHERE kind='retention'
         AND scope=(SELECT value FROM day2_meta WHERE key='scope')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(scoped, 2);
    Ok(())
}
