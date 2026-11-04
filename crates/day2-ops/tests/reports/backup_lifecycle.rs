//! Composed ordinary backup histories. The oracle owns event-derived rows;
//! neither a database read nor a backup receipt supplies its expectations.
use anyhow::{Context, Result, ensure};
use day2::{authority_state, development, identity, store::Runtime};
use day2_ops::backup;
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

const MAX_EVENTS: usize = 64;
const MAX_REPLAY_BYTES: u64 = 2 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Event {
    Write { row: u8, value: u16 },
    Begin { row: u8, value: u16 },
    Commit,
    Rollback,
    Take { slot: u8, lose_reply: bool },
    Verify { slot: u8 },
    Restore { slot: u8, output: u8, lose_reply: bool },
    RemoveMarker { slot: u8 },
    DamageDatabase { slot: u8 },
    DamageArtifact { slot: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    format: u8,
    artifact: String,
    sources: String,
    seed: u64,
    events: Vec<Event>,
}

type Rows = BTreeMap<u8, (u16, u64)>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    rows: Rows,
    valid: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Model {
    rows: Rows,
    pending: Option<Rows>,
    bundles: BTreeMap<u8, Bundle>,
    restored: BTreeMap<u8, Rows>,
    lost_replies: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Decision {
    Applied,
    Refused,
    ReplyLost,
}

impl Model {
    fn step(&mut self, event: &Event) -> Decision {
        match *event {
            Event::Write { row, value } | Event::Begin { row, value } => {
                if self.pending.is_some() {
                    return Decision::Refused;
                }
                let mut next = self.rows.clone();
                let revision = next.get(&row).map_or(1, |(_, revision)| revision + 1);
                next.insert(row, (value, revision));
                if matches!(event, Event::Begin { .. }) {
                    self.pending = Some(next);
                } else {
                    self.rows = next;
                }
            }
            Event::Commit | Event::Rollback => {
                let Some(pending) = self.pending.take() else {
                    return Decision::Refused;
                };
                if matches!(event, Event::Commit) {
                    self.rows = pending;
                }
            }
            Event::Take { slot, lose_reply } => {
                if self.bundles.contains_key(&slot) {
                    return Decision::Refused;
                }
                self.bundles.insert(slot, Bundle { rows: self.rows.clone(), valid: true });
                if lose_reply {
                    self.lost_replies += 1;
                    return Decision::ReplyLost;
                }
            }
            Event::Verify { slot } => {
                if !self.bundles.get(&slot).is_some_and(|bundle| bundle.valid) {
                    return Decision::Refused;
                }
            }
            Event::Restore { slot, output, lose_reply } => {
                let Some(bundle) = self.bundles.get(&slot).filter(|bundle| bundle.valid) else {
                    return Decision::Refused;
                };
                if self.restored.contains_key(&output) {
                    return Decision::Refused;
                }
                self.restored.insert(output, bundle.rows.clone());
                if lose_reply {
                    self.lost_replies += 1;
                    return Decision::ReplyLost;
                }
            }
            Event::RemoveMarker { slot } | Event::DamageDatabase { slot } | Event::DamageArtifact { slot } => {
                let Some(bundle) = self.bundles.get_mut(&slot).filter(|bundle| bundle.valid) else {
                    return Decision::Refused;
                };
                bundle.valid = false;
            }
        }
        Decision::Applied
    }
}

fn sources() -> String {
    day2::digest(concat!(
        include_str!("../../src/backup.rs"),
        include_str!("../../../day2/src/authority_state.rs"),
        include_str!("backup_lifecycle.rs")
    ).as_bytes())
}

fn validate(program: &Program, artifact: &str) -> Result<()> {
    ensure!(program.format == 1 && program.sources == sources() && program.artifact == artifact, "backup_replay_identity");
    ensure!(!program.events.is_empty() && program.events.len() <= MAX_EVENTS, "backup_replay_event_bound");
    for event in &program.events {
        match *event {
            Event::Write { row, .. } | Event::Begin { row, .. } => ensure!(row < 4, "backup_replay_row"),
            Event::Restore { slot, output, .. } => ensure!(slot < 4 && output < 4, "backup_replay_slot"),
            Event::Take { slot, .. } | Event::Verify { slot } | Event::RemoveMarker { slot }
            | Event::DamageDatabase { slot } | Event::DamageArtifact { slot } => ensure!(slot < 4, "backup_replay_slot"),
            Event::Commit | Event::Rollback => {}
        }
    }
    Ok(())
}

fn generated(seed: u64, artifact: &str) -> Program {
    // This prefix guarantees each semantic cut; generated suffixes vary their
    // ordering and exercise new-directory refusal without retrying an operation.
    let mut events = vec![
        Event::Write { row: 0, value: 1 },
        Event::Begin { row: 0, value: 2 },
        Event::Take { slot: 0, lose_reply: true },
        Event::Rollback,
        Event::Write { row: 0, value: 3 },
        Event::Restore { slot: 0, output: 0, lose_reply: true },
        Event::Restore { slot: 0, output: 0, lose_reply: false },
        Event::Take { slot: 0, lose_reply: false },
        Event::Begin { row: 1, value: 4 },
        Event::Take { slot: 1, lose_reply: false },
        Event::Commit,
        Event::Restore { slot: 1, output: 1, lose_reply: false },
        Event::Take { slot: 2, lose_reply: false },
        Event::DamageDatabase { slot: 2 },
        Event::Restore { slot: 2, output: 2, lose_reply: false },
        Event::Take { slot: 3, lose_reply: false },
        if seed % 2 == 0 { Event::RemoveMarker { slot: 3 } } else { Event::DamageArtifact { slot: 3 } },
        Event::Verify { slot: 3 },
        Event::Restore { slot: 3, output: 3, lose_reply: false },
    ];
    let mut random = seed;
    for index in 0..16 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let slot = ((random >> 32) % 4) as u8;
        events.push(match random % 7 {
            0 => Event::Write { row: slot, value: index + 10 },
            1 => Event::Begin { row: slot, value: index + 10 },
            2 => Event::Commit,
            3 => Event::Rollback,
            4 => Event::Verify { slot },
            5 => Event::Take { slot, lose_reply: false },
            _ => Event::Restore { slot, output: slot, lose_reply: false },
        });
    }
    Program { format: 1, artifact: artifact.into(), sources: sources(), seed, events }
}

struct World {
    scratch: tempfile::TempDir,
    runtime: Runtime,
    writer: Connection,
    pending: bool,
    ids: Vec<Vec<u8>>,
    source_epoch: String,
    source_revision: u64,
}

impl World {
    fn new(artifact: &Path) -> Result<Self> {
        let scratch = tempfile::tempdir()?;
        let runtime = development::create(artifact, &scratch.path().join("source"), None)?;
        let writer = Connection::open(runtime.db())?;
        let mode: String = writer.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        ensure!(mode == "wal", "backup_campaign_requires_wal");
        writer.execute_batch("PRAGMA wal_autocheckpoint=0")?;
        writer.execute("INSERT INTO day2_web_sessions VALUES('synthetic-backup-session','developer',253402300799)", [])?;
        writer.execute("INSERT OR REPLACE INTO day2_web_secret VALUES(1,?1)", [vec![7_u8;32]])?;
        let current = authority_state::current(&writer)?;
        let key = &runtime.artifact().contract().schema.models["reports"].identity.as_ref().context("Reports identity")?.key;
        let ids = (1..=4).map(|ordinal| identity::generate(&[23;32], 200_000, key, ordinal).map(|id| id.to_vec())).collect::<Result<Vec<_>>>()?;
        Ok(Self { scratch, runtime, writer, pending: false, ids, source_epoch: current.stamp.epoch, source_revision: current.stamp.revision })
    }

    fn path(&self, kind: &str, slot: u8) -> std::path::PathBuf {
        self.scratch.path().join(format!("{kind}-{slot}"))
    }

    fn write(&self, row: u8, value: u16) -> Result<()> {
        self.writer.execute(
            "INSERT INTO reports(id,version,created_at,title,text,owner,ready,announced,bytes,lines) VALUES(?1,1,?2,?3,'synthetic','developer',1,0,?4,?5) ON CONFLICT(id) DO UPDATE SET title=excluded.title,version=reports.version+1",
            params![self.ids[usize::from(row)], 200_000 + i64::from(row), format!("value-{value}"), 9_u64.to_be_bytes().as_slice(), 1_u64.to_be_bytes().as_slice()],
        )?;
        Ok(())
    }

    fn event(&mut self, event: &Event) -> Result<Decision> {
        let result = match *event {
            Event::Write { row, value } | Event::Begin { row, value } => {
                if self.pending { return Ok(Decision::Refused); }
                if matches!(event, Event::Begin { .. }) {
                    self.writer.execute_batch("BEGIN IMMEDIATE")?;
                    self.pending = true;
                }
                self.write(row, value)
            }
            Event::Commit | Event::Rollback => {
                if !self.pending { return Ok(Decision::Refused); }
                self.writer.execute_batch(if matches!(event, Event::Commit) { "COMMIT" } else { "ROLLBACK" })?;
                self.pending = false;
                Ok(())
            }
            Event::Take { slot, .. } => backup::take(self.runtime.instance_path(), "app", &self.path("backup", slot)).map(|_| ()),
            Event::Verify { slot } => backup::verify(&self.path("backup", slot)).map(|_| ()),
            Event::Restore { slot, output, .. } => backup::restore(&self.path("backup", slot), &self.path("restored", output)).map(|_| ()),
            Event::RemoveMarker { slot } => {
                if backup::verify(&self.path("backup", slot)).is_err() { return Ok(Decision::Refused); }
                fs::remove_file(self.path("backup", slot).join("backup.json")).map_err(Into::into)
            },
            Event::DamageDatabase { slot } => {
                let path = self.path("backup", slot).join("app.sqlite");
                if !path.exists() || backup::verify(&self.path("backup", slot)).is_err() { return Ok(Decision::Refused); }
                fs::write(path, b"synthetic corruption").map_err(Into::into)
            }
            Event::DamageArtifact { slot } => {
                let Ok(manifest) = backup::verify(&self.path("backup", slot)) else { return Ok(Decision::Refused); };
                let path = self.path("backup", slot).join(&manifest.instance.apps["app"].artifact).join("artifact.json");
                ensure!(path.is_file(), "backup_artifact_fixture_file");
                fs::write(path, b"synthetic corruption").map_err(Into::into)
            }
        };
        if result.is_err() { return Ok(Decision::Refused); }
        // This is caller-side reply loss AFTER the real operation succeeded.
        // It is not an injected SQLite crash or evidence of an unapplied write.
        Ok(if matches!(event, Event::Take { lose_reply: true, .. } | Event::Restore { lose_reply: true, .. }) { Decision::ReplyLost } else { Decision::Applied })
    }

    fn expected_rows(&self, rows: &Rows) -> Vec<Value> {
        let mut expected = rows.iter().map(|(slot,(value,revision))| {
            let id = self.ids[usize::from(*slot)].iter().map(|byte| format!("{byte:02X}")).collect::<String>();
            json!([id, revision, 200_000 + u64::from(*slot), format!("value-{value}"), "synthetic", "developer", true, false, "0000000000000009", "0000000000000001"])
        }).collect::<Vec<_>>();
        expected.sort_by(|a,b| a[0].as_str().cmp(&b[0].as_str()));
        expected
    }

    fn observe(&self, model: &Model) -> Result<Value> {
        let source = Connection::open_with_flags(self.runtime.db(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let rows = actual_rows(&source)?;
        ensure!(rows == self.expected_rows(&model.rows), "backup_source_rows");
        let authority = authority_state::current(&source)?;
        ensure!(authority.stamp.epoch == self.source_epoch && authority.stamp.revision == self.source_revision && authority.document.enabled, "backup_source_authority");
        ensure!(sessions(&source)? == [1,1], "backup_source_sessions");
        let mut bundles = BTreeMap::new();
        for (slot, expected) in &model.bundles {
            let path = self.path("backup", *slot);
            let valid = backup::verify(&path).is_ok();
            ensure!(valid == expected.valid, "backup_bundle_verification");
            if valid {
                let database = Connection::open_with_flags(path.join("app.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                ensure!(actual_rows(&database)? == self.expected_rows(&expected.rows), "backup_snapshot_rows");
                let current = authority_state::current(&database)?;
                ensure!(current.stamp.epoch == self.source_epoch && current.stamp.revision == self.source_revision, "backup_snapshot_authority");
                ensure!(sessions(&database)? == [1,1], "backup_snapshot_sessions");
            }
            bundles.insert(*slot, valid);
        }
        let mut restored = BTreeMap::new();
        let mut epochs = std::collections::BTreeSet::new();
        for (slot, expected) in &model.restored {
            let runtime = Runtime::load(&self.path("restored", *slot).join("instance.json"), "app")?;
            let database = Connection::open_with_flags(runtime.db(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let rows = actual_rows(&database)?;
            ensure!(rows == self.expected_rows(expected), "backup_restored_rows");
            let current = authority_state::current(&database)?;
            ensure!(current.stamp.epoch != self.source_epoch && epochs.insert(current.stamp.epoch) && current.stamp.revision == self.source_revision + 1 && !current.document.enabled, "backup_restore_authority_fence");
            ensure!(sessions(&database)? == [0,0], "backup_restore_session_fence");
            let desired = day2::artifact::Instance::load(runtime.instance_path())?;
            let binding = &desired.apps["app"];
            ensure!(binding.authority.is_none() && binding.readers.is_empty() && binding.writers.is_empty(), "backup_restore_desired_fence");
            ensure!(runtime.authorize_audit(development::ACTOR).is_err(), "backup_restore_granted_authority");
            restored.insert(*slot, rows);
        }
        // Refusal must not create an output, including corrupt/missing-marker
        // bundles. Earlier successful outputs remain completely checked above.
        for slot in 0..4 {
            ensure!(self.path("restored", slot).exists() == model.restored.contains_key(&slot), "backup_restore_output_presence");
        }
        Ok(json!({"rows":rows,"bundles":bundles,"restored":restored,"source_sessions":[1,1],"restored_sessions":[0,0],"restores_fenced":true}))
    }
}

fn actual_rows(database: &Connection) -> Result<Vec<Value>> {
    let mut statement = database.prepare("SELECT hex(id),version,created_at,title,text,owner,ready,announced,hex(bytes),hex(lines) FROM reports ORDER BY id")?;
    Ok(statement.query_map([], |row| Ok(json!([
        row.get::<_,String>(0)?,row.get::<_,u64>(1)?,row.get::<_,u64>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,bool>(6)?,row.get::<_,bool>(7)?,row.get::<_,String>(8)?,row.get::<_,String>(9)?
    ])))?.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn sessions(database: &Connection) -> Result<[u64;2]> {
    Ok([database.query_row("SELECT COUNT(*) FROM day2_web_sessions", [], |row| row.get(0))?, database.query_row("SELECT COUNT(*) FROM day2_web_secret", [], |row| row.get(0))?])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    expected: Model,
    decision: Decision,
    observed: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    program: Program,
    records: Vec<Record>,
    failed_at: Option<usize>,
}

fn run(program: &Program, artifact: &Path) -> Result<Replay> {
    let selected = day2::artifact::LoadedArtifact::load(artifact)?;
    validate(program, selected.id())?;
    let mut world = World::new(artifact)?;
    let mut model = Model::default();
    world.observe(&model)?;
    let mut records = Vec::new();
    for (index,event) in program.events.iter().enumerate() {
        let expected = model.step(event);
        let actual = world.event(event)?;
        let observed = world.observe(&model);
        if actual != expected || observed.is_err() {
            return Ok(Replay { program: program.clone(), records, failed_at: Some(index) });
        }
        records.push(Record { expected: model.clone(), decision: actual, observed: observed? });
    }
    Ok(Replay { program: program.clone(), records, failed_at: None })
}

fn read_replay(path: &Path) -> Result<Replay> {
    ensure!(fs::symlink_metadata(path)?.file_type().is_file(), "backup_replay_regular_file");
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(MAX_REPLAY_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_REPLAY_BYTES, "backup_replay_byte_bound");
    // The shared strict decoder rejects duplicate keys, including nested ones.
    day2::json::decode_evidence(&bytes)
}

fn retain(replay: &Replay) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let root = Path::new("artifacts/simulations/backup-lifecycle");
    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let file = tempfile::Builder::new().prefix("replay-").suffix(".json").tempfile_in(root)?;
    let bytes = serde_json::to_vec(replay)?;
    ensure!(bytes.len() as u64 <= MAX_REPLAY_BYTES, "backup_replay_byte_bound");
    fs::write(file.path(), bytes)?;
    let (_,path) = file.keep()?;
    Ok(path)
}

#[test]
fn composed_backup_histories_replay_commits_reply_loss_and_restore_fences() -> Result<()> {
    let artifact = super::artifact()?;
    let selected = day2::artifact::LoadedArtifact::load(&artifact)?;
    for seed in [0,1,17,71] {
        let program = generated(seed, selected.id());
        let first = run(&program, &artifact)?;
        let second = run(&program, &artifact)?;
        if first.failed_at.is_some() || first != second {
            let path = retain(&first)?;
            anyhow::bail!("backup lifecycle divergence; replay={}", path.display());
        }
        ensure!(first.records.len() == program.events.len(), "backup_campaign_incomplete");
        ensure!(first.records.last().context("last record")?.expected.lost_replies == 2, "backup_reply_loss_not_exercised");
    }
    Ok(())
}

#[test]
fn saved_backup_history_rejects_false_expectations_and_stale_source_identity() -> Result<()> {
    let artifact = super::artifact()?;
    let selected = day2::artifact::LoadedArtifact::load(&artifact)?;
    let mut program = generated(17, selected.id());
    program.events.truncate(8);
    let actual = run(&program, &artifact)?;
    ensure!(actual.failed_at.is_none(), "backup_control_history_failed");
    let scratch = tempfile::tempdir()?;
    let path = scratch.path().join("replay.json");
    fs::write(&path, serde_json::to_vec(&actual)?)?;
    let saved = read_replay(&path)?;
    ensure!(run(&saved.program, &artifact)? == saved, "backup_saved_history_changed");
    let mut false_expectation = saved.clone();
    false_expectation.records[2].expected.bundles.get_mut(&0).context("snapshot")?.rows.insert(0,(2,2));
    ensure!(run(&false_expectation.program, &artifact)? != false_expectation, "backup_uncommitted_row_oracle_bypassed");
    let mut false_observation = saved.clone();
    false_observation.records[5].observed["restores_fenced"] = json!(false);
    ensure!(run(&false_observation.program, &artifact)? != false_observation, "backup_restore_fence_oracle_bypassed");
    program.sources = "sha256:stale-source".into();
    ensure!(run(&program, &artifact).is_err(), "backup_stale_replay_accepted");
    Ok(())
}

#[test]
fn externally_supplied_backup_history_is_strict_and_replayed_twice() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_BACKUP_REPLAY") else { return Ok(()); };
    let saved = read_replay(Path::new(&path))?;
    let artifact = super::artifact()?;
    let first = run(&saved.program, &artifact)?;
    let second = run(&saved.program, &artifact)?;
    ensure!(first == saved && second == saved, "backup_external_replay_changed");
    Ok(())
}
