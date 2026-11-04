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
    Write {
        row: u8,
        value: u16,
    },
    Begin {
        row: u8,
        value: u16,
    },
    Commit {},
    Rollback {},
    Take {
        slot: u8,
        lose_reply: bool,
    },
    Verify {
        slot: u8,
    },
    Restore {
        slot: u8,
        output: u8,
        lose_reply: bool,
    },
    RemoveMarker {
        slot: u8,
    },
    DamageDatabase {
        slot: u8,
    },
    DamageArtifact {
        slot: u8,
    },
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
    marker: bool,
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
            Event::Commit {} | Event::Rollback {} => {
                let Some(pending) = self.pending.take() else {
                    return Decision::Refused;
                };
                if matches!(event, Event::Commit {}) {
                    self.rows = pending;
                }
            }
            Event::Take { slot, lose_reply } => {
                if self.bundles.contains_key(&slot) {
                    return Decision::Refused;
                }
                self.bundles.insert(
                    slot,
                    Bundle {
                        rows: self.rows.clone(),
                        valid: true,
                        marker: true,
                    },
                );
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
            Event::Restore {
                slot,
                output,
                lose_reply,
            } => {
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
            Event::RemoveMarker { slot }
            | Event::DamageDatabase { slot }
            | Event::DamageArtifact { slot } => {
                let Some(bundle) = self.bundles.get_mut(&slot).filter(|bundle| bundle.valid) else {
                    return Decision::Refused;
                };
                bundle.valid = false;
                if matches!(event, Event::RemoveMarker { .. }) {
                    bundle.marker = false;
                }
            }
        }
        Decision::Applied
    }
}

fn sources() -> String {
    day2::digest(
        concat!(
            include_str!("../../src/backup.rs"),
            include_str!("../../../day2/src/authority_state.rs"),
            include_str!("backup_lifecycle.rs")
        )
        .as_bytes(),
    )
}

fn validate(program: &Program, artifact: &str) -> Result<()> {
    ensure!(
        program.format == 1 && program.sources == sources() && program.artifact == artifact,
        "backup_replay_identity"
    );
    ensure!(
        !program.events.is_empty() && program.events.len() <= MAX_EVENTS,
        "backup_replay_event_bound"
    );
    for event in &program.events {
        match *event {
            Event::Write { row, .. } | Event::Begin { row, .. } => {
                ensure!(row < 4, "backup_replay_row")
            }
            Event::Restore { slot, output, .. } => {
                ensure!(slot < 4 && output < 4, "backup_replay_slot")
            }
            Event::Take { slot, .. }
            | Event::Verify { slot }
            | Event::RemoveMarker { slot }
            | Event::DamageDatabase { slot }
            | Event::DamageArtifact { slot } => ensure!(slot < 4, "backup_replay_slot"),
            Event::Commit {} | Event::Rollback {} => {}
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
        Event::Take {
            slot: 0,
            lose_reply: true,
        },
        Event::Rollback {},
        Event::Write { row: 0, value: 3 },
        Event::Restore {
            slot: 0,
            output: 0,
            lose_reply: true,
        },
        Event::Restore {
            slot: 0,
            output: 0,
            lose_reply: false,
        },
        Event::Take {
            slot: 0,
            lose_reply: false,
        },
        Event::Begin { row: 1, value: 4 },
        Event::Take {
            slot: 1,
            lose_reply: false,
        },
        Event::Commit {},
        Event::Restore {
            slot: 1,
            output: 1,
            lose_reply: false,
        },
        Event::Take {
            slot: 2,
            lose_reply: false,
        },
        Event::DamageDatabase { slot: 2 },
        Event::Restore {
            slot: 2,
            output: 2,
            lose_reply: false,
        },
        Event::Take {
            slot: 3,
            lose_reply: false,
        },
        if seed.is_multiple_of(2) {
            Event::RemoveMarker { slot: 3 }
        } else {
            Event::DamageArtifact { slot: 3 }
        },
        Event::Verify { slot: 3 },
        Event::Restore {
            slot: 3,
            output: 3,
            lose_reply: false,
        },
    ];
    let mut random = seed;
    for index in 0..16 {
        random = random
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let slot = ((random >> 32) % 4) as u8;
        events.push(match random % 7 {
            0 => Event::Write {
                row: slot,
                value: index + 10,
            },
            1 => Event::Begin {
                row: slot,
                value: index + 10,
            },
            2 => Event::Commit {},
            3 => Event::Rollback {},
            4 => Event::Verify { slot },
            5 => Event::Take {
                slot,
                lose_reply: false,
            },
            _ => Event::Restore {
                slot,
                output: slot,
                lose_reply: false,
            },
        });
    }
    Program {
        format: 1,
        artifact: artifact.into(),
        sources: sources(),
        seed,
        events,
    }
}

struct World {
    scratch: tempfile::TempDir,
    runtime: Runtime,
    writer: Connection,
    pending: bool,
    ids: Vec<Vec<u8>>,
    source_epoch: String,
    source_revision: u64,
    restored_epochs: BTreeMap<u8, String>,
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
        writer.execute(
            "INSERT OR REPLACE INTO day2_web_secret VALUES(1,?1)",
            [vec![7_u8; 32]],
        )?;
        let current = authority_state::current(&writer)?;
        let key = &runtime.artifact().contract().schema.models["reports"]
            .identity
            .as_ref()
            .context("Reports identity")?
            .key;
        let ids = (1..=4)
            .map(|ordinal| {
                identity::generate(&[23; 32], 200_000, key, ordinal).map(|id| id.to_vec())
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            scratch,
            runtime,
            writer,
            pending: false,
            ids,
            source_epoch: current.stamp.epoch,
            source_revision: current.stamp.revision,
            restored_epochs: BTreeMap::new(),
        })
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
                if self.pending {
                    return Ok(Decision::Refused);
                }
                if matches!(event, Event::Begin { .. }) {
                    self.writer.execute_batch("BEGIN IMMEDIATE")?;
                    self.pending = true;
                }
                self.write(row, value)
            }
            Event::Commit {} | Event::Rollback {} => {
                if !self.pending {
                    return Ok(Decision::Refused);
                }
                self.writer
                    .execute_batch(if matches!(event, Event::Commit {}) {
                        "COMMIT"
                    } else {
                        "ROLLBACK"
                    })?;
                self.pending = false;
                Ok(())
            }
            Event::Take { slot, .. } => backup::take(
                self.runtime.instance_path(),
                "app",
                &self.path("backup", slot),
            )
            .map(|_| ()),
            Event::Verify { slot } => backup::verify(&self.path("backup", slot)).map(|_| ()),
            Event::Restore { slot, output, .. } => {
                backup::restore(&self.path("backup", slot), &self.path("restored", output))
                    .map(|_| ())
            }
            Event::RemoveMarker { slot } => {
                if backup::verify(&self.path("backup", slot)).is_err() {
                    return Ok(Decision::Refused);
                }
                fs::remove_file(self.path("backup", slot).join("backup.json")).map_err(Into::into)
            }
            Event::DamageDatabase { slot } => {
                let path = self.path("backup", slot).join("app.sqlite");
                if !path.exists() || backup::verify(&self.path("backup", slot)).is_err() {
                    return Ok(Decision::Refused);
                }
                fs::write(path, b"synthetic corruption").map_err(Into::into)
            }
            Event::DamageArtifact { slot } => {
                let Ok(manifest) = backup::verify(&self.path("backup", slot)) else {
                    return Ok(Decision::Refused);
                };
                let path = self
                    .path("backup", slot)
                    .join(&manifest.instance.apps["app"].artifact)
                    .join("artifact.json");
                ensure!(path.is_file(), "backup_artifact_fixture_file");
                fs::write(path, b"synthetic corruption").map_err(Into::into)
            }
        };
        if result.is_err() {
            return Ok(Decision::Refused);
        }
        // This is caller-side reply loss AFTER the real operation succeeded.
        // It is not an injected SQLite crash or evidence of an unapplied write.
        Ok(
            if matches!(
                event,
                Event::Take {
                    lose_reply: true,
                    ..
                } | Event::Restore {
                    lose_reply: true,
                    ..
                }
            ) {
                Decision::ReplyLost
            } else {
                Decision::Applied
            },
        )
    }

    fn expected_rows(&self, rows: &Rows) -> Vec<Value> {
        let mut expected = rows
            .iter()
            .map(|(slot, (value, revision))| {
                let id = self.ids[usize::from(*slot)]
                    .iter()
                    .map(|byte| format!("{byte:02X}"))
                    .collect::<String>();
                json!([
                    id,
                    revision,
                    200_000 + u64::from(*slot),
                    format!("value-{value}"),
                    "synthetic",
                    "developer",
                    true,
                    false,
                    "0000000000000009",
                    "0000000000000001"
                ])
            })
            .collect::<Vec<_>>();
        expected.sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
        expected
    }

    fn expected(&self, model: &Model) -> Value {
        let bundles = model.bundles.iter().map(|(slot,bundle)| (*slot, if bundle.valid {
            json!({"valid":true,"marker":true,"rows":self.expected_rows(&bundle.rows),"same_authority":true,"sessions":[1,1]})
        } else { json!({"valid":false,"marker":bundle.marker}) })).collect::<BTreeMap<_,_>>();
        let restored = model.restored.iter().map(|(slot,rows)| (*slot,json!({
            "rows":self.expected_rows(rows),"new_unique_epoch":true,"epoch_stable":true,"revision_advanced_once":true,
            "disabled":true,"sessions":[0,0],"desired_fenced":true,"authorization_refused":true
        }))).collect::<BTreeMap<_,_>>();
        json!({"rows":self.expected_rows(&model.rows),"same_source_authority":true,"source_enabled":true,"source_sessions":[1,1],"bundles":bundles,"restored":restored})
    }

    fn observe(&mut self) -> Result<Value> {
        let source =
            Connection::open_with_flags(self.runtime.db(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let authority = authority_state::current(&source)?;
        let mut bundles = BTreeMap::new();
        for slot in 0..4 {
            let path = self.path("backup", slot);
            if !path.exists() {
                continue;
            }
            let marker = path.join("backup.json").is_file();
            let observed = if backup::verify(&path).is_ok() {
                let database = Connection::open_with_flags(
                    path.join("app.sqlite"),
                    OpenFlags::SQLITE_OPEN_READ_ONLY,
                )?;
                let current = authority_state::current(&database)?;
                json!({"valid":true,"marker":marker,"rows":actual_rows(&database)?,"same_authority":current.stamp.epoch == self.source_epoch && current.stamp.revision == self.source_revision,"sessions":sessions(&database)?})
            } else {
                json!({"valid":false,"marker":marker})
            };
            bundles.insert(slot, observed);
        }
        let mut restored = BTreeMap::new();
        let mut epochs = std::collections::BTreeSet::new();
        for slot in 0..4 {
            let path = self.path("restored", slot);
            if !path.exists() {
                continue;
            }
            let observed = (|| -> Result<Value> {
                let runtime = Runtime::load(&path.join("instance.json"), "app")?;
                let database =
                    Connection::open_with_flags(runtime.db(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let current = authority_state::current(&database)?;
                let desired = day2::artifact::Instance::load(runtime.instance_path())?;
                let binding = &desired.apps["app"];
                let epoch_stable = self.restored_epochs.entry(slot).or_insert_with(|| current.stamp.epoch.clone()) == &current.stamp.epoch;
                Ok(json!({"rows":actual_rows(&database)?,
                    "new_unique_epoch":current.stamp.epoch != self.source_epoch && epochs.insert(current.stamp.epoch),
                    "epoch_stable":epoch_stable,
                    "revision_advanced_once":current.stamp.revision == self.source_revision + 1,
                    "disabled":!current.document.enabled,"sessions":sessions(&database)?,
                    "desired_fenced":binding.authority.is_none() && binding.readers.is_empty() && binding.writers.is_empty(),
                    "authorization_refused":runtime.authorize_audit(development::ACTOR).is_err()}))
            })();
            // Preserve unexpected partial-output evidence without formatting any
            // adapter error. It cannot compare equal to a completed restore.
            restored.insert(
                slot,
                observed.unwrap_or_else(|_| json!({"load_refused":true})),
            );
        }
        Ok(json!({"rows":actual_rows(&source)?,
            "same_source_authority":authority.stamp.epoch == self.source_epoch && authority.stamp.revision == self.source_revision,
            "source_enabled":authority.document.enabled,"source_sessions":sessions(&source)?,"bundles":bundles,"restored":restored}))
    }
}

fn actual_rows(database: &Connection) -> Result<Vec<Value>> {
    let mut statement = database.prepare("SELECT hex(id),version,created_at,title,text,owner,ready,announced,hex(bytes),hex(lines) FROM reports ORDER BY id")?;
    Ok(statement
        .query_map([], |row| {
            Ok(json!([
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, bool>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?
            ]))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn sessions(database: &Connection) -> Result<[i64; 2]> {
    Ok([
        database.query_row("SELECT COUNT(*) FROM day2_web_sessions", [], |row| {
            row.get(0)
        })?,
        database.query_row("SELECT COUNT(*) FROM day2_web_secret", [], |row| row.get(0))?,
    ])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    expected: Model,
    expected_decision: Decision,
    actual_decision: Decision,
    expected_observation: Value,
    observed: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum OracleControl {
    Correct,
    IncludeUncommitted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replay {
    control: OracleControl,
    program: Program,
    records: Vec<Record>,
    failed_at: Option<usize>,
}

fn run(program: &Program, artifact: &Path) -> Result<Replay> {
    run_with(program, artifact, OracleControl::Correct)
}

fn run_with(program: &Program, artifact: &Path, control: OracleControl) -> Result<Replay> {
    let selected = day2::artifact::LoadedArtifact::load(artifact)?;
    validate(program, selected.id())?;
    let mut world = World::new(artifact)?;
    let mut model = Model::default();
    ensure!(
        world.observe()? == world.expected(&model),
        "backup_initial_state"
    );
    let mut records = Vec::new();
    for (index, event) in program.events.iter().enumerate() {
        let expected_decision = model.step(event);
        if control == OracleControl::IncludeUncommitted
            && let Event::Take { slot, .. } = event
            && let Some(pending) = &model.pending
            && let Some(bundle) = model.bundles.get_mut(slot)
        {
            bundle.rows = pending.clone();
        }
        let actual_decision = world.event(event).unwrap_or(Decision::Refused);
        let expected_observation = world.expected(&model);
        let observed = world
            .observe()
            .unwrap_or_else(|_| json!({"observation_refused":true}));
        let failed = actual_decision != expected_decision || observed != expected_observation;
        records.push(Record {
            expected: model.clone(),
            expected_decision,
            actual_decision,
            expected_observation,
            observed,
        });
        if failed {
            return Ok(Replay {
                control,
                program: program.clone(),
                records,
                failed_at: Some(index),
            });
        }
    }
    Ok(Replay {
        control,
        program: program.clone(),
        records,
        failed_at: None,
    })
}

fn read_replay(path: &Path) -> Result<Replay> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "backup_replay_regular_file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_REPLAY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_REPLAY_BYTES,
        "backup_replay_byte_bound"
    );
    // The shared strict decoder rejects duplicate keys, including nested ones.
    let replay: Replay = day2::json::decode_evidence(&bytes)?;
    ensure!(
        replay.records.len() <= MAX_EVENTS,
        "backup_replay_record_bound"
    );
    Ok(replay)
}

fn retain(replay: &Replay) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let root = Path::new("artifacts/simulations/backup-lifecycle");
    fs::create_dir_all(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let file = tempfile::Builder::new()
        .prefix("replay-")
        .suffix(".json")
        .tempfile_in(root)?;
    let bytes = serde_json::to_vec(replay)?;
    ensure!(
        bytes.len() as u64 <= MAX_REPLAY_BYTES,
        "backup_replay_byte_bound"
    );
    fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600))?;
    fs::write(file.path(), bytes)?;
    let (_, path) = file.keep()?;
    Ok(path)
}

#[test]
fn composed_backup_histories_replay_commits_reply_loss_and_restore_fences() -> Result<()> {
    let artifact = super::artifact()?;
    let selected = day2::artifact::LoadedArtifact::load(&artifact)?;
    for seed in [0, 1, 17, 71] {
        let program = generated(seed, selected.id());
        let first = run(&program, &artifact)?;
        let second = run(&program, &artifact)?;
        if first.failed_at.is_some() || first != second {
            let first_path = retain(&first)?;
            let second_path = retain(&second)?;
            anyhow::bail!("backup lifecycle divergence; first={} second={}", first_path.display(), second_path.display());
        }
        ensure!(
            first.records.len() == program.events.len(),
            "backup_campaign_incomplete"
        );
        ensure!(
            first
                .records
                .last()
                .context("last record")?
                .expected
                .lost_replies
                == 2,
            "backup_reply_loss_not_exercised"
        );
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
    ensure!(
        run(&saved.program, &artifact)? == saved,
        "backup_saved_history_changed"
    );
    let mut false_expectation = saved.clone();
    false_expectation.records[2]
        .expected
        .bundles
        .get_mut(&0)
        .context("snapshot")?
        .rows
        .insert(0, (2, 2));
    ensure!(
        run(&false_expectation.program, &artifact)? != false_expectation,
        "backup_uncommitted_row_oracle_bypassed"
    );
    let mut false_observation = saved.clone();
    false_observation.records[5].observed["restored"]["0"]["disabled"] = json!(false);
    ensure!(
        run(&false_observation.program, &artifact)? != false_observation,
        "backup_restore_fence_oracle_bypassed"
    );
    let wrong = run_with(&program, &artifact, OracleControl::IncludeUncommitted)?;
    ensure!(
        wrong.failed_at == Some(2) && wrong.records.len() == 3,
        "backup_wrong_oracle_not_detected"
    );
    ensure!(
        run_with(&program, &artifact, OracleControl::IncludeUncommitted)? == wrong,
        "backup_wrong_oracle_not_replayed"
    );
    let retained = retain(&wrong)?;
    let saved_failure = read_replay(&retained)?;
    ensure!(
        run_with(&saved_failure.program, &artifact, saved_failure.control)? == saved_failure,
        "backup_failure_retention_changed"
    );
    let mut wrong_artifact = program.clone();
    wrong_artifact.artifact = "sha256:wrong-artifact".into();
    ensure!(
        run(&wrong_artifact, &artifact).is_err(),
        "backup_wrong_artifact_accepted"
    );
    program.sources = "sha256:stale-source".into();
    ensure!(
        run(&program, &artifact).is_err(),
        "backup_stale_replay_accepted"
    );
    Ok(())
}

#[test]
fn externally_supplied_backup_history_is_strict_and_replayed_twice() -> Result<()> {
    let Some(path) = std::env::var_os("DAY2_BACKUP_REPLAY") else {
        return Ok(());
    };
    let saved = read_replay(Path::new(&path))?;
    let artifact = super::artifact()?;
    let first = run_with(&saved.program, &artifact, saved.control)?;
    let second = run_with(&saved.program, &artifact, saved.control)?;
    ensure!(
        first == saved && second == saved,
        "backup_external_replay_changed"
    );
    Ok(())
}

#[test]
fn backup_replay_input_refuses_duplicates_unknown_fields_and_out_of_range_events() -> Result<()> {
    let program = generated(71, "synthetic-artifact");
    let encoded = serde_json::to_string(&program)?;
    let duplicate = encoded.replacen("\"seed\":71", "\"seed\":71,\"seed\":17", 1);
    ensure!(
        duplicate != encoded
            && day2::json::decode_evidence::<Program>(duplicate.as_bytes()).is_err(),
        "backup_duplicate_input_accepted"
    );
    let mut unknown = serde_json::to_value(&program)?;
    unknown["events"][0]["unknown"] = json!(true);
    ensure!(
        day2::json::decode_evidence::<Program>(&serde_json::to_vec(&unknown)?).is_err(),
        "backup_unknown_input_accepted"
    );
    let extra_unit = br#"{"kind":"Commit","unknown":true}"#;
    ensure!(
        day2::json::decode_evidence::<Event>(extra_unit).is_err(),
        "backup_unknown_unit_field_accepted"
    );
    let mut invalid = program.clone();
    invalid.events = vec![Event::Take {
        slot: 4,
        lose_reply: false,
    }];
    ensure!(
        validate(&invalid, "synthetic-artifact").is_err(),
        "backup_out_of_range_slot_accepted"
    );
    invalid.events = vec![Event::Commit {}; MAX_EVENTS + 1];
    ensure!(
        validate(&invalid, "synthetic-artifact").is_err(),
        "backup_oversized_history_accepted"
    );
    Ok(())
}
