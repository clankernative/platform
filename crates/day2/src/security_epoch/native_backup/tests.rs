//! Real SQLite/component histories, not enrolled owners or native permission.
use super::*;
use rusqlite::OpenFlags;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub(super) fn source(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

fn writer(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.pragma_update(None, "journal_mode", "WAL")?;
    db.execute_batch(
        "CREATE TABLE public_markers(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE private_versions(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE uncertain_effects(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE budget_debt(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE source_authority(id INTEGER PRIMARY KEY,value INTEGER NOT NULL);
        INSERT INTO source_authority VALUES(1,7);",
    )?;
    Ok(db)
}

pub(super) fn complete(snapshot: &mut MemorySnapshot, tx: &mut Transaction<'_>) -> Result<()> {
    let mut copying = snapshot.start(tx)?;
    while copying.step()? != CopyProgress::Complete {}
    Ok(())
}

fn rows(db: &Connection) -> Result<Vec<Vec<(i64, i64)>>> {
    [
        "public_markers",
        "private_versions",
        "uncertain_effects",
        "budget_debt",
        "source_authority",
    ]
    .into_iter()
    .map(|table| {
        Ok(db
            .prepare(&format!("SELECT id,value FROM {table} ORDER BY id"))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    })
    .collect()
}

#[test]
fn logical_wal_snapshot_preserves_committed_private_history_and_leaves_source_unchanged()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let write = writer(&path)?;
    write.execute_batch(
        "INSERT INTO public_markers VALUES(1,11); INSERT INTO private_versions VALUES(1,12);
        INSERT INTO uncertain_effects VALUES(1,13); INSERT INTO budget_debt VALUES(1,14);",
    )?;
    let expected = vec![
        vec![(1, 11)],
        vec![(1, 12)],
        vec![(1, 13)],
        vec![(1, 14)],
        vec![(1, 7)],
    ];
    let mut read = source(&path)?;
    let mut tx = read.transaction()?;
    let mut snapshot = MemorySnapshot::new()?;
    {
        let mut copying = snapshot.start(&mut tx)?;
        write.execute_batch("BEGIN IMMEDIATE; INSERT INTO public_markers VALUES(2,99);")?;
        while copying.step()? != CopyProgress::Complete {}
    }
    let image = snapshot.finish()?;
    ensure!(
        rows(&image.db)? == expected,
        "controlled_snapshot_divergence"
    );
    // Logical content success is not restorable WAL export. The unchanged
    // standalone guard refuses the actual pinned library's retained 2/2 image.
    assert!(image.into_image().is_err());
    tx.commit()?;
    write.execute_batch("ROLLBACK")?;
    ensure!(rows(&write)? == expected, "controlled_source_changed");
    let mode: String = write.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    ensure!(mode == "wal", "controlled_source_journal_changed");
    Ok(())
}

#[test]
fn rollback_source_produces_a_real_standalone_image_and_wal_export_refuses() -> Result<()> {
    for wal in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("source.sqlite");
        let write = writer(&path)?;
        write.execute_batch("INSERT INTO public_markers VALUES(1,11)")?;
        if !wal {
            write.pragma_update(None, "journal_mode", "DELETE")?;
        }
        let mut read = source(&path)?;
        let mut tx = read.transaction()?;
        let mut snapshot = MemorySnapshot::new()?;
        complete(&mut snapshot, &mut tx)?;
        let content = snapshot.finish()?;
        ensure!(
            rows(&content.db)?[0] == [(1, 11)],
            "controlled_logical_content"
        );
        let image = content.into_image();
        if wal {
            assert!(image.is_err());
        } else {
            let image = image?;
            image_shape(&image.bytes)?;
            let mut decoded = Connection::open_in_memory()?;
            decoded.deserialize_read_exact(MAIN_DB, &image.bytes[..], image.bytes.len(), false)?;
            ensure!(
                rows(&decoded)?[0] == [(1, 11)],
                "controlled_standalone_changed"
            );
        }
        tx.commit()?;
    }
    Ok(())
}

#[test]
fn real_multistep_copy_keeps_one_pinned_snapshot_across_later_writer_commits() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let write = writer(&path)?;
    write.execute_batch(
        "CREATE TABLE payload(id INTEGER PRIMARY KEY,bytes BLOB);
        INSERT INTO payload VALUES(1,zeroblob(300000)); INSERT INTO public_markers VALUES(1,10);",
    )?;
    let mut read = source(&path)?;
    let mut tx = read.transaction()?;
    let mut snapshot = MemorySnapshot::new()?;
    let mut steps = 0;
    {
        let mut copying = snapshot.start(&mut tx)?;
        loop {
            let result = copying.step()?;
            steps += 1;
            if result == CopyProgress::Complete {
                break;
            }
            write.execute("INSERT INTO public_markers VALUES(?1,999)", [steps + 1])?;
        }
    }
    let image = snapshot.finish()?;
    ensure!(steps > 1, "controlled_multistep_not_reached");
    ensure!(
        rows(&image.db)?[0] == [(1, 10)],
        "controlled_snapshot_changed"
    );
    ensure!(
        write.query_row("SELECT count(*) FROM public_markers", [], |r| r
            .get::<_, i64>(0))?
            > 1,
        "controlled_writer_not_reached"
    );
    tx.commit()?;
    Ok(())
}

#[test]
fn readwrite_source_and_abandoned_or_unwound_copies_are_absorbing_refusals() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let mut write = writer(&path)?;
    {
        let mut tx = write.transaction()?;
        let mut refused = MemorySnapshot::new()?;
        assert!(refused.start(&mut tx).is_err());
        assert!(refused.start(&mut tx).is_err());
        assert!(refused.finish().is_err());
    }
    let mut read = source(&path)?;
    let mut tx = read.transaction()?;
    for unwind in [false, true] {
        let mut refused = MemorySnapshot::new()?;
        if unwind {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _copying = refused.start(&mut tx).expect("controlled copy");
                panic!("controlled_abandonment");
            }));
            assert!(result.is_err());
        } else {
            drop(refused.start(&mut tx)?);
        }
        assert!(refused.start(&mut tx).is_err());
        assert!(refused.finish().is_err());
    }
    assert!(MemorySnapshot::new()?.finish().is_err());
    Ok(())
}

#[test]
fn exclusive_transaction_borrow_and_abandoned_copy_cannot_be_repaired() -> Result<()> {
    // This compiled signature pins exclusive source ownership: a caller cannot
    // execute ROLLBACK; BEGIN through tx while the returned handle is in use.
    let _: for<'s, 'tx, 'target> fn(
        &'target mut MemorySnapshot,
        &'s mut Transaction<'tx>,
    ) -> Result<SnapshotCopy<'s, 'tx, 'target>> = MemorySnapshot::start;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let _write = writer(&path)?;
    let mut read = source(&path)?;
    let mut tx = read.transaction()?;
    let mut snapshot = MemorySnapshot::new()?;
    drop(snapshot.start(&mut tx)?);
    tx.rollback()?;
    let mut replacement = read.transaction()?;
    assert!(snapshot.start(&mut replacement).is_err());
    assert!(snapshot.finish().is_err());
    Ok(())
}

#[test]
fn attached_database_and_post_completion_misuse_do_not_repair_the_same_target() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let _write = writer(&path)?;
    let extra = directory.path().join("extra.sqlite");
    Connection::open(&extra)?.execute_batch("CREATE TABLE private_extra(id INTEGER)")?;
    let mut read = source(&path)?;
    read.execute(
        "ATTACH DATABASE ?1 AS extra",
        [extra.to_str().context("controlled_path")?],
    )?;
    let mut refused = MemorySnapshot::new()?;
    {
        let mut tx = read.transaction()?;
        assert!(refused.start(&mut tx).is_err());
    }
    read.execute_batch("DETACH DATABASE extra")?;
    let mut tx = read.transaction()?;
    assert!(refused.start(&mut tx).is_err());
    assert!(refused.finish().is_err());
    let mut snapshot = MemorySnapshot::new()?;
    {
        let mut copy = snapshot.start(&mut tx)?;
        while copy.step()? != CopyProgress::Complete {}
        assert!(copy.step().is_err());
    }
    assert!(snapshot.finish().is_err());
    Ok(())
}

#[test]
fn oversize_and_every_reserved_schema_name_refuse_without_source_mutation() -> Result<()> {
    for object in ["TABLE", "VIEW"] {
        for name in [
            "day2_rollout_generations",
            "DAY2_ROLLOUT_RUNTIME",
            "day2_invocation_runtime",
        ] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().join("source.sqlite");
            let write = writer(&path)?;
            write.execute_batch(&if object == "TABLE" {
                format!("CREATE TABLE {name}(id INTEGER)")
            } else {
                format!("CREATE VIEW {name} AS SELECT 1")
            })?;
            let mut read = source(&path)?;
            let mut tx = read.transaction()?;
            let mut snapshot = MemorySnapshot::new()?;
            assert!(snapshot.start(&mut tx).is_err());
            assert!(snapshot.finish().is_err());
            ensure!(
                write.query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name=?1",
                    [name],
                    |r| r.get::<_, i64>(0)
                )? == 1,
                "controlled_source_schema_changed"
            );
        }
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let write = writer(&path)?;
    write.execute_batch(
        "CREATE TABLE oversized(bytes BLOB); INSERT INTO oversized VALUES(zeroblob(16777216));",
    )?;
    let mut read = source(&path)?;
    let mut tx = read.transaction()?;
    let mut snapshot = MemorySnapshot::new()?;
    assert!(snapshot.start(&mut tx).is_err());
    assert!(snapshot.finish().is_err());
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Event {
    Write,
    BeginUncommitted,
    Commit,
    Rollback,
    Capture,
    Verify,
    AbortCapture,
    PanicCapture,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    version: u32,
    source: String,
    seed: u64,
    events: Vec<Event>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    step: usize,
    expected: String,
    actual: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    Setup,
    Capture,
    Schedule,
    Panic,
    MissingObservation,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    step: usize,
    kind: FailureKind,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    observations: Vec<Observation>,
    failure: Option<Failure>,
}

fn validate(program: &Program) -> Result<()> {
    ensure!(
        program.version == 1
            && program.source == source_digest()
            && !program.events.is_empty()
            && program.events.len() <= 64
            && serde_json::to_vec(program)?.len() <= 65536,
        "backup_program_bound"
    );
    Ok(())
}

// Independent oracle owns committed and pending values. It never reads a SUT
// receipt/database to select the expected snapshot or a native permission.
fn replay(program: &Program, wrong: bool) -> Result<Run> {
    validate(program)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let write = writer(&path)?;
    let mut committed = vec![vec![], vec![], vec![], vec![], vec![(1, 7)]];
    let mut pending: Option<Vec<Vec<(i64, i64)>>> = None;
    let mut images = Vec::new();
    let mut verified_images = 0;
    let mut run = Run {
        observations: Vec::new(),
        failure: None,
    };
    let mut id = 0i64;
    for (step, event) in program.events.iter().enumerate() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            match event {
                Event::Write => {
                    id += 1;
                    let value = id * 13;
                    for (index, table) in [
                        "public_markers",
                        "private_versions",
                        "uncertain_effects",
                        "budget_debt",
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        write
                            .execute(&format!("INSERT INTO {table} VALUES(?1,?2)"), [id, value])?;
                        pending.as_mut().unwrap_or(&mut committed)[index].push((id, value));
                    }
                }
                Event::BeginUncommitted => {
                    ensure!(pending.is_none(), "backup_program_transaction");
                    write.execute_batch("BEGIN IMMEDIATE")?;
                    pending = Some(committed.clone());
                }
                Event::Commit => {
                    write.execute_batch("COMMIT")?;
                    committed = pending.take().context("backup_program_transaction")?;
                }
                Event::Rollback => {
                    write.execute_batch("ROLLBACK")?;
                    pending.take().context("backup_program_transaction")?;
                }
                Event::Capture | Event::AbortCapture | Event::PanicCapture => {
                    let mut read = source(&path)?;
                    let mut tx = read.transaction()?;
                    let mut snapshot = MemorySnapshot::new()?;
                    if *event == Event::AbortCapture {
                        drop(snapshot.start(&mut tx)?);
                        tx.rollback()?;
                        // The real core refuses the abandoned target; no DATA
                        // observation has run yet and the error must be saved.
                        snapshot.finish()?;
                        anyhow::bail!("controlled_abort_not_refused");
                    }
                    if *event == Event::PanicCapture {
                        let _copy = snapshot.start(&mut tx)?;
                        panic!("controlled_snapshot_unwind");
                    }
                    complete(&mut snapshot, &mut tx)?;
                    let image = snapshot.finish()?;
                    tx.commit()?;
                    let expected = if wrong {
                        pending.as_ref().unwrap_or(&committed).clone()
                    } else {
                        committed.clone()
                    };
                    images.push((image, expected));
                }
                Event::Verify => {
                    // Recheck every selected snapshot, but retain one complete
                    // vector digest per Verify. At most 64 events means at most
                    // 64 observations/run, even for the densest replay input.
                    let mut expected_digests = Vec::new();
                    let mut actual_digests = Vec::new();
                    for (image, expected) in &images {
                        expected_digests.push(crate::digest(&serde_json::to_vec(expected)?));
                        actual_digests.push(crate::digest(&serde_json::to_vec(&rows(&image.db)?)?));
                    }
                    if !images.is_empty() {
                        run.observations.push(Observation {
                            step,
                            expected: crate::digest(&serde_json::to_vec(&expected_digests)?),
                            actual: crate::digest(&serde_json::to_vec(&actual_digests)?),
                        });
                        verified_images = images.len();
                    }
                }
            }
            Ok(())
        }));
        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(_)) => Some(Failure {
                step,
                kind: if matches!(
                    event,
                    Event::Capture | Event::AbortCapture | Event::PanicCapture
                ) {
                    FailureKind::Capture
                } else {
                    FailureKind::Schedule
                },
            }),
            Err(_) => Some(Failure {
                step,
                kind: FailureKind::Panic,
            }),
        };
        if let Some(failure) = failure {
            run.failure = Some(failure);
            break;
        }
    }
    if run.failure.is_none() && (run.observations.is_empty() || verified_images != images.len()) {
        run.failure = Some(Failure {
            step: program.events.len(),
            kind: FailureKind::MissingObservation,
        });
    }
    Ok(run)
}

fn source_digest() -> String {
    // Bind the real shared validators, SQL hook configuration and locked build
    // dependencies, not only the local model/core source. This is component
    // replay provenance, never an archive/native-source attestation.
    let inputs: &[(&str, &[u8])] = &[
        ("native_backup.rs", include_bytes!("../native_backup.rs")),
        ("native_backup/tests.rs", include_bytes!("tests.rs")),
        (
            "restore_staging.rs",
            include_bytes!("../restore_staging.rs"),
        ),
        ("store.rs", include_bytes!("../../store.rs")),
        ("oauth/schema.rs", include_bytes!("../../oauth/schema.rs")),
        ("day2/lib.rs", include_bytes!("../../lib.rs")),
        ("day2/Cargo.toml", include_bytes!("../../../Cargo.toml")),
        ("day2/BUILD.bazel", include_bytes!("../../../BUILD.bazel")),
        ("Cargo.toml", include_bytes!("../../../../../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../../../../../Cargo.lock")),
        (
            "MODULE.bazel",
            include_bytes!("../../../../../MODULE.bazel"),
        ),
        (
            "MODULE.bazel.lock",
            include_bytes!("../../../../../MODULE.bazel.lock"),
        ),
        (
            "bazel/toolchain.json",
            include_bytes!("../../../../../build/bazel/toolchain.json"),
        ),
    ];
    let hashes = inputs
        .iter()
        .map(|(name, bytes)| (*name, crate::digest(bytes)))
        .collect::<Vec<_>>();
    crate::digest(&serde_json::to_vec(&hashes).expect("static component input hashes"))
}

fn program(seed: u64) -> Program {
    let mut events = vec![
        Event::Write,
        Event::BeginUncommitted,
        Event::Write,
        Event::Capture,
        Event::Verify,
        Event::Rollback,
        Event::Capture,
        Event::Verify,
        Event::BeginUncommitted,
        Event::Write,
        Event::Commit,
        Event::Capture,
        Event::Verify,
    ];
    let mut random = seed;
    for _ in 0..8 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        events.extend([
            Event::BeginUncommitted,
            Event::Write,
            Event::Capture,
            if (random >> 32) & 1 == 0 {
                Event::Commit
            } else {
                Event::Rollback
            },
            Event::Capture,
            Event::Verify,
        ]);
    }
    Program {
        version: 1,
        source: source_digest(),
        seed,
        events,
    }
}

struct SavedFailure(std::path::PathBuf);
impl std::fmt::Debug for SavedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("backup_component_failure_saved")
    }
}
impl std::fmt::Display for SavedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for SavedFailure {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    program: Program,
    incorrect_pending_oracle: bool,
    first: Run,
    second: Run,
}

fn observed_run(program: &Program, wrong: bool) -> Run {
    replay(program, wrong).unwrap_or_else(|_| Run {
        observations: Vec::new(),
        failure: Some(Failure {
            step: 0,
            kind: FailureKind::Setup,
        }),
    })
}

fn check(program: &Program, wrong: bool) -> Result<()> {
    validate(program)?;
    let first = observed_run(program, wrong);
    let second = observed_run(program, wrong);
    if first != second
        || first.failure.is_some()
        || first.observations.iter().any(|r| r.expected != r.actual)
    {
        // Only schedule and closed digest/failure observations are retained,
        // never database rows, credentials, raw errors or the environment.
        let bytes = serde_json::to_vec(&Bundle {
            program: program.clone(),
            incorrect_pending_oracle: wrong,
            first,
            second,
        })?;
        ensure!(bytes.len() <= 65536, "backup_failure_bound");
        let parent =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/control-slot-replays");
        std::fs::create_dir_all(&parent)?;
        let directory = tempfile::Builder::new()
            .prefix("native-backup-component-")
            .tempdir_in(parent)?
            .keep();
        let path = directory.join("replay.json.gz");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
        encoder.write_all(&bytes)?;
        encoder.finish()?.sync_all()?;
        return Err(SavedFailure(path).into());
    }
    Ok(())
}

fn saved_payload(error: &anyhow::Error) -> Result<Vec<u8>> {
    let path = &error
        .downcast_ref::<SavedFailure>()
        .context("backup_failure_missing")?
        .0;
    let file = std::fs::File::open(path)?;
    ensure!(file.metadata()?.is_file(), "backup_failure_file");
    let mut encoded = Vec::new();
    file.take(66561).read_to_end(&mut encoded)?;
    ensure!(encoded.len() <= 66560, "backup_failure_encoded_bound");
    let mut decoder = flate2::bufread::GzDecoder::new(&encoded[..]);
    let mut bytes = Vec::new();
    decoder.by_ref().take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "backup_failure_bound");
    ensure!(
        decoder.into_inner().is_empty(),
        "backup_failure_trailing_bytes"
    );
    Ok(bytes)
}

fn saved(error: &anyhow::Error) -> Result<Bundle> {
    let bytes = saved_payload(error)?;
    let value: serde_json::Value = crate::json::decode(&bytes)?;
    let bundle: Bundle = serde_json::from_value(value.clone())?;
    ensure!(
        serde_json::to_value(&bundle)? == value,
        "backup_failure_shape"
    );
    validate(&bundle.program)?;
    Ok(bundle)
}

#[test]
fn generated_sqlite_snapshot_histories_match_independent_oracle_and_replay_twice() -> Result<()> {
    let mut schedules = std::collections::BTreeSet::new();
    for seed in [1, 7, 41, 701] {
        let program = program(seed);
        schedules.insert(serde_json::to_vec(&program.events)?);
        check(&program, false)?;
    }
    ensure!(schedules.len() == 4, "backup_generator_degenerate");
    Ok(())
}

#[test]
fn independent_oracle_rejects_including_an_uncommitted_value() -> Result<()> {
    let failure = check(&program(7), true).expect_err("bad oracle must diverge");
    let bundle = saved(&failure)?;
    let first = observed_run(&bundle.program, true);
    let second = observed_run(&bundle.program, true);
    ensure!(
        first == second && first == bundle.first && first == bundle.second,
        "backup_saved_replay_changed"
    );
    ensure!(
        first.observations.iter().any(|r| r.expected != r.actual),
        "backup_bad_oracle_not_reproduced"
    );
    Ok(())
}

#[test]
fn actual_capture_refusal_and_unwind_before_observation_retain_replayable_closed_failures()
-> Result<()> {
    for (event, kind) in [
        (Event::AbortCapture, FailureKind::Capture),
        (Event::PanicCapture, FailureKind::Panic),
    ] {
        let input = Program {
            version: 1,
            source: source_digest(),
            seed: 0,
            events: vec![event],
        };
        let failure = check(&input, false).expect_err("actual cut must refuse");
        let bundle = saved(&failure)?;
        let first = observed_run(&bundle.program, false);
        let second = observed_run(&bundle.program, false);
        ensure!(
            first == bundle.first && second == bundle.second && first == second,
            "backup_refusal_replay_changed"
        );
        ensure!(
            first.observations.is_empty() && first.failure == Some(Failure { step: 0, kind }),
            "backup_refusal_not_retained"
        );
    }
    Ok(())
}

#[test]
fn histories_without_an_observation_refuse_and_retain_the_same_frontier() -> Result<()> {
    for events in [
        vec![Event::Write],
        vec![Event::Verify],
        vec![Event::Capture, Event::Verify, Event::Write, Event::Capture],
    ] {
        let input = Program {
            version: 1,
            source: source_digest(),
            seed: 0,
            events,
        };
        let failure = check(&input, false).expect_err("missing observation must refuse");
        let bundle = saved(&failure)?;
        let first = observed_run(&bundle.program, false);
        let second = observed_run(&bundle.program, false);
        ensure!(
            first == second && first == bundle.first && first == bundle.second,
            "backup_empty_replay_changed"
        );
        ensure!(
            first.failure
                == Some(Failure {
                    step: input.events.len(),
                    kind: FailureKind::MissingObservation,
                }),
            "backup_empty_obligation_accepted"
        );
    }
    Ok(())
}

#[test]
fn maximum_dense_bad_oracle_retains_complete_bounded_program_and_replays() -> Result<()> {
    let mut events = vec![Event::BeginUncommitted, Event::Write];
    events.extend(std::iter::repeat_n(Event::Capture, 31));
    events.extend(std::iter::repeat_n(Event::Verify, 31));
    let input = Program {
        version: 1,
        source: source_digest(),
        seed: 0,
        events,
    };
    assert_eq!(input.events.len(), 64);
    let failure = check(&input, true).expect_err("dense bad oracle must diverge");
    let bundle = saved(&failure)?;
    ensure!(
        serde_json::to_vec(&bundle)?.len() <= 65536,
        "backup_dense_bundle_bound"
    );
    let first = observed_run(&bundle.program, true);
    let second = observed_run(&bundle.program, true);
    ensure!(
        first == second && first == bundle.first && first == bundle.second,
        "backup_dense_replay_changed"
    );
    ensure!(
        first.failure.is_none()
            && first.observations.len() == 31
            && first.observations.iter().all(|r| r.expected != r.actual),
        "backup_dense_oracle_not_executed"
    );
    Ok(())
}

#[test]
fn retained_gzip_keeps_complete_payload_and_refuses_truncation_trailing_or_expansion() -> Result<()>
{
    use std::os::unix::fs::PermissionsExt;
    let first = check(&program(7), true).expect_err("controlled bad oracle");
    let second = check(&program(7), true).expect_err("controlled second bad oracle");
    let a = &first
        .downcast_ref::<SavedFailure>()
        .context("saved first")?
        .0;
    let b = &second
        .downcast_ref::<SavedFailure>()
        .context("saved second")?
        .0;
    ensure!(a != b, "backup_failure_overwrote_attempt");
    ensure!(
        a.file_name() == Some(std::ffi::OsStr::new("replay.json.gz"))
            && std::fs::metadata(a)?.permissions().mode() & 0o777 == 0o600,
        "backup_retained_file_shape"
    );
    let expected = serde_json::to_vec(&saved(&first)?)?;
    ensure!(
        saved_payload(&first)? == expected && saved_payload(&second)? == expected,
        "backup_retained_payload_changed"
    );
    ensure!(
        include_str!("../../../../../.github/workflows/ci.yml")
            .contains("artifacts/control-slot-replays/*/replay.json.gz"),
        "backup_ci_retention_missing"
    );
    let good = std::fs::read(a)?;
    let mut trailing = good.clone();
    trailing.push(0);
    let truncated = good[..good.len() - 1].to_vec();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&[b' '; 65537])?;
    let expansion = encoder.finish()?;
    let directory = tempfile::tempdir()?;
    for (index, bytes) in [trailing, truncated, expansion].into_iter().enumerate() {
        let path = directory.path().join(index.to_string());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        assert!(saved_payload(&SavedFailure(path).into()).is_err());
    }
    Ok(())
}

#[test]
fn component_source_has_no_native_factory_requester_or_raw_source_opener() -> Result<()> {
    let file = syn::parse_file(include_str!("../native_backup.rs"))?;
    use syn::visit::Visit;
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, e: &'ast syn::ExprCall) {
            if let syn::Expr::Path(p) = &*e.func {
                self.0.push(
                    p.path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::"),
                );
            }
            syn::visit::visit_expr_call(self, e);
        }
    }
    let mut calls = Calls(Vec::new());
    calls.visit_file(&file);
    assert!(!calls.0.iter().any(|c| c.ends_with("Runtime::load")
        || c.contains("enroll_current_thread")
        || c.contains("NativeBackupAuthorization")
        || c.ends_with("Connection::open")
        || c.ends_with("open_with_flags")));
    assert!(
        calls
            .0
            .iter()
            .any(|c| c.ends_with("backup_archive::verify_snapshot"))
    );
    assert!(
        calls
            .0
            .iter()
            .any(|c| c.ends_with("require_no_runtime_generation_objects"))
    );
    Ok(())
}
