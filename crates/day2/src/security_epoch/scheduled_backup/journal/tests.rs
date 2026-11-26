//! Real filesystem/portable DATA checks, never native activation or source grants.
use super::*;
use crate::security_epoch::scheduled_backup::{Destination, Requester, Source, Transport};
use serde_json::json;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

fn digest(text: &str) -> Digest {
    Digest::new(text.as_bytes())
}

fn binding() -> RootBindingData {
    RootBindingData {
        scope: AuthorityScope {
            installation: "fixture".to_owned().try_into().unwrap(),
            environment: "test".to_owned().try_into().unwrap(),
            app: "calendar".to_owned().try_into().unwrap(),
        },
        cron_job_uid: "00000000-0000-0000-0000-000000000001"
            .to_owned()
            .try_into()
            .unwrap(),
        physical_disk: digest("qualified-disk-fixture-DATA"),
        creator_nonce: digest("creator-fixture-DATA"),
    }
}

fn intent(minute: u8, revision: u8) -> Intent {
    let root = binding();
    let uid = |index: u8| {
        format!("00000000-0000-0000-0000-{index:012}")
            .try_into()
            .unwrap()
    };
    Intent {
        slot: Slot {
            scope: root.scope,
            cron_job_uid: root.cron_job_uid,
            scheduled_at: format!("2026-11-22T17:{minute:02}:00Z").try_into().unwrap(),
        },
        policy_generation: digest(&format!("policy-{revision}")),
        admission_generation: digest(&format!("admission-{revision}")),
        cron_job_spec: digest(&format!("template-{revision}")),
        requester: Requester {
            cluster: digest("cluster"),
            node: digest("node"),
            namespace_uid: uid(2),
            job_uid: uid(revision + 3),
            pod_uid: uid(revision + 4),
            ksa_uid: uid(5),
            uploader_uid: "100000000000000000002".to_owned().try_into().unwrap(),
            image: digest("image"),
            executable: digest("executable"),
            process: digest("process"),
        },
        source: Source {
            store: digest("store"),
            authority: digest(&format!("authority-{revision}")),
            epoch: u64::from(revision + 1).try_into().unwrap(),
            artifact: digest("artifact"),
        },
        transport: Transport {
            controller: digest("controller"),
            connection: digest("connection"),
            requester_nonce: digest("requester-nonce"),
            controller_nonce: digest("controller-nonce"),
            original: digest(&format!("original-{revision}")),
        },
        operation: digest(&format!("operation-{revision}")),
        destination: Destination {
            bucket: "fixture-private-backups".into(),
            prefix: format!("calendar/20261122T17{minute:02}00Z"),
            readers: digest("readers"),
        },
    }
}

fn root() -> Result<(tempfile::TempDir, File)> {
    let temp = tempfile::Builder::new()
        .prefix("backup-journal-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let directory = File::from(rustix::fs::open(
        temp.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    Ok((temp, directory))
}

#[test]
fn stable_domain_never_keys_on_disk_nonce_generation_epoch_key_or_job() -> Result<()> {
    let first = binding();
    let mut other = first.clone();
    other.physical_disk = digest("different-disk");
    other.creator_nonce = digest("different-nonce");
    assert_eq!(first.key_data()?, other.key_data()?);
    assert_ne!(
        ImageData::new_data(first.clone())?.bytes,
        ImageData::new_data(other.clone())?.bytes
    );
    assert!(ImageData::decode_data(&ImageData::new_data(first.clone())?.bytes, &other).is_err());
    let image = ImageData::new_data(first.clone())?;
    let mut bytes = image.bytes.clone();
    bytes.extend(image.append_data(&intent(0, 0))?);
    let spent = ImageData::decode_data(&bytes, &first)?;
    for generation in 0..12 {
        assert!(spent.append_data(&intent(0, generation)).is_err());
    }
    assert!(spent.append_data(&intent(1, 0)).is_ok());
    other = first.clone();
    other.cron_job_uid = "00000000-0000-0000-0000-000000000009"
        .to_owned()
        .try_into()?;
    assert_ne!(first.key_data()?, other.key_data()?);
    other = first.clone();
    other.scope.app = "another".to_owned().try_into()?;
    assert_ne!(first.key_data()?, other.key_data()?);
    Ok(())
}

fn actual_create_append_sync_reopen_preserves_spent_even_if_ack_or_remote_result_is_lost()
-> Result<()> {
    let (temp, parent) = root()?;
    assert!(AttemptFile::open_existing(&parent, &binding()).is_err());
    let mut file = AttemptFile::create_new(&parent, binding())?;
    assert_eq!(
        std::fs::metadata(temp.path().join(FILE_NAME))?
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(AttemptFile::create_new(&parent, binding()).is_err());
    file.append(&intent(0, 0))?;
    // Drop the real owner without delivering any ACK/counter outcome.
    drop(file);
    let mut reopened = AttemptFile::open_existing(&parent, &binding())?;
    assert!(reopened.append(&intent(0, 1)).is_err());
    assert!(
        reopened.append(&intent(1, 0)).is_err(),
        "failed owner stays poisoned"
    );
    drop(reopened);
    let mut reopened = AttemptFile::open_existing(&parent, &binding())?;
    reopened.append(&intent(1, 0))?;
    assert_eq!(reopened.image.slots.len(), 2);
    Ok(())
}

fn independent_open_description_cannot_take_the_live_serialized_writer() -> Result<()> {
    let (_temp, parent) = root()?;
    let held = AttemptFile::create_new(&parent, binding())?;
    assert!(AttemptFile::open_existing(&parent, &binding()).is_err());
    drop(held);
    AttemptFile::open_existing(&parent, &binding())?;
    Ok(())
}

fn every_partial_append_refuses_the_entire_root_without_repair_or_truncation() -> Result<()> {
    let image = ImageData::new_data(binding())?;
    let record = image.append_data(&intent(0, 0))?;
    for cut in 1..record.len() {
        let mut bytes = image.bytes.clone();
        bytes.extend_from_slice(&record[..cut]);
        assert!(
            ImageData::decode_data(&bytes, &binding()).is_err(),
            "cut {cut}"
        );
    }
    // Actual filesystem partial tail, then two independent reopen refusals.
    let (temp, parent) = root()?;
    let mut file = AttemptFile::create_new(&parent, binding())?;
    file.file.write_all(&record[..record.len() / 2])?;
    file.file.sync_all()?;
    drop(file);
    let before = std::fs::read(temp.path().join(FILE_NAME))?;
    for _ in 0..2 {
        assert!(AttemptFile::open_existing(&parent, &binding()).is_err());
    }
    assert_eq!(std::fs::read(temp.path().join(FILE_NAME))?, before);
    Ok(())
}

#[test]
fn strict_header_chain_order_checksum_duplicate_and_complete_line_controls() -> Result<()> {
    let image = ImageData::new_data(binding())?;
    let one = image.append_data(&intent(0, 0))?;
    let mut bytes = image.bytes.clone();
    bytes.extend_from_slice(&one);
    let image = ImageData::decode_data(&bytes, &binding())?;
    let two = image.append_data(&intent(1, 0))?;
    let mut valid = bytes.clone();
    valid.extend_from_slice(&two);
    assert_eq!(ImageData::decode_data(&valid, &binding())?.slots.len(), 2);
    for bad in [
        Vec::new(),
        vec![b'\n'],
        [valid.clone(), vec![b'\n']].concat(),
        valid[..valid.len() - 1].to_vec(),
        [bytes.clone(), one.clone()].concat(),
        [
            image.bytes[..image.bytes.len() - one.len()].to_vec(),
            two.clone(),
            one.clone(),
        ]
        .concat(),
    ] {
        assert!(ImageData::decode_data(&bad, &binding()).is_err());
    }
    for field in ["ordinal", "scheduled_at", "intent", "previous", "checksum"] {
        let mut changed: serde_json::Value = serde_json::from_slice(&one[..one.len() - 1])?;
        changed[field] = match field {
            "ordinal" => json!(2),
            "scheduled_at" => json!("2026-11-22T17:02:00Z"),
            _ => json!(digest("changed")),
        };
        let bad = [ImageData::new_data(binding())?.bytes, line_data(&changed)?].concat();
        assert!(ImageData::decode_data(&bad, &binding()).is_err(), "{field}");
    }
    let header = ImageData::new_data(binding())?.bytes;
    let duplicate =
        String::from_utf8(one.clone())?.replacen("\"ordinal\":1", "\"ordinal\":1,\"ordinal\":1", 1);
    for record in [
        duplicate.into_bytes(),
        [b" ".as_slice(), one.as_slice()].concat(),
        line_data(&json!({"unknown":0}))?,
    ] {
        assert!(ImageData::decode_data(&[header.clone(), record].concat(), &binding()).is_err());
    }
    Ok(())
}

fn changed_path_link_mode_bytes_and_birth_binding_refuse_without_new_file() -> Result<()> {
    for cut in 0..5 {
        let (temp, parent) = root()?;
        let mut file = AttemptFile::create_new(&parent, binding())?;
        match cut {
            0 => {
                std::fs::rename(temp.path().join(FILE_NAME), temp.path().join("retained"))?;
                std::fs::write(temp.path().join(FILE_NAME), &file.image.bytes)?;
            }
            1 => std::fs::hard_link(temp.path().join(FILE_NAME), temp.path().join("linked"))?,
            2 => std::fs::set_permissions(
                temp.path().join(FILE_NAME),
                std::fs::Permissions::from_mode(0o640),
            )?,
            3 => {
                let mut other = std::fs::OpenOptions::new()
                    .write(true)
                    .open(temp.path().join(FILE_NAME))?;
                other.write_all(b"!")?;
            }
            _ => std::fs::remove_file(temp.path().join(FILE_NAME))?,
        }
        assert!(file.append(&intent(0, 0)).is_err());
        assert!(file.append(&intent(1, 0)).is_err());
    }
    let (temp, parent) = root()?;
    symlink("missing", temp.path().join(FILE_NAME))?;
    assert!(AttemptFile::create_new(&parent, binding()).is_err());
    assert!(AttemptFile::open_existing(&parent, &binding()).is_err());
    let (temp, parent) = root()?;
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))?;
    assert!(AttemptFile::create_new(&parent, binding()).is_err());
    assert!(!temp.path().join(FILE_NAME).exists());
    Ok(())
}

#[test]
fn bounds_refuse_without_eviction_rollover_or_partial_append() -> Result<()> {
    let mut image = ImageData::new_data(binding())?;
    // Unique canonical slots, independent of the small generated-fixture range.
    let start = time::OffsetDateTime::parse(
        "2026-11-22T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )?;
    for index in 0..MAX_RECORDS {
        let mut value = intent(0, 0);
        value.slot.scheduled_at = (start + time::Duration::minutes(i64::try_from(index)?))
            .format(&time::format_description::well_known::Rfc3339)?
            .try_into()?;
        let bytes = image.append_data(&value)?;
        // Avoid quadratic decoding while constructing this bounded fixture;
        // the production decoder independently validates every record below.
        let record: RecordData = decode_canonical(&bytes[..bytes.len() - 1])?;
        image.slots.insert(value.slot.scheduled_at.0);
        image.tail = record.checksum;
        image.bytes.extend(bytes);
    }
    let decoded = ImageData::decode_data(&image.bytes, &binding())?;
    assert_eq!(decoded.slots.len(), MAX_RECORDS);
    let before = image.bytes.clone();
    let mut next = intent(0, 9);
    next.slot.scheduled_at = (start + time::Duration::minutes(i64::try_from(MAX_RECORDS)?))
        .format(&time::format_description::well_known::Rfc3339)?
        .try_into()?;
    assert!(!decoded.slots.contains(&next.slot.scheduled_at.0));
    assert_eq!(
        decoded.append_data(&next).unwrap_err().to_string(),
        "backup_journal_slot_spent_or_full"
    );
    assert_eq!(image.bytes, before);
    // Independently encode a valid chained 4097th record; the decoder must not
    // rely on the writer's capacity predicate to enforce the file limit.
    let commitment = next.commitment_data()?;
    let mut extra = RecordData {
        ordinal: u32::try_from(MAX_RECORDS + 1)?,
        scheduled_at: next.slot.scheduled_at,
        intent: commitment,
        previous: decoded.tail.clone(),
        checksum: decoded.tail.clone(),
    };
    extra.checksum = extra.checksum_data()?;
    let mut oversized = before;
    oversized.extend(line_data(&extra)?);
    assert_eq!(
        ImageData::decode_data(&oversized, &binding())
            .err()
            .unwrap()
            .to_string(),
        "backup_journal_record_bound"
    );
    assert!(ImageData::decode_data(&vec![b' '; MAX_BYTES + 1], &binding()).is_err());
    assert!(
        ImageData::decode_data(&[vec![b' '; MAX_LINE], vec![b'\n']].concat(), &binding()).is_err()
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cut {
    Before,
    Partial,
    DurableLostAck,
    CounterUnknown,
    Complete,
    Reopen,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    minute: u8,
    revision: u8,
    cut: Cut,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    index: usize,
    append: bool,
    spent: Option<usize>,
    refused: Option<bool>,
    counter_may: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    Setup,
    Step,
    Panic,
    Mismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    step: usize,
    kind: FailureKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    format: u8,
    source: Digest,
    seed: u64,
    events: Vec<Event>,
    wrong: Option<usize>,
    fault: Option<Failure>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    observations: Vec<Observation>,
    failure: Option<Failure>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    program: Program,
    first: Run,
    second: Run,
}

fn source() -> Result<Digest> {
    let inputs: &[(&str, &[u8])] = &[
        ("journal.rs", include_bytes!("../journal.rs")),
        ("journal/birth.rs", include_bytes!("birth.rs")),
        ("journal/birth/tests.rs", include_bytes!("birth/tests.rs")),
        ("reservation.rs", include_bytes!("../reservation.rs")),
        ("tests.rs", include_bytes!("tests.rs")),
        (
            "scheduled_backup.rs",
            include_bytes!("../../scheduled_backup.rs"),
        ),
        ("json.rs", include_bytes!("../../../json.rs")),
        (
            "capabilities/lib.rs",
            include_bytes!("../../../../../day2-capabilities/src/lib.rs"),
        ),
        (
            "capabilities/security_epoch.rs",
            include_bytes!("../../../../../day2-capabilities/src/security_epoch.rs"),
        ),
        ("Cargo.toml", include_bytes!("../../../../../../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../../../../../../Cargo.lock")),
        (
            "day2/BUILD.bazel",
            include_bytes!("../../../../BUILD.bazel"),
        ),
        (
            "MODULE.bazel.lock",
            include_bytes!("../../../../../../MODULE.bazel.lock"),
        ),
        (
            "toolchain.json",
            include_bytes!("../../../../../../build/bazel/toolchain.json"),
        ),
    ];
    Digest::of(
        &inputs
            .iter()
            .map(|(name, bytes)| (*name, Digest::new(bytes)))
            .collect::<Vec<_>>(),
    )
}

fn validate(program: &Program) -> Result<()> {
    ensure!(
        program.format == 1
            && program.source == source()?
            && program.events.len() <= 128
            && program
                .events
                .iter()
                .all(|event| event.minute < 60 && event.revision < 12)
            && program.wrong.is_none_or(|step| step < program.events.len())
            && program
                .fault
                .as_ref()
                .is_none_or(|fault| fault.step < program.events.len()
                    && matches!(fault.kind, FailureKind::Step | FailureKind::Panic)),
        "backup_journal_program"
    );
    Ok(())
}

/// Independent oracle uses numeric slots and absorbing broken state; no journal
/// slot hash, checksum, decoder or acceptance predicate supplies expectations.
/// Every failure retains the FULL attempted prefix, including the failing step.
fn run(program: &Program) -> Run {
    let mut run = Run {
        observations: Vec::new(),
        failure: None,
    };
    let Ok(initial) = ImageData::new_data(binding()) else {
        run.failure = Some(Failure {
            step: 0,
            kind: FailureKind::Setup,
        });
        return run;
    };
    let mut bytes = initial.bytes;
    let mut model_slots = BTreeSet::new();
    let mut model_broken = false;
    for (index, event) in program.events.iter().enumerate() {
        let mut expected_append = !model_broken
            && !model_slots.contains(&event.minute)
            && !matches!(event.cut, Cut::Before | Cut::Reopen);
        if program.wrong == Some(index) {
            expected_append = !expected_append;
        }
        let mut observation = Observation {
            index,
            append: false,
            spent: None,
            refused: None,
            counter_may: false,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            if let Some(fault) = &program.fault
                && fault.step == index
            {
                match fault.kind {
                    FailureKind::Step => anyhow::bail!("private-error-must-not-be-retained"),
                    FailureKind::Panic => panic!("controlled_backup_journal_unwind"),
                    _ => {}
                }
            }
            if let Ok(image) = ImageData::decode_data(&bytes, &binding())
                && !matches!(event.cut, Cut::Before | Cut::Reopen)
                && let Ok(record) = image.append_data(&intent(event.minute, event.revision))
            {
                observation.append = true;
                if matches!(event.cut, Cut::Partial) {
                    bytes.extend_from_slice(&record[..record.len() / 2]);
                } else {
                    bytes.extend_from_slice(&record);
                }
                observation.counter_may = matches!(event.cut, Cut::CounterUnknown | Cut::Complete);
            }
            if expected_append {
                if matches!(event.cut, Cut::Partial) {
                    model_broken = true;
                } else {
                    model_slots.insert(event.minute);
                }
            }
            let decoded = ImageData::decode_data(&bytes, &binding());
            observation.spent = decoded.as_ref().ok().map(|image| image.slots.len());
            observation.refused = Some(decoded.is_err());
            Ok(())
        }));
        let failure = match result {
            Err(_) => Some(FailureKind::Panic),
            Ok(Err(_)) => Some(FailureKind::Step),
            Ok(Ok(()))
                if observation.append != expected_append
                    || observation.refused != Some(model_broken)
                    || observation.spent
                        != if model_broken {
                            None
                        } else {
                            Some(model_slots.len())
                        }
                    || observation.counter_may
                        != (expected_append
                            && matches!(event.cut, Cut::CounterUnknown | Cut::Complete)) =>
            {
                Some(FailureKind::Mismatch)
            }
            _ => None,
        };
        run.observations.push(observation);
        if let Some(kind) = failure {
            run.failure = Some(Failure { step: index, kind });
            break;
        }
    }
    run
}

const MAX_BUNDLE: usize = 262_144;
struct Saved(std::path::PathBuf);
impl std::fmt::Display for Saved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("backup_journal_replay_saved")
    }
}
impl std::fmt::Debug for Saved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Saved {}

fn check(program: Program) -> Result<()> {
    validate(&program)?;
    let first = run(&program);
    let second = run(&program);
    if first == second && first.failure.is_none() {
        return Ok(());
    }
    let bytes = serde_json::to_vec(&Bundle {
        program,
        first,
        second,
    })?;
    ensure!(bytes.len() <= MAX_BUNDLE, "backup_journal_bundle_bound");
    let parent = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/control-slot-replays");
    std::fs::create_dir_all(&parent)?;
    let directory = tempfile::Builder::new()
        .prefix("backup-journal-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?
        .keep();
    let path = directory.join("replay.json.gz");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let mut encoded = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    encoded.write_all(&bytes)?;
    encoded.finish()?.sync_all()?;
    Err(Saved(path).into())
}

fn saved(error: &anyhow::Error) -> Result<Bundle> {
    let path = &error
        .downcast_ref::<Saved>()
        .context("backup_journal_missing_failure")?
        .0;
    ensure!(
        std::fs::metadata(path)?.permissions().mode() & 0o7777 == 0o600
            && std::fs::metadata(path.parent().context("backup_journal_parent")?)?
                .permissions()
                .mode()
                & 0o7777
                == 0o700,
        "backup_journal_failure_private"
    );
    let mut encoded = Vec::new();
    File::open(path)?
        .take(u64::try_from(MAX_BUNDLE + 1_025)?)
        .read_to_end(&mut encoded)?;
    ensure!(
        encoded.len() <= MAX_BUNDLE + 1_024,
        "backup_journal_encoded_bound"
    );
    let mut decoder = flate2::bufread::GzDecoder::new(&encoded[..]);
    let mut bytes = Vec::new();
    decoder
        .by_ref()
        .take(u64::try_from(MAX_BUNDLE + 1)?)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BUNDLE && decoder.into_inner().is_empty(),
        "backup_journal_decoded_bound"
    );
    let value: serde_json::Value = crate::json::decode(&bytes)?;
    let bundle: Bundle = serde_json::from_value(value.clone())?;
    ensure!(
        serde_json::to_value(&bundle)? == value,
        "backup_journal_bundle_shape"
    );
    validate(&bundle.program)?;
    Ok(bundle)
}

fn events(seed: u64) -> Vec<Event> {
    let mut state = seed;
    (0..128)
        .map(|index| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            Event {
                minute: ((state >> 9) % 12) as u8,
                revision: ((state >> 17) % 12) as u8,
                cut: match (state >> 25) % 6 {
                    0 => Cut::Before,
                    1 if index > 80 => Cut::Partial,
                    1 | 2 => Cut::DurableLostAck,
                    3 => Cut::CounterUnknown,
                    4 => Cut::Complete,
                    _ => Cut::Reopen,
                },
            }
        })
        .collect()
}

#[test]
fn generated_histories_replay_twice_with_independent_unknown_and_partial_tail_expectations()
-> Result<()> {
    let mut schedules = BTreeSet::new();
    for seed in 0..32 {
        let events = events(seed);
        schedules.insert(serde_json::to_vec(&events)?);
        check(Program {
            format: 1,
            source: source()?,
            seed,
            events,
            wrong: None,
            fault: None,
        })?;
    }
    assert_eq!(schedules.len(), 32);
    Ok(())
}

#[test]
fn failed_oracle_step_and_panic_keep_both_full_prefixes_and_replay_binding() -> Result<()> {
    for (wrong, fault) in [
        (Some(0), None),
        (Some(70), None),
        (
            None,
            Some(Failure {
                step: 0,
                kind: FailureKind::Step,
            }),
        ),
        (
            None,
            Some(Failure {
                step: 71,
                kind: FailureKind::Panic,
            }),
        ),
    ] {
        let program = Program {
            format: 1,
            source: source()?,
            seed: 91,
            events: events(91),
            wrong,
            fault,
        };
        let error = check(program.clone()).unwrap_err();
        assert_eq!(error.to_string(), "backup_journal_replay_saved");
        let bundle = saved(&error)?;
        assert_eq!(bundle.first, run(&bundle.program));
        assert_eq!(bundle.second, run(&bundle.program));
        assert_eq!(bundle.first, bundle.second);
        let failure = bundle.first.failure.as_ref().unwrap();
        assert_eq!(bundle.first.observations.len(), failure.step + 1);
        assert_eq!(bundle.program.events.len(), 128);
        let encoded = serde_json::to_string(&bundle)?;
        for excluded in [
            "private-error-must-not-be-retained",
            "controlled_backup_journal_unwind",
        ] {
            assert!(!encoded.contains(excluded));
        }
        let mut stale = program;
        stale.source = digest("stale");
        assert!(validate(&stale).is_err());
    }
    Ok(())
}

fn same_inode_rollback_is_explicitly_not_detected_by_nonce_or_checksum_data() -> Result<()> {
    let (temp, parent) = root()?;
    let mut file = AttemptFile::create_new(&parent, binding())?;
    let empty = file.image.bytes.clone();
    file.append(&intent(0, 0))?;
    // An intentionally hostile TCB-level rollback demonstrates the limit,
    // rather than pretending the checksum supplies monotonic storage.
    drop(file);
    let mut raw = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(temp.path().join(FILE_NAME))?;
    raw.write_all(&empty)?;
    raw.sync_all()?;
    drop(raw);
    let historical = AttemptFile::open_existing(&parent, &binding())?;
    assert!(
        historical.image.slots.is_empty(),
        "DATA alone cannot detect rollback"
    );
    // There is deliberately no runtime constructor converting it to admission.
    Ok(())
}

fn ordered_append_boundary(source: &str) -> Result<()> {
    use quote::ToTokens;
    let parsed = syn::parse_file(source)?;
    let functions = parsed
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            let syn::Type::Path(owner) = &*item.self_ty else {
                return None;
            };
            if owner.path.segments.last()?.ident != "AttemptFile" {
                return None;
            }
            Some(item.items.iter().filter_map(|item| match item {
                syn::ImplItem::Fn(function) => Some((
                    function.sig.ident.to_string(),
                    function.block.to_token_stream().to_string(),
                )),
                _ => None,
            }))
        })
        .flatten()
        .collect::<std::collections::BTreeMap<_, _>>();
    let append = functions
        .get("append")
        .context("actual journal append missing")?;
    let ordered = [
        "self . refused . replace (true)",
        "self . require_identity () ?",
        "self . require_image () ?",
        "self . image . append_data (intent) ?",
        "self . file . write_all (& bytes) ?",
        "self . file . sync_all () ?",
        "self . parent . sync_all () ?",
        "self . require_identity () ?",
        "read_data (& mut self . file) ?",
        "ImageData :: decode_data",
        "self . require_identity () ?",
        "self . refused . set (false)",
        "Ok (self . image . tail . clone ())",
    ];
    let mut from = 0;
    for call in ordered {
        let found = append[from..]
            .find(call)
            .context("journal durability order")?;
        from += found + call.len();
    }
    let open = functions
        .get("open_existing")
        .context("actual existing open missing")?;
    ensure!(
        !open.contains("CREATE") && !open.contains("TRUNC") && !open.contains("EXCL"),
        "existing-only flags"
    );
    let lock = open
        .find("file . try_lock () ?")
        .context("existing lock missing")?;
    let read = open
        .find("read_data (& mut file) ?")
        .context("existing read missing")?;
    ensure!(lock < read, "read before serialized lock");
    let create = functions
        .get("create_new")
        .context("actual create missing")?;
    ensure!(
        create.contains("OFlags :: EXCL")
            && create.contains("OFlags :: NOFOLLOW")
            && create.contains("value . file . sync_all () ?")
            && create.contains("value . parent . sync_all () ?"),
        "exclusive durable birth"
    );
    Ok(())
}

#[test]
fn actual_source_durability_before_return_and_existing_only_lock_are_mutation_bound() -> Result<()>
{
    let source = include_str!("../journal.rs");
    ordered_append_boundary(source)?;
    for (from, to) in [
        ("self.file.sync_all()?;", "Ok::<(), anyhow::Error>(())?;"),
        ("self.parent.sync_all()?;", "Ok::<(), anyhow::Error>(())?;"),
        ("self.require_image()?;", "Ok::<(), anyhow::Error>(())?;"),
        ("self.refused.replace(true)", "self.refused.replace(false)"),
        ("self.refused.set(false);", "self.refused.set(true);"),
        ("OFlags::EXCL", "OFlags::empty()"),
    ] {
        assert_eq!(source.matches(from).count(), 1, "actual mutation target");
        assert!(
            ordered_append_boundary(&source.replacen(from, to, 1)).is_err(),
            "{from}"
        );
    }
    let open = "fn open_existing";
    let start = source.find(open).unwrap();
    let prefix = &source[..start];
    let suffix = &source[start..];
    assert_eq!(suffix.matches("file.try_lock()?;").count(), 1);
    let bypass = format!("{prefix}{}", suffix.replacen("file.try_lock()?;", "", 1));
    assert!(ordered_append_boundary(&bypass).is_err());
    Ok(())
}

#[test]
fn actual_filesystem_lifecycle_executes_in_a_singleton_without_fork_inherited_lock_flakes()
-> Result<()> {
    struct ChildOwner(Option<std::process::Child>);
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let case = "security_epoch::scheduled_backup::journal::tests::filesystem_singleton_child";
    let mut child = ChildOwner(Some(
        std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                case,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?,
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if child
            .0
            .as_mut()
            .context("backup_journal_child_missing")?
            .try_wait()?
            .is_some()
        {
            break;
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "backup_journal_child_deadline"
        );
        std::thread::yield_now();
    }
    let output = child
        .0
        .take()
        .context("backup_journal_child_missing")?
        .wait_with_output()?;
    let stdout = std::str::from_utf8(&output.stdout)?;
    ensure!(
        output.status.success()
            && stdout
                .lines()
                .filter(|line| *line == format!("test {case} ... ok"))
                .count()
                == 1
            && stdout
                .lines()
                .filter(|line| line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;"))
                .count()
                == 1,
        "backup_journal_singleton_failed"
    );
    Ok(())
}

#[test]
#[ignore = "exec'd singleton; parent requires actual case and one passing result"]
fn filesystem_singleton_child() -> Result<()> {
    // No concurrent in-process test forks can inherit the actual file lock.
    // These are the real create/append/sync/reopen/substitution/rollback cases,
    // not a retry after a denied reacquisition or a skipped filesystem test.
    actual_create_append_sync_reopen_preserves_spent_even_if_ack_or_remote_result_is_lost()?;
    independent_open_description_cannot_take_the_live_serialized_writer()?;
    every_partial_append_refuses_the_entire_root_without_repair_or_truncation()?;
    changed_path_link_mode_bytes_and_birth_binding_refuse_without_new_file()?;
    same_inode_rollback_is_explicitly_not_detected_by_nonce_or_checksum_data()?;
    Ok(())
}
