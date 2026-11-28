//! Portable comparison/codec models only. No real Job, native owner, provider
//! request, source capture or accepting requester is constructed by these tests.
use super::super::*;
use super::*;
use day2_capabilities::{
    Name,
    security_epoch::{EpochIam, EpochProvider},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

fn digest(value: &str) -> Digest {
    Digest::new(value.as_bytes())
}

fn uid(index: u64) -> WorkloadUid {
    format!("12345678-1234-1234-1234-{index:012x}")
        .try_into()
        .unwrap()
}

fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

pub(in crate::security_epoch::scheduled_backup) fn selection() -> EpochStore {
    EpochStore {
        scope: AuthorityScope {
            installation: name("fixture"),
            environment: name("test"),
            app: name("calendar"),
        },
        provider: EpochProvider::FirestoreNativeV1 {
            project: name("fixture-project"),
            project_number: 7.try_into().unwrap(),
            database: name("control"),
            database_uid: uid(50).0,
            iam_source: EpochIam::GkeWorkloadIdentityV1 {
                service_account: "controller@fixture-project.iam.gserviceaccount.com".into(),
                service_account_uid: "100000000000000000001".to_owned().try_into().unwrap(),
            },
        },
        key_set: digest("keys"),
        max_lease_seconds: 5,
    }
}

fn intent(selected: &EpochStore) -> Intent {
    Intent {
        slot: Slot {
            scope: selected.scope.clone(),
            cron_job_uid: uid(1),
            scheduled_at: "2026-11-22T17:00:00Z".to_owned().try_into().unwrap(),
        },
        policy_generation: digest("policy-one"),
        admission_generation: digest("admission-one"),
        cron_job_spec: digest("cron-spec"),
        requester: Requester {
            cluster: digest("cluster"),
            node: digest("node"),
            namespace_uid: uid(2),
            job_uid: uid(3),
            pod_uid: uid(4),
            ksa_uid: uid(5),
            uploader_uid: "100000000000000000002".to_owned().try_into().unwrap(),
            image: digest("image"),
            executable: digest("executable"),
            process: digest("process"),
        },
        source: Source {
            store: Digest::of(selected).unwrap(),
            authority: digest("authority"),
            epoch: 7.try_into().unwrap(),
            artifact: digest("artifact"),
        },
        transport: Transport {
            controller: digest("controller"),
            connection: digest("connection"),
            requester_nonce: digest("requester-nonce"),
            controller_nonce: digest("controller-nonce"),
            original: digest("original"),
        },
        operation: digest("operation"),
        destination: Destination {
            bucket: "fixture-private-backups".into(),
            prefix: "calendar/20261122T170000Z".into(),
            readers: digest("reviewed-readers"),
        },
    }
}

pub(in crate::security_epoch::scheduled_backup) fn ack() -> Vec<u8> {
    serde_json::to_vec(&json!({"writeResults":[{"updateTime":"2026-11-22T17:00:01.000001Z"}],"commitTime":"2026-11-22T17:00:01.000001Z"})).unwrap()
}

fn pending(selected: &EpochStore, value: &Intent) -> CreateTurn {
    let mut turn = CreateTurn::new_data(selected, value.clone()).unwrap();
    turn.submit_data().unwrap();
    turn
}

fn stored(write: &Value) -> Value {
    let mut doc = write["writes"][0]["update"].clone();
    doc["createTime"] = json!("2026-11-22T17:00:01.000001Z");
    doc["updateTime"] = doc["createTime"].clone();
    doc
}

#[test]
fn canonical_slot_and_uid_profile_refuses_aliases_and_unsupported_forms() -> Result<()> {
    for raw in [
        "2026-11-22T17:00:00+00:00",
        "2026-11-22T17:00:00.000Z",
        "2026-11-22T17:00:00z",
        "2026-11-22 17:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-11-22T17:00:60Z",
    ] {
        assert!(
            ScheduledSlot::try_from(raw.to_owned()).is_err(),
            "unsupported slot"
        );
    }
    let _: ScheduledSlot = "2026-11-22T17:00:00Z".to_owned().try_into()?;
    for raw in [
        "",
        "job-name",
        "12345678-1234-1234-1234-123456789ABC",
        "12345678/1234/1234/1234/123456789abc",
    ] {
        assert!(WorkloadUid::try_from(raw.to_owned()).is_err());
    }
    Ok(())
}

#[test]
fn stable_slot_excludes_every_generation_winner_source_transport_and_destination_field()
-> Result<()> {
    let selected = selection();
    let original = intent(&selected);
    let key = original.slot.key_data()?;
    let expected_name = document_name_data(&selected, &original.slot)?;
    let original_commitment = original.commitment_data()?;
    let mut variants = Vec::new();
    macro_rules! changed { ($path:ident $(.$tail:ident)*, $value:expr) => {{ let mut next = original.clone(); next.$path$(.$tail)* = $value; variants.push(next); }}; }
    changed!(policy_generation, digest("policy-two"));
    changed!(admission_generation, digest("admission-two"));
    changed!(cron_job_spec, digest("new-template"));
    changed!(requester.cluster, digest("foreign-cluster"));
    changed!(requester.node, digest("replacement-node"));
    changed!(requester.namespace_uid, uid(20));
    changed!(requester.job_uid, uid(21));
    changed!(requester.pod_uid, uid(22));
    changed!(requester.ksa_uid, uid(23));
    changed!(
        requester.uploader_uid,
        "100000000000000000003".to_owned().try_into()?
    );
    changed!(requester.image, digest("replacement-image"));
    changed!(requester.executable, digest("replacement-executable"));
    changed!(requester.process, digest("replacement-process"));
    changed!(source.store, digest("replacement-selection"));
    changed!(source.authority, digest("replacement-authority"));
    changed!(source.epoch, 8.try_into()?);
    changed!(source.artifact, digest("replacement-artifact"));
    changed!(transport.controller, digest("replacement-controller"));
    changed!(transport.connection, digest("replacement-connection"));
    changed!(
        transport.requester_nonce,
        digest("replacement-requester-nonce")
    );
    changed!(
        transport.controller_nonce,
        digest("replacement-controller-nonce")
    );
    changed!(transport.original, digest("replacement-original"));
    changed!(operation, digest("replacement-operation"));
    changed!(destination.bucket, "other-private-bucket".into());
    changed!(destination.prefix, "calendar/20261122T180000Z".into());
    changed!(destination.readers, digest("replacement-readers"));
    assert_eq!(variants.len(), 26);
    for value in variants {
        assert_eq!(value.slot.key_data()?, key);
        assert_eq!(document_name_data(&selected, &value.slot)?, expected_name);
        assert_ne!(value.commitment_data()?, original_commitment);
    }
    assert!(expected_name.contains("/documents/day2_scheduled_backup_attempts_v1/"));
    Ok(())
}

#[test]
fn stable_key_has_an_explicit_primitive_wire_vector_independent_of_scope_record_layout()
-> Result<()> {
    let value = intent(&selection());
    let canonical = br#"["day2-scheduled-backup-slot-v1","fixture","test","calendar","12345678-1234-1234-1234-000000000001","2026-11-22T17:00:00Z"]"#;
    assert_eq!(value.slot.key_data()?, Digest::new(canonical));
    Ok(())
}

#[test]
fn only_scope_cronjob_and_canonical_slot_partition_the_stable_key() -> Result<()> {
    let original = intent(&selection()).slot;
    let mut slots = Vec::new();
    for field in 0..5 {
        let mut next = original.clone();
        match field {
            0 => next.scope.installation = name("different-installation"),
            1 => next.scope.environment = name("different-environment"),
            2 => next.scope.app = name("different-app"),
            3 => next.cron_job_uid = uid(999),
            4 => next.scheduled_at = "2026-11-22T18:00:00Z".to_owned().try_into()?,
            _ => unreachable!(),
        }
        slots.push(next);
    }
    let mut keys = BTreeSet::from([original.key_data()?.as_str().to_owned()]);
    for slot in slots {
        assert!(keys.insert(slot.key_data()?.as_str().to_owned()));
    }
    assert_eq!(keys.len(), 6);
    Ok(())
}

#[test]
fn full_intent_is_bounded_canonical_map_data_not_a_legacy_or_sequence_shape() -> Result<()> {
    let original = intent(&selection());
    let bytes = serde_json::to_vec(&original)?;
    assert_eq!(Intent::decode_data(&bytes)?, original);
    let mut extra = serde_json::to_value(&original)?;
    extra["unknown"] = json!(true);
    assert!(Intent::decode_data(&serde_json::to_vec(&extra)?).is_err());
    let canonical = String::from_utf8(bytes)?;
    let key = format!(
        "\"policy_generation\":\"{}\"",
        original.policy_generation.as_str()
    );
    let duplicate = canonical.replacen(&key, &format!("{key},{key}"), 1);
    assert!(Intent::decode_data(duplicate.as_bytes()).is_err());
    assert!(Intent::decode_data(format!(" {canonical}").as_bytes()).is_err());
    let mut fields = serde_json::to_value(&original)?;
    fields["slot"] = json!([
        original.slot.scope,
        original.slot.cron_job_uid,
        original.slot.scheduled_at
    ]);
    assert!(Intent::decode_data(&serde_json::to_vec(&fields)?).is_err());
    assert!(Intent::decode_data(&vec![b' '; MAX_PAYLOAD + 1]).is_err());
    for invalid in [
        "calendar/../outside",
        "calendar/20261122T170000Z/",
        "other/20261122T170000Z",
        "calendar/20260230T170000Z",
        "https://foreign.invalid",
    ] {
        let mut value = original.clone();
        value.destination.prefix = invalid.into();
        assert!(value.validate_data().is_err());
    }
    let mut reflected = original.clone();
    reflected.transport.controller_nonce = reflected.transport.requester_nonce.clone();
    assert!(reflected.validate_data().is_err());
    Ok(())
}

#[test]
fn create_body_is_single_fixed_namespace_create_only_and_complete_intent_is_bound() -> Result<()> {
    let selected = selection();
    let value = intent(&selected);
    let mut turn = CreateTurn::new_data(&selected, value.clone())?;
    let request = turn.submit_data()?;
    assert_eq!(
        request.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["writes"]
    );
    let writes = request["writes"].as_array().unwrap();
    assert_eq!(writes.len(), 1);
    let write = &writes[0];
    assert_eq!(write["currentDocument"], json!({"exists":false}));
    assert_eq!(write.as_object().unwrap().len(), 2);
    assert_eq!(
        write["update"]["name"],
        document_name_data(&selected, &value.slot)?
    );
    let record: AttemptRecord = decode_canonical(
        write["update"]["fields"]["attempt_json"]["stringValue"]
            .as_str()
            .unwrap()
            .as_bytes(),
    )?;
    assert_eq!(record.intent, value);
    assert_eq!(record.commitment, value.commitment_data()?);
    assert_eq!(
        write["update"]["fields"]["attempt_digest"]["stringValue"],
        Digest::of(&(RECORD_DOMAIN, &record))?.as_str()
    );
    assert_eq!(turn.disposition, DispositionData::MayHaveBeenSent);
    assert!(turn.submit_data().is_err());
    assert_eq!(turn.disposition, DispositionData::Unknown);
    Ok(())
}

#[test]
fn selection_changes_refuse_before_encoding_instead_of_restamping_the_intent() -> Result<()> {
    let selected = selection();
    let original = intent(&selected);
    for field in 0..4 {
        let mut changed = selected.clone();
        match field {
            0 => changed.scope.app = name("foreign"),
            1 => changed.key_set = digest("rotated-keys"),
            2 => changed.max_lease_seconds = 6,
            3 => {
                let EpochProvider::FirestoreNativeV1 { database_uid, .. } = &mut changed.provider;
                *database_uid = uid(999).0;
            }
            _ => unreachable!(),
        }
        assert!(CreateTurn::new_data(&changed, original.clone()).is_err());
    }
    assert_eq!(original, intent(&selected));
    Ok(())
}

#[test]
fn commit_ack_requires_one_map_result_valid_times_and_a_single_submitted_turn() -> Result<()> {
    let selected = selection();
    let value = intent(&selected);
    let mut good = pending(&selected, &value);
    good.observe_commit_data(200, &ack())?;
    assert_eq!(good.disposition, DispositionData::Created);
    assert!(good.submit_data().is_err());
    assert!(good.observe_commit_data(200, &ack()).is_err());
    let mut before = CreateTurn::new_data(&selected, value.clone())?;
    assert!(before.observe_commit_data(200, &ack()).is_err());
    assert_eq!(before.disposition, DispositionData::Unknown);
    assert!(before.submit_data().is_err());
    let valid: Value = serde_json::from_slice(&ack())?;
    let mut mutations = vec![json!([valid["writeResults"], valid["commitTime"]])];
    for field in 0..7 {
        let mut v = valid.clone();
        match field {
            0 => v["unknown"] = json!(true),
            1 => v["writeResults"] = json!([]),
            2 => v["writeResults"] = json!([valid["writeResults"][0], valid["writeResults"][0]]),
            3 => v["writeResults"][0] = json!([valid["writeResults"][0]["updateTime"]]),
            4 => v["writeResults"][0]["transformResults"] = json!([]),
            5 => v["commitTime"] = json!("2026-11-22T17:00:00Z"),
            6 => v["writeResults"][0]["updateTime"] = json!("not-a-time"),
            _ => unreachable!(),
        }
        mutations.push(v);
    }
    for v in mutations {
        let mut turn = pending(&selected, &value);
        assert!(
            turn.observe_commit_data(200, &serde_json::to_vec(&v)?)
                .is_err()
        );
        assert_eq!(turn.disposition, DispositionData::Unknown);
        assert!(turn.submit_data().is_err());
        assert!(turn.observe_commit_data(200, &ack()).is_err());
    }
    for status in [0, 201, 204, 400, 401, 403, 409, 412, 429, 500, 503] {
        let mut turn = pending(&selected, &value);
        assert!(turn.observe_commit_data(status, &ack()).is_err());
        assert!(turn.submit_data().is_err());
    }
    let mut lost = pending(&selected, &value);
    lost.lose_result_data();
    assert!(lost.observe_commit_data(200, &ack()).is_err());
    assert!(lost.submit_data().is_err());
    Ok(())
}

#[test]
fn existing_record_is_historical_spent_data_even_after_generation_or_winner_change() -> Result<()> {
    let selected = selection();
    let original = intent(&selected);
    let mut turn = CreateTurn::new_data(&selected, original.clone())?;
    let doc = stored(&turn.submit_data()?);
    let next = {
        let mut value = original.clone();
        value.policy_generation = digest("second-policy");
        value.admission_generation = digest("second-admission");
        value.requester.job_uid = uid(300);
        value
    };
    assert_eq!(
        document_name_data(&selected, &original.slot)?,
        document_name_data(&selected, &next.slot)?
    );
    let record = decode_spent_document_data(&selected, &next.slot, &serde_json::to_vec(&doc)?)?;
    assert_eq!(record.intent, original);
    assert_ne!(record.intent, next);
    let mut errors = Vec::new();
    for field in 0..7 {
        let mut bad = doc.clone();
        match field {
            0 => bad["name"] = json!("projects/foreign/databases/control/documents/foreign/slot"),
            1 => bad["fields"]["extra"] = json!({"stringValue":"not-admitted"}),
            2 => bad["fields"]["attempt_json"]["extra"] = json!(true),
            3 => bad["fields"]["attempt_digest"]["stringValue"] = json!(digest("wrong-record")),
            4 => bad["updateTime"] = json!("2026-11-22T17:00:00Z"),
            5 => bad["future"] = json!(true),
            6 => bad["fields"]["attempt_json"]["stringValue"] = json!("[]"),
            _ => unreachable!(),
        }
        errors.push(bad);
    }
    for v in errors {
        assert!(
            decode_spent_document_data(&selected, &next.slot, &serde_json::to_vec(&v)?).is_err()
        );
    }
    let bytes = serde_json::to_vec(&doc)?;
    let raw = String::from_utf8(bytes)?;
    let duplicate = raw.replacen("\"fields\":", "\"fields\":{},\"fields\":", 1);
    assert!(decode_spent_document_data(&selected, &next.slot, duplicate.as_bytes()).is_err());
    Ok(())
}

/// A tiny provider interpreter exercises the ACTUAL production write shape.
/// The independent oracle below uses logical tuples, never the encoded hash or
/// the production transition functions. This is not a production provider port.
#[derive(Default)]
struct ModelProvider {
    documents: BTreeMap<String, Value>,
}

impl ModelProvider {
    fn create(&mut self, write: &Value) -> bool {
        assert_eq!(write.as_object().unwrap().len(), 1);
        let writes = write["writes"].as_array().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0]["currentDocument"], json!({"exists":false}));
        assert_eq!(writes[0].as_object().unwrap().len(), 2);
        let name = writes[0]["update"]["name"].as_str().unwrap().to_owned();
        if self.documents.contains_key(&name) {
            return false;
        }
        self.documents.insert(name, stored(write));
        true
    }

    fn reopen(self) -> Result<Self> {
        Ok(Self {
            documents: serde_json::from_slice(&serde_json::to_vec(&self.documents)?)?,
        })
    }
}

const MAX_EVENTS: usize = 192;
const MAX_BUNDLE: usize = 65_536;
const MAX_ENCODED: usize = MAX_BUNDLE + 1_024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    scope: u8,
    cron: u8,
    minute: u8,
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
    source: String,
    seed: u64,
    events: Vec<Event>,
    wrong_oracle_at: Option<usize>,
    fault: Option<Failure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    step: usize,
    expected_created: bool,
    actual_created: Option<bool>,
    disposition: Option<DispositionData>,
    remote_records: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

fn source_digest() -> String {
    // Actual codecs/shared validators and locked native build inputs, not only
    // this generator. Hashes bind local component replay, never native authority.
    let inputs: &[(&str, &[u8])] = &[
        (
            "scheduled_backup.rs",
            include_bytes!("../../scheduled_backup.rs"),
        ),
        (
            "scheduled_backup/reservation.rs",
            include_bytes!("../reservation.rs"),
        ),
        (
            "scheduled_backup/reservation/tests.rs",
            include_bytes!("tests.rs"),
        ),
        ("kernel.rs", include_bytes!("../../kernel.rs")),
        ("json.rs", include_bytes!("../../../json.rs")),
        (
            "day2-capabilities/lib.rs",
            include_bytes!("../../../../../day2-capabilities/src/lib.rs"),
        ),
        (
            "day2-capabilities/security_epoch.rs",
            include_bytes!("../../../../../day2-capabilities/src/security_epoch.rs"),
        ),
        (
            "day2-capabilities/oauth.rs",
            include_bytes!("../../../../../day2-capabilities/src/oauth.rs"),
        ),
        ("day2/Cargo.toml", include_bytes!("../../../../Cargo.toml")),
        (
            "day2/BUILD.bazel",
            include_bytes!("../../../../BUILD.bazel"),
        ),
        ("Cargo.toml", include_bytes!("../../../../../../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../../../../../../Cargo.lock")),
        (
            "MODULE.bazel.lock",
            include_bytes!("../../../../../../MODULE.bazel.lock"),
        ),
        (
            "bazel/toolchain.json",
            include_bytes!("../../../../../../build/bazel/toolchain.json"),
        ),
    ];
    let hashes = inputs
        .iter()
        .map(|(name, bytes)| (*name, crate::digest(bytes)))
        .collect::<Vec<_>>();
    crate::digest(&serde_json::to_vec(&hashes).expect("fixed replay source hashes"))
}

fn program(seed: u64) -> Program {
    let mut state = seed;
    let mut events = Vec::new();
    for _ in 0..MAX_EVENTS {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        events.push(Event {
            scope: ((state >> 3) % 3) as u8,
            cron: ((state >> 7) % 2) as u8,
            minute: ((state >> 13) % 7) as u8,
        });
    }
    Program {
        format: 1,
        source: source_digest(),
        seed,
        events,
        wrong_oracle_at: None,
        fault: None,
    }
}

fn validate_program(p: &Program) -> Result<()> {
    ensure!(
        p.format == 1
            && p.source == source_digest()
            && !p.events.is_empty()
            && p.events.len() <= MAX_EVENTS,
        "backup_attempt_replay_program"
    );
    ensure!(
        p.events
            .iter()
            .all(|e| e.scope < 3 && e.cron < 2 && e.minute < 7),
        "backup_attempt_replay_event"
    );
    ensure!(
        p.wrong_oracle_at.is_none_or(|n| n < p.events.len())
            && p.fault.as_ref().is_none_or(|f| f.step < p.events.len()
                && match f.kind {
                    FailureKind::Setup => f.step == 0,
                    FailureKind::Step | FailureKind::Panic => true,
                    FailureKind::Mismatch => false,
                }),
        "backup_attempt_replay_fault"
    );
    Ok(())
}

fn replay(p: &Program) -> Run {
    let mut provider = ModelProvider::default();
    let mut independent = BTreeSet::new();
    let mut run = Run {
        observations: Vec::new(),
        failure: None,
    };
    if validate_program(p).is_err()
        || p.fault
            .as_ref()
            .is_some_and(|f| f.kind == FailureKind::Setup)
    {
        run.failure = Some(Failure {
            step: 0,
            kind: FailureKind::Setup,
        });
        return run;
    }
    for (step, event) in p.events.iter().enumerate() {
        // Independent oracle uses the logical tuple, never the production hash,
        // body, receipt or remote document to decide whether creation is new.
        let expected = independent.insert((event.scope, event.cron, event.minute));
        let mut observation = Observation {
            step,
            expected_created: if p.wrong_oracle_at == Some(step) {
                !expected
            } else {
                expected
            },
            actual_created: None,
            disposition: None,
            remote_records: provider.documents.len(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            if let Some(fault) = &p.fault
                && fault.step == step
            {
                match fault.kind {
                    FailureKind::Step => anyhow::bail!("PRIVATE-ERROR-MUST-NOT-BE-RETAINED"),
                    FailureKind::Panic => panic!("controlled_backup_replay_unwind"),
                    _ => {}
                }
            }
            let mut selected = selection();
            selected.scope.app = name(&format!("app{}", event.scope));
            let mut value = intent(&selected);
            value.slot.cron_job_uid = uid(u64::from(event.cron) + 1);
            value.slot.scheduled_at =
                format!("2026-11-22T17:{:02}:00Z", event.minute).try_into()?;
            value.requester.job_uid = uid(step as u64 + 100);
            value.requester.pod_uid = uid(step as u64 + 1000);
            value.policy_generation = digest(&format!("generation{}", step % 5));
            value.admission_generation = digest(&format!("admission{}", step % 3));
            value.transport.requester_nonce = digest(&format!("nonce{step}"));
            value.operation = digest(&format!("operation{step}"));
            value.destination.prefix = format!("app{}/20261122T170000Z", event.scope);
            let mut turn = CreateTurn::new_data(&selected, value.clone())?;
            let write = turn.submit_data()?;
            let created = provider.create(&write);
            observation.actual_created = Some(created);
            if created && step % 4 == 0 {
                // Applied create, lost acknowledgement: immutable remote row
                // survives reopen. It still confers no source permission.
                turn.lose_result_data();
                ensure!(
                    turn.disposition == DispositionData::Unknown,
                    "backup_attempt_model_lost"
                );
            } else if created {
                turn.observe_commit_data(200, &ack())?;
                ensure!(
                    turn.disposition == DispositionData::Created,
                    "backup_attempt_model_created"
                );
            } else {
                ensure!(
                    turn.observe_commit_data(409, b"unexamined provider body")
                        .is_err()
                        && turn.disposition == DispositionData::Unknown,
                    "backup_attempt_model_conflict"
                );
            }
            observation.disposition = Some(turn.disposition);
            ensure!(
                turn.submit_data().is_err() && turn.observe_commit_data(200, &ack()).is_err(),
                "backup_attempt_model_reuse"
            );
            let doc = provider
                .documents
                .get(&document_name_data(&selected, &value.slot)?)
                .context("backup_attempt_model_document")?;
            let spent =
                decode_spent_document_data(&selected, &value.slot, &serde_json::to_vec(doc)?)?;
            ensure!(spent.intent.slot == value.slot, "backup_attempt_model_slot");
            if step % 11 == 0 {
                provider = std::mem::take(&mut provider).reopen()?;
            }
            Ok(())
        }));
        observation.remote_records = provider.documents.len();
        let failure = match result {
            Err(_) => Some(FailureKind::Panic),
            Ok(Err(_)) => Some(FailureKind::Step),
            Ok(Ok(())) if observation.actual_created != Some(observation.expected_created) => {
                Some(FailureKind::Mismatch)
            }
            Ok(Ok(())) => None,
        };
        run.observations.push(observation);
        if let Some(kind) = failure {
            run.failure = Some(Failure { step, kind });
            break;
        }
    }
    run
}

struct SavedFailure(PathBuf);
impl std::fmt::Debug for SavedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scheduled_backup_replay_saved")
    }
}
impl std::fmt::Display for SavedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for SavedFailure {}

fn check_program(p: &Program) -> Result<()> {
    validate_program(p)?;
    let first = replay(p);
    let second = replay(p);
    if first == second && first.failure.is_none() {
        return Ok(());
    }
    // No error messages, panic payloads, provider bytes or environment data.
    // Full bounded program and both observed prefixes survive every step error.
    let bytes = serde_json::to_vec(&Bundle {
        program: p.clone(),
        first,
        second,
    })?;
    ensure!(
        bytes.len() <= MAX_BUNDLE,
        "backup_attempt_replay_bundle_bound"
    );
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/control-slot-replays");
    std::fs::create_dir_all(&parent)?;
    let directory = tempfile::Builder::new()
        .prefix("scheduled-backup-attempt-")
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
    Err(SavedFailure(path).into())
}

fn decode_bundle(bytes: &[u8]) -> Result<Bundle> {
    ensure!(
        bytes.len() <= MAX_BUNDLE,
        "backup_attempt_replay_bundle_bound"
    );
    let value: Value = crate::json::decode(bytes)?;
    let bundle: Bundle = serde_json::from_value(value.clone())?;
    ensure!(
        serde_json::to_value(&bundle)? == value,
        "backup_attempt_replay_bundle_shape"
    );
    validate_program(&bundle.program)?;
    Ok(bundle)
}

fn saved_payload(error: &anyhow::Error) -> Result<Vec<u8>> {
    let path = &error
        .downcast_ref::<SavedFailure>()
        .context("backup_attempt_replay_missing")?
        .0;
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.permissions().mode() & 0o777 == 0o600,
        "backup_attempt_replay_file"
    );
    ensure!(
        std::fs::metadata(path.parent().context("backup_attempt_replay_parent")?)?
            .permissions()
            .mode()
            & 0o777
            == 0o700,
        "backup_attempt_replay_directory"
    );
    let mut encoded = Vec::new();
    file.take((MAX_ENCODED + 1) as u64)
        .read_to_end(&mut encoded)?;
    ensure!(
        encoded.len() <= MAX_ENCODED,
        "backup_attempt_replay_encoded_bound"
    );
    let mut decoder = flate2::bufread::GzDecoder::new(&encoded[..]);
    let mut bytes = Vec::new();
    decoder
        .by_ref()
        .take((MAX_BUNDLE + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BUNDLE && decoder.into_inner().is_empty(),
        "backup_attempt_replay_bundle_bound"
    );
    Ok(bytes)
}

#[test]
fn generated_generation_replacement_and_applied_uncertainty_histories_replay_twice() -> Result<()> {
    let mut schedules = BTreeSet::new();
    for seed in [0, 1, 7, 31, 197, 0xabcdef, u64::MAX] {
        let p = program(seed);
        schedules.insert(serde_json::to_vec(&p.events)?);
        check_program(&p)?;
    }
    ensure!(schedules.len() == 7, "backup_attempt_generator_degenerate");
    Ok(())
}

#[test]
fn failed_history_retains_seed_full_prefix_source_binding_and_both_replays() -> Result<()> {
    for fault in [
        Failure {
            step: 0,
            kind: FailureKind::Setup,
        },
        Failure {
            step: 7,
            kind: FailureKind::Step,
        },
        Failure {
            step: 9,
            kind: FailureKind::Panic,
        },
    ] {
        let mut p = program(197);
        p.fault = Some(fault.clone());
        let error = check_program(&p).expect_err("actual model fault must be retained");
        let payload = saved_payload(&error)?;
        assert!(!String::from_utf8_lossy(&payload).contains("PRIVATE-ERROR-MUST-NOT-BE-RETAINED"));
        let bundle = decode_bundle(&payload)?;
        assert_eq!(bundle.program.seed, 197);
        assert_eq!(bundle.program.source, source_digest());
        assert_eq!(bundle.first.failure, Some(fault.clone()));
        assert_eq!(bundle.first, bundle.second);
        assert_eq!(replay(&bundle.program), bundle.first);
        assert_eq!(
            bundle.first.observations.len(),
            if fault.kind == FailureKind::Setup {
                0
            } else {
                fault.step + 1
            }
        );
    }
    Ok(())
}

#[test]
fn maximal_late_oracle_failure_is_not_truncated_and_rejects_other_source_or_shape() -> Result<()> {
    let mut p = program(31);
    p.wrong_oracle_at = Some(MAX_EVENTS - 1);
    let error = check_program(&p).expect_err("wrong independent expectation must fail");
    let payload = saved_payload(&error)?;
    assert!(payload.len() <= MAX_BUNDLE);
    let bundle = decode_bundle(&payload)?;
    assert_eq!(bundle.first.observations.len(), MAX_EVENTS);
    assert_eq!(
        bundle.first.failure,
        Some(Failure {
            step: MAX_EVENTS - 1,
            kind: FailureKind::Mismatch
        })
    );
    assert_eq!(bundle.first, bundle.second);
    assert_eq!(replay(&bundle.program), bundle.first);
    let last = bundle.first.observations.last().unwrap();
    assert_ne!(last.actual_created, Some(last.expected_created));
    let mut other = serde_json::to_value(&bundle)?;
    other["program"]["source"] = json!(digest("different-source"));
    assert!(decode_bundle(&serde_json::to_vec(&other)?).is_err());
    let mut future = serde_json::to_value(&bundle)?;
    future["unknown"] = json!(true);
    assert!(decode_bundle(&serde_json::to_vec(&future)?).is_err());
    let raw = String::from_utf8(payload)?;
    let duplicate = raw.replacen("\"format\":1", "\"format\":1,\"format\":1", 1);
    assert!(decode_bundle(duplicate.as_bytes()).is_err());
    assert!(decode_bundle(&vec![b' '; MAX_BUNDLE + 1]).is_err());
    Ok(())
}

#[test]
fn unknown_unapplied_result_cannot_retry_or_adopt_a_later_reply_on_the_same_turn() -> Result<()> {
    let selected = selection();
    let value = intent(&selected);
    let mut turn = pending(&selected, &value);
    turn.lose_result_data();
    assert_eq!(turn.disposition, DispositionData::Unknown);
    assert!(turn.observe_commit_data(200, &ack()).is_err());
    assert!(turn.submit_data().is_err());
    // Empty/missing provider state does not decode to a receipt or a turn. The
    // later genuine driver must preserve uncertainty across NEW authentications
    // and process death; this DATA-only component does not claim to supply that.
    assert!(decode_spent_document_data(&selected, &value.slot, b"{}").is_err());
    assert!(decode_spent_document_data(&selected, &value.slot, b"null").is_err());
    Ok(())
}
