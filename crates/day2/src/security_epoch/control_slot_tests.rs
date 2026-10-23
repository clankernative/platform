//! Independent conditional provider oracle. SQLite knows only create-only and
//! exact version CAS, not the production slot transition functions. These
//! controlled tests never qualify original CreatorFD, native roles or Ready.

use super::{
    control_slot::*,
    control_slot_firestore::{self as codec, VersionedSlot},
    kernel::{Holder, Request, UpdateTime, Versions},
    seed_core::{Incarnations, OriginalSeedCore},
    tests,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Barrier},
    time::Duration,
};

fn completion(create: &LogicalCore) -> LogicalCore {
    let mut counter = Request::CompleteInitialFirstActivation {
        bootstrap: create.counter.bootstrap().clone(),
        operation: Digest::new(b"uncomputed"),
        parent_receipt: create.counter.receipt().unwrap().digest().unwrap(),
        before: Versions {
            root: version(1),
            sentinel: version(1),
        },
        holder: Holder {
            principal: Digest::new(b"app-principal"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"original-app-process"),
            ephemeral_key: Digest::new(b"original-app-key"),
        },
    };
    let id = complete_operation(&counter, &create.seed.digest().unwrap()).unwrap();
    let Request::CompleteInitialFirstActivation { operation, .. } = &mut counter else {
        unreachable!()
    };
    *operation = id;
    LogicalCore::new(
        &tests::selection(),
        create.policy.clone(),
        create.seed.clone(),
        &counter,
    )
    .unwrap()
}

fn fixture() -> (EpochStore, LogicalCore) {
    let selection = tests::selection();
    let policy = policy(&selection);
    let seed = OriginalSeedCore::new(
        &policy,
        &selection,
        Incarnations {
            record: Digest::new(b"record"),
            database: Digest::new(b"database"),
            activation: Digest::new(b"activation"),
        },
    )
    .unwrap();
    let counter = Request::CreateInitialAuthority {
        bootstrap: seed.bootstrap().unwrap(),
    };
    (
        selection.clone(),
        LogicalCore::new(&selection, policy, seed, &counter).unwrap(),
    )
}

pub(super) fn policy(store: &EpochStore) -> InitialBootstrapPolicy {
    let epoch = json!({"id":"epoch","revision":Digest::of(store).unwrap()});
    let app = match &store.provider {
        day2_capabilities::security_epoch::EpochProvider::FirestoreNativeV1 {
            iam_source, ..
        } => iam_source,
    };
    let role = |account: Value, name: &str| {
        json!({
            "namespace":{"name":"native","uid":"namespace-uid"},
            "kubernetes_service_account":{"name":name,"uid":format!("{name}-ksa-uid")},
            "google_service_account":account,"workload_kind":if name=="app" { "stateful_set_v1" } else { "deployment_v1" },
        "workload":{"name":name,"uid":format!("{name}-workload-uid")},
        "container":{"name":name,"image":Digest::new(format!("{name}-image").as_bytes())},
        "token_review_audience":"https://kubernetes.default.svc"
        })
    };
    serde_json::from_value(json!({
        "scope":store.scope,"epoch_store":epoch,
        "cluster":{"project":"project-seven","location":"us-central1","name":"native","uid":"cluster-uid","api_origin":"https://10.0.0.1:443","certificate_authority":Digest::new(b"ca")},
        "controller":role(json!({"kind":"gke_workload_identity_v1","service_account":"controller@project-seven.iam.gserviceaccount.com","service_account_uid":"200000000000000000007"}),"controller"),
        "app":role(serde_json::to_value(app).unwrap(),"app"),
        "shell":role(json!({"kind":"gke_workload_identity_v1","service_account":"shell@project-seven.iam.gserviceaccount.com","service_account_uid":"300000000000000000007"}),"shell"),
        "control_store":{"kind":"firestore_authority_database_v1","epoch_store":epoch},
        "runtime_profile":{"kind":"gke_linux_trusted_native_v1","manifest":Digest::new(b"profile"),"controller_code":Digest::new(b"code"),"app_host_code":Digest::new(b"app-host-code"),"security_shell_code":Digest::new(b"shell-code"),"app_artifact":Digest::new(b"artifact")},
        "fresh_storage":{"provider_volume_uid":"provider-volume-uid","mount_binding":Digest::new(b"mount"),"schema_contract":Digest::new(b"schema"),"marker_format":"initial-v1"}
    })).unwrap()
}

fn version(n: u64) -> UpdateTime {
    format!("2026-10-14T00:00:00.{n:06}Z").try_into().unwrap()
}

fn attempt(
    core: &LogicalCore,
    version: UpdateTime,
    ordinal: AttemptOrdinal,
    nonce: &[u8],
) -> AttemptCore {
    AttemptCore {
        logical: core.digest().unwrap(),
        request: core.request_digest.clone(),
        ordinal,
        expected: version,
        controller_incarnation: Digest::new(b"controller-data"),
        nonce: Digest::new(nonce),
    }
}

struct Provider {
    db: Connection,
    handle: i64,
    next_attempt: u64,
    fault: ExitPoint,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExitPoint {
    None,
    BeforeMutation,
    BeforeCommit,
    AfterCommit,
}

impl Provider {
    fn open(path: impl AsRef<Path>) -> Self {
        let db = Connection::open(path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db.execute_batch("CREATE TABLE IF NOT EXISTS slots(name TEXT PRIMARY KEY,fields TEXT NOT NULL,version INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS handles(id INTEGER PRIMARY KEY); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,handle INTEGER NOT NULL,attempt TEXT NOT NULL,kind TEXT NOT NULL,payload TEXT NOT NULL);").unwrap();
        db.execute("INSERT INTO handles DEFAULT VALUES", [])
            .unwrap();
        let handle = db.last_insert_rowid();
        Self {
            db,
            handle,
            next_attempt: 0,
            fault: ExitPoint::None,
        }
    }

    fn apply(&mut self, write: &Value, lose_ack: bool) -> Result<()> {
        self.next_attempt = self
            .next_attempt
            .checked_add(1)
            .context("oracle attempt overflow")?;
        let attempt = format!("handle-{}-attempt-{}", self.handle, self.next_attempt);
        // This dispatch record commits independently of the provider mutation.
        // A rejected CAS or process exit cannot roll it back with that write.
        self.event(
            &attempt,
            "dispatch",
            json!({"write":write,"lose_ack":lose_ack}),
        )?;
        self.persist("oracle-before-dispatch");
        if self.fault == ExitPoint::BeforeMutation {
            std::process::exit(86);
        }
        let mutation = self.mutate(write, &attempt);
        let result = match mutation {
            Ok(committed_version) => {
                self.event(
                    &attempt,
                    if lose_ack {
                        "ack_lost"
                    } else {
                        "ack_delivered"
                    },
                    json!({"committed_version":committed_version}),
                )?;
                if lose_ack {
                    Err(anyhow::anyhow!("oracle ack lost after commit"))
                } else {
                    Ok(())
                }
            }
            Err(error) => {
                self.event(&attempt, "refused", json!({"reason":error.to_string()}))?;
                Err(error)
            }
        };
        self.persist("oracle-after-outcome");
        result
    }

    fn event(&self, attempt: &str, kind: &str, payload: Value) -> Result<()> {
        self.db.execute(
            "INSERT INTO events(handle,attempt,kind,payload) VALUES(?1,?2,?3,?4)",
            params![self.handle, attempt, kind, serde_json::to_string(&payload)?],
        )?;
        Ok(())
    }

    fn mutate(&mut self, write: &Value, attempt: &str) -> Result<i64> {
        ensure!(
            write.as_object().is_some_and(|m| m.len() == 2),
            "oracle write shape"
        );
        let name = write
            .pointer("/update/name")
            .and_then(Value::as_str)
            .context("oracle name")?;
        let fields =
            serde_json::to_string(write.pointer("/update/fields").context("oracle fields")?)?;
        let guard = write
            .get("currentDocument")
            .and_then(Value::as_object)
            .context("oracle guard")?;
        ensure!(guard.len() == 1, "oracle guard shape");
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<i64> = tx
            .query_row("SELECT version FROM slots WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        let permitted = if guard.get("exists") == Some(&json!(false)) {
            previous.is_none()
        } else {
            let expected = guard
                .get("updateTime")
                .and_then(Value::as_str)
                .context("oracle exact version")?;
            previous.is_some_and(|current| expected == format!("2026-10-14T00:00:00.{current:06}Z"))
        };
        if !permitted {
            tx.execute("INSERT INTO events(handle,attempt,kind,payload) VALUES(?1,?2,'provider_refusal',?3)",params![self.handle,attempt,serde_json::to_string(&json!({"name":name,"observed_before":previous,"expected":guard}))?])?;
            tx.commit()?;
            anyhow::bail!("oracle conditional conflict");
        }
        let next = previous
            .unwrap_or(0)
            .checked_add(1)
            .context("oracle version overflow")?;
        tx.execute("INSERT INTO slots(name,fields,version) VALUES(?1,?2,?3) ON CONFLICT(name) DO UPDATE SET fields=excluded.fields,version=excluded.version",params![name,fields,next])?;
        if self.fault == ExitPoint::BeforeCommit {
            std::process::exit(86);
        }
        // Commit order and the exact observed version belong to the independent
        // journal. This event is atomic with the write, before any reply/exit.
        tx.execute(
            "INSERT INTO events(handle,attempt,kind,payload) VALUES(?1,?2,'provider_commit',?3)",
            params![
                self.handle,
                attempt,
                serde_json::to_string(
                    &json!({"name":name,"observed_before":previous,"committed_version":next})
                )?
            ],
        )?;
        tx.commit()?;
        if self.fault == ExitPoint::AfterCommit {
            std::process::exit(86);
        }
        Ok(next)
    }

    fn read(&self, name: &str) -> Vec<u8> {
        let (fields, n): (String, i64) = self
            .db
            .query_row(
                "SELECT fields,version FROM slots WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        serde_json::to_vec(&json!({"name":name,"fields":serde_json::from_str::<Value>(&fields).unwrap(),
            "createTime":"2026-10-14T00:00:00.000001Z","updateTime":format!("2026-10-14T00:00:00.{n:06}Z")})).unwrap()
    }

    fn rows(&self) -> i64 {
        self.db
            .query_row("SELECT COUNT(*) FROM slots", [], |r| r.get(0))
            .unwrap()
    }

    fn replay(&self) -> Value {
        // Both racing handles contribute to one consistent journal snapshot.
        // Event/attempt identity does not depend on equal request payloads.
        let tx = self.db.unchecked_transaction().unwrap();
        let events=tx.prepare("SELECT id,handle,attempt,kind,payload FROM events ORDER BY id").unwrap()
            .query_map([],|r| Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?))).unwrap()
            .map(|r| { let (event,handle,attempt,kind,payload)=r.unwrap();json!({"event":event,"handle":handle,"attempt":attempt,"kind":kind,"payload":serde_json::from_str::<Value>(&payload).unwrap()}) }).collect::<Vec<_>>();
        let final_rows=tx.prepare("SELECT name,fields,version FROM slots ORDER BY name").unwrap()
            .query_map([],|r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?))).unwrap()
            .map(|r| { let (name,fields,version)=r.unwrap();json!({"name":name,"fields":serde_json::from_str::<Value>(&fields).unwrap(),"version":version}) }).collect::<Vec<_>>();
        tx.commit().unwrap();
        json!({"seed":3664912422_u64,"events":events,"final_rows":final_rows})
    }

    fn persist(&self, label: &str) {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/control-slot-replays");
        std::fs::create_dir_all(&root).unwrap();
        let payload =
            serde_json::to_vec_pretty(&json!({"label":label,"replay":self.replay()})).unwrap();
        // Keep every capture, including identical requests and partial traces;
        // no content-addressed overwrite can collapse independent attempts.
        let directory = tempfile::Builder::new()
            .prefix(label)
            .tempdir_in(root)
            .unwrap()
            .keep();
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("replay.json"))
            .unwrap();
        file.write_all(&payload).unwrap();
    }
}

#[test]
fn attempt_ordinals_are_nominal_nonzero_strings_and_do_not_wrap() {
    for input in ["0", "01", "-1", "1.0", "", "18446744073709551616"] {
        assert!(
            AttemptOrdinal::try_from(input.to_owned()).is_err(),
            "{input}"
        );
    }
    let last = AttemptOrdinal::try_from(u64::MAX.to_string()).unwrap();
    assert!(last.next().is_err());
    assert!(crate::json::decode::<AttemptOrdinal>(b"1").is_err());
    assert_eq!(String::from(AttemptOrdinal::first().next().unwrap()), "2");
}

#[test]
fn immutable_reservation_survives_unknown_accept_and_late_replacement() {
    let (selection, core) = fixture();
    let mut provider = Provider::open(":memory:");
    let prepared = Slot::prepared(core.clone());
    let write = codec::create_data(&selection, &prepared).unwrap();
    assert!(provider.apply(&write, true).is_err());
    let name = codec::name(&selection, &core).unwrap();
    let observed = codec::decode(&selection, &core, &provider.read(&name)).unwrap();
    assert_eq!(observed.slot, prepared);
    assert_eq!(provider.rows(), 1);
    assert!(provider.apply(&write, false).is_err());
    let mut other = core.clone();
    other.seed.incarnations.record = Digest::new(b"replacement");
    let Request::CreateInitialAuthority { bootstrap } = &mut other.counter else {
        unreachable!()
    };
    *bootstrap = other.seed.bootstrap().unwrap();
    other.canonical_counter = serde_json::to_string(&other.counter).unwrap();
    other.request_digest = other.counter.digest().unwrap();
    assert_eq!(codec::name(&selection, &other).unwrap(), name);
    assert!(
        provider
            .apply(
                &codec::create_data(&selection, &Slot::prepared(other.clone())).unwrap(),
                false
            )
            .is_err()
    );
    assert!(codec::decode(&selection, &other, &provider.read(&name)).is_err());
    provider.persist("permanent-unknown-accept");
}

#[test]
fn concurrent_accepts_reserve_one_authority_stage_and_cas_only_one_attempt() {
    let (selection, core) = fixture();
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("oracle.sqlite");
    let provider = Provider::open(&path);
    let create = codec::create_data(&selection, &Slot::prepared(core.clone())).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut children = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let path = path.clone();
        let create = create.clone();
        children.push(std::thread::spawn(move || {
            let mut provider = Provider::open(path);
            barrier.wait();
            provider.apply(&create, false).is_ok()
        }));
    }
    barrier.wait();
    assert_eq!(
        children
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|v| *v)
            .count(),
        1
    );
    let name = codec::name(&selection, &core).unwrap();
    let original = codec::decode(&selection, &core, &provider.read(&name)).unwrap();
    let first = original
        .slot
        .claim_data(
            &selection,
            &original.version,
            attempt(
                &core,
                original.version.clone(),
                AttemptOrdinal::first(),
                b"one",
            ),
        )
        .unwrap();
    let second = original
        .slot
        .claim_data(
            &selection,
            &original.version,
            attempt(
                &core,
                original.version.clone(),
                AttemptOrdinal::first(),
                b"two",
            ),
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut children = Vec::new();
    for slot in [&first, &second] {
        let write = codec::cas_data(&selection, &original, slot).unwrap();
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        children.push(std::thread::spawn(move || {
            let mut provider = Provider::open(path);
            barrier.wait();
            provider.apply(&write, false).is_ok()
        }));
    }
    barrier.wait();
    assert_eq!(
        children
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|v| *v)
            .count(),
        1
    );
    let winner = codec::decode(&selection, &core, &provider.read(&name))
        .unwrap()
        .slot;
    assert_eq!(provider.rows(), 1);
    assert!(winner == first || winner == second);
    provider.persist("concurrent-reservation-exact-cas");
    let replay = provider.replay();
    assert_eq!(
        replay["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "dispatch")
            .count(),
        4
    );
    assert_eq!(
        replay["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "refused")
            .count(),
        2
    );
    assert_eq!(
        replay["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "provider_commit")
            .count(),
        2
    );
    assert_eq!(replay["final_rows"][0]["version"], 2);
    replay_provider(&replay);
}

#[test]
fn unknown_claim_rearm_and_settlement_keep_original_request_and_version_fences() {
    let (selection, core) = fixture();
    let mut provider = Provider::open(":memory:");
    provider
        .apply(
            &codec::create_data(&selection, &Slot::prepared(core.clone())).unwrap(),
            false,
        )
        .unwrap();
    let name = codec::name(&selection, &core).unwrap();
    let prepared = codec::decode(&selection, &core, &provider.read(&name)).unwrap();
    let may = prepared
        .slot
        .claim_data(
            &selection,
            &prepared.version,
            attempt(
                &core,
                prepared.version.clone(),
                AttemptOrdinal::first(),
                b"one",
            ),
        )
        .unwrap();
    let claim = codec::cas_data(&selection, &prepared, &may).unwrap();
    assert!(provider.apply(&claim, true).is_err());
    assert!(provider.apply(&claim, false).is_err());
    let current = codec::decode(&selection, &core, &provider.read(&name)).unwrap();
    assert!(
        current
            .slot
            .claim_data(
                &selection,
                &current.version,
                attempt(
                    &core,
                    current.version.clone(),
                    AttemptOrdinal::first(),
                    b"new"
                )
            )
            .is_err()
    );
    let SlotState::MayHaveBeenSent { attempt: last } = &current.slot.state else {
        unreachable!()
    };
    let rearm = RearmCore {
        logical: core.digest().unwrap(),
        request: core.request_digest.clone(),
        previous: last.id.clone(),
        expected: current.version.clone(),
        not_applied_observation: Digest::new(b"historical-not-applied-data"),
        next: last.core.ordinal.next().unwrap(),
    };
    let retryable = current
        .slot
        .rearm_data(&selection, &current.version, rearm)
        .unwrap();
    let write = codec::cas_data(&selection, &current, &retryable).unwrap();
    assert!(provider.apply(&write, true).is_err());
    assert!(provider.apply(&write, false).is_err());
    let retry = codec::decode(&selection, &core, &provider.read(&name)).unwrap();
    let receipt = core.counter.receipt().unwrap();
    let settlement = SettlementCore {
        logical: core.digest().unwrap(),
        expected: retry.version.clone(),
        control_attempt: last.id.clone(),
        receipt: receipt.digest().unwrap(),
    };
    let settled = retry
        .slot
        .settle_data(&selection, &retry.version, settlement, receipt)
        .unwrap();
    let write = codec::cas_data(&selection, &retry, &settled).unwrap();
    assert!(provider.apply(&write, true).is_err());
    assert_eq!(
        codec::decode(&selection, &core, &provider.read(&name))
            .unwrap()
            .slot,
        settled
    );
    assert!(provider.apply(&write, false).is_err());
    assert!(
        codec::cas_data(
            &selection,
            &VersionedSlot {
                slot: settled,
                version: version(4)
            },
            &Slot::prepared(core.clone())
        )
        .is_err()
    );
    assert_eq!(provider.rows(), 1);
    provider.persist("unknown-claim-rearm-settlement");
    // No native send-permit API exists in this pure DATA model. Stored May,
    // Retryable and Observed cannot be loaded as authority by this harness.
}

#[test]
fn closed_codec_rejects_sequences_duplicates_replaced_core_and_tampered_ids() {
    let (selection, core) = fixture();
    let prepared = Slot::prepared(core.clone());
    let mut provider = Provider::open(":memory:");
    provider
        .apply(&codec::create_data(&selection, &prepared).unwrap(), false)
        .unwrap();
    let name = codec::name(&selection, &core).unwrap();
    let good: Value = serde_json::from_slice(&provider.read(&name)).unwrap();
    for (pointer, value) in [
        ("/name", json!("other")),
        (
            "/fields/control_digest/stringValue",
            json!(Digest::new(b"tamper")),
        ),
        ("/fields/control_json/stringValue", json!("[]")),
        (
            "/fields/control_json/stringValue",
            json!("{\"format\":\"day2_credential_control_slot_v1\",\"format\":\"wrong\"}"),
        ),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            codec::decode(&selection, &core, &serde_json::to_vec(&bad).unwrap()).is_err(),
            "{pointer}"
        );
    }
    assert!(crate::json::decode::<SlotState>(br#"["prepared","1"]"#).is_err());
    assert!(
        crate::json::decode::<SlotState>(br#"{"state":"prepared","next":"1","ready":true}"#)
            .is_err()
    );
    let original = VersionedSlot {
        slot: prepared,
        version: version(1),
    };
    let mut invalid = attempt(&core, version(2), AttemptOrdinal::first(), b"one");
    assert!(
        original
            .slot
            .claim_data(&selection, &original.version, invalid.clone())
            .is_err()
    );
    invalid.expected = version(1);
    invalid.ordinal = AttemptOrdinal::first().next().unwrap();
    assert!(
        original
            .slot
            .claim_data(&selection, &original.version, invalid)
            .is_err()
    );
}

// Independent replay of the provider's conditional-write contract. It does not
// call production slot transitions, codecs, request reconciliation or IDs.
fn replay_provider(replay: &Value) {
    use std::collections::BTreeMap;
    let mut attempts = BTreeMap::new();
    let mut rows: BTreeMap<String, (Value, i64)> = BTreeMap::new();
    let mut last_event = 0;
    for event in replay["events"].as_array().unwrap() {
        let order = event["event"].as_i64().unwrap();
        assert!(order > last_event);
        last_event = order;
        let id = event["attempt"].as_str().unwrap();
        match event["kind"].as_str().unwrap() {
            "dispatch" => {
                assert!(
                    attempts
                        .insert(id.to_owned(), event["payload"]["write"].clone())
                        .is_none()
                );
            }
            "provider_commit" | "provider_refusal" => {
                let write = attempts.get(id).unwrap();
                let name = write["update"]["name"].as_str().unwrap();
                let previous = rows.get(name).map(|row| row.1);
                assert_eq!(event["payload"]["name"], name);
                assert_eq!(event["payload"]["observed_before"], json!(previous));
                let condition = &write["currentDocument"];
                let allowed = if condition["exists"] == false {
                    previous.is_none()
                } else {
                    previous.is_some_and(|n| {
                        condition["updateTime"] == format!("2026-10-14T00:00:00.{n:06}Z")
                    })
                };
                if event["kind"] == "provider_refusal" {
                    assert!(!allowed);
                    assert_eq!(event["payload"]["expected"], *condition);
                } else {
                    assert!(allowed);
                    let next = previous.unwrap_or(0) + 1;
                    assert_eq!(event["payload"]["committed_version"], next);
                    rows.insert(name.to_owned(), (write["update"]["fields"].clone(), next));
                }
            }
            "ack_delivered" | "ack_lost" | "refused" => {
                assert!(attempts.contains_key(id));
            }
            other => panic!("unknown oracle event {other}"),
        }
    }
    let expected = rows
        .into_iter()
        .map(|(name, (fields, version))| json!({"name":name,"fields":fields,"version":version}))
        .collect::<Vec<_>>();
    assert_eq!(replay["final_rows"], json!(expected));
}

#[test]
fn seed_marker_and_request_ids_are_acyclic_and_exactly_bound() {
    let (selection, core) = fixture();
    let seed = core.seed.digest().unwrap();
    let marker = core.seed.marker().unwrap();
    assert_eq!(marker.seed, seed);
    assert_eq!(marker.schema, core.seed.schema_contract);
    assert_eq!(
        core.counter.bootstrap().manifest.marker,
        marker.digest().unwrap()
    );
    assert_eq!(
        core.counter.bootstrap().create_operation,
        create_operation(&core.seed.authority, &seed).unwrap()
    );
    let bytes = serde_json::to_value(&core.seed).unwrap();
    for excluded in [
        "marker",
        "operation",
        "receipt",
        "holder",
        "attempt",
        "clock",
        "process_incarnation",
        "after",
    ] {
        assert!(bytes.get(excluded).is_none(), "{excluded}");
    }
    let complete = completion(&core);
    let expected = complete_operation(&complete.counter, &seed).unwrap();
    let mut changed = complete.counter.clone();
    let Request::CompleteInitialFirstActivation { operation, .. } = &mut changed else {
        unreachable!()
    };
    *operation = Digest::new(b"self-id-must-not-feed-back");
    assert_eq!(complete_operation(&changed, &seed).unwrap(), expected);
    assert!(
        LogicalCore::new(&selection, core.policy.clone(), core.seed.clone(), &changed).is_err()
    );
    let mut replaced = core.clone();
    let Request::CreateInitialAuthority { bootstrap } = &mut replaced.counter else {
        unreachable!()
    };
    bootstrap.manifest.marker = Digest::new(b"copied-marker");
    replaced.canonical_counter = serde_json::to_string(&replaced.counter).unwrap();
    replaced.request_digest = replaced.counter.digest().unwrap();
    assert!(replaced.validate(&selection).is_err());
    let mut generated = serde_json::to_value(&core.policy).unwrap();
    generated
        .as_object_mut()
        .unwrap()
        .insert("seed".into(), json!(seed));
    assert!(
        crate::json::decode::<InitialBootstrapPolicy>(&serde_json::to_vec(&generated).unwrap())
            .is_err()
    );
}

#[test]
fn complete_reservation_never_replaces_the_original_app_candidate_or_key() {
    let (selection, create) = fixture();
    let core = completion(&create);
    let original = Slot::prepared(core.clone());
    let mut provider = Provider::open(":memory:");
    provider
        .apply(&codec::create_data(&selection, &original).unwrap(), true)
        .unwrap_err();
    let mut replacement = core.clone();
    let Request::CompleteInitialFirstActivation { holder, .. } = &mut replacement.counter else {
        unreachable!()
    };
    holder.process_incarnation = Digest::new(b"replacement-process");
    holder.ephemeral_key = Digest::new(b"replacement-key");
    let id = complete_operation(&replacement.counter, &replacement.seed.digest().unwrap()).unwrap();
    let Request::CompleteInitialFirstActivation { operation, .. } = &mut replacement.counter else {
        unreachable!()
    };
    *operation = id;
    replacement.canonical_counter = serde_json::to_string(&replacement.counter).unwrap();
    replacement.request_digest = replacement.counter.digest().unwrap();
    let name = codec::name(&selection, &core).unwrap();
    assert_eq!(codec::name(&selection, &replacement).unwrap(), name);
    assert!(
        provider
            .apply(
                &codec::create_data(&selection, &Slot::prepared(replacement.clone())).unwrap(),
                false
            )
            .is_err()
    );
    let before = codec::decode(&selection, &core, &provider.read(&name)).unwrap();
    assert_eq!(before.slot, original);
    assert!(codec::decode(&selection, &replacement, &provider.read(&name)).is_err());
    let changed = Slot::prepared(replacement);
    assert!(codec::cas_data(&selection, &before, &changed).is_err());
    provider.persist("permanent-complete-candidate");
    replay_provider(&provider.replay());
}

#[test]
fn control_slot_exit_child() {
    let Ok(path) = std::env::var("DAY2_CONTROL_SLOT_EXIT_PATH") else {
        return;
    };
    let point = std::env::var("DAY2_CONTROL_SLOT_EXIT_POINT").unwrap();
    let payload = std::fs::read(std::env::var("DAY2_CONTROL_SLOT_EXIT_WRITE").unwrap()).unwrap();
    let write: Value = crate::json::decode(&payload).unwrap();
    let mut provider = Provider::open(path);
    provider.fault = match point.as_str() {
        "before_mutation" => ExitPoint::BeforeMutation,
        "before_commit" => ExitPoint::BeforeCommit,
        "after_commit" => ExitPoint::AfterCommit,
        _ => panic!("unexpected controlled exit point"),
    };
    provider.apply(&write, false).unwrap();
    panic!("controlled process exit did not occur");
}

#[test]
fn actual_process_exit_keeps_dispatch_and_atomic_claim_for_both_stages() {
    let (selection, create) = fixture();
    let complete = completion(&create);
    for core in [&create, &complete] {
        for point in ["before_mutation", "before_commit", "after_commit"] {
            let temporary = tempfile::tempdir().unwrap();
            let path = temporary.path().join("oracle.sqlite");
            let mut provider = Provider::open(&path);
            let prepared = Slot::prepared(core.clone());
            provider
                .apply(&codec::create_data(&selection, &prepared).unwrap(), false)
                .unwrap();
            let name = codec::name(&selection, core).unwrap();
            let before = codec::decode(&selection, core, &provider.read(&name)).unwrap();
            let claim = prepared
                .claim_data(
                    &selection,
                    &before.version,
                    attempt(
                        core,
                        before.version.clone(),
                        AttemptOrdinal::first(),
                        b"original-attempt",
                    ),
                )
                .unwrap();
            let write = codec::cas_data(&selection, &before, &claim).unwrap();
            let write_path = temporary.path().join("request.json");
            std::fs::write(&write_path, serde_json::to_vec(&write).unwrap()).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "security_epoch::control_slot_tests::control_slot_exit_child",
                    "--nocapture",
                ])
                .env("DAY2_CONTROL_SLOT_EXIT_PATH", &path)
                .env("DAY2_CONTROL_SLOT_EXIT_WRITE", &write_path)
                .env("DAY2_CONTROL_SLOT_EXIT_POINT", point)
                .status()
                .unwrap();
            let replay = provider.replay();
            provider.persist(&format!("process-exit-{point}"));
            assert_eq!(status.code(), Some(86));
            let after = codec::decode(&selection, core, &provider.read(&name)).unwrap();
            if point == "after_commit" {
                assert_eq!(after.slot, claim);
                assert_eq!(after.version, version(2));
                assert!(
                    after
                        .slot
                        .claim_data(
                            &selection,
                            &after.version,
                            attempt(
                                core,
                                after.version.clone(),
                                AttemptOrdinal::first(),
                                b"replacement"
                            )
                        )
                        .is_err()
                );
            } else {
                assert_eq!(after.slot, prepared);
                assert_eq!(after.version, version(1));
            }
            assert_eq!(
                replay["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|e| e["kind"] == "dispatch")
                    .count(),
                2
            );
            assert_eq!(
                replay["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|e| e["kind"] == "provider_commit")
                    .count(),
                if point == "after_commit" { 2 } else { 1 }
            );
            replay_provider(&replay);
        }
    }
}

use super::{
    control_slot_io as guarded,
    firestore::{self, Budget, EpochReply, Port, Sample},
    journal::{CurrentBootstrapExecution, Purpose},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimReply {
    Known,
    LostAfterCommit,
    MalformedAfterCommit,
    ExpiredAfterCommit,
}

struct SharedPort {
    counter: tests::Provider,
    slots: Provider,
    claim_reply: ClaimReply,
    slot_posts: usize,
    counter_posts: usize,
    retained_counter_owner: Option<std::rc::Weak<()>>,
    expire_after_counter_commit: bool,
    lose_counter_reply: bool,
}

impl SharedPort {
    /// New model transport only; preserve the independent slot/counter state,
    /// permanent May record and complete send observations.
    fn reopen_model_transport(self) -> Self {
        Self { counter: self.counter.reopen_model_transport(), ..self }
    }

    fn new() -> Self {
        Self {
            counter: tests::Provider::new(),
            slots: Provider::open(":memory:"),
            claim_reply: ClaimReply::Known,
            slot_posts: 0,
            counter_posts: 0,
            retained_counter_owner: None,
            expire_after_counter_commit: false,
            lose_counter_reply: false,
        }
    }

    fn evidence(
        &mut self,
        selection: &EpochStore,
        core: &LogicalCore,
        purpose: Purpose,
    ) -> (
        firestore::EpochObservation,
        guarded::SlotObservation,
        CurrentBootstrapExecution<'static, 'static>,
    ) {
        let counter = self.counter.observe(&core.counter).unwrap();
        let context = CurrentBootstrapExecution::fixture(
            selection,
            &core.counter,
            counter.snapshot(),
            purpose,
            self.sample().unwrap(),
        )
        .unwrap();
        let sample = self.sample().unwrap();
        let budget = Budget::for_context(sample, Duration::from_secs(105)).unwrap();
        let slot = guarded::read_with_budget(selection, core, self, budget).unwrap();
        (counter, slot, context)
    }

    fn pending(&mut self, selection: &EpochStore, core: &LogicalCore) {
        let body = firestore::commit_body(selection, &core.counter).unwrap();
        // Provider-side setup, not a native dispatch or an admitted port call.
        self.post_wire("https://firestore.googleapis.com/v1/projects/project-seven/databases/security/documents:commit", &body, Duration::from_secs(5), 65_536).unwrap();
    }
}

impl SharedPort {
    fn post_wire(
        &mut self,
        url: &str,
        body: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        ensure!(url.starts_with("https://firestore.googleapis.com/v1/projects/project-seven/databases/security/documents:"),"oracle fixed endpoint");
        ensure!(
            body.len() <= 65_536
                && max_bytes == 65_536
                && !timeout.is_zero()
                && timeout <= Duration::from_secs(5),
            "oracle bounded request"
        );
        let value: Value = crate::json::decode(body)?;
        if url.ends_with(":rollback") && value == json!({"transaction":"c2xvdC10eG4="}) {
            return Ok(EpochReply {
                status: 200,
                body: b"{}".to_vec(),
            });
        }
        if url.ends_with(":batchGet")
            && value["documents"][0]
                .as_str()
                .is_some_and(|name| name.contains("/day2_credential_control_v1/"))
        {
            ensure!(
                value["documents"].as_array().unwrap().len() == 1
                    && value["newTransaction"] == json!({"readOnly":{}}),
                "oracle exact slot read"
            );
            let name = value["documents"][0].as_str().unwrap();
            let found: bool = self.slots.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM slots WHERE name=?1)",
                [name],
                |r| r.get(0),
            )?;
            let mut entry = if found {
                json!({"found":serde_json::from_slice::<Value>(&self.slots.read(name))?})
            } else {
                json!({"missing":name})
            };
            entry["readTime"] = json!("2026-10-14T00:00:00.000010Z");
            return Ok(EpochReply {
                status: 200,
                body: serde_json::to_vec(&json!([{"transaction":"c2xvdC10eG4="},entry]))?,
            });
        }
        if url.ends_with(":commit")
            && value["writes"]
                .as_array()
                .is_some_and(|writes| writes.len() == 1)
        {
            self.slot_posts += 1;
            let write = &value["writes"][0];
            let reply = self.claim_reply;
            self.claim_reply = ClaimReply::Known;
            self.slots
                .apply(write, reply == ClaimReply::LostAfterCommit)?;
            let name = write["update"]["name"]
                .as_str()
                .context("oracle slot name")?;
            let document: Value = serde_json::from_slice(&self.slots.read(name))?;
            if reply == ClaimReply::ExpiredAfterCommit {
                self.counter.set_slot_fixture_time(Duration::from_secs(105));
            }
            let body = if reply == ClaimReply::MalformedAfterCommit {
                b"{}".to_vec()
            } else {
                serde_json::to_vec(
                    &json!({"writeResults":[{"updateTime":document["updateTime"]}],"commitTime":document["updateTime"]}),
                )?
            };
            return Ok(EpochReply { status: 200, body });
        }
        if url.ends_with(":commit") {
            self.counter_posts += 1;
            if let Some(owner) = &self.retained_counter_owner {
                ensure!(
                    owner.upgrade().is_some(),
                    "counter execution owner dropped before transport"
                );
            }
        }
        let reply = self.counter.post_wire(url, body, timeout, max_bytes)?;
        if url.ends_with(":commit") {
            if self.expire_after_counter_commit {
                self.counter.set_slot_fixture_time(Duration::from_secs(105));
            }
            ensure!(!self.lose_counter_reply, "counter reply lost after commit");
        }
        Ok(reply)
    }
}

impl Port for SharedPort {
    fn sample(&mut self) -> Result<Sample> {
        self.counter.sample()
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        let timeout = budget.remaining(self)?.min(Duration::from_secs(5));
        self.post_wire(url, body, timeout, max_bytes)
    }

    fn refuse(&mut self) {
        self.counter.refuse();
    }
}

#[test]
fn counter_send_keeps_the_known_claim_owner_through_transport_and_releases_on_every_result() {
    let (selection, create) = fixture();
    let complete = completion(&create);
    for core in [&create, &complete] {
        for outcome in ["known", "expired", "lost"] {
            let mut port = SharedPort::new();
            if core.stage == Stage::Complete {
                port.pending(&selection, &create);
            }
            let baseline = port.counter_posts;
            let (counter, slot, context) = port.evidence(&selection, core, Purpose::Dispatch);
            guarded::accept(&selection, core.clone(), counter, slot, context, &mut port)
                .unwrap()
                .send(&selection, &mut port)
                .unwrap();
            let (counter, slot, mut context) = port.evidence(&selection, core, Purpose::Dispatch);
            let retained = context.observe_fixture_lifetime();
            port.retained_counter_owner = Some(retained.clone());
            let before = codec::decode(
                &selection,
                core,
                &port.slots.read(&codec::name(&selection, core).unwrap()),
            )
            .unwrap();
            let claim = guarded::claim(
                &selection,
                core.clone(),
                counter,
                slot,
                context,
                attempt(
                    core,
                    before.version,
                    AttemptOrdinal::first(),
                    b"retained-owner",
                ),
                &mut port,
            )
            .unwrap()
            .send(&selection, &mut port)
            .unwrap();
            assert!(retained.upgrade().is_some());
            port.expire_after_counter_commit = outcome == "expired";
            port.lose_counter_reply = outcome == "lost";
            let result = claim.send(&selection, &mut port);
            assert_eq!(result.is_ok(), outcome == "known", "{outcome}");
            assert_eq!(port.counter_posts, baseline + 1);
            assert!(retained.upgrade().is_none());
            let stored = codec::decode(
                &selection,
                core,
                &port.slots.read(&codec::name(&selection, core).unwrap()),
            )
            .unwrap();
            assert!(matches!(
                stored.slot.state,
                SlotState::MayHaveBeenSent { .. }
            ));
            // A lost/expired reply does not free the permanent slot or turn
            // its stored state into another local send permission.
            replay_provider(&port.slots.replay());
        }
    }
}

#[test]
fn only_known_current_claim_commit_yields_one_consuming_counter_send() {
    let (selection, create) = fixture();
    let complete = completion(&create);
    for core in [&create, &complete] {
        for reply in [
            ClaimReply::Known,
            ClaimReply::LostAfterCommit,
            ClaimReply::MalformedAfterCommit,
            ClaimReply::ExpiredAfterCommit,
        ] {
            let mut port = SharedPort::new();
            if core.stage == Stage::Complete {
                port.pending(&selection, &create);
            }
            let baseline = port.counter_posts;
            let (counter, slot, context) = port.evidence(&selection, core, Purpose::Dispatch);
            guarded::accept(&selection, core.clone(), counter, slot, context, &mut port)
                .unwrap()
                .send(&selection, &mut port)
                .unwrap();
            let (counter, slot, context) = port.evidence(&selection, core, Purpose::Dispatch);
            let before = codec::decode(
                &selection,
                core,
                &port.slots.read(&codec::name(&selection, core).unwrap()),
            )
            .unwrap();
            let mutation = guarded::claim(
                &selection,
                core.clone(),
                counter,
                slot,
                context,
                attempt(core, before.version, AttemptOrdinal::first(), b"original"),
                &mut port,
            )
            .unwrap();
            port.claim_reply = reply;
            let result = mutation.send(&selection, &mut port);
            if reply == ClaimReply::Known {
                result.unwrap().send(&selection, &mut port).unwrap();
                assert_eq!(port.counter_posts, baseline + 1);
            } else {
                assert!(result.is_err());
                assert_eq!(port.counter_posts, baseline);
            }
            port.slots.persist("guarded-claim-outcome");
            replay_provider(&port.slots.replay());
        }
    }
}

#[test]
fn matching_stored_may_and_rearm_ack_never_reconstruct_counter_send_authority() {
    let (selection, core) = fixture();
    let mut port = SharedPort::new();
    let (counter, slot, context) = port.evidence(&selection, &core, Purpose::Dispatch);
    guarded::accept(&selection, core.clone(), counter, slot, context, &mut port)
        .unwrap()
        .send(&selection, &mut port)
        .unwrap();
    let name = codec::name(&selection, &core).unwrap();
    let before = codec::decode(&selection, &core, &port.slots.read(&name)).unwrap();
    let (counter, slot, context) = port.evidence(&selection, &core, Purpose::Dispatch);
    let mutation = guarded::claim(
        &selection,
        core.clone(),
        counter,
        slot,
        context,
        attempt(&core, before.version, AttemptOrdinal::first(), b"original"),
        &mut port,
    )
    .unwrap();
    port.claim_reply = ClaimReply::LostAfterCommit;
    assert!(mutation.send(&selection, &mut port).is_err());
    assert_eq!(port.counter_posts, 0);
    let may = codec::decode(&selection, &core, &port.slots.read(&name)).unwrap();
    port = port.reopen_model_transport();
    let (counter, slot, context) = port.evidence(&selection, &core, Purpose::Dispatch);
    assert!(
        guarded::claim(
            &selection,
            core.clone(),
            counter,
            slot,
            context,
            attempt(
                &core,
                may.version.clone(),
                AttemptOrdinal::first(),
                b"replacement"
            ),
            &mut port
        )
        .is_err()
    );
    let SlotState::MayHaveBeenSent { attempt: previous } = &may.slot.state else {
        unreachable!()
    };
    let (counter, slot, context) = port.evidence(&selection, &core, Purpose::Reconcile);
    let rearm = RearmCore {
        logical: core.digest().unwrap(),
        request: core.request_digest.clone(),
        previous: previous.id.clone(),
        expected: may.version,
        not_applied_observation: super::journal::snapshot_digest(counter.snapshot()).unwrap(),
        next: previous.core.ordinal.next().unwrap(),
    };
    guarded::rearm(
        &selection,
        core.clone(),
        counter,
        slot,
        context,
        rearm,
        &mut port,
    )
    .unwrap()
    .send(&selection, &mut port)
    .unwrap();
    assert_eq!(port.counter_posts, 0);
    let retry = codec::decode(&selection, &core, &port.slots.read(&name)).unwrap();
    let (counter, slot, context) = port.evidence(&selection, &core, Purpose::Dispatch);
    let mutation = guarded::claim(
        &selection,
        core.clone(),
        counter,
        slot,
        context,
        attempt(
            &core,
            retry.version,
            AttemptOrdinal::first().next().unwrap(),
            b"explicit-next",
        ),
        &mut port,
    )
    .unwrap();
    mutation
        .send(&selection, &mut port)
        .unwrap()
        .send(&selection, &mut port)
        .unwrap();
    assert_eq!(port.counter_posts, 1);
    port.slots.persist("guarded-explicit-rearm");
    replay_provider(&port.slots.replay());
}

#[test]
fn lost_original_creator_fixture_refuses_even_absent_reservation_and_known_claim() {
    let (selection, core) = fixture();
    let mut port = SharedPort::new();
    let (counter, slot, mut context) = port.evidence(&selection, &core, Purpose::Dispatch);
    context.lose_original_creator_fixture();
    assert!(guarded::accept(&selection, core.clone(), counter, slot, context, &mut port).is_err());
    assert_eq!(port.slot_posts, 0);
    assert_eq!(port.counter_posts, 0);
    let (counter, slot, context) = port.evidence(&selection, &core, Purpose::Dispatch);
    guarded::accept(&selection, core.clone(), counter, slot, context, &mut port)
        .unwrap()
        .send(&selection, &mut port)
        .unwrap();
    let name = codec::name(&selection, &core).unwrap();
    let before = codec::decode(&selection, &core, &port.slots.read(&name)).unwrap();
    let (counter, slot, mut context) = port.evidence(&selection, &core, Purpose::Dispatch);
    context.lose_original_creator_fixture();
    assert!(
        guarded::claim(
            &selection,
            core.clone(),
            counter,
            slot,
            context,
            attempt(
                &core,
                before.version.clone(),
                AttemptOrdinal::first(),
                b"denied"
            ),
            &mut port
        )
        .is_err()
    );
    assert_eq!(port.slot_posts, 1);
    let (counter, slot, context) = port.evidence(&selection, &core, Purpose::Dispatch);
    let mutation = guarded::claim(
        &selection,
        core.clone(),
        counter,
        slot,
        context,
        attempt(&core, before.version, AttemptOrdinal::first(), b"current"),
        &mut port,
    )
    .unwrap();
    let claim = mutation.send(&selection, &mut port).unwrap();
    port.counter.set_slot_fixture_time(Duration::from_secs(105));
    assert!(claim.send(&selection, &mut port).is_err());
    assert_eq!(port.counter_posts, 0);
    port.slots.persist("guarded-creator-loss-and-expiry");
    replay_provider(&port.slots.replay());
    // These are controlled context invalidation/expiry tests. Actual original
    // FD loss/P3 durability remain the separate native producer's qualification.
}

#[test]
fn boxed_observed_receipts_keep_exact_unboxed_wire_bytes_for_both_stages() {
    #[derive(serde::Serialize)]
    struct ObservedWire<'a> {
        state: &'static str,
        control_lineage: &'a Attempt,
        receipt: &'a super::kernel::Receipt,
        settlement: &'a Settlement,
    }
    let (selection, create) = fixture();
    let complete = completion(&create);
    for core in [&create, &complete] {
        let prepared = Slot::prepared(core.clone());
        let may = prepared
            .claim_data(
                &selection,
                &version(1),
                attempt(core, version(1), AttemptOrdinal::first(), b"wire-fixture"),
            )
            .unwrap();
        let SlotState::MayHaveBeenSent { attempt: lineage } = &may.state else {
            unreachable!()
        };
        let receipt = core.counter.receipt().unwrap();
        let settled = may
            .settle_data(
                &selection,
                &version(2),
                SettlementCore {
                    logical: core.digest().unwrap(),
                    expected: version(2),
                    control_attempt: lineage.id.clone(),
                    receipt: receipt.digest().unwrap(),
                },
                receipt,
            )
            .unwrap();
        let SlotState::Observed {
            control_lineage,
            receipt,
            settlement,
        } = &settled.state
        else {
            unreachable!()
        };
        let expected = serde_json::to_vec(&ObservedWire {
            state: "observed",
            control_lineage,
            receipt: receipt.as_ref(),
            settlement,
        })
        .unwrap();
        assert_eq!(serde_json::to_vec(&settled.state).unwrap(), expected);
        assert_eq!(
            crate::json::decode::<SlotState>(&expected).unwrap(),
            settled.state
        );
    }
}
