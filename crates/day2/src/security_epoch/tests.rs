//! Native protocol conformance, with an independently conditional SQLite provider
//! model. No Google requests or serving-build execution context is available.
use super::{
    firestore::{self, Names, Port, Response, Sample},
    journal::{CurrentBootstrapExecution, Journal, Purpose},
    kernel::*,
};
use anyhow::{Context, Result, bail, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, VecDeque},
    path::Path,
    time::Duration,
};

fn selection() -> EpochStore {
    serde_json::from_value(json!({
        "scope":{"installation":"company","environment":"canary","app":"calendar"},
        "provider":{"kind":"firestore_native_v1","project":"project-seven","project_number":7,
            "database":"security","database_uid":"01234567-89ab-4cde-8fab-0123456789ab",
            "iam_source":{"kind":"gke_workload_identity_v1","service_account":"epoch@project-seven.iam.gserviceaccount.com"}},
        "key_set":Digest::new(b"keys"),"max_lease_seconds":5
    })).unwrap()
}

fn create() -> Request {
    let selected = selection();
    Request::CreateInitialAuthority {
        bootstrap: Bootstrap {
            authority: selected.authority_key().unwrap(),
            scope: selected.scope,
            project_number: "7".into(),
            database_uid: "01234567-89ab-4cde-8fab-0123456789ab".into(),
            record_incarnation: Digest::new(b"record"),
            key_set: selected.key_set,
            policy: Digest::new(b"policy"),
            controller_role: Digest::new(b"controller"),
            create_operation: Digest::new(b"create-op"),
            manifest: Manifest {
                activation: Digest::new(b"activation"),
                database_incarnation: Digest::new(b"fresh-db"),
                provider_volume_uid: "projects/p/zones/z/disks/fresh-volume-uid".into(),
                mount_binding: Digest::new(b"mount"),
                schema: Digest::new(b"schema"),
                marker: Digest::new(b"marker"),
                artifact: Digest::new(b"artifact"),
                app_workload: Digest::new(b"app"),
            },
        },
    }
}

fn activation(create: &Request, pending: &Snapshot) -> Request {
    Request::CompleteInitialFirstActivation {
        bootstrap: create.bootstrap().clone(),
        operation: Digest::new(b"activate-op"),
        parent_receipt: create.receipt().unwrap().digest().unwrap(),
        before: Versions {
            root: pending.root.as_ref().unwrap().version.clone(),
            sentinel: pending.sentinel.as_ref().unwrap().version.clone(),
        },
        holder: Holder {
            principal: Digest::new(b"app-principal"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"process-A"),
            ephemeral_key: Digest::new(b"key-A"),
        },
    }
}

fn context(request: &Request, snapshot: &Snapshot, purpose: Purpose) -> CurrentBootstrapExecution {
    CurrentBootstrapExecution::fixture(
        &selection(),
        request,
        snapshot,
        purpose,
        Sample {
            domain: Digest::new(b"controller-process-clock"),
            elapsed: Duration::from_secs(100),
        },
    )
    .unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    LoseBefore,
    LoseAfter,
    BadAck,
    FailAfterTwo,
    ExitAfterTwo,
    ExitAfterCommit,
}

struct Provider {
    db: Connection,
    fault: Fault,
    tick: Duration,
    samples: VecDeque<(Digest, Duration)>,
    read_override: Option<Vec<u8>>,
    calls: Vec<(String, Value, Duration)>,
}

fn timestamp(version: i64) -> String {
    format!("2026-10-14T00:00:00.{version:06}Z")
}

impl Provider {
    fn open(path: impl AsRef<Path>) -> Self {
        Self::from_db(Connection::open(path).unwrap())
    }

    fn new() -> Self {
        Self::from_db(Connection::open_in_memory().unwrap())
    }

    fn from_db(db: Connection) -> Self {
        db.execute_batch("CREATE TABLE IF NOT EXISTS documents(name TEXT PRIMARY KEY,fields TEXT NOT NULL,version INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS sends(id INTEGER PRIMARY KEY);").unwrap();
        Self {
            db,
            fault: Fault::None,
            tick: Duration::from_secs(100),
            samples: VecDeque::new(),
            read_override: None,
            calls: Vec::new(),
        }
    }

    fn read(&mut self, request: &Request) -> Result<Snapshot> {
        let active = match request {
            Request::CompleteInitialFirstActivation { operation, .. } => Some(operation),
            _ => None,
        };
        let names = Names::new(&selection(), request.bootstrap(), active)?;
        firestore::read(self, &names)
    }

    fn sends(&self) -> i64 {
        self.db
            .query_row("SELECT COUNT(*) FROM sends", [], |row| row.get(0))
            .unwrap()
    }

    fn documents(&self) -> i64 {
        self.db
            .query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))
            .unwrap()
    }

    // This oracle interprets provider preconditions independently. It never
    // calls Request::records, reconcile or the production Firestore field codec.
    fn apply(&mut self, body: &Value) -> Result<Vec<u8>> {
        self.db.execute("INSERT INTO sends DEFAULT VALUES", [])?;
        if self.fault == Fault::LoseBefore {
            bail!("scripted request loss");
        }
        let writes = body["writes"].as_array().context("writes")?;
        ensure!(
            body.as_object().unwrap().len() == 1 && writes.len() == 3,
            "closed commit"
        );
        let tx = self.db.transaction()?;
        let next: i64 = tx.query_row(
            "SELECT COALESCE(MAX(version),0)+1 FROM documents",
            [],
            |row| row.get(0),
        )?;
        let mut names = BTreeSet::new();
        for (index, write) in writes.iter().enumerate() {
            ensure!(
                write.as_object().unwrap().len() == 2,
                "no transform/delete/mask"
            );
            let document = write["update"].as_object().context("document")?;
            ensure!(document.len() == 2, "closed write document");
            let name = document["name"].as_str().context("name")?;
            ensure!(names.insert(name), "no duplicate writes");
            let current: Option<i64> = tx
                .query_row(
                    "SELECT version FROM documents WHERE name=?1",
                    [name],
                    |row| row.get(0),
                )
                .optional()?;
            let precondition = write["currentDocument"]
                .as_object()
                .context("precondition")?;
            ensure!(precondition.len() == 1, "single condition");
            match (precondition.get("exists"), precondition.get("updateTime")) {
                (Some(Value::Bool(false)), None) => ensure!(current.is_none(), "already exists"),
                (None, Some(Value::String(expected))) => ensure!(
                    current.is_some_and(|value| timestamp(value) == *expected),
                    "CAS conflict"
                ),
                _ => bail!("unsafe condition"),
            }
            tx.execute("INSERT INTO documents(name,fields,version) VALUES(?1,?2,?3) ON CONFLICT(name) DO UPDATE SET fields=excluded.fields,version=excluded.version",params![name,serde_json::to_string(&document["fields"] )?,next])?;
            if index == 1 {
                if self.fault == Fault::FailAfterTwo {
                    bail!("scripted mid-commit failure");
                }
                if self.fault == Fault::ExitAfterTwo {
                    std::process::exit(86);
                }
            }
        }
        tx.commit()?;
        if self.fault == Fault::ExitAfterCommit {
            std::process::exit(86);
        }
        if self.fault == Fault::LoseAfter {
            bail!("scripted lost acknowledgement");
        }
        if self.fault == Fault::BadAck {
            return Ok(br#"{"commitTime":"bad"}"#.to_vec());
        }
        Ok(serde_json::to_vec(
            &json!({"writeResults":[{"updateTime":timestamp(next)},{"updateTime":timestamp(next)},{"updateTime":timestamp(next)}],"commitTime":timestamp(next)}),
        )?)
    }

    fn batch(&self, body: &Value) -> Result<Vec<u8>> {
        ensure!(
            body.as_object().unwrap().len() == 2
                && body["newTransaction"] == json!({"readOnly":{}}),
            "only fresh read-only transactions"
        );
        let mut result = vec![json!({"transaction":"dHhuLTE="})];
        for name in body["documents"]
            .as_array()
            .context("documents")?
            .iter()
            .rev()
        {
            let name = name.as_str().context("document name")?;
            let found: Option<(String, i64)> = self
                .db
                .query_row(
                    "SELECT fields,version FROM documents WHERE name=?1",
                    [name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            result.push(if let Some((fields,version))=found {
                json!({"found":{"name":name,"fields":serde_json::from_str::<Value>(&fields)?,"createTime":timestamp(1),"updateTime":timestamp(version)},"readTime":timestamp(100)})
            } else {json!({"missing":name,"readTime":timestamp(100)})});
        }
        Ok(serde_json::to_vec(&result)?)
    }
}

impl Port for Provider {
    fn sample(&mut self) -> Result<Sample> {
        let (domain, elapsed) = self
            .samples
            .pop_front()
            .unwrap_or((Digest::new(b"controller-process-clock"), self.tick));
        Ok(Sample { domain, elapsed })
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Response> {
        ensure!(url.starts_with("https://firestore.googleapis.com/v1/projects/project-seven/databases/security/documents:"),"fixed selected endpoint");
        ensure!(
            body.len() <= 65_536
                && max_bytes == 65_536
                && timeout > Duration::ZERO
                && timeout <= Duration::from_secs(5),
            "bounded transport"
        );
        let value: Value = serde_json::from_slice(body)?;
        self.calls.push((url.into(), value.clone(), timeout));
        let bytes = if url.ends_with(":commit") {
            self.apply(&value)?
        } else if url.ends_with(":batchGet") {
            if let Some(bytes) = self.read_override.take() {
                bytes
            } else {
                self.batch(&value)?
            }
        } else if url.ends_with(":rollback") {
            ensure!(
                value == json!({"transaction":"dHhuLTE="}),
                "exact read transaction"
            );
            b"{}".to_vec()
        } else {
            bail!("unknown endpoint");
        };
        Ok(Response {
            status: 200,
            body: bytes,
        })
    }
}

fn create_pending(
    journal: &mut Journal<'_>,
    provider: &mut Provider,
    request: &Request,
) -> Snapshot {
    let absent = provider.read(request).unwrap();
    journal.accept(&selection(), request).unwrap();
    journal
        .authorize_create(
            &selection(),
            request,
            &absent,
            context(request, &absent, Purpose::Dispatch),
            provider,
        )
        .unwrap()
        .send(&selection(), provider)
        .unwrap();
    let pending = provider.read(request).unwrap();
    assert!(matches!(
        journal
            .reconcile_attempt(
                &selection(),
                request,
                &pending,
                context(request, &pending, Purpose::Reconcile),
                provider
            )
            .unwrap(),
        Outcome::Applied(_)
    ));
    pending
}

#[test]
fn first_activation_has_distinct_cas_receipt_and_permanent_candidate() {
    let mut db = Connection::open_in_memory().unwrap();
    let mut journal = Journal::create(&mut db).unwrap();
    let mut provider = Provider::new();
    let create = create();
    let pending = create_pending(&mut journal, &mut provider, &create);
    let activate = activation(&create, &pending);
    journal.accept(&selection(), &activate).unwrap();
    assert!(
        journal
            .authorize_create(
                &selection(),
                &activate,
                &pending,
                context(&activate, &pending, Purpose::Dispatch),
                &mut provider
            )
            .is_err()
    );
    let canonical = firestore::commit_body(&selection(), &activate).unwrap();
    let wire: Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(
        wire["writes"][0]["currentDocument"],
        json!({"updateTime":timestamp(1)})
    );
    assert_eq!(
        wire["writes"][1]["currentDocument"],
        json!({"updateTime":timestamp(1)})
    );
    assert_eq!(
        wire["writes"][2]["currentDocument"],
        json!({"exists":false})
    );
    assert_eq!(
        wire["writes"][0]["update"]["fields"]["epoch"],
        json!({"stringValue":"1"})
    );
    // Authority/sentinel change together and retain the immutable create receipt.
    journal
        .authorize_activate(
            &selection(),
            &activate,
            &pending,
            context(&activate, &pending, Purpose::Dispatch),
            &mut provider,
        )
        .unwrap()
        .send(&selection(), &mut provider)
        .unwrap();
    let active = provider.read(&activate).unwrap();
    assert!(matches!(
        reconcile(&selection(), &activate, &active).unwrap(),
        Outcome::Applied(_)
    ));
    assert!(matches!(
        reconcile(&selection(), &create, &active).unwrap(),
        Outcome::Applied(_)
    ));
    let before_read = provider.calls.len();
    let recovered_create = provider.read(&create).unwrap();
    assert_eq!(provider.calls.len() - before_read, 4); // discovery+cleanup, full coherent read+cleanup
    assert!(matches!(
        reconcile(&selection(), &create, &recovered_create).unwrap(),
        Outcome::Applied(_)
    ));
    assert_eq!(recovered_create.activate, active.activate);
    // The second acquisition shares the first deadline. A reset would permit
    // another five seconds and incorrectly succeed with the now-105 clock.
    provider.tick = Duration::from_secs(105);
    provider.samples = vec![
        (
            Digest::new(b"controller-process-clock"),
            Duration::from_secs(100)
        );
        7
    ]
    .into();
    let before_read = provider.calls.len();
    assert!(provider.read(&create).is_err());
    assert_eq!(provider.calls.len() - before_read, 2);
    provider.tick = Duration::from_secs(100);
    assert_eq!(
        active.create.as_ref().unwrap().value,
        create.receipt().unwrap()
    );
    assert_eq!(
        active.create.as_ref().unwrap().version,
        pending.create.as_ref().unwrap().version
    );
    assert_eq!(provider.documents(), 4);
    assert_eq!(provider.sends(), 2);
    journal
        .reconcile_attempt(
            &selection(),
            &activate,
            &active,
            context(&activate, &active, Purpose::Reconcile),
            &mut provider,
        )
        .unwrap();
    assert_eq!(journal.state(&activate).unwrap(), ("observed".into(), 1));
    let mut replacement = activate.clone();
    if let Request::CompleteInitialFirstActivation {
        operation, holder, ..
    } = &mut replacement
    {
        *operation = Digest::new(b"replacement");
        holder.process_incarnation = Digest::new(b"process-B");
    }
    assert!(journal.accept(&selection(), &replacement).is_err());
    assert!(reconcile(&selection(), &replacement, &active).is_err());
    assert_eq!(
        canonical,
        firestore::commit_body(&selection(), &activate).unwrap()
    );
    assert_eq!(provider.sends(), 2);
    let names = Names::new(&selection(), create.bootstrap(), Some(activate.operation())).unwrap();
    provider
        .db
        .execute(
            "DELETE FROM documents WHERE name=?1",
            [names.activate.as_ref().unwrap()],
        )
        .unwrap();
    assert!(provider.read(&create).is_err());
    assert!(journal.accept(&selection(), &replacement).is_err());
}

#[test]
fn ambiguous_sends_require_explicit_same_request_reconciliation() {
    for fault in [
        Fault::LoseBefore,
        Fault::LoseAfter,
        Fault::BadAck,
        Fault::FailAfterTwo,
    ] {
        let mut db = Connection::open_in_memory().unwrap();
        let mut provider = Provider::new();
        let request = create();
        let absent = provider.read(&request).unwrap();
        {
            let mut journal = Journal::create(&mut db).unwrap();
            journal.accept(&selection(), &request).unwrap();
            provider.fault = fault;
            let permit = journal
                .authorize_create(
                    &selection(),
                    &request,
                    &absent,
                    context(&request, &absent, Purpose::Dispatch),
                    &mut provider,
                )
                .unwrap();
            assert!(permit.send(&selection(), &mut provider).is_err());
            assert_eq!(
                journal.state(&request).unwrap(),
                ("may_have_been_sent".into(), 1)
            );
        }
        provider.fault = Fault::None;
        let mut journal = Journal::open(&mut db).unwrap();
        let observed = provider.read(&request).unwrap();
        assert!(
            journal
                .authorize_create(
                    &selection(),
                    &request,
                    &absent,
                    context(&request, &absent, Purpose::Dispatch),
                    &mut provider
                )
                .is_err()
        );
        let outcome = journal
            .reconcile_attempt(
                &selection(),
                &request,
                &observed,
                context(&request, &observed, Purpose::Reconcile),
                &mut provider,
            )
            .unwrap();
        let mut other = request.clone();
        if let Request::CreateInitialAuthority { bootstrap } = &mut other {
            bootstrap.create_operation = Digest::new(b"new-ID");
        }
        assert!(journal.accept(&selection(), &other).is_err());
        if fault == Fault::LoseBefore || fault == Fault::FailAfterTwo {
            assert_eq!(outcome, Outcome::NotApplied);
            assert_eq!(provider.documents(), 0);
            journal
                .authorize_create(
                    &selection(),
                    &request,
                    &observed,
                    context(&request, &observed, Purpose::Dispatch),
                    &mut provider,
                )
                .unwrap()
                .send(&selection(), &mut provider)
                .unwrap();
            assert_eq!(provider.sends(), 2);
        } else {
            assert!(matches!(outcome, Outcome::Applied(_)));
            assert_eq!(provider.sends(), 1);
        }
        assert_eq!(provider.documents(), 3);
    }
}

#[test]
fn activation_unknown_never_releases_the_accepted_holder_or_changes_request_bytes() {
    for fault in [
        Fault::LoseBefore,
        Fault::LoseAfter,
        Fault::BadAck,
        Fault::FailAfterTwo,
    ] {
        let mut db = Connection::open_in_memory().unwrap();
        let mut journal = Journal::create(&mut db).unwrap();
        let mut provider = Provider::new();
        let create = create();
        let pending = create_pending(&mut journal, &mut provider, &create);
        let request = activation(&create, &pending);
        journal.accept(&selection(), &request).unwrap();
        let bytes = firestore::commit_body(&selection(), &request).unwrap();
        let mut replacement = request.clone();
        if let Request::CompleteInitialFirstActivation {
            operation, holder, ..
        } = &mut replacement
        {
            *operation = Digest::new(b"takeover");
            holder.process_incarnation = Digest::new(b"different process");
        }
        assert!(journal.accept(&selection(), &replacement).is_err());
        provider.fault = fault;
        let permit = journal
            .authorize_activate(
                &selection(),
                &request,
                &pending,
                context(&request, &pending, Purpose::Dispatch),
                &mut provider,
            )
            .unwrap();
        assert!(permit.send(&selection(), &mut provider).is_err());
        assert_eq!(
            journal.state(&request).unwrap(),
            ("may_have_been_sent".into(), 1)
        );
        assert!(journal.accept(&selection(), &replacement).is_err());
        provider.fault = Fault::None;
        let current = provider.read(&request).unwrap();
        let outcome = journal
            .reconcile_attempt(
                &selection(),
                &request,
                &current,
                context(&request, &current, Purpose::Reconcile),
                &mut provider,
            )
            .unwrap();
        if matches!(fault, Fault::LoseBefore | Fault::FailAfterTwo) {
            assert_eq!(provider.documents(), 3);
            assert_eq!(outcome, Outcome::NotApplied);
            journal
                .authorize_activate(
                    &selection(),
                    &request,
                    &current,
                    context(&request, &current, Purpose::Dispatch),
                    &mut provider,
                )
                .unwrap()
                .send(&selection(), &mut provider)
                .unwrap();
            assert_eq!(provider.sends(), 3);
        } else {
            assert_eq!(provider.sends(), 2);
            assert!(matches!(outcome, Outcome::Applied(_)));
        }
        assert_eq!(provider.documents(), 4);
        assert_eq!(
            bytes,
            firestore::commit_body(&selection(), &request).unwrap()
        );
        assert!(journal.accept(&selection(), &replacement).is_err());
        // A historical create receipt proves creation, never first activation.
        assert_eq!(create.receipt().unwrap().request, create);
        assert_ne!(
            create.receipt().unwrap().request_digest,
            request.receipt().unwrap().request_digest
        );
    }
}

#[test]
fn either_conditional_record_conflict_aborts_the_entire_activation() {
    for conflict in ["root", "sentinel"] {
        let mut db = Connection::open_in_memory().unwrap();
        let mut journal = Journal::create(&mut db).unwrap();
        let mut provider = Provider::new();
        let create = create();
        let pending = create_pending(&mut journal, &mut provider, &create);
        let request = activation(&create, &pending);
        journal.accept(&selection(), &request).unwrap();
        let permit = journal
            .authorize_activate(
                &selection(),
                &request,
                &pending,
                context(&request, &pending, Purpose::Dispatch),
                &mut provider,
            )
            .unwrap();
        let names = Names::new(&selection(), create.bootstrap(), None).unwrap();
        let name = if conflict == "root" {
            &names.root
        } else {
            &names.sentinel
        };
        provider
            .db
            .execute(
                "UPDATE documents SET version=version+1 WHERE name=?1",
                [name],
            )
            .unwrap();
        assert!(permit.send(&selection(), &mut provider).is_err());
        assert_eq!(provider.documents(), 3);
        let snapshot = provider.read(&request).unwrap();
        assert!(reconcile(&selection(), &request, &snapshot).is_err());
        assert!(matches!(
            snapshot.root.unwrap().value.phase,
            Phase::PendingFirstHolder
        ));
        assert!(matches!(
            snapshot.sentinel.unwrap().value.phase,
            Phase::PendingFirstHolder
        ));
        assert_eq!(
            journal.state(&request).unwrap(),
            ("may_have_been_sent".into(), 1)
        );
    }
}

#[test]
fn independent_controller_connections_accept_only_one_first_holder() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.sqlite");
    let mut db = Connection::open(&path).unwrap();
    let mut journal = Journal::create(&mut db).unwrap();
    let mut provider = Provider::new();
    let create = create();
    let pending = create_pending(&mut journal, &mut provider, &create);
    let first = activation(&create, &pending);
    let mut second = first.clone();
    if let Request::CompleteInitialFirstActivation {
        operation, holder, ..
    } = &mut second
    {
        *operation = Digest::new(b"other-controller-op");
        holder.process_incarnation = Digest::new(b"other-app-process");
    }
    drop(db);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for request in [first, second] {
        let path = path.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut db = Connection::open(path).unwrap();
            db.busy_timeout(Duration::from_secs(2)).unwrap();
            let mut journal = Journal::open(&mut db).unwrap();
            barrier.wait();
            journal.accept(&selection(), &request).is_ok()
        }));
    }
    let accepted = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(accepted, 1);
    let db = Connection::open(path).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM external_epoch_operations WHERE stage='activate'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn clock_domain_rewind_expiry_and_selection_changes_refuse_before_send() {
    for fault in 0..5 {
        let mut db = Connection::open_in_memory().unwrap();
        let mut journal = Journal::create(&mut db).unwrap();
        let mut provider = Provider::new();
        let request = create();
        let absent = provider.read(&request).unwrap();
        journal.accept(&selection(), &request).unwrap();
        let permit = journal
            .authorize_create(
                &selection(),
                &request,
                &absent,
                context(&request, &absent, Purpose::Dispatch),
                &mut provider,
            )
            .unwrap();
        let mut selected = selection();
        match fault {
            0 => provider.tick = Duration::from_secs(99),
            1 => provider.tick = Duration::from_secs(105),
            2 => provider
                .samples
                .push_back((Digest::new(b"different-process"), Duration::from_secs(100))),
            3 => selected.max_lease_seconds = 4,
            _ => {
                provider.samples.push_back((
                    Digest::new(b"controller-process-clock"),
                    Duration::from_secs(104),
                ));
                provider.samples.push_back((
                    Digest::new(b"controller-process-clock"),
                    Duration::from_secs(105),
                ));
            }
        }
        assert!(permit.send(&selected, &mut provider).is_err());
        assert_eq!(provider.sends(), 0);
        assert_eq!(
            journal.state(&request).unwrap(),
            ("may_have_been_sent".into(), 1)
        );
    }
}

#[test]
fn mismatched_partial_and_tampered_records_never_recover_a_receipt() {
    let mut db = Connection::open_in_memory().unwrap();
    let mut journal = Journal::create(&mut db).unwrap();
    let mut provider = Provider::new();
    let request = create();
    let pending = create_pending(&mut journal, &mut provider, &request);
    let activate = activation(&request, &pending);
    for fault in 0..9 {
        let mut snapshot = pending.clone();
        match fault {
            0 => snapshot.sentinel = None,
            1 => snapshot.create = None,
            2 => snapshot.root.as_mut().unwrap().value.epoch = 2.try_into().unwrap(),
            3 => {
                snapshot.sentinel.as_mut().unwrap().value.bootstrap.key_set =
                    Digest::new(b"different keys")
            }
            4 => {
                snapshot.create.as_mut().unwrap().value.request_digest =
                    Digest::new(b"tampered request")
            }
            5 => {
                snapshot.create.as_mut().unwrap().value.after_root = Digest::new(b"tampered after")
            }
            6 => {
                snapshot
                    .root
                    .as_mut()
                    .unwrap()
                    .value
                    .bootstrap
                    .manifest
                    .database_incarnation = Digest::new(b"copied db")
            }
            7 => snapshot.sentinel.as_mut().unwrap().version = timestamp(2).try_into().unwrap(),
            _ => {
                snapshot.root.as_mut().unwrap().value.bootstrap.database_uid =
                    "11234567-89ab-4cde-8fab-0123456789ab".into()
            }
        }
        assert!(
            reconcile(&selection(), &activate, &snapshot).is_err(),
            "fault {fault}"
        );
    }
    let mut receipt = serde_json::to_value(request.receipt().unwrap()).unwrap();
    receipt["request"]["advance"] = json!(true);
    assert!(serde_json::from_value::<Receipt>(receipt).is_err());
    let mut root = serde_json::to_value(pending.root.as_ref().unwrap().value.clone()).unwrap();
    root["epoch"] = json!("01");
    assert!(serde_json::from_value::<AuthorityRecord>(root).is_err());
    for value in ["0", "-1", "+1", "18446744073709551616"] {
        let mut root = serde_json::to_value(pending.root.as_ref().unwrap().value.clone()).unwrap();
        root["epoch"] = json!(value);
        assert!(serde_json::from_value::<AuthorityRecord>(root).is_err());
    }
}

#[test]
fn phase_decoder_rejects_unknown_duplicate_and_nonmap_states() {
    for raw in [
        r#"{"phase":"pending_first_holder","advance":"1"}"#,
        r#"{"phase":"pending_first_holder","completion":{}}"#,
        r#"{"phase":"pending_first_holder","phase":"pending_first_holder"}"#,
        r#"["pending_first_holder"]"#,
        r#"{"phase":["pending_first_holder"]}"#,
        r#"{"phase":"active_first_holder","completion":[]}"#,
        r#"{"phase":"advance"}"#,
    ] {
        assert!(serde_json::from_str::<Phase>(raw).is_err(), "{raw}");
    }
    assert!(
        serde_json::from_value::<Phase>(json!({"phase":"pending_first_holder","advance":"1"}))
            .is_err()
    );
    assert!(serde_json::from_value::<Phase>(json!(["pending_first_holder"])).is_err());
    assert_eq!(
        serde_json::from_value::<Phase>(json!({"phase":"pending_first_holder"})).unwrap(),
        Phase::PendingFirstHolder
    );
    // Exercise the actual Firestore decoder for both lifecycle documents.
    let mut db = Connection::open_in_memory().unwrap();
    let mut journal = Journal::create(&mut db).unwrap();
    let mut provider = Provider::new();
    let create = create();
    create_pending(&mut journal, &mut provider, &create);
    let names = Names::new(&selection(), create.bootstrap(), None).unwrap();
    for name in [&names.root, &names.sentinel] {
        let original: String = provider
            .db
            .query_row(
                "SELECT fields FROM documents WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        let mut fields: Value = serde_json::from_str(&original).unwrap();
        fields["phase"]["mapValue"]["fields"]["advance"] = json!({"stringValue":"1"});
        provider
            .db
            .execute(
                "UPDATE documents SET fields=?2 WHERE name=?1",
                params![name, serde_json::to_string(&fields).unwrap()],
            )
            .unwrap();
        assert!(provider.read(&create).is_err());
        assert!(provider.calls.last().unwrap().0.ends_with(":rollback"));
        provider
            .db
            .execute(
                "UPDATE documents SET fields=?2 WHERE name=?1",
                params![name, original],
            )
            .unwrap();
    }
}

#[test]
fn streamed_parser_is_closed_complete_and_rolls_back_on_semantic_failure() {
    let request = create();
    let names = Names::new(&selection(), request.bootstrap(), None).unwrap();
    let provider = Provider::new();
    let valid: Vec<Value> = serde_json::from_slice(
        &provider
            .batch(&serde_json::from_slice(&names.read_body().unwrap()).unwrap())
            .unwrap(),
    )
    .unwrap();
    for fault in 0..9 {
        let mut entries = valid.clone();
        match fault {
            0 => {
                entries.pop();
            }
            1 => entries[2] = entries[1].clone(),
            2 => {
                entries[1]["missing"] = json!("projects/other/databases/security/documents/root/x")
            }
            3 => entries[1]["transaction"] = json!("dHhuLTE="),
            4 => entries[1]["readTime"] = json!("not-a-time"),
            5 => entries[1]["unexpected"] = json!(true),
            6 => {
                entries[0].as_object_mut().unwrap().remove("transaction");
            }
            7 => entries[0]["transaction"] = json!("not base64"),
            _ => {
                entries[1]["found"] = json!({"name":"wrong","fields":{},"createTime":timestamp(1),"updateTime":timestamp(1)})
            }
        }
        let mut provider = Provider::new();
        provider.read_override = Some(serde_json::to_vec(&entries).unwrap());
        assert!(
            firestore::read(&mut provider, &names).is_err(),
            "fault {fault}"
        );
        // Once a valid transaction is extracted, semantic errors close it.
        if matches!(fault, 0..=4 | 8) {
            assert!(provider.calls.last().unwrap().0.ends_with(":rollback"));
        }
    }
    let mut provider = Provider::new();
    provider.read_override =
        Some(br#"[{"transaction":"dHhuLTE=","\u0074ransaction":"dHhuLTI="}]"#.to_vec());
    assert!(firestore::read(&mut provider, &names).is_err());
    let mut provider = Provider::new();
    provider.read_override = Some(vec![b' '; 65_537]);
    assert!(firestore::read(&mut provider, &names).is_err());
    let mut provider = Provider::new();
    assert!(
        firestore::read(&mut provider, &names)
            .unwrap()
            .root
            .is_none()
    );
    assert_eq!(provider.calls.len(), 2);
    assert!(provider.calls[0].1.get("transaction").is_none());
    assert!(provider.calls[0].1.get("readTime").is_none());
}

#[test]
fn native_process_exit_retains_dispatch_and_provider_atomicity() {
    const CHILD: &str = "DAY2_EPOCH_PROTOCOL_CRASH_CHILD";
    if let Ok(case) = std::env::var(CHILD) {
        let root = std::env::var("DAY2_EPOCH_PROTOCOL_CRASH_ROOT").unwrap();
        let root = Path::new(&root);
        let mut db = Connection::open(root.join("journal.sqlite")).unwrap();
        let mut journal = Journal::create(&mut db).unwrap();
        let mut provider = Provider::open(root.join("provider.sqlite"));
        let request = create();
        let absent = provider.read(&request).unwrap();
        journal.accept(&selection(), &request).unwrap();
        let permit = journal
            .authorize_create(
                &selection(),
                &request,
                &absent,
                context(&request, &absent, Purpose::Dispatch),
                &mut provider,
            )
            .unwrap();
        match case.as_str() {
            "dispatch" => std::process::exit(86),
            "mid-commit" => provider.fault = Fault::ExitAfterTwo,
            "provider-commit" => provider.fault = Fault::ExitAfterCommit,
            "observed" => {}
            _ => panic!("unknown case"),
        };
        permit.send(&selection(), &mut provider).unwrap();
        let snapshot = provider.read(&request).unwrap();
        journal
            .reconcile_attempt(
                &selection(),
                &request,
                &snapshot,
                context(&request, &snapshot, Purpose::Reconcile),
                &mut provider,
            )
            .unwrap();
        std::process::exit(86);
    }
    let temp = tempfile::tempdir().unwrap();
    let result = std::panic::catch_unwind(|| {
        for case in ["dispatch", "mid-commit", "provider-commit", "observed"] {
            let directory = temp.path().join(case);
            std::fs::create_dir(&directory).unwrap();
            let stdout = std::fs::File::create(directory.join("stdout.log")).unwrap();
            let stderr = std::fs::File::create(directory.join("stderr.log")).unwrap();
            let mut child=std::process::Command::new(std::env::current_exe().unwrap()).arg("--exact").arg("security_epoch::tests::native_process_exit_retains_dispatch_and_provider_atomicity").arg("--nocapture").env(CHILD,case).env("DAY2_EPOCH_PROTOCOL_CRASH_ROOT",&directory).stdout(stdout).stderr(stderr).spawn().unwrap();
            let start = std::time::Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if start.elapsed() > Duration::from_secs(30) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("child timed out: {case}");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(86), "{case}");
            let mut db = Connection::open(directory.join("journal.sqlite")).unwrap();
            let mut journal = Journal::open(&mut db).unwrap();
            let mut provider = Provider::open(directory.join("provider.sqlite"));
            let request = create();
            let observed = provider.read(&request).unwrap();
            let committed = matches!(case, "provider-commit" | "observed");
            assert_eq!(provider.documents(), if committed { 3 } else { 0 });
            assert_eq!(provider.sends(), if case == "dispatch" { 0 } else { 1 });
            assert_eq!(
                journal.state(&request).unwrap(),
                (
                    if case == "observed" {
                        "observed"
                    } else {
                        "may_have_been_sent"
                    }
                    .into(),
                    1
                )
            );
            let outcome = journal
                .reconcile_attempt(
                    &selection(),
                    &request,
                    &observed,
                    context(&request, &observed, Purpose::Reconcile),
                    &mut provider,
                )
                .unwrap();
            assert_eq!(matches!(outcome, Outcome::Applied(_)), committed);
            let mut other = request.clone();
            if let Request::CreateInitialAuthority { bootstrap } = &mut other {
                bootstrap.create_operation = Digest::new(b"replacement after crash");
            }
            assert!(journal.accept(&selection(), &other).is_err());
        }
    });
    if let Err(panic) = result {
        let retained = temp.keep();
        eprintln!(
            "retained external epoch crash evidence: {}",
            retained.display()
        );
        std::panic::resume_unwind(panic);
    }
}
