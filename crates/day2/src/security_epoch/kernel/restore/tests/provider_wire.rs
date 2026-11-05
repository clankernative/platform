//! Local wire/SQLite conformance, not a live Firestore or native owner test.
use super::*;
use crate::security_epoch::{firestore::restore as wire, kernel::restore::approval_use as model};
use serde_json::json;

const TX: &str = "cmVzdG9yZS1maXh0dXJl";
const READ: &str = "2026-11-04T00:00:01Z";

fn fields(value: Value) -> Result<Value> {
    let Value::Object(value) = value else {
        anyhow::bail!("fixture_object")
    };
    let mut result = serde_json::Map::new();
    for (key, value) in value {
        result.insert(
            key,
            match value {
                Value::String(text) => json!({"stringValue":text}),
                Value::Object(_) => json!({"mapValue":{"fields":fields(value)?}}),
                _ => anyhow::bail!("fixture_field_type"),
            },
        );
    }
    Ok(Value::Object(result))
}

fn names(selection: &EpochStore, plan: &model::Plan) -> Result<Vec<String>> {
    let request = &plan.reservation.receipt.request;
    let bootstrap = &plan
        .reservation
        .before
        .root
        .as_ref()
        .unwrap()
        .value
        .bootstrap;
    let activation = plan
        .reservation
        .before
        .activate
        .as_ref()
        .unwrap()
        .value
        .request
        .operation();
    let day2_capabilities::security_epoch::EpochProvider::FirestoreNativeV1 {
        project,
        database,
        ..
    } = &selection.provider;
    let root = format!(
        "projects/{}/databases/{}/documents/day2_credential_authority_v1/{}",
        project.as_str(),
        database.as_str(),
        &selection.authority_key()?.as_str()[7..]
    );
    Ok(vec![
        root.clone(),
        format!(
            "projects/{}/databases/{}/documents/day2_credential_bootstrap_v1/{}",
            project.as_str(),
            database.as_str(),
            &selection.authority_key()?.as_str()[7..]
        ),
        format!(
            "{root}/operations/{}",
            &bootstrap.create_operation.as_str()[7..]
        ),
        format!("{root}/operations/{}", &activation.as_str()[7..]),
        format!(
            "{root}/operations/{}",
            &request.intent.advance_operation(selection)?.as_str()[7..]
        ),
        format!(
            "{root}/restore_reservations/{}",
            &request.intent.operation.as_str()[7..]
        ),
        format!(
            "{root}/restore_grants/{}",
            &plan.approval_use.key(selection)?.as_str()[7..]
        ),
    ])
}

fn initial_reply(selection: &EpochStore, plan: &model::Plan) -> Result<Vec<Value>> {
    let names = names(selection, plan)?;
    let snapshot = &plan.reservation.before;
    let mut result = vec![json!({"transaction":TX})];
    let values = [
        serde_json::to_value(&snapshot.root.as_ref().unwrap().value)?,
        serde_json::to_value(&snapshot.sentinel.as_ref().unwrap().value)?,
        serde_json::to_value(&snapshot.create.as_ref().unwrap().value)?,
        serde_json::to_value(&snapshot.activate.as_ref().unwrap().value)?,
    ];
    for (index, value) in values.into_iter().enumerate() {
        result.push(json!({"readTime":READ,"found":{"name":names[index],"fields":fields(value)?,"createTime":version(1),"updateTime":if index==2 {version(1)} else {version(2)}}}));
    }
    for name in &names[4..] {
        result.push(json!({"readTime":READ,"missing":name}));
    }
    Ok(result)
}

fn commit(selection: &EpochStore, plan: &model::Plan, current: &Current) -> Result<Value> {
    let reply = serde_json::to_vec(&initial_reply(selection, plan)?)?;
    let transaction = wire::Names::new(selection, plan)?.transaction(&reply)?;
    assert_eq!(transaction.observed()?.snapshot, plan.reservation.before);
    Ok(crate::json::decode(
        &transaction.commit_body(selection, plan, current, 1000)?,
    )?)
}

#[test]
fn exact_read_write_transaction_and_all_five_writes_pin_scope_and_conditions() -> Result<()> {
    let (selection, before) = initial();
    let (current, plan) = approval_use::plan(&selection, &before, 41)?;
    let selected = wire::Names::new(&selection, &plan)?;
    let read: Value = crate::json::decode(&selected.begin_body()?)?;
    assert_eq!(
        read,
        json!({"documents":names(&selection,&plan)?,"newTransaction":{"readWrite":{}}})
    );
    let strong: Value = crate::json::decode(&selected.strong_body()?)?;
    assert_eq!(strong, json!({"documents":names(&selection,&plan)?}));
    assert!(selected.endpoint("beginTransaction").is_err());
    let value = commit(&selection, &plan, &current)?;
    let mut combined = initial_reply(&selection, &plan)?;
    combined.remove(0);
    combined[0]["transaction"] = json!(TX);
    let transaction =
        wire::Names::new(&selection, &plan)?.transaction(&serde_json::to_vec(&combined)?)?;
    let combined: Value =
        crate::json::decode(&transaction.commit_body(&selection, &plan, &current, 1000)?)?;
    assert_eq!(combined, value);
    assert_eq!(value.as_object().unwrap().len(), 2);
    assert_eq!(value["transaction"], TX);
    let writes = value["writes"].as_array().unwrap();
    assert_eq!(writes.len(), 5);
    let expected = names(&selection, &plan)?;
    for (index, write) in writes.iter().enumerate() {
        assert_eq!(write.as_object().unwrap().len(), 2);
        assert_eq!(write["update"]["name"], expected[[0, 1, 4, 5, 6][index]]);
        assert_eq!(
            write["currentDocument"],
            if index < 2 {
                json!({"updateTime":version(2)})
            } else {
                json!({"exists":false})
            }
        );
        if index >= 2 {
            assert_eq!(write["update"]["fields"].as_object().unwrap().len(), 2);
        }
    }
    let root = &writes[0]["update"]["fields"];
    assert_eq!(root["epoch"]["stringValue"], "2");
    assert_eq!(
        root["phase"]["mapValue"]["fields"]["phase"]["stringValue"],
        "fenced"
    );
    Ok(())
}

#[test]
fn semantic_rejection_keeps_the_canonical_transaction_available_only_for_cleanup() -> Result<()> {
    let (selection, before) = initial();
    let (_, plan) = approval_use::plan(&selection, &before, 42)?;
    let original = initial_reply(&selection, &plan)?;
    for cut in 0..13 {
        let mut reply = original.clone();
        match cut {
            0 => {
                let duplicate = reply[1].clone();
                reply.push(duplicate);
            }
            1 => {
                reply.remove(4);
            }
            2 => {
                reply[1]["found"]["name"] =
                    json!("projects/foreign/databases/foreign/documents/foreign/id")
            }
            3 => reply[1]["missing"] = json!("extra"),
            4 => reply[2]["transaction"] = json!(TX),
            5 => reply[2]["readTime"] = json!("bad"),
            6 => reply[2]["readTime"] = json!("2026-11-03T00:00:01Z"),
            7 => reply[1]["found"]["unexpected"] = json!(true),
            8 => reply[1]["found"]["fields"] = json!([]),
            9 => reply[1]["found"]["fields"]["phase"]["mapValue"] = json!([]),
            10 => reply[0]["readTime"] = json!(READ),
            11 => reply[2]["unexpected"] = json!(true),
            _ => reply[2] = json!([null, null, null, null]),
        }
        // A ninth entry is rejected before any header can be trusted.
        if reply.len() > 8 {
            reply.remove(0);
            reply[0]["transaction"] = json!(TX);
        }
        let transaction =
            wire::Names::new(&selection, &plan)?.transaction(&serde_json::to_vec(&reply)?)?;
        assert!(transaction.observed().is_err(), "cut={cut}");
        let cleanup: Value = crate::json::decode(&transaction.rollback_body()?)?;
        assert_eq!(cleanup, json!({"transaction":TX}));
    }
    for header in ["", "cmVzdG9yZQ", "not base64!", "===="] {
        let mut reply = original.clone();
        reply[0]["transaction"] = json!(header);
        assert!(
            wire::Names::new(&selection, &plan)?
                .transaction(&serde_json::to_vec(&reply)?)
                .is_err()
        );
    }
    assert!(
        wire::Names::new(&selection, &plan)?
            .transaction(br#"[["cmVzdG9yZS1maXh0dXJl",null,null,null]]"#)
            .is_err()
    );
    Ok(())
}

#[test]
fn changed_original_expiry_and_equal_value_rewrites_cannot_prepare_a_send() -> Result<()> {
    let (selection, before) = initial();
    let (current, plan) = approval_use::plan(&selection, &before, 43)?;
    for index in 1..=4 {
        let mut reply = initial_reply(&selection, &plan)?;
        reply[index]["found"]["updateTime"] = json!(version(4));
        let transaction =
            wire::Names::new(&selection, &plan)?.transaction(&serde_json::to_vec(&reply)?)?;
        assert!(
            transaction
                .commit_body(&selection, &plan, &current, 1000)
                .is_err(),
            "row={index}"
        );
    }
    let original = serde_json::to_vec(&initial_reply(&selection, &plan)?)?;
    let transaction = wire::Names::new(&selection, &plan)?.transaction(&original)?;
    assert!(
        transaction
            .commit_body(&selection, &plan, &current, 1005)
            .is_err()
    );
    let cleanup: Value = crate::json::decode(&transaction.rollback_body()?)?;
    assert_eq!(cleanup, json!({"transaction":TX}));
    let (_, other) = approval_use::plan(&selection, &before, 44)?;
    let transaction = wire::Names::new(&selection, &plan)?.transaction(&original)?;
    assert!(
        transaction
            .commit_body(&selection, &other, &current, 1000)
            .is_err()
    );
    Ok(())
}

#[test]
fn all_four_retained_documents_require_update_before_read_and_keep_cleanup_on_refusal() -> Result<()>
{
    let (selection, before) = initial();
    let (current, plan) = approval_use::plan(&selection, &before, 49)?;
    for index in 1..=4 {
        for field in ["updateTime", "createTime"] {
            let mut reply = initial_reply(&selection, &plan)?;
            reply[index]["found"][field] = json!("2026-11-05T00:00:00Z");
            let transaction =
                wire::Names::new(&selection, &plan)?.transaction(&serde_json::to_vec(&reply)?)?;
            assert!(transaction.observed().is_err(), "row={index}field={field}");
            assert!(
                transaction
                    .commit_body(&selection, &plan, &current, 1000)
                    .is_err()
            );
            let cleanup: Value = crate::json::decode(&transaction.rollback_body()?)?;
            assert_eq!(cleanup, json!({"transaction":TX}));
            let strong: Vec<_> = reply.into_iter().skip(1).collect();
            assert!(
                wire::Names::new(&selection, &plan)?
                    .strong(&serde_json::to_vec(&strong)?)
                    .is_err()
            );
        }
    }
    Ok(())
}

fn seed(db: &Connection, reply: &[Value]) -> Result<()> {
    db.execute_batch("CREATE TABLE records(name TEXT PRIMARY KEY,fields TEXT NOT NULL,version TEXT NOT NULL) STRICT")?;
    for entry in reply.iter().skip(1) {
        if let Some(found) = entry.get("found") {
            db.execute(
                "INSERT INTO records VALUES(?1,?2,?3)",
                params![
                    found["name"].as_str(),
                    serde_json::to_string(&found["fields"])?,
                    found["updateTime"].as_str()
                ],
            )?;
        }
    }
    Ok(())
}

fn captured(reply: &[Value]) -> Result<BTreeMap<String, Option<(String, String)>>> {
    let mut result = BTreeMap::new();
    for entry in reply.iter().skip(1) {
        let row = if let Some(found) = entry.get("found") {
            (
                found["name"].as_str().unwrap().to_owned(),
                Some((
                    serde_json::to_string(&found["fields"])?,
                    found["updateTime"].as_str().unwrap().to_owned(),
                )),
            )
        } else {
            (entry["missing"].as_str().unwrap().to_owned(), None)
        };
        assert!(result.insert(row.0, row.1).is_none());
    }
    Ok(result)
}

fn apply_wire(
    db: &mut Connection,
    reads: &BTreeMap<String, Option<(String, String)>>,
    body: &Value,
    cut: usize,
) -> Result<()> {
    ensure!(cut != 0, "controlled_cut");
    ensure!(body["transaction"] == TX, "fixture_transaction");
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for (name, expected) in reads {
        let actual = tx
            .query_row(
                "SELECT fields,version FROM records WHERE name=?1",
                [name],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?;
        ensure!(&actual == expected, "controlled_read_version_conflict");
    }
    let writes = body["writes"].as_array().context("fixture_writes")?;
    ensure!(writes.len() == 5, "fixture_write_count");
    for (index, write) in writes.iter().enumerate() {
        let name = write["update"]["name"].as_str().context("fixture_name")?;
        let payload = serde_json::to_string(&write["update"]["fields"])?;
        if let Some(version) = write["currentDocument"]["updateTime"].as_str() {
            ensure!(
                tx.execute(
                    "UPDATE records SET fields=?1,version=?2 WHERE name=?3 AND version=?4",
                    params![payload, String::from(super::version(3)), name, version]
                )? == 1,
                "fixture_cas"
            );
        } else {
            ensure!(
                write["currentDocument"] == json!({"exists":false}),
                "fixture_create_only"
            );
            tx.execute(
                "INSERT INTO records VALUES(?1,?2,?3)",
                params![name, payload, String::from(super::version(3))],
            )?;
        }
        ensure!(cut != index + 1, "controlled_cut");
    }
    tx.commit()?;
    ensure!(cut != 6, "controlled_unknown_commit");
    Ok(())
}

fn read_back(db: &Connection, names: &[String]) -> Result<Vec<u8>> {
    let mut reply = Vec::new();
    for name in names {
        let row: Option<(String, String)> = db
            .query_row(
                "SELECT fields,version FROM records WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        reply.push(if let Some((fields,version))=row {
            json!({"readTime":READ,"found":{"name":name,"fields":crate::json::decode::<Value>(fields.as_bytes())?,"createTime":super::version(1),"updateTime":version}})
        }else{json!({"readTime":READ,"missing":name})});
    }
    Ok(serde_json::to_vec(&reply)?)
}

#[test]
fn five_wire_write_cuts_and_unknown_completion_reopen_against_independent_expectations_twice()
-> Result<()> {
    for seed_value in 0..4 {
        let (selection, before) = initial();
        let (current, plan) = approval_use::plan(&selection, &before, seed_value)?;
        let reply = initial_reply(&selection, &plan)?;
        let captured = captured(&reply)?;
        let body = commit(&selection, &plan, &current)?;
        let names = names(&selection, &plan)?;
        let mut runs = Vec::new();
        for _ in 0..2 {
            let mut observations = Vec::new();
            for cut in 0..=7 {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("provider.sqlite");
                let mut db = Connection::open(&path)?;
                seed(&db, &reply)?;
                let result = apply_wire(&mut db, &captured, &body, cut);
                assert_eq!(result.is_ok(), cut == 7, "seed={seed_value}cut={cut}");
                drop(db);
                let mut db = Connection::open(&path)?;
                let committed = cut >= 6;
                let count: i64 = db.query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
                assert_eq!(count, if committed { 7 } else { 4 });
                let bytes = read_back(&db, &names)?;
                let observed = wire::Names::new(&selection, &plan)?.strong(&bytes)?;
                assert_eq!(
                    observed.snapshot.root.as_ref().unwrap().value.epoch.value(),
                    if committed { 2 } else { 1 }
                );
                assert_eq!(observed.grant.is_some(), committed);
                let historical = model::reconcile(
                    &selection,
                    &plan,
                    &observed.snapshot,
                    observed.advance.as_ref(),
                    observed.reservation.as_ref(),
                    observed.grant.as_ref(),
                )?;
                assert_eq!(matches!(historical, Outcome::Applied(_)), committed);
                assert_eq!(matches!(historical, Outcome::NotApplied), !committed);
                if committed {
                    assert!(apply_wire(&mut db, &captured, &body, 7).is_err());
                }
                observations.push(bytes);
            }
            runs.push(observations);
        }
        assert_eq!(runs[0], runs[1]);
    }
    Ok(())
}

#[test]
fn every_captured_read_and_absence_is_a_transaction_condition() -> Result<()> {
    let (selection, before) = initial();
    let (current, plan) = approval_use::plan(&selection, &before, 45)?;
    let reply = initial_reply(&selection, &plan)?;
    let reads = captured(&reply)?;
    let body = commit(&selection, &plan, &current)?;
    for (name, old) in &reads {
        let mut db = Connection::open_in_memory()?;
        seed(&db, &reply)?;
        if old.is_some() {
            db.execute(
                "UPDATE records SET version=?1 WHERE name=?2",
                params![String::from(version(4)), name],
            )?;
        } else {
            db.execute(
                "INSERT INTO records VALUES(?1,'{}',?2)",
                params![name, String::from(version(4))],
            )?;
        }
        let baseline: Vec<(String, String, String)> = {
            let mut q = db.prepare("SELECT name,fields,version FROM records ORDER BY name")?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        assert!(apply_wire(&mut db, &reads, &body, 7).is_err());
        let after: Vec<(String, String, String)> = {
            let mut q = db.prepare("SELECT name,fields,version FROM records ORDER BY name")?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        assert_eq!(baseline, after);
    }
    Ok(())
}

#[test]
fn canonical_receipt_envelopes_refuse_mutation_after_known_commit() -> Result<()> {
    let (selection, before) = initial();
    let (current, plan) = approval_use::plan(&selection, &before, 46)?;
    let original = initial_reply(&selection, &plan)?;
    let body = commit(&selection, &plan, &current)?;
    let mut db = Connection::open_in_memory()?;
    seed(&db, &original)?;
    apply_wire(&mut db, &captured(&original)?, &body, 7)?;
    let reply: Value = crate::json::decode(&read_back(&db, &names(&selection, &plan)?)?)?;
    for cut in 0..9 {
        let mut changed = reply.clone();
        match cut {
            0 => {
                changed[6]["found"]["fields"]["restore_digest"]["stringValue"] =
                    json!(Digest::new(b"wrong"))
            }
            1 => {
                let text = changed[6]["found"]["fields"]["restore_json"]["stringValue"]
                    .as_str()
                    .unwrap();
                changed[6]["found"]["fields"]["restore_json"]["stringValue"] =
                    json!(format!(" {text}"));
            }
            2 => changed[6]["found"]["fields"]["extra"] = json!({"stringValue":"unknown"}),
            3 => {
                changed[6]["found"]["fields"]["restore_json"] =
                    json!({"stringValue":"{}","extra":true})
            }
            4 => changed[6]["found"]["updateTime"] = json!("2026-11-05T00:00:00Z"),
            5 => changed[6]["transaction"] = json!(TX),
            6 => {
                changed[6]["found"]["fields"]["restore_json"]["stringValue"] = json!(
                    "{\"format\":\"day2_restore_approval_use_v1\",\"format\":\"day2_restore_approval_use_v1\"}"
                )
            }
            7 => changed[6]["found"]["fields"] = json!([]),
            _ => changed[6]["found"]["fields"]["restore_json"] = json!(["{}"]),
        }
        assert!(
            wire::Names::new(&selection, &plan)?
                .strong(&serde_json::to_vec(&changed)?)
                .is_err(),
            "cut={cut}"
        );
    }
    macro_rules! opaque {
        ($bound:path) => {{
            trait Ambiguous<A> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <wire::Transaction as Ambiguous<_>>::check;
        }};
    }
    opaque!(Clone);
    opaque!(Copy);
    opaque!(Default);
    opaque!(Send);
    opaque!(Sync);
    opaque!(serde::Serialize);
    opaque!(serde::Deserialize<'static>);
    Ok(())
}

#[test]
fn exactly_five_acknowledgements_and_post_commit_read_time_are_historical_data_only() -> Result<()>
{
    let (selection, before) = initial();
    let (_, plan) = approval_use::plan(&selection, &before, 47)?;
    let initial = initial_reply(&selection, &plan)?;
    let strong: Vec<_> = initial.into_iter().skip(1).collect();
    let observed = wire::Names::new(&selection, &plan)?.strong(&serde_json::to_vec(&strong)?)?;
    let reply =
        json!({"writeResults":vec![json!({"updateTime":version(3)});5],"commitTime":version(3)});
    let record = wire::commit_reply(&serde_json::to_vec(&reply)?)?;
    observed.after_commit(&record)?;
    assert!(matches!(
        model::reconcile(
            &selection,
            &plan,
            &observed.snapshot,
            observed.advance.as_ref(),
            observed.reservation.as_ref(),
            observed.grant.as_ref()
        )?,
        Outcome::NotApplied
    ));
    for cut in 0..7 {
        let mut changed = reply.clone();
        match cut {
            0 => {
                changed["writeResults"].as_array_mut().unwrap().pop();
            }
            1 => changed["writeResults"]
                .as_array_mut()
                .unwrap()
                .push(json!({"updateTime":version(3)})),
            2 => changed["writeResults"][2]["updateTime"] = json!("2026-11-05T00:00:00Z"),
            3 => changed["writeResults"][2]["transformResults"] = json!([]),
            4 => changed["unexpected"] = json!(true),
            5 => changed["writeResults"][2] = json!([version(3)]),
            _ => changed = json!([vec![json!({"updateTime":version(3)}); 5], version(3)]),
        }
        assert!(
            wire::commit_reply(&serde_json::to_vec(&changed)?).is_err(),
            "cut={cut}"
        );
    }
    let future = json!({"writeResults":vec![json!({"updateTime":"2026-11-05T00:00:00Z"});5],"commitTime":"2026-11-05T00:00:00Z"});
    let record = wire::commit_reply(&serde_json::to_vec(&future)?)?;
    assert!(observed.after_commit(&record).is_err());
    Ok(())
}

#[test]
fn provider_owned_parse_details_and_oversize_bytes_never_escape_closed_errors() -> Result<()> {
    const PRIVATE: &str = "PRIVATE-provider-fixture-not-operator-data";
    let (selection, before) = initial();
    let (_, plan) = approval_use::plan(&selection, &before, 48)?;
    let mut reply = initial_reply(&selection, &plan)?;
    reply[1]["found"]["fields"]["phase"]["mapValue"]["fields"]["phase"]["stringValue"] =
        json!(PRIVATE);
    let transaction =
        wire::Names::new(&selection, &plan)?.transaction(&serde_json::to_vec(&reply)?)?;
    let error = match transaction.observed() {
        Ok(_) => anyhow::bail!("unexpected provider admission"),
        Err(error) => error,
    };
    assert_eq!(format!("{error:#}"), "restore_provider_initial_snapshot");
    let cleanup: Value = crate::json::decode(&transaction.rollback_body()?)?;
    assert_eq!(cleanup, json!({"transaction":TX}));
    let duplicate = format!("[{{\"transaction\":\"{TX}\",\"transaction\":\"{PRIVATE}\"}}]");
    for bytes in [duplicate.into_bytes(), vec![b' '; 65_537]] {
        let error = match wire::Names::new(&selection, &plan)?.transaction(&bytes) {
            Ok(_) => anyhow::bail!("unexpected malformed transaction"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(PRIVATE));
    }
    let invalid = format!("{{\"writeResults\":\"{PRIVATE}\",\"commitTime\":\"{PRIVATE}\"}}");
    let error = match wire::commit_reply(invalid.as_bytes()) {
        Ok(_) => anyhow::bail!("unexpected malformed acknowledgement"),
        Err(error) => error,
    };
    assert!(!format!("{error:#}").contains(PRIVATE));
    Ok(())
}
