//! Actual bounded codec controls over synthetic protocol DATA. No HTTP request,
//! approval/current-role owner or native writer is constructed by these tests.
use super::*;
use crate::security_epoch::kernel::restore::writer::tests::{Fixture, fixture};
use serde::Serialize;

const READ: &str = "2026-11-04T00:00:01Z";
const TX: &str = "d3JpdGVyLXRva2Vu";

fn version(n: u64) -> UpdateTime {
    format!("2026-11-04T00:00:00.{n:06}Z").try_into().unwrap()
}

// Separate simple encoder oracle: authority fields are string/map ONLY.
fn fields(value: Value) -> Result<Value> {
    let Value::Object(values) = value else {
        anyhow::bail!("writer_fixture_object");
    };
    let mut out = serde_json::Map::new();
    for (key, value) in values {
        out.insert(
            key,
            match value {
                Value::String(text) => json!({"stringValue":text}),
                Value::Object(_) => json!({"mapValue":{"fields":fields(value)?}}),
                _ => anyhow::bail!("writer_fixture_authority_field_type"),
            },
        );
    }
    Ok(Value::Object(out))
}

fn doc<T: Serialize>(name: &str, value: &T, token: u64, domain: Option<&str>) -> Result<Value> {
    let value = match domain {
        None => fields(serde_json::to_value(value)?)?,
        Some(domain) => json!({
            "restore_json":{"stringValue":serde_json::to_string(value)?},
            "restore_digest":{"stringValue":Digest::of(&(domain,value))?},
        }),
    };
    Ok(json!({"readTime":READ,"found":{"name":name,"fields":value,
        "createTime":version(1),"updateTime":version(token)}}))
}

fn reply(f: &Fixture, p: &kernel::Plan, after: bool, header: bool) -> Result<Vec<Value>> {
    let names = Names::new(&f.selected, &f.request, p)?;
    let n = names.documents();
    let s = &f.before.settled;
    let mut values = vec![
        doc(
            n[0],
            if after {
                &p.root
            } else {
                &s.snapshot.root.as_ref().unwrap().value
            },
            if after { 5 } else { 3 },
            None,
        )?,
        doc(
            n[1],
            if after {
                &p.sentinel
            } else {
                &s.snapshot.sentinel.as_ref().unwrap().value
            },
            if after { 5 } else { 3 },
            None,
        )?,
        doc(n[2], &s.snapshot.create.as_ref().unwrap().value, 1, None)?,
        doc(n[3], &s.snapshot.activate.as_ref().unwrap().value, 2, None)?,
        doc(
            n[4],
            &s.advance.value,
            3,
            Some("day2-restore-advance-document-v1"),
        )?,
        doc(
            n[5],
            &s.reservation.value,
            3,
            Some("day2-restore-reservation-document-v1"),
        )?,
        doc(
            n[6],
            &f.before.consumed.value,
            3,
            Some("day2-restore-grant-document-v1"),
        )?,
        doc(
            n[7],
            &f.before.terminal.value,
            4,
            Some("day2-restore-settlement-document-v1"),
        )?,
    ];
    values.push(if after {
        doc(n[8], &p.receipt, 5, Some("day2-restore-writer-document-v1"))?
    } else {
        json!({"readTime":READ,"missing":n[8]})
    });
    if header {
        values.insert(0, json!({"transaction":TX}));
    }
    Ok(values)
}

fn plan(f: &Fixture) -> Result<kernel::Plan> {
    f.request
        .prepare(&f.selected, &f.authority, 1002, &f.before, None)
}

#[test]
fn writer_transaction_reads_all_nine_and_cas_updates_two_creates_one() -> Result<()> {
    let f = fixture(80, true)?;
    let p = plan(&f)?;
    let names = Names::new(&f.selected, &f.request, &p)?;
    let begin: Value = crate::json::decode(&names.begin_body()?)?;
    assert_eq!(
        begin,
        json!({"documents":names.documents(),"newTransaction":{"readWrite":{}}})
    );
    assert_eq!(names.documents().len(), 9);
    let strong: Value = crate::json::decode(&names.strong_body()?)?;
    assert_eq!(strong, json!({"documents":names.documents()}));
    assert!(names.endpoint("beginTransaction").is_err());
    let tx = names.transaction(&serde_json::to_vec(&reply(&f, &p, false, true)?)?)?;
    assert_eq!(tx.observed()?.state, f.before);
    let body: Value =
        crate::json::decode(&tx.commit_body(&f.selected, &f.request, &p, &f.authority, 1002)?)?;
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(body["transaction"], TX);
    let writes = body["writes"].as_array().unwrap();
    assert_eq!(writes.len(), 3);
    assert_eq!(
        writes[0]["update"]["fields"],
        fields(serde_json::to_value(&p.root)?)?
    );
    assert_eq!(
        writes[1]["update"]["fields"],
        fields(serde_json::to_value(&p.sentinel)?)?
    );
    assert_eq!(
        writes[0]["currentDocument"],
        json!({"updateTime":version(3)})
    );
    assert_eq!(
        writes[1]["currentDocument"],
        json!({"updateTime":version(3)})
    );
    assert_eq!(writes[2]["currentDocument"], json!({"exists":false}));
    assert_eq!(
        writes[2]["update"]["fields"]["restore_json"]["stringValue"],
        serde_json::to_string(&p.receipt)?
    );
    assert_eq!(
        tx.rollback_body()?,
        serde_json::to_vec(&json!({"transaction":TX}))?
    );
    Ok(())
}

#[test]
fn every_observed_record_version_and_occupied_writer_refuses_before_commit_body() -> Result<()> {
    let f = fixture(81, true)?;
    let p = plan(&f)?;
    for index in 0..8 {
        let mut values = reply(&f, &p, false, true)?;
        values[index + 1]["found"]["updateTime"] = json!(version(90));
        let tx =
            Names::new(&f.selected, &f.request, &p)?.transaction(&serde_json::to_vec(&values)?)?;
        assert!(
            tx.commit_body(&f.selected, &f.request, &p, &f.authority, 1002)
                .is_err()
        );
        assert!(!tx.rollback_body()?.is_empty());
    }
    let tx = Names::new(&f.selected, &f.request, &p)?
        .transaction(&serde_json::to_vec(&reply(&f, &p, true, true)?)?)?;
    assert!(
        tx.commit_body(&f.selected, &f.request, &p, &f.authority, 1002)
            .is_err()
    );
    let mut current = f.authority.clone();
    current.enabled = false;
    let tx = Names::new(&f.selected, &f.request, &p)?
        .transaction(&serde_json::to_vec(&reply(&f, &p, false, true)?)?)?;
    assert!(
        tx.commit_body(&f.selected, &f.request, &p, &current, 1002)
            .is_err()
    );
    assert!(
        tx.commit_body(
            &f.selected,
            &f.request,
            &p,
            &f.authority,
            f.authority.ready_until
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn malformed_streams_keep_known_header_but_never_become_valid_observations() -> Result<()> {
    let f = fixture(82, true)?;
    let p = plan(&f)?;
    for change in 0..7 {
        let mut values = reply(&f, &p, false, true)?;
        match change {
            0 => {
                values.pop();
            }
            1 => values[2] = values[1].clone(),
            2 => {
                values[1]["found"]["name"] =
                    json!("projects/foreign/databases/foreign/documents/foreign")
            }
            3 => values[7]["transaction"] = json!(TX),
            4 => {
                values[8]["found"]["fields"]["restore_digest"]["stringValue"] =
                    json!(Digest::new(b"wrong"))
            }
            5 => values[8]["readTime"] = json!("2026-11-03T00:00:00Z"),
            _ => values[8]["found"]["fields"]["unexpected"] = json!({"stringValue":"not-admitted"}),
        }
        let tx =
            Names::new(&f.selected, &f.request, &p)?.transaction(&serde_json::to_vec(&values)?)?;
        assert!(tx.observed().is_err());
        assert!(!tx.rollback_body()?.is_empty());
    }
    let raw = serde_json::to_string(&reply(&f, &p, false, true)?)?;
    let duplicate = raw.replacen(
        "\"transaction\":",
        "\"transaction\":\"AQ==\",\"transaction\":",
        1,
    );
    assert_ne!(raw, duplicate);
    assert!(
        Names::new(&f.selected, &f.request, &p)?
            .transaction(duplicate.as_bytes())
            .is_err()
    );
    assert!(
        Names::new(&f.selected, &f.request, &p)?
            .transaction(&vec![b' '; 65_537])
            .is_err()
    );
    Ok(())
}

#[test]
fn exact_three_result_ack_and_strong_read_join_actual_versions() -> Result<()> {
    let f = fixture(83, true)?;
    let p = plan(&f)?;
    let ack = json!({"writeResults":[{"updateTime":version(5)},{"updateTime":version(5)},{"updateTime":version(5)}],"commitTime":version(5)});
    let commit = commit_reply(&serde_json::to_vec(&ack)?)?;
    let names = Names::new(&f.selected, &f.request, &p)?;
    let observed = names.strong(&serde_json::to_vec(&reply(&f, &p, true, false)?)?)?;
    observed.after_commit(&commit)?;
    assert!(matches!(
        kernel::reconcile(
            &f.selected,
            &f.request,
            &p,
            &observed.state,
            observed.writer.as_ref()
        )?,
        kernel::Outcome::Applied(_)
    ));
    for index in [1, 2, 9] {
        let mut values = reply(&f, &p, true, true)?;
        values.remove(0);
        values[index - 1]["found"]["updateTime"] = json!(version(6));
        assert!(
            names
                .strong(&serde_json::to_vec(&values)?)?
                .after_commit(&commit)
                .is_err()
        );
    }
    for mutation in 0..4 {
        let mut wrong = ack.clone();
        match mutation {
            0 => {
                wrong["writeResults"].as_array_mut().unwrap().pop();
            }
            1 => wrong["writeResults"][0] = json!([]),
            2 => wrong["writeResults"][0]["updateTime"] = json!(version(8)),
            _ => wrong["unknown"] = json!("refused"),
        }
        assert!(commit_reply(&serde_json::to_vec(&wrong)?).is_err());
    }
    Ok(())
}
