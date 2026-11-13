//! Synthetic provider DATA and controlled ports; no native owner is made here.
use super::*;
use crate::security_epoch::{
    firestore::{Budget, EpochReply, Port, Sample},
    kernel::restore::writer::tests::{Fixture, fixture},
};
use serde::Serialize;
use std::{collections::VecDeque, time::Duration};

const READ: &str = "2026-11-04T00:00:01Z";
const TX: &str = "dGFyZ2V0LXRva2Vu";

fn version(n: u64) -> UpdateTime {
    format!("2026-11-04T00:00:00.{n:06}Z").try_into().unwrap()
}

fn fields(value: Value) -> Result<Value> {
    let Value::Object(values) = value else {
        anyhow::bail!("target_fixture_object");
    };
    let mut result = serde_json::Map::new();
    for (name, value) in values {
        result.insert(
            name,
            match value {
                Value::String(text) => json!({"stringValue":text}),
                Value::Object(_) => json!({"mapValue":{"fields":fields(value)?}}),
                _ => anyhow::bail!("target_fixture_string_map_only"),
            },
        );
    }
    Ok(Value::Object(result))
}

fn document<T: Serialize>(name: &str, value: &T, at: u64, domain: Option<&str>) -> Result<Value> {
    let fields = match domain {
        None => fields(serde_json::to_value(value)?)?,
        Some(domain) => json!({"restore_json":{"stringValue":serde_json::to_string(value)?},
            "restore_digest":{"stringValue":Digest::of(&(domain,value))?}}),
    };
    Ok(json!({"readTime":READ,"found":{"name":name,"fields":fields,
        "createTime":version(1),"updateTime":version(at)}}))
}

fn known(f: &Fixture) -> Result<super::super::Observed> {
    Ok(super::super::Observed {
        snapshot: f.before.settled.snapshot.clone(),
        advance: Some(f.before.settled.advance.clone()),
        reservation: Some(f.before.settled.reservation.clone()),
        grant: Some(f.before.consumed.clone()),
        publication: Versioned {
            value: crate::security_epoch::restore_approval::fixture_publication_for_request_data(
                &f.selected,
                &f.authority.grant.approval,
            )?,
            version: version(2),
        },
        first_read: timestamp(READ)?,
    })
}

fn confirmation(known: &super::super::Observed) -> Result<super::super::ReservationConfirmation> {
    Ok(super::super::ReservationConfirmation {
        grant_id: known.grant.as_ref().unwrap().value.grant_id_data().clone(),
        committed_at: version(3),
        written_versions: std::array::from_fn(|_| version(3)),
        records: known.commitment_data()?,
    })
}

fn request(f: &Fixture) -> Result<kernel::Request> {
    // The existing independent kernel fixture's completed disposition is DATA.
    // No native target/approval owner is inferred from this serialized record.
    let receipt = serde_json::to_value(&f.before.terminal.value)?;
    let report = serde_json::from_value(receipt["disposition"]["completed"]["report"].clone())?;
    kernel::Request::new(
        &f.selected,
        &f.request.reservation_data().reservation,
        &f.before.settled,
        &f.authority,
        1001,
        kernel::Disposition::Completed { report },
    )
}

fn names(f: &Fixture, plan: &kernel::Plan) -> Result<Names> {
    let before = known(f)?;
    Names::new(
        &f.selected,
        f.request.reservation_data(),
        &before,
        &confirmation(&before)?,
        plan,
    )
}

fn reply(f: &Fixture, plan: &kernel::Plan, after: bool, header: bool) -> Result<Vec<Value>> {
    let names = names(f, plan)?;
    let n = names.documents();
    let known = known(f)?;
    let s = &known.snapshot;
    let mut values = vec![
        document(n[0], &s.root.as_ref().unwrap().value, 3, None)?,
        document(n[1], &s.sentinel.as_ref().unwrap().value, 3, None)?,
        document(n[2], &s.create.as_ref().unwrap().value, 1, None)?,
        document(n[3], &s.activate.as_ref().unwrap().value, 2, None)?,
        document(
            n[4],
            &known.advance.as_ref().unwrap().value,
            3,
            Some("day2-restore-advance-document-v1"),
        )?,
        document(
            n[5],
            &known.reservation.as_ref().unwrap().value,
            3,
            Some("day2-restore-reservation-document-v1"),
        )?,
        document(
            n[6],
            &known.grant.as_ref().unwrap().value,
            3,
            Some("day2-restore-grant-document-v1"),
        )?,
        json!({"readTime":READ,"found":{"name":n[7],"createTime":version(1),"updateTime":version(2),
            "fields":{"payload":{"stringValue":String::from_utf8(known.publication.value.encode(&f.selected)?)?},
                "commitment":{"stringValue":Digest::of(&("day2-restore-approval-publication-document-v1",&known.publication.value))?}}}}),
    ];
    values.push(if after {
        document(
            n[8],
            &plan.receipt,
            4,
            Some("day2-restore-settlement-document-v1"),
        )?
    } else {
        json!({"readTime":READ,"missing":n[8]})
    });
    if header {
        values.insert(0, json!({"transaction":TX}));
    }
    Ok(values)
}

#[test]
fn target_transaction_reads_exact_known_eight_and_absence_then_creates_only_terminal() -> Result<()>
{
    let f = fixture(600, true)?;
    let request = request(&f)?;
    let plan = request.prepare(&f.selected, &f.authority, 1001, &f.before.settled, None)?;
    let selected = names(&f, &plan)?;
    assert_eq!(selected.documents().len(), 9);
    assert_eq!(
        crate::json::decode::<Value>(&selected.begin_body()?)?,
        json!({"documents":selected.documents(),"newTransaction":{"readWrite":{}}})
    );
    assert_eq!(
        crate::json::decode::<Value>(&selected.strong_body()?)?,
        json!({"documents":selected.documents()})
    );
    assert!(selected.endpoint("beginTransaction").is_err());
    let tx = selected.transaction(&serde_json::to_vec(&reply(&f, &plan, false, true)?)?)?;
    let body: Value =
        crate::json::decode(&tx.commit_body(&f.selected, &request, &plan, &f.authority, 1001)?)?;
    assert_eq!(body["transaction"], TX);
    let writes = body["writes"].as_array().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0]["currentDocument"], json!({"exists":false}));
    assert!(
        writes[0]["update"]["name"]
            .as_str()
            .unwrap()
            .contains("/restore_settlements/")
    );
    assert_eq!(
        tx.rollback_body()?,
        serde_json::to_vec(&json!({"transaction":TX}))?
    );
    Ok(())
}

#[test]
fn every_known_version_rewrite_and_changed_ack_refuse_before_terminal_commit() -> Result<()> {
    let f = fixture(601, true)?;
    let request = request(&f)?;
    let plan = request.prepare(&f.selected, &f.authority, 1001, &f.before.settled, None)?;
    for index in 0..8 {
        let mut rows = reply(&f, &plan, false, true)?;
        rows[index + 1]["found"]["updateTime"] = json!(version(90));
        let tx = names(&f, &plan)?.transaction(&serde_json::to_vec(&rows)?)?;
        assert!(
            tx.commit_body(&f.selected, &request, &plan, &f.authority, 1001)
                .is_err()
        );
        assert!(!tx.rollback_body()?.is_empty());
    }
    let known = known(&f)?;
    let mut ack = confirmation(&known)?;
    ack.written_versions[2] = version(9);
    assert!(
        Names::new(
            &f.selected,
            f.request.reservation_data(),
            &known,
            &ack,
            &plan
        )
        .is_err()
    );
    let mut denied = f.authority.clone();
    denied.enabled = false;
    let tx =
        names(&f, &plan)?.transaction(&serde_json::to_vec(&reply(&f, &plan, false, true)?)?)?;
    assert!(
        tx.commit_body(&f.selected, &request, &plan, &denied, 1001)
            .is_err()
    );
    assert!(
        tx.commit_body(
            &f.selected,
            &request,
            &plan,
            &f.authority,
            f.authority.ready_until
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn malformed_missing_duplicate_foreign_and_occupied_terminal_never_admit_a_commit() -> Result<()> {
    let f = fixture(602, true)?;
    let request = request(&f)?;
    let plan = request.prepare(&f.selected, &f.authority, 1001, &f.before.settled, None)?;
    for change in 0..7 {
        let mut rows = reply(&f, &plan, false, true)?;
        match change {
            0 => {
                rows.pop();
            }
            1 => rows[2] = rows[1].clone(),
            2 => {
                rows[1]["found"]["name"] =
                    json!("projects/foreign/databases/foreign/documents/foreign")
            }
            3 => rows[7]["transaction"] = json!(TX),
            4 => rows[9] = reply(&f, &plan, true, true)?[9].clone(),
            5 => rows[9]["readTime"] = json!("2026-11-03T00:00:00Z"),
            _ => rows[5]["found"]["fields"]["unexpected"] = json!({"stringValue":"closed"}),
        }
        let tx = names(&f, &plan)?.transaction(&serde_json::to_vec(&rows)?)?;
        assert!(
            tx.commit_body(&f.selected, &request, &plan, &f.authority, 1001)
                .is_err()
        );
    }
    let raw = serde_json::to_string(&reply(&f, &plan, false, true)?)?;
    let duplicate = raw.replacen(
        "\"transaction\":",
        "\"transaction\":\"AQ==\",\"transaction\":",
        1,
    );
    assert_ne!(raw, duplicate);
    assert!(names(&f, &plan)?.transaction(duplicate.as_bytes()).is_err());
    assert!(names(&f, &plan)?.transaction(&vec![b' '; 65_537]).is_err());
    Ok(())
}

struct ControlledPort {
    replies: VecDeque<Option<Vec<u8>>>,
    calls: Vec<&'static str>,
    refused: bool,
}

impl Port for ControlledPort {
    fn sample(&mut self) -> Result<Sample> {
        ensure!(!self.refused, "target_fixture_refused");
        Ok(Sample {
            domain: Digest::new(b"target-fixture-clock"),
            elapsed: Duration::from_millis(1),
        })
    }
    fn post(
        &mut self,
        url: &str,
        _body: &[u8],
        _budget: &mut Budget,
        max: usize,
    ) -> Result<EpochReply> {
        assert_eq!(max, 65_536);
        self.calls.push(if url.ends_with(":commit") {
            "commit"
        } else if url.ends_with(":batchGet") {
            "read"
        } else {
            "rollback"
        });
        let body = self
            .replies
            .pop_front()
            .flatten()
            .context("target_fixture_unknown")?;
        Ok(EpochReply { status: 200, body })
    }
    fn refuse(&mut self) {
        self.refused = true;
    }
}

#[test]
fn consuming_send_requires_actual_ack_and_full_postread_without_retry_or_late_rollback()
-> Result<()> {
    let f = fixture(603, true)?;
    let request = request(&f)?;
    let plan = request.prepare(&f.selected, &f.authority, 1001, &f.before.settled, None)?;
    for change in 0..6 {
        let mut ack = json!({"writeResults":[{"updateTime":version(4)}],"commitTime":version(4)});
        let mut after = reply(&f, &plan, true, false)?;
        match change {
            0 => {}
            1 => ack["writeResults"] = json!([]),
            2 => ack["writeResults"] = json!([{"updateTime":version(4)},{"updateTime":version(4)}]),
            3 => after[8]["found"]["updateTime"] = json!(version(5)),
            4 => after[0]["found"]["updateTime"] = json!(version(5)),
            _ => after[8]["readTime"] = json!("2026-11-03T00:00:00Z"),
        }
        let mut port = ControlledPort {
            replies: VecDeque::from([
                Some(serde_json::to_vec(&ack)?),
                Some(serde_json::to_vec(&after)?),
            ]),
            calls: Vec::new(),
            refused: false,
        };
        let budget = Budget::for_context(port.sample()?, Duration::from_secs(5))?;
        let tx =
            names(&f, &plan)?.transaction(&serde_json::to_vec(&reply(&f, &plan, false, true)?)?)?;
        let result = tx.commit_and_readback(
            &mut port,
            budget,
            &f.selected,
            &request,
            &plan,
            (&f.authority, 1001),
        );
        if change == 0 {
            assert_eq!(result?.receipt_data()?, plan.receipt);
            assert!(!port.refused);
        } else {
            assert!(result.is_err());
            assert!(port.refused);
        }
        assert!(port.calls == ["commit"] || port.calls == ["commit", "read"]);
    }
    let mut port = ControlledPort {
        replies: VecDeque::from([None]),
        calls: Vec::new(),
        refused: false,
    };
    let budget = Budget::for_context(port.sample()?, Duration::from_secs(5))?;
    let tx =
        names(&f, &plan)?.transaction(&serde_json::to_vec(&reply(&f, &plan, false, true)?)?)?;
    assert!(
        tx.commit_and_readback(
            &mut port,
            budget,
            &f.selected,
            &request,
            &plan,
            (&f.authority, 1001)
        )
        .is_err()
    );
    assert_eq!(port.calls, ["commit"]);
    assert!(port.refused);
    Ok(())
}

#[test]
fn acknowledged_target_preserves_complete_writer_predecessor_data_and_refuses_lost_parts()
-> Result<()> {
    let f = fixture(605, true)?;
    let request = request(&f)?;
    let plan = request.prepare(&f.selected, &f.authority, 1001, &f.before.settled, None)?;
    let names = names(&f, &plan)?;
    let make = || -> Result<KnownSettlement> {
        Ok(KnownSettlement {
            observed: names.strong(&serde_json::to_vec(&reply(&f, &plan, true, false)?)?)?,
            acknowledged: CommitRecord {
                committed: timestamp(&String::from(version(4)))?,
                version: version(4),
            },
        })
    };
    let known = make()?;
    let state = known.writer_state_data()?;
    assert_eq!(state.settled, f.before.settled);
    assert_eq!(state.consumed, f.before.consumed);
    assert_eq!(state.terminal.value, plan.receipt);
    assert_eq!(state.terminal.version, version(4));
    for cut in 0..5 {
        let mut changed = make()?;
        match cut {
            0 => changed.observed.base.grant = None,
            1 => changed.observed.base.advance = None,
            2 => changed.observed.base.reservation = None,
            3 => changed.observed.terminal.as_mut().unwrap().version = version(9),
            _ => changed.observed.first_read = timestamp(&String::from(version(3)))?,
        }
        assert!(
            changed.writer_state_data().is_err(),
            "predecessor cut {cut}"
        );
    }
    Ok(())
}
