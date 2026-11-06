//! Scripted provider INPUT tests. The port cannot construct any native owner;
//! exact requests and refusal after ambiguous writes are checked independently.
use super::*;
use crate::security_epoch::{
    firestore::{EpochReply, Sample},
    kernel::approval_time::Utc,
    kernel::{Holder, Request, Versions},
};
use std::{collections::VecDeque, time::Duration};

fn version(n: u64) -> UpdateTime {
    format!("2026-11-05T00:00:00.{n:06}Z").try_into().unwrap()
}

struct Fixture {
    selected: EpochStore,
    root: Snapshot,
    floor: Versioned<Floor>,
    plan: Plan,
    record: SignedApprovalRecord,
}

fn fixture() -> Result<Fixture> {
    let (selected, record) = crate::security_epoch::restore_approval::fixture_publication_data()?;
    let create = crate::security_epoch::tests::create();
    let activate = Request::CompleteInitialFirstActivation {
        bootstrap: create.bootstrap().clone(),
        operation: Digest::new(b"approval-fixture-activation"),
        parent_receipt: create.receipt()?.digest()?,
        before: Versions {
            root: version(1),
            sentinel: version(1),
        },
        holder: Holder {
            principal: Digest::new(b"app"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"process"),
            ephemeral_key: Digest::new(b"key"),
        },
    };
    let (root, sentinel) = activate.records()?;
    let root = Snapshot {
        root: Some(Versioned {
            value: root,
            version: version(2),
        }),
        sentinel: Some(Versioned {
            value: sentinel,
            version: version(2),
        }),
        create: Some(Versioned {
            value: create.receipt()?,
            version: version(1),
        }),
        activate: Some(Versioned {
            value: activate.receipt()?,
            version: version(2),
        }),
    };
    // Explicit fixture installation DATA; production has no initializer/default.
    let floor = Versioned {
        value: serde_json::from_value(
            json!({"format":"day2_restore_time_floor_v1","authority":selected.authority_key()?,"upper":{"seconds":99,"nanos":0},"operation":Digest::new(b"fixture-installed")}),
        )?,
        version: version(3),
    };
    let plan = Plan::prepare(
        &selected,
        &root,
        Some(&floor),
        Digest::new(b"qualified-operation"),
        Interval {
            domain: Digest::new(b"actual-fixture-domain"),
            lower: Utc {
                seconds: 100,
                nanos: 0,
            },
            upper: Utc {
                seconds: 100,
                nanos: 1,
            },
        },
    )?;
    Ok(Fixture {
        selected,
        root,
        floor,
        plan,
        record,
    })
}

fn root_fields(value: Value) -> Value {
    Value::Object(
        value
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    match v {
                        Value::String(s) => json!({"stringValue":s}),
                        Value::Object(_) => json!({"mapValue":{"fields":root_fields(v.clone())}}),
                        _ => panic!("canonical root has only string/map values"),
                    },
                )
            })
            .collect(),
    )
}

fn entry<T: Serialize>(name: &str, value: &Versioned<T>) -> Result<Value> {
    Ok(
        json!({"found":{"name":name,"fields":root_fields(serde_json::to_value(&value.value)?),"createTime":value.version,"updateTime":value.version},"readTime":version(20)}),
    )
}

fn payload_entry<T: Serialize>(name: &str, domain: &str, value: &T, at: u64) -> Result<Value> {
    let payload = serde_json::to_string(value)?;
    // Independent literal wire encoding; do not use the implementation fields().
    Ok(
        json!({"found":{"name":name,"fields":{"payload":{"stringValue":payload},"commitment":{"stringValue":Digest::of(&(domain,value))?}},"createTime":version(at),"updateTime":version(at)},"readTime":version(20)}),
    )
}

fn snapshot(f: &Fixture, after: bool, publication: bool, published: bool) -> Result<Value> {
    let mut names = Selection::new(&f.selected, &f.root, &f.plan.receipt.operation_data())?;
    if publication {
        let key = publication::key(&f.selected, &f.record.statement.request.grant_id)?;
        names.publication = Some(format!(
            "{}/documents/day2_restore_approval_publications_v1/{}",
            names.names.database,
            &key.as_str()[7..]
        ));
    }
    let mut rows = vec![
        json!({"transaction":STANDARD.encode(b"fixture-transaction")}),
        entry(&names.names.root, f.root.root.as_ref().unwrap())?,
        entry(&names.names.sentinel, f.root.sentinel.as_ref().unwrap())?,
        entry(&names.names.create, f.root.create.as_ref().unwrap())?,
        entry(
            names.names.activate.as_ref().unwrap(),
            f.root.activate.as_ref().unwrap(),
        )?,
    ];
    rows.push(payload_entry(
        &names.floor,
        "day2-restore-time-floor-document-v1",
        if after { &f.plan.after } else { &f.floor.value },
        if after { 4 } else { 3 },
    )?);
    rows.push(if after {
        payload_entry(
            &names.receipt,
            "day2-restore-time-receipt-document-v1",
            &f.plan.receipt,
            4,
        )?
    } else {
        json!({"missing":names.receipt,"readTime":version(20)})
    });
    if let Some(name) = names.publication {
        rows.push(if published {
            payload_entry(
                &name,
                "day2-restore-approval-publication-document-v1",
                &Publication::record_data(&f.selected, f.record.clone())?,
                5,
            )?
        } else {
            json!({"missing":name,"readTime":version(20)})
        });
    }
    Ok(rows.into())
}

fn ack(count: usize, n: u64) -> Value {
    json!({"writeResults":(0..count).map(|_|json!({"updateTime":version(n)})).collect::<Vec<_>>(),"commitTime":version(n)})
}

struct Script {
    replies: VecDeque<Result<Vec<u8>>>,
    calls: Vec<(String, Value)>,
    refused: bool,
}

impl Script {
    fn new(values: Vec<Value>) -> Self {
        Self {
            replies: values
                .into_iter()
                .map(|v| Ok(serde_json::to_vec(&v).unwrap()))
                .collect(),
            calls: Vec::new(),
            refused: false,
        }
    }
    fn budget(&mut self) -> Result<Budget> {
        Budget::from_native_origin(self.sample()?, Duration::ZERO, Duration::from_secs(5))
    }
}

impl Port for Script {
    fn sample(&mut self) -> Result<Sample> {
        ensure!(!self.refused, "fixture-refused");
        Ok(Sample {
            domain: Digest::new(b"fixture-clock"),
            elapsed: Duration::from_millis(1),
        })
    }
    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        _budget: &mut Budget,
        _max_bytes: usize,
    ) -> Result<EpochReply> {
        ensure!(!self.refused, "fixture-refused");
        self.calls.push((url.into(), crate::json::decode(body)?));
        Ok(EpochReply {
            status: 200,
            body: self
                .replies
                .pop_front()
                .context("fixture-unexpected-rpc")??,
        })
    }
    fn refuse(&mut self) {
        self.refused = true;
    }
}

#[test]
fn safe_floor_uses_one_complete_transaction_exact_cas_and_known_readback() -> Result<()> {
    let f = fixture()?;
    let mut port = Script::new(vec![
        snapshot(&f, false, false, false)?,
        ack(2, 4),
        snapshot(&f, true, false, false)?,
    ]);
    let budget = port.budget()?;
    let plan = advance(
        &mut port,
        budget,
        &f.selected,
        &f.root,
        f.plan.receipt.operation_data(),
        interval(),
    )?;
    assert_eq!(plan.after, f.plan.after);
    assert_eq!(port.calls.len(), 3);
    assert!(port.replies.is_empty());
    let names = Selection::new(&f.selected, &f.root, &f.plan.receipt.operation_data())?;
    assert_eq!(
        port.calls[0].1,
        json!({"documents":names.documents(),"newTransaction":{"readWrite":{}}})
    );
    let commit = &port.calls[1].1;
    assert!(port.calls[1].0.ends_with(":commit"));
    assert_eq!(
        commit["transaction"],
        STANDARD.encode(b"fixture-transaction")
    );
    assert_eq!(commit["writes"].as_array().unwrap().len(), 2);
    assert_eq!(
        commit["writes"][0]["currentDocument"],
        json!({"updateTime":version(3)})
    );
    assert_eq!(
        commit["writes"][1]["currentDocument"],
        json!({"exists":false})
    );
    assert_eq!(commit["writes"][0]["update"]["name"], names.floor);
    assert_eq!(commit["writes"][1]["update"]["name"], names.receipt);
    assert_eq!(port.calls[2].1["newTransaction"], json!({"readOnly":{}}));
    Ok(())
}

#[test]
fn malformed_or_foreign_floor_snapshots_refuse_before_any_write() -> Result<()> {
    let f = fixture()?;
    for fault in 0..6 {
        let mut before = snapshot(&f, false, false, false)?;
        match fault {
            0 => {
                before.as_array_mut().unwrap().remove(5);
            }
            1 => {
                before[5] = json!({"missing":before[5]["found"]["name"],"readTime":version(20)});
            }
            2 => {
                before[5]["found"]["fields"]["commitment"]["stringValue"] =
                    Digest::new(b"wrong-world").as_str().into();
            }
            3 => {
                before[2]["found"]["updateTime"] = serde_json::to_value(version(9))?;
            }
            4 => {
                before[6] = before[5].clone();
            }
            _ => {
                before[5]["readTime"] = serde_json::to_value(version(1))?;
            }
        }
        let mut port = Script::new(vec![before, json!({})]);
        let budget = port.budget()?;
        assert!(
            advance(
                &mut port,
                budget,
                &f.selected,
                &f.root,
                f.plan.receipt.operation_data(),
                interval()
            )
            .is_err(),
            "fault {fault}"
        );
        assert!(port.calls.iter().all(|(url, _)| !url.ends_with(":commit")));
        assert!(port.calls.len() <= 2);
    }
    Ok(())
}

fn interval() -> Interval {
    Interval {
        domain: Digest::new(b"actual-fixture-domain"),
        lower: Utc {
            seconds: 100,
            nanos: 0,
        },
        upper: Utc {
            seconds: 100,
            nanos: 1,
        },
    }
}

#[test]
fn ambiguous_floor_commit_and_changed_readback_never_retry_or_return_qualification() -> Result<()> {
    let f = fixture()?;
    let mut port = Script::new(vec![snapshot(&f, false, false, false)?]);
    port.replies
        .push_back(Err(anyhow::anyhow!("fixture-lost-ack")));
    let budget = port.budget()?;
    assert!(
        advance(
            &mut port,
            budget,
            &f.selected,
            &f.root,
            f.plan.receipt.operation_data(),
            interval()
        )
        .is_err()
    );
    assert_eq!(port.calls.len(), 2);
    for fault in 0..3 {
        let mut after = snapshot(&f, true, false, false)?;
        match fault {
            0 => after[5]["found"]["updateTime"] = serde_json::to_value(version(6))?,
            1 => after[6] = json!({"missing":after[6]["found"]["name"],"readTime":version(20)}),
            _ => after[1]["found"]["updateTime"] = serde_json::to_value(version(8))?,
        }
        let mut port = Script::new(vec![snapshot(&f, false, false, false)?, ack(2, 4), after]);
        let budget = port.budget()?;
        assert!(
            advance(
                &mut port,
                budget,
                &f.selected,
                &f.root,
                f.plan.receipt.operation_data(),
                interval()
            )
            .is_err()
        );
        assert_eq!(port.calls.len(), 3);
    }
    Ok(())
}

#[test]
fn publication_is_create_only_and_exact_readback_is_required() -> Result<()> {
    let f = fixture()?;
    let mut port = Script::new(vec![
        snapshot(&f, true, true, false)?,
        ack(1, 5),
        snapshot(&f, true, true, true)?,
    ]);
    let budget = port.budget()?;
    publish(&mut port, budget, &f.selected, &f.root, &f.plan, &f.record)?;
    assert_eq!(port.calls.len(), 3);
    assert_eq!(port.calls[1].1["writes"].as_array().unwrap().len(), 1);
    assert_eq!(
        port.calls[1].1["writes"][0]["currentDocument"],
        json!({"exists":false})
    );
    assert!(
        port.calls
            .iter()
            .all(|(url, _)| !url.ends_with(":rollback"))
    );
    let mut port = Script::new(vec![snapshot(&f, true, true, true)?, json!({})]);
    let budget = port.budget()?;
    assert!(publish(&mut port, budget, &f.selected, &f.root, &f.plan, &f.record).is_err());
    assert_eq!(port.calls.len(), 2);
    assert!(port.calls[1].0.ends_with(":rollback"));
    let mut after = snapshot(&f, true, true, true)?;
    after[7]["found"]["updateTime"] = serde_json::to_value(version(6))?;
    let mut port = Script::new(vec![snapshot(&f, true, true, false)?, ack(1, 5), after]);
    let budget = port.budget()?;
    assert!(publish(&mut port, budget, &f.selected, &f.root, &f.plan, &f.record).is_err());
    assert_eq!(port.calls.len(), 3);
    let mut port = Script::new(vec![snapshot(&f, true, true, false)?]);
    port.replies
        .push_back(Err(anyhow::anyhow!("fixture-lost-publication-ack")));
    let budget = port.budget()?;
    assert!(publish(&mut port, budget, &f.selected, &f.root, &f.plan, &f.record).is_err());
    assert_eq!(port.calls.len(), 2);
    Ok(())
}
