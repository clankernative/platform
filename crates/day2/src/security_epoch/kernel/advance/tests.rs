use super::*;
use crate::security_epoch::kernel::{Bootstrap, Holder, Outcome as InitialOutcome};
use rusqlite::{Connection, OptionalExtension, params};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

mod history;

fn version(value: u64) -> super::super::UpdateTime {
    format!("2026-11-02T00:00:00.{value:06}Z")
        .try_into()
        .unwrap()
}

fn initial() -> (EpochStore, Snapshot) {
    let selection = crate::security_epoch::tests::selection();
    let create = crate::security_epoch::tests::create();
    let activate = InitialRequest::CompleteInitialFirstActivation {
        bootstrap: create.bootstrap().clone(),
        operation: Digest::new(b"advance-fixture-activation"),
        parent_receipt: create.receipt().unwrap().digest().unwrap(),
        before: Versions {
            root: version(1),
            sentinel: version(1),
        },
        holder: Holder {
            principal: Digest::new(b"first-app"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"first-process"),
            ephemeral_key: Digest::new(b"first-key"),
        },
    };
    let (root, sentinel) = activate.records().unwrap();
    let snapshot = Snapshot {
        root: Some(Versioned {
            value: root,
            version: version(2),
        }),
        sentinel: Some(Versioned {
            value: sentinel,
            version: version(2),
        }),
        create: Some(Versioned {
            value: create.receipt().unwrap(),
            version: version(1),
        }),
        activate: Some(Versioned {
            value: activate.receipt().unwrap(),
            version: version(2),
        }),
    };
    assert!(matches!(
        super::super::reconcile(&selection, &activate, &snapshot).unwrap(),
        InitialOutcome::Applied(_)
    ));
    (selection, snapshot)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cut {
    Known,
    BeforeWrite,
    AfterRoot,
    AfterSentinel,
    AfterCommit,
}

/// A conditional provider, not a native mutator: SQLite interprets only exact
/// versions and create-only receipt keys, independently of the epoch kernel.
struct Provider {
    db: Connection,
}

fn require_fixture_versions(before: &Snapshot) -> Result<()> {
    ensure!(
        before
            .root
            .as_ref()
            .is_some_and(|r| r.version == version(2))
            && before
                .sentinel
                .as_ref()
                .is_some_and(|r| r.version == version(2))
            && before
                .create
                .as_ref()
                .is_some_and(|r| r.version == version(1))
            && before
                .activate
                .as_ref()
                .is_some_and(|r| r.version == version(2)),
        "epoch_advance_fixture_version_domain"
    );
    Ok(())
}

impl Provider {
    fn new(initial: &Snapshot) -> Result<Self> {
        require_fixture_versions(initial)?;
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE records(name TEXT PRIMARY KEY, body TEXT NOT NULL, version INTEGER NOT NULL); CREATE TABLE sends(id INTEGER PRIMARY KEY);")?;
        let provider = Self { db };
        for (name, value, revision) in [
            (
                "root",
                serde_json::to_string(&initial.root.as_ref().unwrap().value)?,
                2,
            ),
            (
                "sentinel",
                serde_json::to_string(&initial.sentinel.as_ref().unwrap().value)?,
                2,
            ),
            (
                "create",
                serde_json::to_string(&initial.create.as_ref().unwrap().value)?,
                1,
            ),
            (
                "activate",
                serde_json::to_string(&initial.activate.as_ref().unwrap().value)?,
                2,
            ),
        ] {
            provider.db.execute(
                "INSERT INTO records VALUES(?1,?2,?3)",
                params![name, value, revision],
            )?;
        }
        Ok(provider)
    }

    fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<Versioned<T>>> {
        let row: Option<(String, i64)> = self
            .db
            .query_row(
                "SELECT body,version FROM records WHERE name=?1",
                [name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(body, revision)| {
            Ok(Versioned {
                value: serde_json::from_str(&body)?,
                version: version(revision.try_into()?),
            })
        })
        .transpose()
    }

    fn snapshot(&self) -> Result<Snapshot> {
        Ok(Snapshot {
            root: self.read("root")?,
            sentinel: self.read("sentinel")?,
            create: self.read("create")?,
            activate: self.read("activate")?,
        })
    }

    fn sends(&self) -> i64 {
        self.db
            .query_row("SELECT COUNT(*) FROM sends", [], |r| r.get(0))
            .unwrap()
    }

    fn rows(&self) -> Result<Value> {
        let mut statement = self
            .db
            .prepare("SELECT name,body,version FROM records ORDER BY name")?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Value::Array(rows.into_iter().map(|(name,body,revision)| Ok(json!({"name":name,"body":serde_json::from_str::<Value>(&body)?,"version":revision}))).collect::<Result<Vec<_>>>()?))
    }

    fn apply(&mut self, plan: &Plan, cut: Cut) -> Result<()> {
        self.db.execute("INSERT INTO sends DEFAULT VALUES", [])?;
        ensure!(
            !matches!(cut, Cut::BeforeWrite),
            "fixture reply lost before mutation"
        );
        let transaction = self.db.transaction()?;
        for (name, expected) in [
            ("root", &plan.before.root),
            ("sentinel", &plan.before.sentinel),
        ] {
            let revision: i64 = transaction.query_row(
                "SELECT version FROM records WHERE name=?1",
                [name],
                |r| r.get(0),
            )?;
            ensure!(
                &version(revision.try_into()?) == expected,
                "fixture CAS refused"
            );
        }
        let key = plan.receipt.request.operation.as_str();
        for (name, body, revision) in [
            ("root", serde_json::to_string(&plan.root)?, 3),
            ("sentinel", serde_json::to_string(&plan.sentinel)?, 3),
            (key, serde_json::to_string(&plan.receipt)?, 3),
        ] {
            if name == key {
                transaction.execute(
                    "INSERT INTO records VALUES(?1,?2,?3)",
                    params![name, body, revision],
                )?;
            } else {
                transaction.execute(
                    "UPDATE records SET body=?2,version=?3 WHERE name=?1",
                    params![name, body, revision],
                )?;
            }
            ensure!(
                !matches!(cut, Cut::AfterRoot) || name != "root",
                "fixture transaction interrupted"
            );
            ensure!(
                !matches!(cut, Cut::AfterSentinel) || name != "sentinel",
                "fixture transaction interrupted"
            );
        }
        transaction.commit()?;
        ensure!(
            !matches!(cut, Cut::AfterCommit),
            "fixture acknowledgement lost after commit"
        );
        Ok(())
    }
}

/// Independent reference transition: manipulate the known initial records and
/// compute the published wire digests, never call advance::records/receipt.
fn expected(
    request: &Request,
    before: &Snapshot,
) -> Result<(AuthorityRecord, SentinelRecord, Receipt)> {
    let mut root = before.root.as_ref().unwrap().value.clone();
    let mut sentinel = before.sentinel.as_ref().unwrap().value.clone();
    let fence = Fence {
        operation: request.operation.clone(),
        request: Digest::of(&("day2-external-epoch-advance-request-v1", request))?,
        activation_receipt: request.activation.digest()?,
        previous_root: Digest::of(&root)?,
        previous_sentinel: Digest::of(&sentinel)?,
        previous_epoch: SecurityEpoch::try_from(1)?,
    };
    root.epoch = SecurityEpoch::try_from(2)?;
    root.phase = Phase::Fenced {
        fence: Box::new(fence.clone()),
    };
    sentinel.phase = Phase::Fenced {
        fence: Box::new(fence),
    };
    let receipt = Receipt {
        format: ReceiptFormat::Day2CredentialEpochAdvanceV1,
        request: request.clone(),
        request_digest: Digest::of(&("day2-external-epoch-advance-request-v1", request))?,
        after_root: Digest::of(&root)?,
        after_sentinel: Digest::of(&sentinel)?,
    };
    Ok((root, sentinel, receipt))
}

#[test]
fn conditional_advance_preserves_unknown_completion_and_fences_both_initial_requests() -> Result<()>
{
    for seed in 0u64..4 {
        for cut in [
            Cut::Known,
            Cut::BeforeWrite,
            Cut::AfterRoot,
            Cut::AfterSentinel,
            Cut::AfterCommit,
        ] {
            let (selection, before) = initial();
            let request = Request::new(&selection, Digest::of(&("advance", seed))?, &before)?;
            let plan = request.prepare(&selection, &before)?;
            let (root, sentinel, receipt) = expected(&request, &before)?;
            assert_eq!(plan.root, root);
            assert_eq!(plan.sentinel, sentinel);
            assert_eq!(plan.receipt, receipt);
            let mut provider = Provider::new(&before)?;
            let initial_rows = provider.rows()?;
            let result = provider.apply(&plan, cut);
            assert_eq!(result.is_ok(), matches!(cut, Cut::Known));
            assert!(provider.db.is_autocommit());
            let observed = provider.snapshot()?;
            let stored = provider.read::<Receipt>(request.operation.as_str())?;
            let outcome = reconcile(&selection, &request, &observed, stored.as_ref())?;
            if matches!(cut, Cut::Known | Cut::AfterCommit) {
                assert_eq!(outcome, Outcome::Applied(Box::new(receipt)));
                assert_eq!(observed.root.as_ref().unwrap().value, root);
                assert_eq!(observed.sentinel.as_ref().unwrap().value, sentinel);
                assert_eq!(observed.root.as_ref().unwrap().version, version(3));
                assert_eq!(observed.sentinel.as_ref().unwrap().version, version(3));
                let create = InitialRequest::CreateInitialAuthority {
                    bootstrap: request.activation.request.bootstrap().clone(),
                };
                for old in [&create, &request.activation.request] {
                    assert!(super::super::reconcile(&selection, old, &observed).is_err());
                }
                assert!(request.prepare(&selection, &observed).is_err());
                assert!(Request::new(&selection, Digest::new(b"new attempt"), &observed).is_err());
                let after = provider.rows()?;
                assert!(provider.apply(&plan, Cut::Known).is_err());
                assert_eq!(provider.rows()?, after);
                assert_eq!(provider.sends(), 2);
            } else {
                assert_eq!(outcome, Outcome::NotApplied);
                assert_eq!(provider.rows()?, initial_rows);
                assert_eq!(provider.sends(), 1);
            }
        }
    }
    Ok(())
}

#[test]
fn exact_request_receipt_and_both_versions_are_required() -> Result<()> {
    let (selection, before) = initial();
    let request = Request::new(&selection, Digest::new(b"advance"), &before)?;
    for which in ["root", "sentinel"] {
        let mut changed = before.clone();
        if which == "root" {
            changed.root.as_mut().unwrap().version = version(9);
        } else {
            changed.sentinel.as_mut().unwrap().version = version(9);
        }
        assert!(request.prepare(&selection, &changed).is_err());
    }
    assert_eq!(request.selection, Digest::of(&selection)?);
    for (pointer, replacement) in [
        ("/scope/installation", json!("other")),
        ("/scope/environment", json!("other")),
        ("/scope/app", json!("other")),
        ("/provider/project", json!("other-project")),
        ("/provider/project_number", json!(8)),
        (
            "/provider/database_uid",
            json!("11234567-89ab-4cde-8fab-0123456789ab"),
        ),
        (
            "/provider/iam_source/service_account_uid",
            json!("100000000000000000008"),
        ),
        ("/key_set", json!(Digest::new(b"other keys"))),
        ("/max_lease_seconds", json!(4)),
    ] {
        let mut value = serde_json::to_value(&selection)?;
        *value
            .pointer_mut(pointer)
            .context("selection fixture field")? = replacement;
        let foreign: EpochStore = serde_json::from_value(value)?;
        assert!(request.prepare(&foreign, &before).is_err(), "{pointer}");
    }
    let mut provider = Provider::new(&before)?;
    provider.apply(&request.prepare(&selection, &before)?, Cut::Known)?;
    let observed = provider.snapshot()?;
    let stored = provider
        .read::<Receipt>(request.operation.as_str())?
        .unwrap();
    assert!(reconcile(&selection, &request, &observed, None).is_err());
    assert!(reconcile(&selection, &request, &before, Some(&stored)).is_err());
    let mut changed = stored.clone();
    changed.value.request_digest = Digest::new(b"foreign receipt");
    assert!(reconcile(&selection, &request, &observed, Some(&changed)).is_err());
    for component in ["root", "sentinel", "create", "activate"] {
        let mut changed = observed.clone();
        match component {
            "root" => changed.root = before.root.clone(),
            "sentinel" => changed.sentinel = before.sentinel.clone(),
            "create" => {
                changed.create.as_mut().unwrap().value.request_digest =
                    Digest::new(b"substituted history")
            }
            "activate" => {
                changed.activate.as_mut().unwrap().value.request_digest =
                    Digest::new(b"substituted history")
            }
            _ => unreachable!(),
        }
        assert!(
            reconcile(&selection, &request, &changed, Some(&stored)).is_err(),
            "{component}"
        );
    }
    let competing = Request::new(&selection, Digest::new(b"competing"), &before)?;
    assert!(
        provider
            .apply(&competing.prepare(&selection, &before)?, Cut::Known)
            .is_err()
    );
    assert!(reconcile(&selection, &competing, &observed, None).is_err());
    Ok(())
}

#[test]
fn fenced_phase_wire_is_closed_and_preserves_the_bootstrap_epoch() -> Result<()> {
    let (selection, before) = initial();
    let request = Request::new(&selection, Digest::new(b"advance"), &before)?;
    let plan = request.prepare(&selection, &before)?;
    assert_eq!(plan.root.epoch.value(), 2);
    assert_eq!(plan.sentinel.initial_epoch.value(), 1);
    let encoded = serde_json::to_value(&plan.root.phase)?;
    assert_eq!(
        serde_json::from_value::<Phase>(encoded.clone())?,
        plan.root.phase
    );
    for mutation in ["extra", "null", "completion", "zero", "number"] {
        let mut value = encoded.clone();
        match mutation {
            "extra" => value["extra"] = json!(true),
            "null" => value["fence"] = Value::Null,
            "completion" => value["completion"] = json!({}),
            "zero" => value["fence"]["previous_epoch"] = json!("0"),
            "number" => value["fence"]["previous_epoch"] = json!(1),
            _ => unreachable!(),
        }
        assert!(
            serde_json::from_value::<Phase>(value).is_err(),
            "{mutation}"
        );
    }
    let bootstrap: &Bootstrap = request.activation.request.bootstrap();
    for reused in [
        &bootstrap.create_operation,
        request.activation.request.operation(),
    ] {
        assert!(Request::new(&selection, reused.clone(), &before).is_err());
    }
    let fence = serde_json::to_string(&encoded["fence"])?;
    let duplicate = format!("{{\"phase\":\"fenced\",\"fence\":{fence},\"fence\":{fence}}}");
    assert!(serde_json::from_str::<Phase>(&duplicate).is_err());
    assert!(crate::json::decode::<Phase>(duplicate.as_bytes()).is_err());
    let repeated = serde_json::to_string(&encoded["fence"]["operation"])?;
    let nested = fence.replacen("{", &format!("{{\"operation\":{repeated},"), 1);
    let nested = format!("{{\"phase\":\"fenced\",\"fence\":{nested}}}");
    assert!(serde_json::from_str::<Phase>(&nested).is_err());
    let mut sequence = encoded.clone();
    sequence["fence"] = json!([
        encoded["fence"]["operation"],
        encoded["fence"]["request"],
        encoded["fence"]["activation_receipt"],
        encoded["fence"]["previous_root"],
        encoded["fence"]["previous_sentinel"],
        encoded["fence"]["previous_epoch"],
    ]);
    assert_eq!(
        serde_json::from_value::<Fence>(sequence["fence"].clone())?,
        serde_json::from_value::<Fence>(encoded["fence"].clone())?
    );
    assert!(serde_json::from_value::<Phase>(sequence).is_err());
    let completion = serde_json::to_value(&before.root.as_ref().unwrap().value.phase)?;
    let completion_payload = serde_json::to_string(&completion["completion"])?;
    let repeated = serde_json::to_string(&completion["completion"]["operation"])?;
    let duplicate_completion =
        completion_payload.replacen("{", &format!("{{\"operation\":{repeated},"), 1);
    let raw =
        format!("{{\"phase\":\"active_first_holder\",\"completion\":{duplicate_completion}}}");
    assert!(serde_json::from_str::<Phase>(&raw).is_err());
    let mut sequence = completion.clone();
    sequence["completion"] = json!([
        completion["completion"]["operation"],
        completion["completion"]["request"],
        completion["completion"]["parent_receipt"],
        completion["completion"]["before"],
        completion["completion"]["holder"],
    ]);
    assert_eq!(
        serde_json::from_value::<super::super::Completion>(sequence["completion"].clone())?,
        serde_json::from_value::<super::super::Completion>(completion["completion"].clone())?
    );
    assert!(serde_json::from_value::<Phase>(sequence).is_err());
    let mut unsupported = serde_json::to_value(&request.activation.request)?;
    unsupported["action"] = json!("advance_epoch");
    assert!(serde_json::from_value::<InitialRequest>(unsupported).is_err());
    Ok(())
}
