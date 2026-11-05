use super::super::{Holder, Request as InitialRequest, Versions};
use super::*;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

mod approval_use;
mod history;
#[cfg(unix)]
mod process;

pub(super) fn version(n: u64) -> super::super::UpdateTime {
    format!("2026-11-04T00:00:00.{n:06}Z").try_into().unwrap()
}

pub(super) fn initial() -> (EpochStore, Snapshot) {
    let selection = crate::security_epoch::tests::selection();
    let create = crate::security_epoch::tests::create();
    let activate = InitialRequest::CompleteInitialFirstActivation {
        bootstrap: create.bootstrap().clone(),
        operation: Digest::new(b"restore-fixture-initial-activation"),
        parent_receipt: create.receipt().unwrap().digest().unwrap(),
        before: Versions {
            root: version(1),
            sentinel: version(1),
        },
        holder: Holder {
            principal: Digest::new(b"incumbent-app"),
            pod_uid: "11234567-89ab-4cde-8fab-0123456789ab".into(),
            process_incarnation: Digest::new(b"incumbent-process"),
            ephemeral_key: Digest::new(b"incumbent-key"),
        },
    };
    let (root, sentinel) = activate.records().unwrap();
    (
        selection,
        Snapshot {
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
        },
    )
}

pub(super) fn intent(selected: &EpochStore, seed: u64) -> Intent {
    Intent {
        operation: Digest::of(&("restore-fixture-operation", seed)).unwrap(),
        archive: Backup {
            scope: selected.scope.clone(),
            authority: selected.authority_key().unwrap(),
            source_incarnation: crate::security_epoch::tests::create()
                .bootstrap()
                .manifest
                .database_incarnation
                .clone(),
            security_epoch: 1,
            full_archive_digest: Digest::of(&("complete-archive", seed)).unwrap(),
            image: Digest::of(&("backup-image", seed)).unwrap(),
            schema: Digest::new(b"exact-private-schema"),
            artifact: Digest::new(b"admitted-artifact"),
            key_set: selected.key_set.clone(),
            required_keys: vec![ExactKey {
                binding: BindingRef {
                    id: "custody".to_owned().try_into().unwrap(),
                    revision: Digest::new(b"binding"),
                },
                version: "version-7".into(),
                purpose: KeyPurpose::CustodyEncryption,
            }],
        },
        target_incarnation: Digest::of(&("new-database-incarnation", seed)).unwrap(),
    }
}

pub(super) fn current(selected: &EpochStore, intent: &Intent, before: &Snapshot) -> Current {
    let root = &before.root.as_ref().unwrap().value;
    let Phase::ActiveFirstHolder { completion } = &root.phase else {
        panic!("fixture root");
    };
    let target = crate::security_epoch::restore_approval::TargetBinding {
        scope: selected.scope.clone(),
        binding_generation: 1,
        authority: selected.authority_key().unwrap(),
        selection: Digest::of(selected).unwrap(),
        incarnation: intent.target_incarnation.clone(),
        security_epoch: 2,
        artifact: intent.archive.artifact.clone(),
        schema: intent.archive.schema.clone(),
    };
    let custody = intent.archive.required_keys[0].binding.clone();
    let executor = crate::security_epoch::restore_approval::AdminIdentity {
        email: "operator@example.test".into(),
        subject: "stable-operator-subject".into(),
    };
    Current {
        target: target.clone(),
        custody: custody.clone(),
        executor: executor.clone(),
        grant: Grant {
            intent: intent.commitment(selected).unwrap(),
            issuer: Digest::new(b"independent-maintenance-issuer"),
            revision: Digest::new(b"original-approval-revision"),
            policy: Digest::new(b"restore-only-policy"),
            clock_domain: Digest::new(b"maintenance-clock-domain"),
            approval: crate::security_epoch::restore_approval::ApprovalRequest {
                grant_id: Digest::of(&("approval-id", &intent.operation)).unwrap(),
                full_archive_digest: intent.archive.full_archive_digest.clone(),
                target,
                executor,
                custody,
                approved_at: 1000,
                expires_at: 4600,
            },
            fence: Fence {
                root: Digest::of(root).unwrap(),
                holder: Digest::of(&completion.holder).unwrap(),
                receipt: Digest::new(b"controlled-fencing-statement"),
            },
        },
        enabled: true,
        observed_at: 1000,
        ready_until: 1005,
        available_keys: intent.archive.required_keys.clone(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cut {
    BeforeWrite,
    AfterRoot,
    AfterSentinel,
    AfterAdvanceReceipt,
    AfterRestoreLedger,
    AfterCommit,
    Complete,
}

impl Cut {
    const ALL: [Self; 7] = [
        Self::BeforeWrite,
        Self::AfterRoot,
        Self::AfterSentinel,
        Self::AfterAdvanceReceipt,
        Self::AfterRestoreLedger,
        Self::AfterCommit,
        Self::Complete,
    ];

    fn committed(self) -> bool {
        matches!(self, Self::AfterCommit | Self::Complete)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    name: String,
    body: Value,
    version: i64,
}

fn initial_rows(before: &Snapshot) -> Result<Vec<Row>> {
    Ok(vec![
        Row {
            name: "activate".into(),
            body: serde_json::to_value(&before.activate.as_ref().unwrap().value)?,
            version: 2,
        },
        Row {
            name: "create".into(),
            body: serde_json::to_value(&before.create.as_ref().unwrap().value)?,
            version: 1,
        },
        Row {
            name: "root".into(),
            body: serde_json::to_value(&before.root.as_ref().unwrap().value)?,
            version: 2,
        },
        Row {
            name: "sentinel".into(),
            body: serde_json::to_value(&before.sentinel.as_ref().unwrap().value)?,
            version: 2,
        },
    ])
}

/// Interprets conditional versions, body equality and create-only keys only.
/// It does not implement restore decisions, maintenance or native fencing.
struct Provider {
    db: Connection,
}

impl Provider {
    fn open(path: &Path, initial: &Snapshot) -> Result<Self> {
        let db = Connection::open(path)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS records(name TEXT PRIMARY KEY, body TEXT NOT NULL, version INTEGER NOT NULL) STRICT;
            CREATE TABLE IF NOT EXISTS sends(id INTEGER PRIMARY KEY) STRICT;")?;
        let empty: bool =
            db.query_row("SELECT NOT EXISTS(SELECT 1 FROM records)", [], |r| r.get(0))?;
        if empty {
            let tx = db.unchecked_transaction()?;
            for row in initial_rows(initial)? {
                tx.execute(
                    "INSERT INTO records VALUES(?1,?2,?3)",
                    params![row.name, serde_json::to_string(&row.body)?, row.version],
                )?;
            }
            tx.commit()?;
        }
        Ok(Self { db })
    }

    fn read<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<Versioned<T>>> {
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
                value: crate::json::decode_evidence(body.as_bytes())?,
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

    fn rows(&self) -> Result<Vec<Row>> {
        let mut query = self
            .db
            .prepare("SELECT name,body,version FROM records ORDER BY name")?;
        let raw = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(|(name, body, version)| {
                Ok(Row {
                    name,
                    body: crate::json::decode_evidence(body.as_bytes())?,
                    version,
                })
            })
            .collect()
    }

    fn sends(&self) -> Result<u64> {
        let count: i64 = self
            .db
            .query_row("SELECT count(*) FROM sends", [], |r| r.get(0))?;
        Ok(count.try_into()?)
    }

    fn reopen(&mut self, path: &Path) -> Result<()> {
        let old = std::mem::replace(&mut self.db, Connection::open_in_memory()?);
        drop(old);
        self.db = Connection::open(path)?;
        Ok(())
    }

    fn advance_name(selected: &EpochStore, plan: &Plan) -> Result<String> {
        Ok(format!(
            "advance/{}",
            plan.receipt
                .request
                .intent
                .advance_operation(selected)?
                .as_str()
        ))
    }

    fn ledger_name(plan: &Plan) -> String {
        format!("restore/{}", plan.receipt.request.intent.operation.as_str())
    }

    fn outcome(&self, selected: &EpochStore, plan: &Plan) -> Result<Outcome> {
        reconcile(
            selected,
            plan,
            &self.snapshot()?,
            self.read(&Self::advance_name(selected, plan)?)?.as_ref(),
            self.read(&Self::ledger_name(plan))?.as_ref(),
        )
    }

    fn apply(
        &mut self,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        plan: &Plan,
        mut checkpoint: impl FnMut(Cut) -> Result<()>,
    ) -> Result<()> {
        plan.revalidate(
            selected,
            current,
            at,
            &self.snapshot()?,
            self.read(&Self::ledger_name(plan))?.as_ref(),
        )?;
        self.db.execute("INSERT INTO sends DEFAULT VALUES", [])?;
        checkpoint(Cut::BeforeWrite)?;
        let tx = self.db.transaction()?;
        for (name, before, after, cut) in [
            (
                "root",
                serde_json::to_string(&serde_json::to_value(
                    &plan.before.root.as_ref().unwrap().value,
                )?)?,
                serde_json::to_string(&plan.advance.root)?,
                Cut::AfterRoot,
            ),
            (
                "sentinel",
                serde_json::to_string(&serde_json::to_value(
                    &plan.before.sentinel.as_ref().unwrap().value,
                )?)?,
                serde_json::to_string(&plan.advance.sentinel)?,
                Cut::AfterSentinel,
            ),
        ] {
            let changed = tx.execute(
                "UPDATE records SET body=?1,version=3 WHERE name=?2 AND version=2 AND body=?3",
                params![after, name, before],
            )?;
            ensure!(changed == 1, "fixture_restore_conditional_conflict");
            checkpoint(cut)?;
        }
        for (name, body, cut) in [
            (
                Self::advance_name(selected, plan)?,
                serde_json::to_string(&plan.advance.receipt)?,
                Cut::AfterAdvanceReceipt,
            ),
            (
                Self::ledger_name(plan),
                serde_json::to_string(&plan.receipt)?,
                Cut::AfterRestoreLedger,
            ),
        ] {
            tx.execute("INSERT INTO records VALUES(?1,?2,3)", params![name, body])?;
            checkpoint(cut)?;
        }
        tx.commit()?;
        checkpoint(Cut::AfterCommit)
    }

    fn apply_cut(
        &mut self,
        selected: &EpochStore,
        current: &Current,
        at: i64,
        plan: &Plan,
        cut: Cut,
    ) -> Result<()> {
        self.apply(selected, current, at, plan, |reached| {
            ensure!(reached != cut, "fixture_restore_interrupted");
            Ok(())
        })
    }
}

/// Independent complete wire model. Immutable seeds and hashing/serialization
/// are shared; no production request/receipt/transition helper predicts state.
fn expected(
    selected: &EpochStore,
    intent: &Intent,
    current: &Current,
    before: &Snapshot,
    at: i64,
) -> Result<Vec<Row>> {
    let original = initial_rows(before)?;
    let mut rows = original
        .into_iter()
        .map(|r| (r.name.clone(), r))
        .collect::<BTreeMap<_, _>>();
    let intent_hash = Digest::of(&(
        "day2-secure-restore-intent-v1",
        selected,
        intent,
        "reissue_and_reauthorize_v1",
    ))?;
    let operation = Digest::of(&("day2-secure-restore-advance-operation-v1", intent_hash))?;
    // Wire order is part of Digest::of, which hashes typed JSON bytes. The
    // reference owns its wire records rather than hashing sorted Value maps or
    // calling the production record/receipt constructors.
    #[derive(Serialize)]
    struct Advance<'a> {
        selection: Digest,
        operation: &'a Digest,
        activation: &'a super::super::Receipt,
        before: Versions,
    }
    #[derive(Serialize)]
    struct ReferenceFence<'a> {
        operation: &'a Digest,
        request: &'a Digest,
        activation_receipt: Digest,
        previous_root: Digest,
        previous_sentinel: Digest,
        previous_epoch: &'static str,
    }
    #[derive(Serialize)]
    struct ReferencePhase<'a> {
        phase: &'static str,
        fence: ReferenceFence<'a>,
    }
    #[derive(Serialize)]
    struct Root<'a> {
        format: &'static str,
        bootstrap: &'a super::super::Bootstrap,
        epoch: &'static str,
        phase: &'a ReferencePhase<'a>,
    }
    #[derive(Serialize)]
    struct Sentinel<'a> {
        format: &'static str,
        bootstrap: &'a super::super::Bootstrap,
        initial_epoch: &'static str,
        phase: &'a ReferencePhase<'a>,
    }
    #[derive(Serialize)]
    struct AdvanceReceipt<'a> {
        format: &'static str,
        request: &'a Advance<'a>,
        request_digest: &'a Digest,
        after_root: Digest,
        after_sentinel: Digest,
    }
    #[derive(Serialize)]
    struct ReferenceRequest<'a> {
        intent: &'a Intent,
        advance: &'a Advance<'a>,
        authorization: &'a Current,
        prepared_at: i64,
    }
    #[derive(Serialize)]
    struct Ledger<'a> {
        format: &'static str,
        request: &'a ReferenceRequest<'a>,
        request_digest: Digest,
        advance_receipt: Digest,
        target_epoch: u64,
        policy: &'static str,
    }
    let activation = &before.activate.as_ref().unwrap().value;
    let advance = Advance {
        selection: Digest::of(selected)?,
        operation: &operation,
        activation,
        before: Versions {
            root: version(2),
            sentinel: version(2),
        },
    };
    let advance_hash = Digest::of(&("day2-external-epoch-advance-request-v1", &advance))?;
    let phase = ReferencePhase {
        phase: "fenced",
        fence: ReferenceFence {
            operation: &operation,
            request: &advance_hash,
            activation_receipt: Digest::of(&("day2-external-epoch-receipt-v1", activation))?,
            previous_root: Digest::of(&before.root.as_ref().unwrap().value)?,
            previous_sentinel: Digest::of(&before.sentinel.as_ref().unwrap().value)?,
            previous_epoch: "1",
        },
    };
    let root = Root {
        format: "day2_credential_authority_v1",
        bootstrap: &before.root.as_ref().unwrap().value.bootstrap,
        epoch: "2",
        phase: &phase,
    };
    let sentinel = Sentinel {
        format: "day2_credential_bootstrap_v1",
        bootstrap: &before.sentinel.as_ref().unwrap().value.bootstrap,
        initial_epoch: "1",
        phase: &phase,
    };
    let advance_receipt = AdvanceReceipt {
        format: "day2_credential_epoch_advance_v1",
        request: &advance,
        request_digest: &advance_hash,
        after_root: Digest::of(&root)?,
        after_sentinel: Digest::of(&sentinel)?,
    };
    let request = ReferenceRequest {
        intent,
        advance: &advance,
        authorization: current,
        prepared_at: at,
    };
    let ledger = Ledger {
        format: "day2_secure_restore_reservation_v1",
        request: &request,
        request_digest: Digest::of(&("day2-secure-restore-request-v1", &request))?,
        advance_receipt: Digest::of(&advance_receipt)?,
        target_epoch: 2,
        policy: "reissue_and_reauthorize_v1",
    };
    let root = serde_json::to_value(&root)?;
    let sentinel = serde_json::to_value(&sentinel)?;
    let advance_receipt = serde_json::to_value(&advance_receipt)?;
    let ledger = serde_json::to_value(&ledger)?;
    for (name, body) in [
        ("root".to_owned(), root),
        ("sentinel".to_owned(), sentinel),
        (format!("advance/{}", operation.as_str()), advance_receipt),
        (format!("restore/{}", intent.operation.as_str()), ledger),
    ] {
        rows.insert(
            name.clone(),
            Row {
                name,
                body,
                version: 3,
            },
        );
    }
    Ok(rows.into_values().collect())
}

#[test]
fn reservation_atomically_fences_all_four_records_and_never_reactivates_the_old_holder()
-> Result<()> {
    let (selected, before) = initial();
    let intent = intent(&selected, 7);
    let current = current(&selected, &intent, &before);
    let request = Request::new(&selected, intent, &current, 1000, &before)?;
    for cut in Cut::ALL {
        let directory = tempfile::tempdir()?;
        let mut provider = Provider::open(&directory.path().join("epoch.sqlite"), &before)?;
        let plan = request.prepare(&selected, &current, 1000, &before, None)?;
        let result = provider.apply_cut(&selected, &current, 1000, &plan, cut);
        assert_eq!(result.is_ok(), cut == Cut::Complete);
        assert_eq!(provider.sends()?, 1);
        assert_eq!(
            provider.rows()?,
            if cut.committed() {
                expected(&selected, &request.intent, &current, &before, 1000)?
            } else {
                initial_rows(&before)?
            }
        );
        assert!(
            matches!(provider.outcome(&selected, &plan)?, Outcome::Applied(_)) == cut.committed()
        );
        if cut.committed() {
            assert!(
                plan.revalidate(&selected, &current, 1000, &provider.snapshot()?, None)
                    .is_err()
            );
            let activate = &before.activate.as_ref().unwrap().value.request;
            assert!(super::super::reconcile(&selected, activate, &provider.snapshot()?).is_err());
            let create = &before.create.as_ref().unwrap().value.request;
            assert!(super::super::reconcile(&selected, create, &provider.snapshot()?).is_err());
        }
    }
    Ok(())
}

#[test]
fn fresh_authority_exact_keys_fence_and_clock_are_required_without_renewing_the_grant() -> Result<()>
{
    let (selected, before) = initial();
    let intent = intent(&selected, 8);
    let current = current(&selected, &intent, &before);
    let request = Request::new(&selected, intent, &current, 1000, &before)?;
    let plan = request.prepare(&selected, &current, 1000, &before, None)?;
    for field in 0..16 {
        let mut changed = current.clone();
        let mut at = 1001;
        match field {
            0 => changed.enabled = false,
            1 => changed.available_keys.clear(),
            2 => changed.available_keys[0].version = "replacement".into(),
            3 => changed.grant.revision = Digest::new(b"revoked-approval"),
            4 => changed.grant.fence.holder = Digest::new(b"foreign-holder"),
            5 => changed.grant.fence.root = Digest::new(b"foreign-root"),
            6 => changed.grant.clock_domain = Digest::new(b"replacement-clock"),
            7 => at = 999,
            8 => at = 1005,
            9 => {
                changed.observed_at = 4599;
                changed.ready_until = 4601;
                at = 4599;
            }
            10 => changed.grant.approval.expires_at = 1200,
            11 => changed.grant.issuer = Digest::new(b"foreign-maintenance-issuer"),
            12 => changed.grant.policy = Digest::new(b"foreign-maintenance-policy"),
            13 => changed.grant.intent = Digest::new(b"another-restore-intent"),
            14 => changed.grant.fence.receipt = Digest::new(b"replacement-fence-statement"),
            15 => changed.available_keys[0].purpose = KeyPurpose::CustodyVerifier,
            _ => unreachable!(),
        }
        assert!(
            plan.revalidate(&selected, &changed, at, &before, None)
                .is_err(),
            "field {field}"
        );
    }
    let mut fresh = current.clone();
    fresh.observed_at = 4599;
    fresh.ready_until = 4600;
    plan.revalidate(&selected, &fresh, 4599, &before, None)?;
    assert!(
        plan.revalidate(&selected, &fresh, 4600, &before, None)
            .is_err()
    );
    let mut original = current.clone();
    original.observed_at = 1002;
    let later = Request::new(&selected, request.intent.clone(), &original, 1002, &before)?
        .prepare(&selected, &original, 1002, &before, None)?;
    let mut rewound = original.clone();
    rewound.observed_at = 1001;
    // Even a later caller time cannot hide an observation older than the
    // captured original source sample. This does not create a new clock.
    assert!(
        later
            .revalidate(&selected, &rewound, 1003, &before, None)
            .is_err()
    );
    Ok(())
}

#[test]
fn different_backup_target_schema_key_manifest_and_selected_store_cannot_share_a_fence()
-> Result<()> {
    let (selected, before) = initial();
    let original = intent(&selected, 9);
    let current = current(&selected, &original, &before);
    let original_operation = original.advance_operation(&selected)?;
    for field in 0..12 {
        let mut changed = original.clone();
        match field {
            0 => changed.archive.image = Digest::new(b"other-image"),
            1 => changed.target_incarnation = Digest::new(b"other-target"),
            2 => changed.archive.schema = Digest::new(b"other-schema"),
            3 => changed.archive.artifact = Digest::new(b"other-artifact"),
            4 => changed.archive.required_keys[0].version = "other-key".into(),
            5 => changed.archive.scope.app = "foreign".to_owned().try_into()?,
            6 => changed.archive.security_epoch = 2,
            7 => changed.target_incarnation = changed.archive.source_incarnation.clone(),
            8 => changed.archive.authority = Digest::new(b"other-authority"),
            9 => changed.archive.key_set = Digest::new(b"other-key-set"),
            10 => changed.archive.source_incarnation = Digest::new(b"foreign-source-database"),
            11 => {
                changed.operation = before
                    .root
                    .as_ref()
                    .unwrap()
                    .value
                    .bootstrap
                    .create_operation
                    .clone()
            }
            _ => unreachable!(),
        }
        assert!(Request::new(&selected, changed.clone(), &current, 1000, &before).is_err());
        if let Ok(operation) = changed.advance_operation(&selected) {
            assert_ne!(operation, original_operation);
        }
    }
    let request = Request::new(&selected, original, &current, 1000, &before)?;
    for epoch in [0, 2, u64::MAX] {
        let mut unsupported = request.intent.clone();
        unsupported.archive.security_epoch = epoch;
        assert!(unsupported.commitment(&selected).is_err());
    }
    for operation in [
        before
            .root
            .as_ref()
            .unwrap()
            .value
            .bootstrap
            .create_operation
            .clone(),
        before
            .activate
            .as_ref()
            .unwrap()
            .value
            .request
            .operation()
            .clone(),
    ] {
        let mut reused = request.intent.clone();
        reused.operation = operation;
        // Rebind the controlled authorization to the changed intent, so the
        // operation-reuse check itself must refuse, not an earlier hash mismatch.
        let rebound = self::current(&selected, &reused, &before);
        assert!(Request::new(&selected, reused, &rebound, 1000, &before).is_err());
    }
    let mut other_store = selected.clone();
    other_store.max_lease_seconds += 1;
    assert!(
        request
            .prepare(&other_store, &current, 1000, &before, None)
            .is_err()
    );
    let mut changed = before.clone();
    changed.root.as_mut().unwrap().version = version(8);
    assert!(
        request
            .prepare(&selected, &current, 1000, &changed, None)
            .is_err()
    );
    changed = before.clone();
    changed.root.as_mut().unwrap().value.epoch = 2.try_into()?;
    assert!(Request::new(&selected, request.intent.clone(), &current, 1000, &changed).is_err());
    Ok(())
}

#[test]
fn receipt_loss_partial_restore_and_foreign_ledger_never_become_not_applied_or_readiness()
-> Result<()> {
    let (selected, before) = initial();
    let intent = intent(&selected, 10);
    let current = current(&selected, &intent, &before);
    let plan = Request::new(&selected, intent, &current, 1000, &before)?
        .prepare(&selected, &current, 1000, &before, None)?;
    let directory = tempfile::tempdir()?;
    let mut provider = Provider::open(&directory.path().join("epoch.sqlite"), &before)?;
    provider.apply_cut(&selected, &current, 1000, &plan, Cut::Complete)?;
    let after = provider.snapshot()?;
    let advance = provider
        .read::<advance::Receipt>(&Provider::advance_name(&selected, &plan)?)?
        .unwrap();
    let ledger = provider
        .read::<Receipt>(&Provider::ledger_name(&plan))?
        .unwrap();
    for (state, a, r) in [
        (&after, None, Some(&ledger)),
        (&after, Some(&advance), None),
        (&after, None, None),
        (&before, Some(&advance), Some(&ledger)),
        (&before, None, Some(&ledger)),
    ] {
        assert_eq!(reconcile(&selected, &plan, state, a, r)?, Outcome::Conflict);
    }
    let mut foreign = ledger.clone();
    foreign.value.request.intent.archive.image = Digest::new(b"substituted-backup");
    assert_eq!(
        reconcile(&selected, &plan, &after, Some(&advance), Some(&foreign))?,
        Outcome::Conflict
    );
    // Reconciliation remains historical after the original authorization ends.
    let mut revoked = current.clone();
    revoked.enabled = false;
    assert!(
        plan.revalidate(&selected, &revoked, 1200, &after, Some(&ledger))
            .is_err()
    );
    assert!(matches!(
        reconcile(&selected, &plan, &after, Some(&advance), Some(&ledger))?,
        Outcome::Applied(_)
    ));
    assert_eq!(provider.sends()?, 1);
    Ok(())
}

#[test]
fn competing_restores_and_equal_value_rewrites_defeat_stale_preparations() -> Result<()> {
    let (selected, before) = initial();
    let first = intent(&selected, 11);
    let current = current(&selected, &first, &before);
    let plan = Request::new(&selected, first, &current, 1000, &before)?
        .prepare(&selected, &current, 1000, &before, None)?;
    let second = intent(&selected, 12);
    let other_current = self::current(&selected, &second, &before);
    let other = Request::new(&selected, second, &other_current, 1000, &before)?.prepare(
        &selected,
        &other_current,
        1000,
        &before,
        None,
    )?;
    let directory = tempfile::tempdir()?;
    let mut provider = Provider::open(&directory.path().join("epoch.sqlite"), &before)?;
    provider.apply_cut(&selected, &current, 1000, &plan, Cut::Complete)?;
    assert!(
        provider
            .apply_cut(&selected, &other_current, 1000, &other, Cut::Complete)
            .is_err()
    );
    assert_eq!(provider.sends()?, 1);
    // Provider revisions are opaque CAS identities, not ordered epochs. An
    // identical rewrite after commit preserves historical Applied, but cannot
    // make the original plan dispatchable. Reusing the before token conflicts.
    provider
        .db
        .execute("UPDATE records SET version=4 WHERE name='root'", [])?;
    assert!(matches!(
        provider.outcome(&selected, &plan)?,
        Outcome::Applied(_)
    ));
    assert!(
        plan.revalidate(&selected, &current, 1000, &provider.snapshot()?, None)
            .is_err()
    );
    provider
        .db
        .execute("UPDATE records SET version=2 WHERE name='root'", [])?;
    assert_eq!(provider.outcome(&selected, &plan)?, Outcome::Conflict);
    let mut rewritten = before.clone();
    rewritten.root.as_mut().unwrap().version = version(9);
    assert!(
        plan.revalidate(&selected, &current, 1000, &rewritten, None)
            .is_err()
    );
    assert_eq!(
        reconcile(&selected, &plan, &rewritten, None, None)?,
        Outcome::Conflict
    );
    Ok(())
}

#[test]
fn closed_restore_codec_rejects_extras_duplicates_and_unpinned_keys() -> Result<()> {
    let (selected, before) = initial();
    let intent = intent(&selected, 13);
    let current = current(&selected, &intent, &before);
    let request = Request::new(&selected, intent, &current, 1000, &before)?;
    let encoded = serde_json::to_string(&request)?;
    assert_eq!(
        crate::json::decode_evidence::<Request>(encoded.as_bytes())?,
        request
    );
    let extra = encoded.replacen('{', "{\"unknown\":true,", 1);
    assert!(crate::json::decode_evidence::<Request>(extra.as_bytes()).is_err());
    let duplicate = encoded.replacen(
        "\"security_epoch\":1",
        "\"security_epoch\":1,\"security_epoch\":1",
        1,
    );
    assert_ne!(duplicate, encoded);
    assert!(crate::json::decode_evidence::<Request>(duplicate.as_bytes()).is_err());
    for version in [
        "latest".to_owned(),
        "LATEST".to_owned(),
        "current".to_owned(),
        "Current".to_owned(),
        "latest/alias".to_owned(),
        String::new(),
        "x".repeat(129),
    ] {
        let mut malformed = request.intent.clone();
        malformed.archive.required_keys[0].version = version;
        assert!(malformed.commitment(&selected).is_err());
    }
    let mut malformed = request.intent.clone();
    malformed
        .archive
        .required_keys
        .push(malformed.archive.required_keys[0].clone());
    assert!(malformed.commitment(&selected).is_err());
    Ok(())
}
