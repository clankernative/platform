#[path = "support/release.rs"]
mod support;

use anyhow::{Result, ensure};
use day2_control::{
    BindingRef, Digest,
    journal::{Journal, RecoveryMode},
    provider_evidence::{EffectAcknowledgement, ReadBarrier, RevisionToken, StateEvidence},
    release::ReleaseApproval,
    runtime_secret::{ResourceScope, VersionState},
    secret_retirement::{
        Capabilities, LEASE_MILLIS, Recipe, RetirementClaim, RetirementEffectResult,
        RetirementExecutionHost, RetirementLease, RetirementObservation, RetirementObserved,
        RetirementOperation, RetirementPhase, RetirementPlan, RetirementRejection,
        RetirementSnapshot, RetirementStepRequest, RetirementTerminal,
    },
};
use durable_temporal::StepOutcome;
use rusqlite::{Connection, params};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};
use support::{actor, name};

/// Only a unit-test selector. Live and simulation drivers use the compiled Roc
/// recipe, whose phase/ordinal mapping has a separate native compiler test.
struct TestRecipe;
impl Recipe for TestRecipe {
    fn revision(&self) -> Result<Digest> {
        Ok(Digest::new(b"retirement-test-recipe"))
    }
    fn choose(&self, snapshot: &RetirementSnapshot) -> Result<RetirementStepRequest> {
        let (operation, label) = match snapshot.phase {
            RetirementPhase::WaitingConsumers => {
                (RetirementOperation::WaitConsumers, "wait_consumers")
            }
            RetirementPhase::Eligible => (RetirementOperation::DisableVersion, "disable_version"),
            RetirementPhase::WaitingDisabled => {
                (RetirementOperation::ObserveDisabled, "observe_disabled")
            }
            RetirementPhase::Disabled => (RetirementOperation::Complete, "complete"),
            _ => anyhow::bail!("terminal test snapshot"),
        };
        Ok(RetirementStepRequest {
            name: name(label),
            ordinal: snapshot.next_step,
            operation,
        })
    }
}

struct Provider {
    path: PathBuf,
    binding: BindingRef,
    mode: AtomicU8,
    qualified_absence: AtomicBool,
}
impl Provider {
    fn new(path: &Path, binding: BindingRef) -> Result<Self> {
        Connection::open(path)?.execute_batch(
            "CREATE TABLE IF NOT EXISTS receipts(effect TEXT PRIMARY KEY,plan TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS calls(kind TEXT NOT NULL,reconcile INTEGER NOT NULL);",
        )?;
        Ok(Self {
            path: path.to_owned(),
            binding,
            mode: AtomicU8::new(0),
            qualified_absence: AtomicBool::new(false),
        })
    }
    fn mutations(&self) -> Result<i64> {
        Ok(Connection::open(&self.path)?
            .query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))?)
    }
    fn executions(&self) -> Result<i64> {
        Ok(Connection::open(&self.path)?.query_row(
            "SELECT count(*) FROM calls WHERE kind='disable' AND reconcile=0",
            [],
            |r| r.get(0),
        )?)
    }
}
impl Capabilities for Provider {
    fn validate(&self, plan: &RetirementPlan) -> Result<()> {
        ensure!(
            plan.resources == self.binding,
            "test provider binding mismatch"
        );
        Ok(())
    }
    fn perform(&self, lease: &RetirementLease) -> Result<RetirementEffectResult> {
        let db = Connection::open(&self.path)?;
        let mode = self.mode.swap(0, Ordering::SeqCst);
        let mut fact = lease.fact(Digest::of(&(&lease.effect, "provider-receipt"))?)?;
        match lease.step.operation {
            RetirementOperation::DisableVersion => {
                db.execute(
                    "INSERT INTO calls VALUES('disable',?1)",
                    [lease.recovery == RecoveryMode::Reconcile],
                )?;
                if mode == 7 {
                    return Ok(RetirementEffectResult::Observed(RetirementObservation {
                        fact,
                        outcome: RetirementObserved::Disabled {
                            disabled: true,
                            evidence: StateEvidence::Observed {
                                revision: RevisionToken::Opaque {
                                    token: "external-disabled-etag".to_owned().try_into()?,
                                },
                            },
                        },
                    }));
                }
                if lease.recovery == RecoveryMode::Reconcile {
                    let exists: bool = db.query_row(
                        "SELECT EXISTS(SELECT 1 FROM receipts WHERE effect=?1)",
                        [lease.effect.as_str()],
                        |r| r.get(0),
                    )?;
                    if !exists {
                        return Ok(if self.qualified_absence.load(Ordering::SeqCst) {
                            RetirementEffectResult::ReconciledAbsent { fact }
                        } else {
                            RetirementEffectResult::Ambiguous {}
                        });
                    }
                } else {
                    if mode == 2 {
                        return Ok(RetirementEffectResult::Ambiguous {});
                    }
                    if mode == 3 {
                        return Ok(RetirementEffectResult::RetryNotApplied { fact });
                    }
                    db.execute(
                        "INSERT INTO receipts VALUES(?1,?2)",
                        params![
                            lease.effect.as_str(),
                            lease.execution.plan.fingerprint()?.as_str()
                        ],
                    )?;
                    if mode == 1 {
                        return Ok(RetirementEffectResult::Ambiguous {});
                    }
                }
                if mode == 4 {
                    fact.key.version = 2_u64.try_into()?;
                }
                Ok(RetirementEffectResult::Observed(RetirementObservation {
                    fact,
                    outcome: RetirementObserved::DisableAcknowledged {
                        acknowledgement: EffectAcknowledgement {
                            effect: lease.effect.clone(),
                            revision: ordered(lease, 1)?,
                            receipt: Digest::new(b"exact-test-disable-acknowledgement"),
                        },
                    },
                }))
            }
            RetirementOperation::ObserveDisabled => {
                db.execute(
                    "INSERT INTO calls VALUES('observe',?1)",
                    [lease.recovery == RecoveryMode::Reconcile],
                )?;
                let after_effect: String = db.query_row(
                    "SELECT effect FROM receipts WHERE plan=?1",
                    [lease.execution.plan.fingerprint()?.as_str()],
                    |row| row.get(0),
                )?;
                let evidence = match mode {
                    5 => StateEvidence::Observed {
                        revision: RevisionToken::Opaque {
                            token: "opaque-weak-disabled".to_owned().try_into()?,
                        },
                    },
                    6 => StateEvidence::Observed {
                        revision: ordered(lease, 999)?,
                    },
                    _ => StateEvidence::Qualified {
                        revision: ordered(lease, 1)?,
                        barrier: ReadBarrier {
                            authority: lease.execution.plan.resources.clone(),
                            resource: Digest::of(&lease.execution.plan.key)?,
                            after_effect: Some(after_effect.try_into()?),
                            receipt: Digest::new(b"qualified-test-disabled-read"),
                        },
                    },
                };
                Ok(RetirementEffectResult::Observed(RetirementObservation {
                    fact,
                    outcome: RetirementObserved::Disabled {
                        disabled: self.mutations()? > 0,
                        evidence,
                    },
                }))
            }
            _ => anyhow::bail!("internal operation reached provider"),
        }
    }
}

fn ordered(lease: &RetirementLease, sequence: u64) -> Result<RevisionToken> {
    Ok(RevisionToken::Ordered {
        stream: Digest::of(&lease.execution.plan.key)?,
        sequence: sequence.try_into()?,
    })
}

struct Fixture {
    _directory: tempfile::TempDir,
    journal: PathBuf,
    plan: RetirementPlan,
    approval: ReleaseApproval,
    provider: Arc<Provider>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("journal.sqlite");
        let mut journal = Journal::open(&path)?;
        support::configure(
            &mut journal,
            &support::target("alpha"),
            &support::plan("alpha", 1),
        );
        let approval = support::approval(&mut journal, "alpha", 1, 0);
        let key = journal
            .runtime_secret_binding(&approval.target, &approval.secret)?
            .key()
            .clone();
        let scope = ResourceScope::from(&approval.target);
        let policy = Digest::new(b"retirement-policy");
        journal.observe_runtime_secret_authority(
            &key.resource,
            &scope,
            &name("configure-resource"),
            0,
            &policy,
            &actor("operator"),
        )?;
        let plan = RetirementPlan {
            key,
            scope,
            request: name("retire-v1"),
            authority_revision: 1,
            policy,
            actor: actor("operator"),
            approval: Digest::new(b"approved-retirement"),
            resources: approval.secret.binding.clone(),
            durability: BindingRef::pin(name("retirement-temporal"), &"runtime-v1")?,
            recipe: TestRecipe.revision()?,
        };
        let provider = Arc::new(Provider::new(
            &directory.path().join("provider.sqlite"),
            plan.resources.clone(),
        )?);
        Ok(Self {
            _directory: directory,
            journal: path,
            plan,
            approval,
            provider,
        })
    }
    fn host(&self) -> RetirementExecutionHost {
        RetirementExecutionHost::new(
            self.journal.clone(),
            name("alpha"),
            name("worker"),
            self.plan.durability.clone(),
            self.provider.clone(),
            Arc::new(TestRecipe),
        )
    }
    fn revoke(&self) -> Result<()> {
        Journal::open(&self.journal)?.observe_runtime_secret_authority(
            &self.plan.key.resource,
            &self.plan.scope,
            &name("new-policy"),
            1,
            &Digest::new(b"revoked-policy"),
            &actor("security-operator"),
        )?;
        Ok(())
    }
    fn counts(&self, table: &str) -> Result<i64> {
        assert!(matches!(
            table,
            "secret_retirements" | "secret_retirement_outbox" | "secret_retirement_events"
        ));
        Ok(Connection::open(&self.journal)?.query_row(
            &format!("SELECT count(*) FROM {table}"),
            [],
            |r| r.get(0),
        )?)
    }
}

fn claim(host: &RetirementExecutionHost, id: &Digest, now: u64) -> Result<RetirementLease> {
    let step = TestRecipe.choose(&host.inspect(id)?)?;
    let RetirementClaim::Acquired(lease) = host.claim_at(id, &step, now)? else {
        anyhow::bail!("expected retirement claim")
    };
    Ok(*lease)
}

fn complete(host: &RetirementExecutionHost, id: &Digest, mut now: u64) -> Result<()> {
    for _ in 0..6 {
        if host.advance_at(id, now)? == StepOutcome::Succeeded {
            return Ok(());
        }
        now += 1;
    }
    anyhow::bail!("test retirement failed to converge")
}

#[test]
fn admission_is_one_physical_barrier_and_atomic_with_outbox_and_operator_audit() -> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let db = Connection::open(&fixture.journal)?;
    db.execute_batch("CREATE TRIGGER fail_retirement_audit BEFORE INSERT ON secret_retirement_events BEGIN SELECT RAISE(ABORT,'injected audit failure');END;")?;
    assert!(host.accept(&fixture.plan).is_err());
    assert_eq!(
        Journal::open(&fixture.journal)?.runtime_secret_version(&fixture.plan.key)?,
        VersionState::Available
    );
    assert_eq!(fixture.counts("secret_retirements")?, 0);
    assert_eq!(fixture.counts("secret_retirement_outbox")?, 0);
    db.execute_batch("DROP TRIGGER fail_retirement_audit;")?;
    let id = host.accept(&fixture.plan)?;
    assert_eq!(host.accept(&fixture.plan)?, id);
    assert_eq!(fixture.counts("secret_retirements")?, 1);
    assert_eq!(fixture.counts("secret_retirement_outbox")?, 1);
    assert_eq!(
        Journal::open(&fixture.journal)?.runtime_secret_version(&fixture.plan.key)?,
        VersionState::Retiring
    );
    let original_events = fixture.counts("secret_retirement_events")?;
    for mutation in 0..3 {
        let mut conflicting = fixture.plan.clone();
        match mutation {
            0 => conflicting.request = name("other-retirement"),
            1 => conflicting.actor = actor("other-operator"),
            _ => conflicting.scope.company = name("beta"),
        }
        assert!(
            Journal::open(&fixture.journal)?
                .accept_secret_retirement(&conflicting)
                .is_err()
        );
    }
    assert_eq!(fixture.counts("secret_retirement_events")?, original_events);
    let audit: String = db.query_row(
        "SELECT body FROM secret_retirement_events WHERE kind='accepted'",
        [],
        |r| r.get(0),
    )?;
    let audit: serde_json::Value = serde_json::from_str(&audit)?;
    assert_eq!(audit["actor"], "operator");
    assert_eq!(audit["approval"], fixture.plan.approval.as_str());
    let other = RetirementExecutionHost::new(
        fixture.journal.clone(),
        name("beta"),
        name("worker"),
        fixture.plan.durability.clone(),
        fixture.provider.clone(),
        Arc::new(TestRecipe),
    );
    assert!(other.inspect(&id).is_err());
    assert!(other.accept(&fixture.plan).is_err());
    Ok(())
}

#[test]
fn pending_consumers_block_disable_and_retirement_barrier_blocks_new_approval() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut journal = Journal::open(&fixture.journal)?;
    let approval = journal.approve_release(&fixture.approval)?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    assert_eq!(host.inspect(&id)?.phase, RetirementPhase::WaitingConsumers);
    assert_eq!(fixture.provider.executions()?, 0);
    let forged = RetirementStepRequest {
        name: name("disable_version"),
        ordinal: host.inspect(&id)?.next_step,
        operation: RetirementOperation::DisableVersion,
    };
    assert!(host.claim_at(&id, &forged, 1).is_err());
    let mut another = fixture.approval.clone();
    another.request = name("new-consumer");
    another.expected_generation = 1;
    assert!(journal.approve_release(&another).is_err());
    journal.cancel_release(&approval, &actor("operator"))?;
    journal.abandon_runtime_secret_consumer(approval.id(), &actor("operator"))?;
    complete(&host, &id, 2)?;
    assert_eq!(fixture.provider.mutations()?, 1);
    assert_eq!(
        journal.runtime_secret_version(&fixture.plan.key)?,
        VersionState::Disabled
    );
    Ok(())
}

#[test]
fn restart_before_dispatch_reclaims_execute_and_lost_ack_reconciles_without_second_disable()
-> Result<()> {
    let mut fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    let first = claim(&host, &id, 1)?;
    assert_eq!(first.until, 1 + LEASE_MILLIS);
    assert!(host.perform_at(&first, first.until).is_err());
    let second = claim(&host, &id, first.until)?;
    assert_eq!(second.recovery, RecoveryMode::Execute);
    assert!(host.perform_at(&first, first.until).is_err());
    fixture.provider.mode.store(1, Ordering::SeqCst);
    assert_eq!(
        host.perform_at(&second, first.until)?,
        RetirementEffectResult::Ambiguous {}
    );
    drop(host);
    fixture.provider = Arc::new(Provider::new(
        &fixture.provider.path,
        fixture.plan.resources.clone(),
    )?);
    let restarted = fixture.host();
    let recovered = claim(&restarted, &id, second.until)?;
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    assert_eq!(recovered.effect, second.effect);
    let result = restarted.perform_at(&recovered, second.until)?;
    restarted.settle_at(&recovered, result, second.until)?;
    complete(&restarted, &id, second.until + 1)?;
    assert_eq!(fixture.provider.executions()?, 1);
    assert_eq!(fixture.provider.mutations()?, 1);
    assert_eq!(
        restarted.inspect(&id)?.terminal,
        Some(RetirementTerminal::Disabled)
    );
    Ok(())
}

#[test]
fn uncertain_disable_requires_exact_qualified_absence_before_retry_and_preserves_ancestry()
-> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    let first = claim(&host, &id, 1)?;
    fixture.provider.mode.store(2, Ordering::SeqCst);
    let result = host.perform_at(&first, 1)?;
    host.settle_at(&first, result, 1)?;
    let recovered = claim(&host, &id, 2)?;
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    let mut forged = recovered.clone();
    forged.recovery = RecoveryMode::Execute;
    assert!(host.perform_at(&forged, 2).is_err());
    let again = claim(&host, &id, recovered.until)?;
    assert_eq!(again.recovery, RecoveryMode::Reconcile);
    let result = host.perform_at(&again, recovered.until)?;
    host.settle_at(&again, result, recovered.until)?;
    assert_eq!(fixture.provider.executions()?, 1);
    let retry = claim(&host, &id, recovered.until + 1)?;
    fixture
        .provider
        .qualified_absence
        .store(true, Ordering::SeqCst);
    let absent = host.perform_at(&retry, recovered.until + 1)?;
    let RetirementEffectResult::ReconciledAbsent { fact } = &absent else {
        anyhow::bail!("expected qualified absence")
    };
    let proof = fact.evidence.clone();
    let unsupported = RetirementEffectResult::RetryNotApplied { fact: fact.clone() };
    let error = host
        .settle_at(&retry, unsupported, recovered.until + 1)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<RetirementRejection>(),
        Some(&RetirementRejection::UncertainMutation)
    );
    host.settle_at(&retry, absent, recovered.until + 1)?;
    let audit: String = Connection::open(&fixture.journal)?.query_row(
        "SELECT body FROM secret_retirement_events WHERE body LIKE '%reconciled_absent%'",
        [],
        |r| r.get(0),
    )?;
    assert!(audit.contains(proof.as_str()));
    complete(&host, &id, recovered.until + 2)?;
    assert_eq!(fixture.provider.executions()?, 2);
    assert_eq!(fixture.provider.mutations()?, 1);
    Ok(())
}

#[test]
fn revocation_before_dispatch_stops_writes_but_after_dispatch_still_drains_physical_receipt()
-> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    let lease = claim(&host, &id, 1)?;
    fixture.revoke()?;
    let result = host.perform_at(&lease, 1)?;
    assert_eq!(result, RetirementEffectResult::GuardChanged {});
    assert_eq!(host.settle_at(&lease, result, 1)?, StepOutcome::Failed);
    assert_eq!(fixture.provider.executions()?, 0);

    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    let lease = claim(&host, &id, 1)?;
    fixture.provider.mode.store(1, Ordering::SeqCst);
    let result = host.perform_at(&lease, 1)?;
    host.settle_at(&lease, result, 1)?;
    fixture.revoke()?;
    let recovered = claim(&host, &id, 2)?;
    assert_eq!(recovered.recovery, RecoveryMode::Reconcile);
    let result = host.perform_at(&recovered, 2)?;
    host.settle_at(&recovered, result, 2)?;
    host.advance_at(&id, 3)?;
    assert_eq!(host.advance_at(&id, 4)?, StepOutcome::Failed);
    assert_eq!(
        host.inspect(&id)?.terminal,
        Some(RetirementTerminal::AuthorityLost)
    );
    assert_eq!(
        Journal::open(&fixture.journal)?.runtime_secret_version(&fixture.plan.key)?,
        VersionState::Disabled
    );
    assert_eq!(fixture.provider.executions()?, 1);
    Ok(())
}

#[test]
fn wrong_version_receipts_fail_atomically_and_historical_duplicates_cannot_change_completion()
-> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    let lease = claim(&host, &id, 1)?;
    fixture.provider.mode.store(4, Ordering::SeqCst);
    let wrong = host.perform_at(&lease, 1)?;
    let before = fixture.counts("secret_retirement_events")?;
    let error = host.settle_at(&lease, wrong, 1).unwrap_err();
    assert_eq!(
        error.downcast_ref::<RetirementRejection>(),
        Some(&RetirementRejection::InvalidFact)
    );
    assert_eq!(fixture.counts("secret_retirement_events")?, before);
    let recovered = claim(&host, &id, lease.until)?;
    let correct = host.perform_at(&recovered, lease.until)?;
    host.settle_at(&recovered, correct.clone(), lease.until)?;
    complete(&host, &id, lease.until + 1)?;
    let snapshot = host.inspect(&id)?;
    let before = fixture.counts("secret_retirement_events")?;
    assert_eq!(
        host.settle_at(&recovered, correct, lease.until + 10)?,
        StepOutcome::Succeeded
    );
    assert_eq!(host.inspect(&id)?, snapshot);
    assert_eq!(fixture.counts("secret_retirement_events")?, before);
    let db = Connection::open(&fixture.journal)?;
    assert!(
        db.execute("UPDATE secret_retirement_events SET kind='forged'", [])
            .is_err()
    );
    assert!(
        db.execute("DELETE FROM secret_retirement_events", [])
            .is_err()
    );
    db.execute_batch("PRAGMA recursive_triggers=OFF;")?;
    assert!(db.execute("INSERT OR REPLACE INTO secret_retirement_events SELECT * FROM secret_retirement_events LIMIT 1",[]).is_err());
    Ok(())
}

#[test]
fn serialized_results_are_strict_and_impossible_persisted_success_is_rejected() -> Result<()> {
    for raw in [
        r#"{"kind":"ambiguous","secret":"unadmitted"}"#,
        r#"{"kind":"wait_consumers","ready":true}"#,
        r#"{"kind":"complete","proof":"invented"}"#,
    ] {
        assert!(serde_json::from_str::<RetirementEffectResult>(raw).is_err());
    }
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    let db = Connection::open(&fixture.journal)?;
    db.execute("UPDATE secret_retirements SET body=json_set(body,'$.snapshot.phase','complete','$.snapshot.terminal','disabled','$.snapshot.waiting',NULL) WHERE id=?1",[id.as_str()])?;
    assert!(host.inspect(&id).is_err());
    Ok(())
}

#[test]
fn future_retirement_schema_is_rejected_without_creating_retirement_tables() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("future.sqlite");
    let db = Connection::open(&path)?;
    db.execute_batch("CREATE TABLE secret_retirement_meta(singleton INTEGER PRIMARY KEY,version INTEGER NOT NULL);
        INSERT INTO secret_retirement_meta VALUES(1,999);")?;
    assert!(Journal::open(&path).is_err());
    let version: i64 = db.query_row("SELECT version FROM secret_retirement_meta", [], |row| {
        row.get(0)
    })?;
    assert_eq!(version, 999);
    let tables: i64 = db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN('secret_retirements','secret_retirement_steps','secret_retirement_outbox','secret_retirement_events')", [], |row| row.get(0))?;
    assert_eq!(tables, 0);
    Ok(())
}

#[test]
fn unacknowledged_disabled_state_survives_restart_without_receipt_or_second_write() -> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    for now in 1..=4 {
        let restarted = fixture.host();
        let lease = claim(&restarted, &id, now)?;
        assert_eq!(
            lease.recovery,
            if now == 1 {
                RecoveryMode::Execute
            } else {
                RecoveryMode::Reconcile
            }
        );
        fixture.provider.mode.store(7, Ordering::SeqCst);
        let result = restarted.perform_at(&lease, now)?;
        restarted.settle_at(&lease, result, now)?;
        let state = restarted.inspect(&id)?;
        assert_eq!(state.phase, RetirementPhase::Eligible);
        assert_eq!(state.next_step, 1);
        assert!(state.terminal.is_none());
    }
    assert_eq!(fixture.provider.executions()?, 1);
    assert_eq!(fixture.provider.mutations()?, 0);
    assert_eq!(
        Journal::open(&fixture.journal)?.runtime_secret_version(&fixture.plan.key)?,
        VersionState::Retiring
    );
    let weak_events: i64 = Connection::open(&fixture.journal)?.query_row(
        "SELECT count(*) FROM secret_retirement_events WHERE kind='settled' AND body LIKE '%external-disabled-etag%'", [], |row| row.get(0))?;
    assert_eq!(weak_events, 4);
    Ok(())
}

#[test]
fn weak_opaque_and_high_ordered_reads_cannot_finish_or_poison_qualified_frontier() -> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    host.advance_at(&id, 1)?;
    for (now, mode) in [(2, 5), (3, 6), (4, 5)] {
        fixture.provider.mode.store(mode, Ordering::SeqCst);
        let restarted = fixture.host();
        restarted.advance_at(&id, now)?;
        assert_eq!(
            restarted.inspect(&id)?.phase,
            RetirementPhase::WaitingDisabled
        );
        assert_eq!(
            Journal::open(&fixture.journal)?.runtime_secret_version(&fixture.plan.key)?,
            VersionState::Retiring
        );
    }
    complete(&fixture.host(), &id, 5)?;
    assert_eq!(fixture.provider.executions()?, 1);
    assert_eq!(
        host.inspect(&id)?.terminal,
        Some(RetirementTerminal::Disabled)
    );
    Ok(())
}

#[test]
fn qualified_readback_requires_exact_ack_resource_binding_and_revision_stream() -> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    host.advance_at(&id, 1)?;
    let lease = claim(&host, &id, 2)?;
    let valid = host.perform_at(&lease, 2)?;
    let before = host.inspect(&id)?;
    let events = fixture.counts("secret_retirement_events")?;
    for mutation in 0..5 {
        let mut invalid = valid.clone();
        let RetirementEffectResult::Observed(RetirementObservation {
            outcome:
                RetirementObserved::Disabled {
                    evidence: StateEvidence::Qualified { revision, barrier },
                    ..
                },
            ..
        }) = &mut invalid
        else {
            anyhow::bail!("expected qualified observation")
        };
        match mutation {
            0 => barrier.after_effect = Some(Digest::new(b"different-disable")),
            1 => barrier.resource = Digest::new(b"different-version"),
            2 => barrier.authority.revision = Digest::new(b"different-authority"),
            3 => {
                *revision = RevisionToken::Ordered {
                    stream: Digest::new(b"different-stream"),
                    sequence: 999_u64.try_into()?,
                }
            }
            _ => {
                *revision = RevisionToken::Opaque {
                    token: "999".to_owned().try_into()?,
                }
            }
        }
        assert!(host.settle_at(&lease, invalid, 2).is_err());
        assert_eq!(host.inspect(&id)?, before);
        assert_eq!(fixture.counts("secret_retirement_events")?, events);
    }
    host.settle_at(&lease, valid, 2)?;
    complete(&host, &id, 3)?;
    Ok(())
}

#[test]
fn opaque_equality_is_not_order_and_still_needs_an_explicit_qualified_barrier() -> Result<()> {
    let fixture = Fixture::new()?;
    let host = fixture.host();
    let id = host.accept(&fixture.plan)?;
    host.advance_at(&id, 0)?;
    let disable = claim(&host, &id, 1)?;
    let mut acknowledged = host.perform_at(&disable, 1)?;
    let token = RevisionToken::Opaque {
        token: "etag-ack".to_owned().try_into()?,
    };
    let RetirementEffectResult::Observed(RetirementObservation {
        outcome: RetirementObserved::DisableAcknowledged { acknowledgement },
        ..
    }) = &mut acknowledged
    else {
        anyhow::bail!("missing ack")
    };
    acknowledgement.revision = token.clone();
    let mut wrong_ack = acknowledged.clone();
    let RetirementEffectResult::Observed(RetirementObservation {
        outcome: RetirementObserved::DisableAcknowledged { acknowledgement },
        ..
    }) = &mut wrong_ack
    else {
        unreachable!()
    };
    acknowledgement.effect = Digest::new(b"other-effect");
    assert!(host.settle_at(&disable, wrong_ack, 1).is_err());
    host.settle_at(&disable, acknowledged, 1)?;
    fixture.provider.mode.store(5, Ordering::SeqCst);
    host.advance_at(&id, 2)?;
    assert_eq!(host.inspect(&id)?.phase, RetirementPhase::WaitingDisabled);
    let read = claim(&host, &id, 3)?;
    let mut observed = host.perform_at(&read, 3)?;
    let RetirementEffectResult::Observed(RetirementObservation {
        outcome:
            RetirementObserved::Disabled {
                evidence: StateEvidence::Qualified { revision, .. },
                ..
            },
        ..
    }) = &mut observed
    else {
        anyhow::bail!("missing readback")
    };
    *revision = RevisionToken::Opaque {
        token: "etag-after".to_owned().try_into()?,
    };
    assert!(host.settle_at(&read, observed.clone(), 3).is_err());
    let RetirementEffectResult::Observed(RetirementObservation {
        outcome:
            RetirementObserved::Disabled {
                evidence: StateEvidence::Qualified { revision, .. },
                ..
            },
        ..
    }) = &mut observed
    else {
        unreachable!()
    };
    *revision = token;
    host.settle_at(&read, observed, 3)?;
    complete(&host, &id, 4)?;
    Ok(())
}

#[test]
fn weaker_legacy_retirement_history_is_never_promoted_by_schema_upgrade() -> Result<()> {
    let empty = tempfile::tempdir()?;
    let path = empty.path().join("empty.sqlite");
    drop(Journal::open(&path)?);
    let db = Connection::open(&path)?;
    db.execute("UPDATE secret_retirement_meta SET version=1", [])?;
    drop(Journal::open(&path)?);
    assert_eq!(
        db.query_row("SELECT version FROM secret_retirement_meta", [], |row| row
            .get::<_, i64>(
            0
        ))?,
        2
    );

    let fixture = Fixture::new()?;
    fixture.host().accept(&fixture.plan)?;
    let db = Connection::open(&fixture.journal)?;
    let before: String =
        db.query_row("SELECT body FROM secret_retirements", [], |row| row.get(0))?;
    db.execute("UPDATE secret_retirement_meta SET version=1", [])?;
    assert!(Journal::open(&fixture.journal).is_err());
    assert_eq!(
        db.query_row("SELECT version FROM secret_retirement_meta", [], |row| row
            .get::<_, i64>(
            0
        ))?,
        1
    );
    assert_eq!(
        db.query_row("SELECT body FROM secret_retirements", [], |row| row
            .get::<_, String>(0))?,
        before
    );
    assert!(
        serde_json::from_str::<RetirementObserved>(
            r#"{"kind":"disabled","disabled":true,"provider_revision":1}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<RetirementObserved>(r#"{"kind":"disable_accepted"}"#).is_err());
    Ok(())
}
