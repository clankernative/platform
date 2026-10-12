//! Persisted local Temporal, real SQLite and the compiled Roc retirement recipe.
//! The independently persisted provider is synthetic, not a cloud qualification.
use crate::support::release as support;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_control::{
    BindingRef, Digest,
    journal::{Journal, RecoveryMode},
    runtime_secret::{ResourceScope, VersionState},
    secret_retirement::{
        Capabilities, RetirementEffectResult, RetirementExecutionHost, RetirementLease,
        RetirementObservation, RetirementObserved, RetirementOperation, RetirementPhase,
        RetirementPlan, RetirementTerminal, RetirementWait,
    },
    secret_retirement_recipe::CompiledSecretRetirementRecipe,
};
use durable_temporal::{
    AdvanceBackend, BackendError, RuntimeConfig, StepOutcome, TemporalAdapter, local::LocalServer,
    replay,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

struct Provider {
    database: PathBuf,
    plan: RetirementPlan,
}

impl Provider {
    fn create(database: &Path, plan: RetirementPlan) -> Result<Self> {
        let provider = Self {
            database: database.to_owned(),
            plan,
        };
        provider.connection()?.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE mutations(effect TEXT PRIMARY KEY,plan TEXT NOT NULL,body TEXT NOT NULL);
             CREATE TABLE calls(sequence INTEGER PRIMARY KEY,operation TEXT NOT NULL,reconcile INTEGER NOT NULL);
             CREATE TABLE settings(id INTEGER PRIMARY KEY CHECK(id=1),receipt_visible INTEGER NOT NULL,activity_ack_lost INTEGER NOT NULL);
             INSERT INTO settings VALUES(1,0,0);",
        )?;
        Ok(provider)
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.database)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(connection)
    }

    fn lose_activity_ack(&self) -> Result<bool> {
        Ok(self.connection()?.execute(
            "UPDATE settings SET activity_ack_lost=1 WHERE id=1 AND activity_ack_lost=0",
            [],
        )? == 1)
    }
}

impl Capabilities for Provider {
    fn validate(&self, plan: &RetirementPlan) -> Result<()> {
        ensure!(plan == &self.plan, "retirement provider scope mismatch");
        Ok(())
    }

    fn perform(&self, lease: &RetirementLease) -> Result<RetirementEffectResult> {
        self.validate(&lease.execution.plan)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let fact = lease.fact(Digest::of(&(
            "persisted-retirement-provider-receipt",
            &lease.effect,
        ))?)?;
        let result = match lease.step.operation {
            RetirementOperation::DisableVersion => {
                tx.execute(
                    "INSERT INTO calls(operation,reconcile) VALUES('disable',?1)",
                    [lease.recovery == RecoveryMode::Reconcile],
                )?;
                let existing: Option<(String, String)> = tx
                    .query_row(
                        "SELECT plan,body FROM mutations WHERE effect=?1",
                        [lease.effect.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match lease.recovery {
                    RecoveryMode::Execute => {
                        ensure!(
                            existing.is_none(),
                            "second Execute attempted the same disable"
                        );
                        let result = RetirementEffectResult::Observed(RetirementObservation {
                            fact,
                            outcome: RetirementObserved::DisableAcknowledged {
                                acknowledgement:
                                    day2_control::provider_evidence::EffectAcknowledgement {
                                        effect: lease.effect.clone(),
                                        revision: retirement_revision(lease)?,
                                        receipt: Digest::new(b"durable-provider-exact-disable-ack"),
                                    },
                            },
                        });
                        tx.execute(
                            "INSERT INTO mutations VALUES(?1,?2,?3)",
                            params![
                                lease.effect.as_str(),
                                self.plan.fingerprint()?.as_str(),
                                serde_json::to_string(&result)?
                            ],
                        )?;
                        // The physical mutation commits, but its acknowledgement is lost.
                        RetirementEffectResult::Ambiguous {}
                    }
                    RecoveryMode::Reconcile => {
                        let visible: bool = tx.query_row(
                            "SELECT receipt_visible FROM settings WHERE id=1",
                            [],
                            |row| row.get(0),
                        )?;
                        if visible {
                            let (plan, body) =
                                existing.context("persisted disable receipt missing")?;
                            ensure!(
                                plan == self.plan.fingerprint()?.as_str(),
                                "persisted receipt belongs to another plan"
                            );
                            serde_json::from_str(&body)?
                        } else {
                            RetirementEffectResult::Ambiguous {}
                        }
                    }
                }
            }
            RetirementOperation::ObserveDisabled => {
                tx.execute(
                    "INSERT INTO calls(operation,reconcile) VALUES('observe_disabled',?1)",
                    [lease.recovery == RecoveryMode::Reconcile],
                )?;
                let disabled: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM mutations WHERE plan=?1)",
                    [self.plan.fingerprint()?.as_str()],
                    |row| row.get(0),
                )?;
                let disable_effect: String = tx.query_row(
                    "SELECT effect FROM mutations WHERE plan=?1",
                    [self.plan.fingerprint()?.as_str()],
                    |row| row.get(0),
                )?;
                RetirementEffectResult::Observed(RetirementObservation {
                    fact,
                    outcome: RetirementObserved::Disabled {
                        disabled,
                        evidence: day2_control::provider_evidence::StateEvidence::Qualified {
                            revision: retirement_revision(lease)?,
                            barrier: day2_control::provider_evidence::ReadBarrier {
                                authority: lease.execution.plan.resources.clone(),
                                resource: Digest::of(&lease.execution.plan.key)?,
                                after_effect: Some(disable_effect.try_into()?),
                                receipt: Digest::new(b"durable-provider-qualified-disabled-read"),
                            },
                        },
                    },
                })
            }
            _ => anyhow::bail!("internal retirement operation reached the provider"),
        };
        tx.commit()?;
        Ok(result)
    }
}

fn retirement_revision(
    lease: &RetirementLease,
) -> Result<day2_control::provider_evidence::RevisionToken> {
    Ok(day2_control::provider_evidence::RevisionToken::Ordered {
        stream: Digest::of(&lease.execution.plan.key)?,
        sequence: 1_u64.try_into()?,
    })
}

struct LoseActivityAcknowledgement {
    host: Arc<RetirementExecutionHost>,
    provider: Arc<Provider>,
}

impl AdvanceBackend for LoseActivityAcknowledgement {
    fn advance(
        &self,
        execution_id: &str,
        runtime: &RuntimeConfig,
    ) -> std::result::Result<StepOutcome, BackendError> {
        let result = self.host.advance(execution_id, runtime)?;
        let id = Digest::try_from(execution_id.to_owned()).map_err(|_| BackendError::Rejected)?;
        let snapshot = self
            .host
            .inspect(&id)
            .map_err(|_| BackendError::Retryable)?;
        if snapshot.phase == RetirementPhase::WaitingDisabled
            && self
                .provider
                .lose_activity_ack()
                .map_err(|_| BackendError::Retryable)?
        {
            return Err(BackendError::Retryable);
        }
        Ok(result)
    }
}

fn count(connection: &Connection, sql: &'static str) -> Result<u64> {
    let count: i64 = connection.query_row(sql, [], |row| row.get(0))?;
    Ok(count.try_into()?)
}

fn assert_redacted(value: &Value, forbidden: &[&str]) {
    match value {
        Value::String(text) => {
            let decoded = STANDARD.decode(text).unwrap_or_default();
            for forbidden in forbidden {
                assert!(!text.contains(forbidden));
                assert!(!String::from_utf8_lossy(&decoded).contains(forbidden));
            }
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| assert_redacted(value, forbidden)),
        Value::Object(values) => values
            .values()
            .for_each(|value| assert_redacted(value, forbidden)),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_retirement_recovers_with_real_temporal_and_one_provider_disable() -> Result<()> {
    tokio::task::LocalSet::new().run_until(async {
        let directory = tempfile::tempdir()?;
        let journal_path = directory.path().join("control.sqlite");
        let mut journal = Journal::open(&journal_path)?;
        let approval = support::approval(&mut journal, "alpha", 1, 0);
        support::configure(&mut journal, &approval.target, &support::plan("alpha", 1));
        let approved = journal.approve_release(&approval)?;
        let key = journal.runtime_secret_binding(&approval.target, &approval.secret)?.key().clone();
        let scope = ResourceScope::from(&approval.target);
        let policy = Digest::new(b"explicit-durable-retirement-policy");
        let authority = journal.observe_runtime_secret_authority(&key.resource, &scope, &support::name("retirement-authority"), 0, &policy, &support::actor("operator"))?;
        let mut server = LocalServer::start(&directory.path().join("temporal")).await?;
        let adapter = server.adapter().await?;
        let recipe = Arc::new(CompiledSecretRetirementRecipe::installed()?);
        let durability = BindingRef::pin(support::name("temporal-retirement"), adapter.binding_configuration())?;
        let plan = RetirementPlan {
            key, scope, request: support::name("retire-v1"), authority_revision: authority.revision,
            policy, actor: support::actor("operator"), approval: Digest::new(b"trusted-retirement-approval"),
            resources: approval.secret.binding.clone(), durability: durability.clone(), recipe: recipe.identity()?,
        };
        let provider = Arc::new(Provider::create(&directory.path().join("provider.sqlite"), plan.clone())?);
        let host = Arc::new(RetirementExecutionHost::new(journal_path.clone(), plan.scope.company.clone(), support::name("first-worker"), durability.clone(), provider.clone(), recipe.clone()));
        let connection = Connection::open(&journal_path)?;
        connection.execute_batch("CREATE TRIGGER fail_retirement_acceptance BEFORE INSERT ON secret_retirement_events WHEN NEW.kind='accepted' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;")?;
        assert!(host.accept(&plan).is_err());
        assert_eq!(journal.runtime_secret_version(&plan.key)?, VersionState::Available);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM runtime_secret_retirements")?, 0);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM secret_retirements")?, 0);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM secret_retirement_outbox")?, 0);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM runtime_secret_events WHERE kind='retirement_barrier'")?, 0);
        connection.execute_batch("DROP TRIGGER fail_retirement_acceptance;")?;
        let id = host.accept(&plan)?;
        assert_eq!(host.accept(&plan)?, id);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM secret_retirement_outbox")?, 1);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM secret_retirement_events WHERE kind='accepted'")?, 1);
        assert_eq!(journal.runtime_secret_version(&plan.key)?, VersionState::Retiring);
        let wrong = TemporalAdapter::connect_local(server.address(), server.namespace(), "wrong-queue").await?;
        assert!(host.dispatch(&wrong).await.is_err());
        assert!(host.advance(id.as_str(), wrong.binding_configuration()).is_err());
        drop(wrong);
        let start = adapter.ensure_started(id.as_str()).await?;
        assert_eq!(host.dispatch(&adapter).await?, 1);
        assert_eq!(host.dispatch(&adapter).await?, 0);
        assert_eq!(adapter.ensure_started(id.as_str()).await?, start);
        let mut worker = adapter.worker(Arc::new(LoseActivityAcknowledgement { host: host.clone(), provider: provider.clone() }))?;
        let shutdown = worker.shutdown_handle();
        let task = tokio::task::spawn_local(async move { worker.run().await });
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if count(&connection, "SELECT COUNT(*) FROM secret_retirement_events WHERE kind='consumers_observed'")? > 0 { break Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.context("retirement did not observe its protected consumer")??;
        assert_eq!(count(&provider.connection()?, "SELECT COUNT(*) FROM mutations")?, 0);
        assert_eq!(journal.runtime_secret_consumer_counts(&plan.key)?.pending, 1);
        journal.cancel_release(&approved, &support::actor("operator"))?;
        journal.abandon_runtime_secret_consumer(approved.id(), &support::actor("operator"))?;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if count(&provider.connection()?, "SELECT COUNT(*) FROM mutations")? == 1 && host.inspect(&id)?.waiting == Some(RetirementWait::Reconciliation) { break Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.context("retirement did not reach its lost-ack boundary")??;
        shutdown();
        tokio::time::timeout(Duration::from_secs(15), task).await???;
        assert_eq!(host.inspect(&id)?.phase, RetirementPhase::Eligible);
        assert_eq!(journal.runtime_secret_version(&plan.key)?, VersionState::Retiring);
        assert_eq!(count(&provider.connection()?, "SELECT COUNT(*) FROM calls WHERE operation='disable' AND reconcile=0")?, 1);
        drop(host);
        drop(provider);
        drop(recipe);
        drop(adapter);
        server.stop()?;
        server.restart().await?;

        let provider = Arc::new(Provider { database: directory.path().join("provider.sqlite"), plan: plan.clone() });
        provider.connection()?.execute("UPDATE settings SET receipt_visible=1 WHERE id=1", [])?;
        let recipe = Arc::new(CompiledSecretRetirementRecipe::installed()?);
        assert_eq!(recipe.identity()?, plan.recipe);
        let host = Arc::new(RetirementExecutionHost::new(journal_path.clone(), plan.scope.company.clone(), support::name("replacement-worker"), durability, provider.clone(), recipe));
        let adapter = server.adapter().await?;
        assert_eq!(host.dispatch(&adapter).await?, 0);
        let mut worker = adapter.worker(Arc::new(LoseActivityAcknowledgement { host: host.clone(), provider: provider.clone() }))?;
        let shutdown = worker.shutdown_handle();
        let task = tokio::task::spawn_local(async move { worker.run().await });
        assert_eq!(tokio::time::timeout(Duration::from_secs(60), adapter.result(id.as_str())).await??, StepOutcome::Succeeded);
        let snapshot = host.inspect(&id)?;
        assert_eq!(snapshot.phase, RetirementPhase::Complete);
        assert_eq!(snapshot.terminal, Some(RetirementTerminal::Disabled));
        assert_eq!(journal.runtime_secret_version(&plan.key)?, VersionState::Disabled);
        assert_eq!(journal.runtime_secret_retirement_for(&plan.key)?.context("retirement barrier missing")?.revision, 2);
        assert_eq!(count(&provider.connection()?, "SELECT COUNT(*) FROM mutations")?, 1);
        assert_eq!(count(&provider.connection()?, "SELECT COUNT(*) FROM calls WHERE operation='disable' AND reconcile=0")?, 1);
        assert!(count(&provider.connection()?, "SELECT COUNT(*) FROM calls WHERE operation='disable' AND reconcile=1")? > 0);
        assert!(count(&provider.connection()?, "SELECT COUNT(*) FROM calls WHERE operation='observe_disabled'")? > 0);
        assert_eq!(count(&provider.connection()?, "SELECT activity_ack_lost FROM settings WHERE id=1")?, 1);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM secret_retirement_outbox WHERE workflow_id IS NOT NULL AND run_id IS NOT NULL")?, 1);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM runtime_secret_events WHERE kind='version_disabled'")?, 1);
        let events = count(&connection, "SELECT COUNT(*) FROM secret_retirement_events")?;
        let resource_events = count(&connection, "SELECT COUNT(*) FROM runtime_secret_events")?;
        assert_eq!(host.advance(id.as_str(), adapter.binding_configuration()), Ok(StepOutcome::Succeeded));
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM secret_retirement_events")?, events);
        assert_eq!(count(&connection, "SELECT COUNT(*) FROM runtime_secret_events")?, resource_events);
        let history = adapter.history(id.as_str()).await?;
        assert_redacted(&serde_json::from_slice(&history)?, &[approval.git.commit.as_str(), plan.key.resource.secret.as_str(), plan.policy.as_str()]);
        shutdown();
        tokio::time::timeout(Duration::from_secs(15), task).await???;
        replay(&history).await?;
        server.stop()?;
        Ok(())
    }).await
}
