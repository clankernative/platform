//! Real persisted Temporal, SQLite and compiled Roc; provider facts are synthetic.
//! This qualifies delivery/restart wiring, not a cloud deployment adapter.
#[path = "support/release.rs"]
mod support;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_control::{
    BindingRef, Digest,
    journal::{Journal, RecoveryMode},
    provider_evidence::{ReadBarrier, RevisionToken, StateEvidence},
    release::ReleaseApproval,
    release_execution::{
        Capabilities, ReleaseEffectResult, ReleaseExecutionHost, ReleaseExecutionPlan,
        ReleaseLease, ReleaseObservation, ReleaseObserved, ReleaseOperation, ReleasePhase,
    },
    release_recipe::CompiledReleaseRecipe,
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
    plan: ReleaseExecutionPlan,
    approval: ReleaseApproval,
}

impl Provider {
    fn create(
        database: &Path,
        plan: ReleaseExecutionPlan,
        approval: ReleaseApproval,
    ) -> Result<Self> {
        let provider = Self {
            database: database.to_owned(),
            plan,
            approval,
        };
        provider.connection()?.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE mutations(effect TEXT PRIMARY KEY, operation TEXT NOT NULL, body TEXT NOT NULL);
             CREATE TABLE observations(sequence INTEGER PRIMARY KEY, effect TEXT NOT NULL, operation TEXT NOT NULL);
             CREATE TABLE settings(id INTEGER PRIMARY KEY CHECK(id=1), ready INTEGER NOT NULL, lost_ack INTEGER NOT NULL);
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
            "UPDATE settings SET lost_ack=1 WHERE id=1 AND lost_ack=0",
            [],
        )? == 1)
    }

    fn secret_reads(&self) -> Result<u64> {
        let count: i64 = self.connection()?.query_row(
            "SELECT COUNT(*) FROM observations WHERE operation='observe_secret'",
            [],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(count)?)
    }
}

impl Capabilities for Provider {
    fn validate(&self, plan: &ReleaseExecutionPlan, approval: &ReleaseApproval) -> Result<()> {
        ensure!(
            plan == &self.plan && approval == &self.approval,
            "provider scope mismatch"
        );
        Ok(())
    }

    fn perform(&self, lease: &ReleaseLease) -> Result<ReleaseEffectResult> {
        self.validate(&lease.execution.plan, &lease.approval)?;
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = serde_json::to_value(lease.step.operation)?;
        let operation = operation.as_str().context("operation string")?;
        tx.execute(
            "INSERT INTO observations(effect,operation) VALUES(?1,?2)",
            params![lease.effect.as_str(), operation],
        )?;
        let observed = |outcome| -> Result<ReleaseEffectResult> {
            Ok(ReleaseEffectResult::Observed(Box::new(
                ReleaseObservation {
                    fact: lease.fact(Digest::of(&(lease.effect.as_str(), "provider-evidence"))?)?,
                    outcome,
                },
            )))
        };
        let result = match lease.step.operation {
            ReleaseOperation::PrepareDependency | ReleaseOperation::PrepareDeployment => {
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT body FROM mutations WHERE effect=?1",
                        [lease.effect.as_str()],
                        |row| row.get(0),
                    )
                    .optional()?;
                match lease.recovery {
                    RecoveryMode::Execute => {
                        ensure!(
                            existing.is_none(),
                            "mutation sent twice without reconciliation"
                        );
                        let outcome = match lease.step.operation {
                            ReleaseOperation::PrepareDependency => {
                                ReleaseObserved::DependencyPrepared {}
                            }
                            _ => ReleaseObserved::DeploymentPrepared {
                                incarnation: support::incarnation(&lease.effect),
                            },
                        };
                        let result = observed(outcome)?;
                        tx.execute(
                            "INSERT INTO mutations VALUES(?1,?2,?3)",
                            params![
                                lease.effect.as_str(),
                                operation,
                                serde_json::to_string(&result)?,
                            ],
                        )?;
                        // Both prepares are applied; their first acknowledgements disappear.
                        ReleaseEffectResult::Ambiguous {}
                    }
                    RecoveryMode::Reconcile => {
                        serde_json::from_str(&existing.context("receipt missing")?)?
                    }
                }
            }
            ReleaseOperation::ObserveSecret => {
                let ready: bool =
                    tx.query_row("SELECT ready FROM settings WHERE id=1", [], |row| {
                        row.get(0)
                    })?;
                observed(ReleaseObserved::Secret {
                    metadata: ready.then(|| support::observation(&self.approval, 1)),
                })?
            }
            ReleaseOperation::ObserveDeployment => {
                let body: String = tx.query_row("SELECT body FROM mutations WHERE operation='prepare_deployment' ORDER BY rowid DESC LIMIT 1", [], |row| row.get(0))?;
                let ReleaseEffectResult::Observed(prepared) = serde_json::from_str(&body)? else {
                    anyhow::bail!("prepared deployment receipt missing")
                };
                observed(ReleaseObserved::Deployment {
                    ready: true,
                    incarnation: support::incarnation(&prepared.fact.effect),
                    evidence: StateEvidence::Qualified {
                        revision: RevisionToken::Ordered {
                            stream: prepared.fact.resource.clone(),
                            sequence: 1.try_into()?,
                        },
                        barrier: ReadBarrier {
                            authority: prepared.fact.binding,
                            resource: prepared.fact.resource,
                            after_effect: Some(prepared.fact.effect),
                            receipt: Digest::new(b"qualified-deployment-read"),
                        },
                    },
                })?
            }
            ReleaseOperation::Activate => {
                anyhow::bail!("activation must remain a journal operation")
            }
        };
        tx.commit()?;
        Ok(result)
    }
}

struct LoseActivityAcknowledgement {
    host: Arc<ReleaseExecutionHost>,
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
        if snapshot.phase == ReleasePhase::WaitingSecret
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
async fn roc_resource_release_resumes_through_real_temporal_without_reapplying_prepares()
-> Result<()> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let directory = tempfile::tempdir()?;
            let journal_path = directory.path().join("journal.sqlite");
            let mut journal = Journal::open(&journal_path)?;
            let approval = support::approval(&mut journal, "alpha", 1, 0);
            support::configure(&mut journal, &approval.target, &support::plan("alpha", 1));
            let approved = journal.approve_release(&approval)?;
            let mut server = LocalServer::start(&directory.path().join("temporal")).await?;
            let adapter = server.adapter().await?;
            let recipe = Arc::new(CompiledReleaseRecipe::installed()?);
            let durability = BindingRef::pin(
                support::name("temporal-release"),
                adapter.binding_configuration(),
            )?;
            let plan = ReleaseExecutionPlan {
                release: approved.id().to_owned(),
                recipe: recipe.identity()?,
                durability: durability.clone(),
                resources: approval.secret.binding.clone(),
                deployment: BindingRef::pin(
                    support::name("deployment"),
                    &"synthetic-inactive-deployment",
                )?,
            };
            let provider = Arc::new(Provider::create(
                &directory.path().join("provider.sqlite"),
                plan.clone(),
                approval.clone(),
            )?);
            let host = Arc::new(ReleaseExecutionHost::new(
                journal_path.clone(),
                approval.target.company.clone(),
                support::name("first-worker"),
                durability.clone(),
                provider.clone(),
                recipe.clone(),
            ));
            let id = host.accept(&plan)?;
            assert_eq!(host.accept(&plan)?, id);
            let wrong =
                TemporalAdapter::connect_local(server.address(), server.namespace(), "wrong-queue")
                    .await?;
            assert!(host.dispatch(&wrong).await.is_err());
            assert!(
                host.advance(id.as_str(), wrong.binding_configuration())
                    .is_err()
            );
            // Start was accepted, but the dispatch publisher lost its acknowledgement.
            let start = adapter.ensure_started(id.as_str()).await?;
            assert_eq!(host.dispatch(&adapter).await?, 1);
            assert_eq!(host.dispatch(&adapter).await?, 0);
            assert_eq!(adapter.ensure_started(id.as_str()).await?, start);
            let backend = Arc::new(LoseActivityAcknowledgement {
                host: host.clone(),
                provider: provider.clone(),
            });
            let mut worker = adapter.worker(backend)?;
            let shutdown = worker.shutdown_handle();
            let task = tokio::task::spawn_local(async move { worker.run().await });
            tokio::time::timeout(Duration::from_secs(45), async {
                loop {
                    if provider.secret_reads()? > 0 {
                        break Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .context("release did not reach secret waiting")??;
            shutdown();
            tokio::time::timeout(Duration::from_secs(15), task).await???;
            assert_eq!(host.inspect(&id)?.phase, ReleasePhase::WaitingSecret);
            assert!(journal.release_state(&approval.target)?.active.is_none());
            drop(host);
            drop(provider);
            drop(adapter);
            server.stop()?;
            server.restart().await?;

            let provider = Arc::new(Provider {
                database: directory.path().join("provider.sqlite"),
                plan: plan.clone(),
                approval: approval.clone(),
            });
            provider
                .connection()?
                .execute("UPDATE settings SET ready=1 WHERE id=1", [])?;
            let host = Arc::new(ReleaseExecutionHost::new(
                journal_path.clone(),
                approval.target.company.clone(),
                support::name("replacement-worker"),
                durability,
                provider.clone(),
                recipe,
            ));
            let adapter = server.adapter().await?;
            assert_eq!(host.dispatch(&adapter).await?, 0);
            let mut worker = adapter.worker(host.clone())?;
            let shutdown = worker.shutdown_handle();
            let task = tokio::task::spawn_local(async move { worker.run().await });
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(45), adapter.result(id.as_str()))
                    .await??,
                StepOutcome::Succeeded
            );
            assert_eq!(host.inspect(&id)?.phase, ReleasePhase::Active);
            let active = journal
                .release_state(&approval.target)?
                .active
                .context("activation missing")?;
            assert_eq!(active.release, *approved.id());
            assert_eq!(active.artifact, approval.artifact);
            assert_eq!(active.secret, approval.secret);
            let mutations: i64 =
                provider
                    .connection()?
                    .query_row("SELECT COUNT(*) FROM mutations", [], |row| row.get(0))?;
            assert_eq!(
                mutations, 2,
                "one dependency prepare and one deployment prepare"
            );
            let events = journal.release_event_count(&approval.target)?;
            assert_eq!(
                host.advance(id.as_str(), adapter.binding_configuration()),
                Ok(StepOutcome::Succeeded)
            );
            assert_eq!(journal.release_event_count(&approval.target)?, events);
            let history = adapter.history(id.as_str()).await?;
            assert_redacted(
                &serde_json::from_slice(&history)?,
                &[
                    approval.git.commit.as_str(),
                    approval.secret.secret.as_str(),
                    "synthetic-resources",
                ],
            );
            shutdown();
            tokio::time::timeout(Duration::from_secs(15), task).await???;
            replay(&history).await?;
            server.stop()?;
            Ok(())
        })
        .await
}
