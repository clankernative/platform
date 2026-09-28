//! Real Temporal and real platform journal; provider/build results below are
//! deliberately synthetic. This test is not evidence of a GitHub write or build.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use day2_control::{
    BindingRef, BuildPlan, Digest, GitOid, Name,
    contracts::BuildProfile,
    engine::{Capabilities, EffectResult, ExecutionHost},
    journal::{Journal, Lease, RecoveryMode},
    kernel::{EffectKind, Observation, State, VerificationEvidence},
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

const PRIVATE_SOURCE: &str = "synthetic-source-payload-not-workflow-input";

fn name(value: &str) -> Name {
    value.to_owned().try_into().unwrap()
}

struct FakeCapabilities {
    database: PathBuf,
    plan: BuildPlan,
}

impl FakeCapabilities {
    fn create(database: &Path, plan: BuildPlan) -> Result<Self> {
        let fixture = Self {
            database: database.to_owned(),
            plan,
        };
        fixture.connection()?.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE effects (id TEXT PRIMARY KEY, kind TEXT NOT NULL);
             CREATE TABLE observations (id INTEGER PRIMARY KEY, effect TEXT NOT NULL,
                kind TEXT NOT NULL, reconcile INTEGER NOT NULL);
             CREATE TABLE control (id INTEGER PRIMARY KEY, reveal_receipt INTEGER NOT NULL,
                lost_activity_ack INTEGER NOT NULL, private_source TEXT NOT NULL);
             INSERT INTO control VALUES (1, 0, 0, 'synthetic-source-payload-not-workflow-input');",
        )?;
        Ok(fixture)
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.database)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(connection)
    }

    fn applications(&self, kind: &str) -> Result<i64> {
        Ok(self.connection()?.query_row(
            "SELECT COUNT(*) FROM effects WHERE kind=?1",
            [kind],
            |row| row.get(0),
        )?)
    }

    fn reveal_receipt(&self) -> Result<()> {
        self.connection()?
            .execute("UPDATE control SET reveal_receipt=1 WHERE id=1", [])?;
        Ok(())
    }

    fn lose_activity_ack_once(&self) -> Result<bool> {
        Ok(self.connection()?.execute(
            "UPDATE control SET lost_activity_ack=1 WHERE id=1 AND lost_activity_ack=0",
            [],
        )? == 1)
    }
}

impl Capabilities for FakeCapabilities {
    fn validate(&self, plan: &BuildPlan) -> Result<()> {
        plan.validate()?;
        ensure!(
            plan == &self.plan,
            "test capabilities cannot substitute a different pinned plan"
        );
        Ok(())
    }

    fn perform(&self, lease: &Lease) -> Result<EffectResult> {
        self.validate(&lease.execution.plan)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let kind = match lease.kind {
            EffectKind::FetchSource => "fetch",
            EffectKind::VerifyArtifact => "verify",
            EffectKind::PublishCheck => "publish",
        };
        transaction.execute(
            "INSERT INTO observations(effect,kind,reconcile) VALUES(?1,?2,?3)",
            params![
                lease.effect.as_str(),
                kind,
                lease.recovery == RecoveryMode::Reconcile
            ],
        )?;
        let prior: Option<String> = transaction
            .query_row(
                "SELECT kind FROM effects WHERE id=?1",
                [lease.effect.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let outcome = match lease.kind {
            EffectKind::FetchSource => {
                ensure!(prior.is_none(), "completed source effect was invoked again");
                transaction.execute(
                    "INSERT INTO effects VALUES(?1,?2)",
                    params![lease.effect.as_str(), kind],
                )?;
                EffectResult::Completed(Observation::Source {
                    source: Digest::new(PRIVATE_SOURCE.as_bytes()),
                })
            }
            EffectKind::VerifyArtifact => {
                ensure!(
                    prior.is_none(),
                    "completed verification effect was invoked again"
                );
                transaction.execute(
                    "INSERT INTO effects VALUES(?1,?2)",
                    params![lease.effect.as_str(), kind],
                )?;
                let State::SourceReady { source } = &lease.execution.state else {
                    anyhow::bail!("verification without source");
                };
                EffectResult::Completed(Observation::Verified {
                    evidence: VerificationEvidence {
                        plan: self.plan.fingerprint()?,
                        source: source.clone(),
                        platform: self.plan.profile.platform.clone(),
                        recipe: self.plan.profile.recipe.clone(),
                        builder: self.plan.profile.builder.clone(),
                        artifact: Digest::new(b"synthetic-artifact"),
                        checks: Digest::new(b"synthetic-verified-checks"),
                        credential_presence: day2_control::kernel::CredentialPresence::Absent,
                    },
                })
            }
            EffectKind::PublishCheck => {
                let State::Verified { evidence, .. } = &lease.execution.state else {
                    anyhow::bail!("publication without verification");
                };
                match lease.recovery {
                    RecoveryMode::Execute => {
                        ensure!(
                            prior.is_none(),
                            "ambiguous publication was blindly applied twice"
                        );
                        transaction.execute(
                            "INSERT INTO effects VALUES(?1,?2)",
                            params![lease.effect.as_str(), kind],
                        )?;
                        // The provider applied the mutation but the HTTP response was lost.
                        EffectResult::Ambiguous
                    }
                    RecoveryMode::Reconcile => {
                        ensure!(
                            prior.as_deref() == Some("publish"),
                            "stable publication identity was lost"
                        );
                        let visible: bool = transaction.query_row(
                            "SELECT reveal_receipt FROM control WHERE id=1",
                            [],
                            |row| row.get(0),
                        )?;
                        if visible {
                            EffectResult::Completed(Observation::Published {
                                evidence: evidence.clone(),
                                publication: Digest::new(b"synthetic-check-receipt"),
                            })
                        } else {
                            EffectResult::Ambiguous
                        }
                    }
                }
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }
}

struct LoseAcknowledgement {
    host: Arc<ExecutionHost>,
    capabilities: Arc<FakeCapabilities>,
    journal: PathBuf,
}

impl AdvanceBackend for LoseAcknowledgement {
    fn advance(
        &self,
        execution_id: &str,
        runtime: &RuntimeConfig,
    ) -> std::result::Result<StepOutcome, BackendError> {
        let outcome = self.host.advance(execution_id, runtime)?;
        let lose = || -> Result<bool> {
            let id = Digest::try_from(execution_id.to_owned())?;
            let state = Journal::open(&self.journal)?.get(&id)?.state;
            Ok(matches!(state, State::SourceReady { .. })
                && self.capabilities.lose_activity_ack_once()?)
        };
        if lose().map_err(|_| BackendError::Rejected)? {
            Err(BackendError::Retryable)
        } else {
            Ok(outcome)
        }
    }
}

fn assert_redacted(value: &Value, forbidden: &[&str]) {
    match value {
        Value::String(text) => {
            let decoded = STANDARD.decode(text).unwrap_or_default();
            for secret in forbidden {
                assert!(!text.contains(secret));
                assert!(!String::from_utf8_lossy(&decoded).contains(secret));
            }
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| assert_redacted(value, forbidden)),
        Value::Object(fields) => fields
            .values()
            .for_each(|value| assert_redacted(value, forbidden)),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_release_outbox_restarts_and_reconciles_without_republishing() -> Result<()> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let directory = tempfile::tempdir()?;
            let journal = directory.path().join("control.sqlite");
            let provider = directory.path().join("fake-provider.sqlite");
            let mut server = LocalServer::start(&directory.path().join("temporal")).await?;
            let adapter = server.adapter().await?;
            let durability =
                BindingRef::pin(name("temporal-local"), adapter.binding_configuration())?;
            let plan = BuildPlan {
                version: 1,
                company: name("private-company-name"),
                app: name("links"),
                request: name("release-01"),
                commit: GitOid::try_from("1234567890abcdef1234567890abcdef12345678".to_owned())?,
                profile: BuildProfile {
                    source: BindingRef::pin(name("fake-source"), &"explicit-test-provider")?,
                    builder: BindingRef::pin(name("fake-builder"), &"synthetic-test-evidence")?,
                    durability: durability.clone(),
                    platform: Digest::new(b"platform-v1"),
                    recipe: Digest::new(b"recipe-v1"),
                },
            };
            let capabilities = Arc::new(FakeCapabilities::create(&provider, plan.clone())?);
            let host = Arc::new(ExecutionHost::new(
                journal.clone(),
                plan.company.clone(),
                name("worker-one"),
                durability.clone(),
                capabilities.clone(),
            ));
            let id = host.accept(&plan)?;
            assert_eq!(host.accept(&plan)?, id);
            assert_eq!(
                Journal::open(&journal)?.pending_dispatches(8)?,
                vec![id.clone()]
            );
            let wrong_adapter = TemporalAdapter::connect_local(
                server.address(),
                server.namespace(),
                "wrong-task-queue",
            )
            .await?;
            assert!(
                host.dispatch(&wrong_adapter).await.is_err(),
                "actual adapter config must match the accepted durability binding"
            );
            let before_wrong_activity = Journal::open(&journal)?.event_count(&id)?;
            assert!(
                host.advance(id.as_str(), wrong_adapter.binding_configuration())
                    .is_err(),
                "incoming activities must check the actual worker binding, not its claimed identity"
            );
            assert_eq!(
                Journal::open(&journal)?.event_count(&id)?,
                before_wrong_activity
            );
            assert_eq!(
                Journal::open(&journal)?.pending_dispatches(8)?,
                vec![id.clone()]
            );
            // Temporal accepted start but the publisher crashed before acknowledging the outbox.
            let receipt = adapter.ensure_started(id.as_str()).await?;
            assert_eq!(host.dispatch(&adapter).await?, 1);
            assert_eq!(host.dispatch(&adapter).await?, 0);
            assert!(Journal::open(&journal)?.pending_dispatches(8)?.is_empty());
            assert_eq!(adapter.ensure_started(id.as_str()).await?, receipt);
            let backend = Arc::new(LoseAcknowledgement {
                host: host.clone(),
                capabilities: capabilities.clone(),
                journal: journal.clone(),
            });
            let mut worker = adapter.worker(backend)?;
            let shutdown = worker.shutdown_handle();
            let task = tokio::task::spawn_local(async move { worker.run().await });
            tokio::time::timeout(Duration::from_secs(35), async {
                loop {
                    if capabilities.applications("publish")? == 1 {
                        break Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .context("release did not reach its ambiguous publication")??;
            shutdown();
            tokio::time::timeout(Duration::from_secs(15), task).await???;
            let before = Journal::open(&journal)?.get(&id)?;
            assert!(matches!(before.state, State::Verified { .. }));
            assert_eq!(before.revision, 2);
            assert_eq!(capabilities.applications("fetch")?, 1);
            assert_eq!(capabilities.applications("verify")?, 1);
            assert_eq!(capabilities.applications("publish")?, 1);
            drop(host);
            drop(capabilities);
            drop(adapter);
            server.stop()?;
            server.restart().await?;
            let adapter = server.adapter().await?;
            durability.verify(adapter.binding_configuration())?;
            let capabilities = Arc::new(FakeCapabilities {
                database: provider,
                plan: plan.clone(),
            });
            capabilities.reveal_receipt()?;
            let host = Arc::new(ExecutionHost::new(
                journal.clone(),
                plan.company.clone(),
                name("worker-two"),
                durability,
                capabilities.clone(),
            ));
            assert_eq!(host.dispatch(&adapter).await?, 0);
            assert_eq!(adapter.ensure_started(id.as_str()).await?, receipt);
            let mut worker = adapter.worker(host.clone())?;
            let shutdown = worker.shutdown_handle();
            let task = tokio::task::spawn_local(async move { worker.run().await });
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(30), adapter.result(id.as_str()))
                    .await??,
                StepOutcome::Succeeded
            );
            let completed = Journal::open(&journal)?.get(&id)?;
            assert_eq!(completed.plan, plan);
            assert_eq!(completed.revision, 3);
            assert!(matches!(completed.state, State::Succeeded { .. }));
            assert_eq!(capabilities.applications("publish")?, 1);
            let reconciliations: i64 = capabilities.connection()?.query_row(
                "SELECT COUNT(*) FROM observations WHERE kind='publish' AND reconcile=1",
                [],
                |row| row.get(0),
            )?;
            assert!(reconciliations >= 1);
            let count = Journal::open(&journal)?.event_count(&id)?;
            assert_eq!(
                host.advance(id.as_str(), adapter.binding_configuration())
                    .unwrap(),
                StepOutcome::Succeeded
            );
            assert_eq!(Journal::open(&journal)?.event_count(&id)?, count);
            assert_eq!(adapter.ensure_started(id.as_str()).await?, receipt);
            let history = adapter.history(id.as_str()).await?;
            assert_redacted(
                &serde_json::from_slice(&history)?,
                &[PRIVATE_SOURCE, plan.company.as_str(), plan.commit.as_str()],
            );
            shutdown();
            tokio::time::timeout(Duration::from_secs(15), task).await???;
            replay(&history).await?;
            server.stop()?;
            Ok(())
        })
        .await
}
