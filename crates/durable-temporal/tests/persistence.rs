use anyhow::{Context, Result, ensure};
use durable_temporal::{
    AdvanceBackend, BackendError, ReleaseWorkflowV1, RuntimeConfig, StepOutcome, TemporalAdapter,
    local::{LOCAL_TASK_QUEUE, LocalServer},
    replay, workflow_id,
};
use rusqlite::{Connection, TransactionBehavior, params};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use temporalio_client::{
    Client, ClientOptions, Connection as TemporalConnection, ConnectionOptions,
    WorkflowStartOptions,
};

const EXECUTION: &str = "durability-execution-01";
const PRIVATE_DETAIL: &str = "provider-private-detail-never-in-temporal";

struct LedgerBackend {
    path: PathBuf,
}

impl LedgerBackend {
    fn new(path: &Path) -> Result<Self> {
        let backend = Self {
            path: path.to_owned(),
        };
        backend.connection()?.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE state (id INTEGER PRIMARY KEY, phase INTEGER NOT NULL,
                allowed INTEGER NOT NULL, deliveries INTEGER NOT NULL, private_detail TEXT NOT NULL);
             INSERT INTO state VALUES (1, 0, 0, 0, 'provider-private-detail-never-in-temporal');
             CREATE TABLE effects (identity TEXT PRIMARY KEY);"
        )?;
        Ok(backend)
    }

    fn connection(&self) -> Result<Connection> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        Ok(connection)
    }

    fn phase(&self) -> Result<(i64, i64)> {
        Ok(self.connection()?.query_row(
            "SELECT phase, deliveries FROM state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }

    fn effect_count(&self) -> Result<i64> {
        Ok(self
            .connection()?
            .query_row("SELECT COUNT(*) FROM effects", [], |row| row.get(0))?)
    }

    fn allow_completion(&self) -> Result<()> {
        self.connection()?
            .execute("UPDATE state SET allowed = 1 WHERE id = 1", [])?;
        Ok(())
    }

    fn step(&self, execution_id: &str) -> Result<std::result::Result<StepOutcome, BackendError>> {
        ensure!(
            execution_id == EXECUTION,
            "unexpected opaque execution identity"
        );
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (phase, allowed): (i64, bool) =
            transaction.query_row("SELECT phase, allowed FROM state WHERE id = 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        transaction.execute(
            "UPDATE state SET deliveries = deliveries + 1 WHERE id = 1",
            [],
        )?;
        let result = match (phase, allowed) {
            (0, _) => {
                transaction.execute(
                    "INSERT INTO effects VALUES (?1)",
                    params![format!("{execution_id}:prepare")],
                )?;
                transaction.execute("UPDATE state SET phase = 1 WHERE id = 1", [])?;
                // Commit an effect, then lose its activity acknowledgement. A retry
                // must observe the durable state instead of applying it twice.
                Err(BackendError::Retryable)
            }
            (1, false) => Ok(StepOutcome::Continue),
            (1, true) => {
                transaction.execute(
                    "INSERT INTO effects VALUES (?1)",
                    params![format!("{execution_id}:verify")],
                )?;
                transaction.execute("UPDATE state SET phase = 2 WHERE id = 1", [])?;
                Ok(StepOutcome::Succeeded)
            }
            (2, _) => Ok(StepOutcome::Succeeded),
            _ => Err(BackendError::Rejected),
        };
        transaction.commit()?;
        Ok(result)
    }
}

impl AdvanceBackend for LedgerBackend {
    fn advance(
        &self,
        execution_id: &str,
        _runtime: &RuntimeConfig,
    ) -> std::result::Result<StepOutcome, BackendError> {
        self.step(execution_id)
            .unwrap_or(Err(BackendError::Rejected))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_server_restart_preserves_execution_effect_identity_and_replay() -> Result<()> {
    tokio::task::LocalSet::new()
        .run_until(async {
            let temporary = tempfile::tempdir()?;
            let backend = Arc::new(LedgerBackend::new(
                &temporary.path().join("journal.sqlite"),
            )?);
            let mut server = LocalServer::start(&temporary.path().join("temporal")).await?;
            let adapter = server.adapter().await?;
            let receipt = adapter.ensure_started(EXECUTION).await?;
            // Models a lost outbox acknowledgement: replay start before recording its receipt.
            assert_eq!(adapter.ensure_started(EXECUTION).await?, receipt);
            let mut worker = adapter.worker(backend.clone())?;
            let shutdown = worker.shutdown_handle();
            let task = tokio::task::spawn_local(async move { worker.run().await });
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if backend.phase()?.1 >= 2 {
                        break Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .context("activity retry did not observe the committed effect")??;
            assert_eq!(backend.effect_count()?, 1);
            shutdown();
            tokio::time::timeout(Duration::from_secs(15), task).await???;
            let before = adapter.history(EXECUTION).await?;
            assert!(!String::from_utf8_lossy(&before).contains(PRIVATE_DETAIL));
            assert!(server.database().metadata()?.len() > 0);
            drop(adapter);
            server.stop()?;
            server.restart().await?;
            let adapter = server.adapter().await?;
            let resumed = adapter.ensure_started(EXECUTION).await?;
            assert_eq!(
                resumed, receipt,
                "restart must recover the existing workflow run"
            );
            let restored = adapter.history(EXECUTION).await?;
            let old_events: Value = serde_json::from_slice(&before)?;
            let new_events: Value = serde_json::from_slice(&restored)?;
            let old_events = old_events["events"]
                .as_array()
                .context("missing old history events")?;
            let new_events = new_events["events"]
                .as_array()
                .context("missing restored history events")?;
            assert!(!old_events.is_empty());
            assert_eq!(&new_events[..old_events.len()], old_events);
            // A fresh backend and SDK worker have no retained in-memory execution state.
            drop(backend);
            let backend = Arc::new(LedgerBackend {
                path: temporary.path().join("journal.sqlite"),
            });
            backend.allow_completion()?;
            let mut worker = adapter.worker(backend.clone())?;
            let shutdown = worker.shutdown_handle();
            let task = tokio::task::spawn_local(async move { worker.run().await });
            let outcome =
                tokio::time::timeout(Duration::from_secs(30), adapter.result(EXECUTION)).await??;
            assert_eq!(outcome, StepOutcome::Succeeded);
            assert_eq!(backend.phase()?.0, 2);
            assert_eq!(backend.effect_count()?, 2);
            assert_eq!(
                adapter.ensure_started(EXECUTION).await?,
                receipt,
                "closed execution IDs must not be reused"
            );
            let history = adapter.history(EXECUTION).await?;
            assert!(!String::from_utf8_lossy(&history).contains(PRIVATE_DETAIL));
            std::fs::write(temporary.path().join("workflow-history.json"), &history)?;
            shutdown();
            tokio::time::timeout(Duration::from_secs(15), task).await???;
            // This executes workflow code against persisted history, with no activities/backend.
            replay(&history).await?;
            let raw_connection = TemporalConnection::connect(
                ConnectionOptions::new(url::Url::parse(&format!("http://{}", server.address()))?)
                    .connect_timeout(Duration::from_secs(2))
                    .build(),
            )
            .await?;
            let raw_client = Client::new(
                raw_connection,
                ClientOptions::new(server.namespace().to_owned()).build(),
            )?;
            raw_client
                .start_workflow(
                    ReleaseWorkflowV1::run,
                    "different-execution".to_owned(),
                    WorkflowStartOptions::new(LOCAL_TASK_QUEUE, workflow_id("mismatched-input")?)
                        .build(),
                )
                .await?;
            assert!(
                adapter.ensure_started("mismatched-input").await.is_err(),
                "same workflow type and queue must not conceal a mismatched execution identity"
            );
            server.stop()?;
            Ok(())
        })
        .await
}

#[tokio::test]
async fn adapter_refuses_non_local_endpoints_before_connecting() {
    assert!(
        TemporalAdapter::connect_local("192.0.2.1:7233".parse().unwrap(), "isolated", "queue")
            .await
            .is_err()
    );
}
