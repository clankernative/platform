#![forbid(unsafe_code)]

//! Private control-plane orchestration. The backend journal, not workflow history,
//! owns business payloads, authorization, effect identities and reconciliation.

pub mod local;

use anyhow::{Context, Result, bail, ensure};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use temporalio_client::{
    Client, ClientOptions, Connection, ConnectionOptions, WorkflowDescribeOptions,
    WorkflowFetchHistoryOptions, WorkflowGetResultOptions, WorkflowHandle, WorkflowHistory,
    WorkflowIdConflictPolicy, WorkflowIdReusePolicy, WorkflowStartOptions,
    errors::WorkflowStartError,
};
use temporalio_common::{
    RetryPolicy, data_converters::SerializationContextData,
    protos::temporal::api::history::v1::history_event::Attributes,
};
use temporalio_macros::{activities, workflow, workflow_methods};
use temporalio_sdk::{
    ActivityOptions, ApplicationFailure, ContinueAsNewOptions, Runtime, TimerResult, Worker,
    WorkerOptions, WorkflowContext, WorkflowResult, WorkflowTermination,
    activities::{ActivityContext, ActivityError},
    workflow_replayer::{WorkflowReplayer, WorkflowReplayerOptions},
};

const WORKFLOW_TYPE: &str = "ReleaseWorkflowV1";
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const WORKFLOW_CONTRACT_VERSION: u32 = 1;
pub const SDK_VERSION: &str = "1.0.0";

/// Only these redacted statuses cross the Temporal payload boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StepOutcome {
    Continue,
    Succeeded,
    Failed,
}

/// Detailed errors must already be in the journal, never embedded in history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    Retryable,
    Rejected,
}

/// Each call may be delivered repeatedly, overlap an expired attempt, or finish
/// after workflow cancellation. Implementations MUST use persisted effect identities
/// and leases; cancelling a workflow does not stop a blocking provider operation.
pub trait AdvanceBackend: Send + Sync + 'static {
    fn advance(
        &self,
        execution_id: &str,
        runtime: &RuntimeConfig,
    ) -> std::result::Result<StepOutcome, BackendError>;
}

struct JournalActivities {
    backend: Arc<dyn AdvanceBackend>,
    runtime: RuntimeConfig,
}

#[activities]
impl JournalActivities {
    #[activity]
    async fn advance(
        self: Arc<Self>,
        _ctx: ActivityContext,
        execution_id: String,
    ) -> std::result::Result<StepOutcome, ActivityError> {
        if validate_id(&execution_id).is_err() {
            return Err(ApplicationFailure::non_retryable("invalid_execution_id").into());
        }
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        match tokio::task::spawn_blocking(move || backend.advance(&execution_id, &runtime)).await {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(BackendError::Rejected)) => {
                Err(ApplicationFailure::non_retryable("backend_rejected").into())
            }
            Ok(Err(BackendError::Retryable)) | Err(_) => {
                Err(ApplicationFailure::new("backend_unavailable").into())
            }
        }
    }
}

// Versioned workflow code only uses recorded activity outcomes and Temporal timers.
// Keep this implementation available while any v1 histories can still be replayed.
#[workflow]
#[derive(Default)]
pub struct ReleaseWorkflowV1;

#[workflow_methods]
impl ReleaseWorkflowV1 {
    #[run]
    pub async fn run(
        ctx: &mut WorkflowContext<Self>,
        execution_id: String,
    ) -> WorkflowResult<StepOutcome> {
        for _ in 0..128 {
            let options = ActivityOptions::with_start_to_close_timeout(ACTIVITY_TIMEOUT)
                .retry_policy(
                    RetryPolicy::builder()
                        .initial_interval(Duration::from_secs(1))
                        .maximum_interval(Duration::from_secs(10))
                        .maximum_attempts(5)
                        .build(),
                )
                .build();
            let outcome = ctx
                .execute_activity(JournalActivities::advance, execution_id.clone(), options)
                .await?;
            if outcome != StepOutcome::Continue {
                return Ok(outcome);
            }
            if ctx.timer(Duration::from_secs(1)).await == TimerResult::Cancelled {
                return Err(WorkflowTermination::cancelled());
            }
        }
        ctx.continue_as_new(execution_id, ContinueAsNewOptions::default())
            .map(|never| match never {})
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartReceipt {
    pub workflow_id: String,
    pub run_id: String,
}

/// Concrete adapter identity to digest into a journal durability binding. These
/// settings are explicit, not resolved again from ambient config on retry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeConfig {
    pub endpoint: String,
    pub namespace: String,
    pub task_queue: String,
    pub workflow_contract_version: u32,
    pub sdk_version: String,
    pub execution_timeout_seconds: u64,
    pub activity_timeout_seconds: u64,
}

impl RuntimeConfig {
    /// Validate and pin the target without contacting it; durable acceptance must survive an outage.
    pub fn local(address: SocketAddr, namespace: &str, task_queue: &str) -> Result<Self> {
        ensure!(
            address.ip().is_loopback() && address.port() != 0,
            "Temporal endpoint must be explicit loopback"
        );
        validate_id(namespace).context("invalid Temporal namespace")?;
        validate_id(task_queue).context("invalid Temporal task queue")?;
        Ok(Self {
            endpoint: format!("http://{address}"),
            namespace: namespace.to_owned(),
            task_queue: task_queue.to_owned(),
            workflow_contract_version: WORKFLOW_CONTRACT_VERSION,
            sdk_version: SDK_VERSION.to_owned(),
            execution_timeout_seconds: EXECUTION_TIMEOUT.as_secs(),
            activity_timeout_seconds: ACTIVITY_TIMEOUT.as_secs(),
        })
    }
}

#[derive(Clone)]
pub struct TemporalAdapter {
    client: Client,
    task_queue: String,
    configuration: RuntimeConfig,
}

impl TemporalAdapter {
    /// The first milestone deliberately supports only a caller-provided loopback
    /// server. No ambient credentials, config profiles or production endpoint fallbacks.
    pub async fn connect_local(
        address: SocketAddr,
        namespace: &str,
        task_queue: &str,
    ) -> Result<Self> {
        let configuration = RuntimeConfig::local(address, namespace, task_queue)?;
        let options = ConnectionOptions::new(url::Url::parse(&format!("http://{address}"))?)
            .identity("day2-local-control-v1")
            .connect_timeout(Duration::from_secs(2))
            .build();
        let connection = Connection::connect(options).await?;
        let client = Client::new(connection, ClientOptions::new(namespace.to_owned()).build())?;
        Ok(Self {
            client,
            task_queue: task_queue.to_owned(),
            configuration,
        })
    }

    pub fn binding_configuration(&self) -> &RuntimeConfig {
        &self.configuration
    }

    /// Acknowledges a durable outbox item only after a successful return. A lost
    /// response is retried with the same ID. Journal terminal receipts must prevent
    /// resubmission after Temporal's finite history retention window.
    pub async fn ensure_started(&self, execution_id: &str) -> Result<StartReceipt> {
        let workflow_id = workflow_id(execution_id)?;
        let options = WorkflowStartOptions::new(&self.task_queue, &workflow_id)
            .id_reuse_policy(WorkflowIdReusePolicy::RejectDuplicate)
            .id_conflict_policy(WorkflowIdConflictPolicy::Fail)
            .execution_timeout(EXECUTION_TIMEOUT)
            .build();
        match self
            .client
            .start_workflow(ReleaseWorkflowV1::run, execution_id.to_owned(), options)
            .await
        {
            Ok(handle) => Ok(StartReceipt {
                workflow_id,
                run_id: handle
                    .run_id()
                    .context("Temporal start omitted run ID")?
                    .to_owned(),
            }),
            Err(WorkflowStartError::AlreadyStarted { .. }) => {
                let description = self
                    .client
                    .get_workflow_handle::<ReleaseWorkflowV1>(&workflow_id)
                    .describe(WorkflowDescribeOptions::default())
                    .await?;
                ensure!(
                    description.workflow_type() == WORKFLOW_TYPE
                        && description.task_queue() == self.task_queue,
                    "existing workflow binding mismatch"
                );
                self.check_existing_input(execution_id, &workflow_id, description.run_id())
                    .await?;
                Ok(StartReceipt {
                    workflow_id,
                    run_id: description.run_id().to_owned(),
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn check_existing_input(
        &self,
        execution_id: &str,
        workflow_id: &str,
        run_id: &str,
    ) -> Result<()> {
        let mut info = self
            .client
            .get_workflow_handle::<ReleaseWorkflowV1>(workflow_id)
            .info()
            .clone();
        info.run_id = Some(run_id.to_owned());
        let handle = WorkflowHandle::<_, ReleaseWorkflowV1>::new(self.client.clone(), info);
        let event = handle
            .fetch_history(WorkflowFetchHistoryOptions::default())
            .next()
            .await
            .context("existing workflow history is empty")??;
        let Some(Attributes::WorkflowExecutionStartedEventAttributes(started)) = event.attributes
        else {
            bail!("existing workflow start event is missing");
        };
        let payloads = started
            .input
            .context("existing workflow input is missing")?
            .payloads;
        ensure!(
            payloads.len() == 1 && payloads[0].data.len() <= 256,
            "existing workflow input shape mismatch"
        );
        let actual: String = self
            .client
            .options()
            .data_converter
            .from_payloads(&SerializationContextData::None, payloads)
            .await?;
        ensure!(
            actual == execution_id,
            "existing workflow execution identity mismatch"
        );
        Ok(())
    }

    pub fn worker(&self, backend: Arc<dyn AdvanceBackend>) -> Result<WorkerRunner> {
        let runtime = Runtime::from_current_tokio(Default::default())?;
        let options = WorkerOptions::new(&self.task_queue)
            .register_activities(JournalActivities {
                backend,
                runtime: self.configuration.clone(),
            })
            .register_workflow::<ReleaseWorkflowV1>()?
            .graceful_shutdown_period(Duration::from_secs(5))
            .build();
        let worker = Worker::new(&runtime, self.client.clone(), options)?;
        Ok(WorkerRunner {
            worker,
            _runtime: runtime,
        })
    }

    pub async fn result(&self, execution_id: &str) -> Result<StepOutcome> {
        Ok(self
            .client
            .get_workflow_handle::<ReleaseWorkflowV1>(workflow_id(execution_id)?)
            .get_result(WorkflowGetResultOptions::default())
            .await?)
    }

    /// Returns the latest run's history. Continue-as-new creates separate histories;
    /// production retention must preserve every pinned run, not just this convenience view.
    pub async fn history(&self, execution_id: &str) -> Result<Vec<u8>> {
        Ok(self
            .client
            .get_workflow_handle::<ReleaseWorkflowV1>(workflow_id(execution_id)?)
            .fetch_history(WorkflowFetchHistoryOptions::default())
            .to_json()
            .await?)
    }
}

pub struct WorkerRunner {
    worker: Worker,
    _runtime: Runtime,
}

impl WorkerRunner {
    pub fn shutdown_handle(&self) -> impl Fn() + Send + Sync + use<> {
        self.worker.shutdown_handle()
    }

    /// Run on a Tokio LocalSet or directly joined future; SDK workflows are !Send.
    pub async fn run(&mut self) -> Result<()> {
        Ok(self.worker.run().await?)
    }
}

pub async fn replay(history_json: &[u8]) -> Result<()> {
    ensure!(
        history_json.len() <= 16 * 1024 * 1024,
        "workflow history exceeds replay budget"
    );
    let replayer = WorkflowReplayer::new(
        WorkflowReplayerOptions::new()
            .register_workflow::<ReleaseWorkflowV1>()?
            .build(),
    )?;
    replayer
        .replay_workflow(WorkflowHistory::from_json(history_json)?)
        .await?;
    Ok(())
}

pub fn workflow_id(execution_id: &str) -> Result<String> {
    validate_id(execution_id)?;
    Ok(format!("day2-release-v1/{execution_id}"))
}

fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:".contains(&byte))
    {
        bail!("expected a bounded opaque identifier");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_identity_is_stable_and_rejects_unbounded_or_structured_input() {
        assert_eq!(
            workflow_id("execution-42").unwrap(),
            "day2-release-v1/execution-42"
        );
        for invalid in [
            "",
            "../other",
            "secret=value",
            "two words",
            "\n",
            &"a".repeat(129),
        ] {
            assert!(workflow_id(invalid).is_err());
        }
    }
}
