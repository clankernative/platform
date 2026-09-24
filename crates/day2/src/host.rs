//! Private nondeterministic inputs. App programs cannot supply or replace these.
use crate::{
    artifact::LoadedArtifact,
    error::Failure,
    protocol::{Phase, Request, Response},
    worker::Worker,
};
use anyhow::{Context, Result, ensure};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) enum WorkerAction {
    Run,
    Timeout,
    Crash,
}

pub(crate) trait Host: Send + Sync {
    fn entropy(&self, scope: &str, invocation: &str) -> Result<[u8; 32]>;
    fn now_ms(&self) -> Result<i64>;
    fn worker_action(&self, phase: Phase, request: &Request) -> Result<WorkerAction>;
    fn record_exchange(
        &self,
        phase: Phase,
        request: &Request,
        result: &Result<Response>,
    ) -> Result<()>;
    fn deadline(&self, phase: Phase, started: Instant) -> Result<()>;
}

pub(crate) struct System;

impl Host for System {
    fn entropy(&self, _scope: &str, _invocation: &str) -> Result<[u8; 32]> {
        let mut seed = [0; 32];
        getrandom::fill(&mut seed)
            .map_err(|error| anyhow::anyhow!("ID entropy unavailable: {error}"))?;
        Ok(seed)
    }

    fn now_ms(&self) -> Result<i64> {
        Ok(i64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        )?)
    }

    fn worker_action(&self, _phase: Phase, _request: &Request) -> Result<WorkerAction> {
        Ok(WorkerAction::Run)
    }

    fn record_exchange(
        &self,
        phase: Phase,
        _request: &Request,
        result: &Result<Response>,
    ) -> Result<()> {
        if let Err(error) = result {
            eprintln!(
                "worker_exchange_failed {}",
                serde_json::json!({"phase":format!("{phase:?}"),"cause":crate::error::diagnostic(error)})
            );
        }
        Ok(())
    }

    fn deadline(&self, phase: Phase, started: Instant) -> Result<()> {
        let (seconds, error) = match phase {
            Phase::Effects => return Ok(()),
            Phase::Prepare => (30, Failure::PreparationDeadline),
            _ => (15, Failure::TransactionDeadline),
        };
        ensure!(started.elapsed() < Duration::from_secs(seconds), error);
        Ok(())
    }
}

pub(crate) struct Session {
    worker: Worker,
    _executable: Arc<tempfile::TempPath>,
    host: Arc<dyn Host>,
    phase: Phase,
    started: Instant,
}

impl Session {
    pub(crate) fn start(
        artifact: &LoadedArtifact,
        host: Arc<dyn Host>,
        phase: Phase,
    ) -> Result<Self> {
        let executable = artifact.materialize_worker()?;
        Ok(Self {
            worker: Worker::start(&executable)?,
            _executable: executable,
            host,
            phase,
            started: Instant::now(),
        })
    }

    pub(crate) fn exchange(&mut self, request: &Request) -> Result<Response> {
        let result = (|| {
            self.host.deadline(self.phase, self.started)?;
            match self.host.worker_action(self.phase, request)? {
                WorkerAction::Run => Ok(serde_json::from_slice(
                    &self.worker.exchange(&serde_json::to_vec(request)?)?,
                )?),
                WorkerAction::Timeout => Err(Failure::WorkerTimeout.into()),
                WorkerAction::Crash => Err(Failure::WorkerCrashed.into()),
            }
        })();
        self.host
            .record_exchange(self.phase, request, &result)
            .context("record worker observation")?;
        result
    }
}
