//! Private nondeterministic inputs. App programs cannot supply or replace these.
use crate::{
    artifact::LoadedArtifact,
    error::Failure,
    host_inputs::Inputs,
    protocol::{Phase, Request, Response},
    worker::Worker,
};
use anyhow::{Context, Result, ensure};
use std::{sync::Arc, time::Duration};

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
    fn monotonic(&self) -> Duration;

    fn deadline(&self, phase: Phase, started: Duration) -> Result<()> {
        let (seconds, error) = match phase {
            Phase::Effects => return Ok(()),
            Phase::Prepare => (30, Failure::PreparationDeadline),
            _ => (15, Failure::TransactionDeadline),
        };
        let elapsed = self
            .monotonic()
            .checked_sub(started)
            .context("invalid_monotonic_clock")?;
        ensure!(elapsed < Duration::from_secs(seconds), error);
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct System(pub(crate) Inputs);

impl Host for System {
    fn entropy(&self, _scope: &str, _invocation: &str) -> Result<[u8; 32]> {
        let mut seed = [0; 32];
        self.0
            .entropy
            .fill(&mut seed)
            .context("ID entropy unavailable")?;
        Ok(seed)
    }

    fn now_ms(&self) -> Result<i64> {
        Ok(i64::try_from(self.0.clock.wall_time()?.as_millis())?)
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

    fn monotonic(&self) -> Duration {
        self.0.clock.monotonic()
    }
}

pub(crate) struct Session {
    worker: Worker,
    _executable: Arc<tempfile::TempPath>,
    host: Arc<dyn Host>,
    phase: Phase,
    started: Duration,
}

impl Session {
    pub(crate) fn start(
        artifact: &LoadedArtifact,
        host: Arc<dyn Host>,
        phase: Phase,
    ) -> Result<Self> {
        let executable = artifact.materialize_worker()?;
        let worker = Worker::start(&executable)?;
        let started = host.monotonic();
        Ok(Self {
            worker,
            _executable: executable,
            host,
            phase,
            started,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_inputs::simulation::VirtualClock;
    use std::sync::Mutex;

    #[test]
    fn phase_deadlines_use_only_monotonic_time_and_strict_existing_thresholds() -> Result<()> {
        let clock = Arc::new(VirtualClock(Mutex::new((
            Duration::from_secs(100),
            Duration::from_secs(7),
        ))));
        let host = System(Inputs {
            clock: clock.clone(),
            ..Inputs::default()
        });
        let started = host.monotonic();
        clock.0.lock().unwrap().0 = Duration::from_secs(9000);
        host.deadline(Phase::Decide, started)?;
        clock.0.lock().unwrap().0 = Duration::from_secs(1);
        host.deadline(Phase::Prepare, started)?;
        for phase in [Phase::Prepare, Phase::Decide, Phase::Complete] {
            let seconds = if phase == Phase::Prepare { 30 } else { 15 };
            clock.0.lock().unwrap().1 =
                started + Duration::from_secs(seconds) - Duration::from_nanos(1);
            host.deadline(phase, started)?;
            clock.0.lock().unwrap().1 = started + Duration::from_secs(seconds);
            let error = host.deadline(phase, started).unwrap_err();
            assert_eq!(
                crate::error::classify(&error),
                if phase == Phase::Prepare {
                    Failure::PreparationDeadline
                } else {
                    Failure::TransactionDeadline
                }
            );
        }
        clock.0.lock().unwrap().1 = Duration::MAX;
        host.deadline(Phase::Effects, started)?;
        clock.0.lock().unwrap().1 = Duration::ZERO;
        host.deadline(Phase::Effects, started)?;
        assert_eq!(
            host.deadline(Phase::Decide, started)
                .unwrap_err()
                .to_string(),
            "invalid_monotonic_clock"
        );
        Ok(())
    }
}
