//! Private host pump decisions. Wakeup delivery is not occurrence time: timers
//! skip missed deliveries, while schedules derive occurrences from the wall clock.
use std::time::Duration;

pub(crate) const COMMAND_TICK: Duration = Duration::from_millis(200);
pub(crate) const COMMAND_BUDGET: usize = 8;
pub(crate) const SCHEDULE_TICK: Duration = Duration::from_secs(10);
pub(crate) const JOURNAL_TICK: Duration = Duration::from_secs(60);
pub(crate) const JOURNAL_BATCH: usize = 500;
pub(crate) const JOURNAL_BATCHES: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
enum Pump {
    Commands,
    Schedules,
    Journal,
}

impl Pump {
    const ALL: [Self; 3] = [Self::Commands, Self::Schedules, Self::Journal];

    fn index(self) -> usize {
        match self {
            Self::Commands => 0,
            Self::Schedules => 1,
            Self::Journal => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Disabled,
    Waiting,
    Ready,
    Running,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
enum Completion {
    Finished,
    Refused,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
enum Event {
    Wake(Pump),
    Dispatch(Pump, bool),
    Complete(Pump, Completion),
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    phases: [Phase; 3],
    stopping: bool,
}

// This same guard is checked by the pure dispatch transition and again at the
// blocking adapter's entry. Passing it admits one call; it does not promise to
// interrupt an already admitted native call when shutdown is observed later.
fn accepts_work(stopping: bool, admitting: bool) -> bool {
    !stopping && admitting
}

impl State {
    fn new(declared: bool) -> Self {
        Self {
            phases: [
                Phase::Waiting,
                if declared {
                    Phase::Waiting
                } else {
                    Phase::Disabled
                },
                Phase::Waiting,
            ],
            stopping: false,
        }
    }

    fn poll(&self, pump: Pump) -> bool {
        !self.stopping && self.phases[pump.index()] == Phase::Waiting
    }

    fn ready(&self) -> Option<Pump> {
        Pump::ALL
            .into_iter()
            .find(|pump| self.phases[pump.index()] == Phase::Ready)
    }

    fn drained(&self) -> bool {
        self.stopping && !self.phases.contains(&Phase::Running)
    }

    fn apply(&mut self, event: Event) -> Result<(), &'static str> {
        match event {
            Event::Stop => {
                self.stopping = true;
                for phase in &mut self.phases {
                    if *phase != Phase::Running {
                        *phase = Phase::Disabled;
                    }
                }
            }
            Event::Wake(pump) => {
                if self.poll(pump) {
                    self.phases[pump.index()] = Phase::Ready;
                }
                // Duplicate or undeliverable wakeups never build an unbounded
                // queue. The live adapter does not poll a running pump's timer.
            }
            Event::Dispatch(pump, admitting) => {
                if self.phases[pump.index()] != Phase::Ready {
                    return Err("host_pump_not_ready");
                }
                if accepts_work(self.stopping, admitting) {
                    self.phases[pump.index()] = Phase::Running;
                } else {
                    self.apply(Event::Stop)?;
                }
            }
            Event::Complete(pump, _) => {
                if self.phases[pump.index()] != Phase::Running {
                    return Err("host_pump_not_running");
                }
                self.phases[pump.index()] = if self.stopping {
                    Phase::Disabled
                } else {
                    Phase::Waiting
                };
            }
        }
        Ok(())
    }
}

// Native supervision stays private. The adapter delivers ticks/completions to
// the same State used by bounded schedules; it does not model DB/provider work.
use crate::{
    host_inputs::{Clock, LiveTicks},
    store::Runtime,
};
use anyhow::Result;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

trait Work: Send + Sync + 'static {
    fn execute(&self, pump: Pump) -> Completion;

    // Instance-local evidence only; no global hook or alternate decision path.
    #[cfg(test)]
    fn observe(&self, _event: Event, _state: &State) {}
}

struct NativeWork {
    runtime: Runtime,
    clock: Arc<dyn Clock>,
    reported: Mutex<crate::schedules::Refusals>,
}

impl Work for NativeWork {
    fn execute(&self, pump: Pump) -> Completion {
        let result = match pump {
            Pump::Commands => crate::invocations::drain(&self.runtime, COMMAND_BUDGET).map(|_| ()),
            Pump::Schedules => (|| -> Result<()> {
                let ticks = crate::schedules::tick(
                    &self.runtime,
                    self.clock.wall_time()?.as_millis().try_into()?,
                )?;
                let mut reported = self
                    .reported
                    .lock()
                    .expect("schedule refusal lock poisoned");
                for tick in ticks {
                    // A refusal is a condition, reported only when it changes.
                    if reported.should_report(&tick.schedule, tick.skipped.as_ref()) {
                        eprintln!("schedule_not_offered {} {:?}", tick.schedule, tick.skipped);
                    }
                    for (occurrence, outcome) in tick.offered {
                        if outcome.status == "failure" {
                            eprintln!(
                                "schedule_run_failed {} {occurrence} {}",
                                tick.schedule, outcome.error
                            );
                        }
                    }
                }
                Ok(())
            })(),
            Pump::Journal => compact_batches(|batch| {
                crate::journal::compact(
                    &self.runtime,
                    self.clock.wall_time()?.as_secs().try_into()?,
                    batch,
                )
            }),
        };
        match result {
            Ok(()) => Completion::Finished,
            Err(error) => {
                let diagnostic = crate::error::diagnostic(&error);
                match pump {
                    Pump::Commands => eprintln!("command_scheduler_tick_failed {diagnostic}"),
                    Pump::Schedules => eprintln!("schedule_source_tick_failed {diagnostic}"),
                    Pump::Journal => eprintln!("journal_compaction_failed {diagnostic}"),
                }
                Completion::Failed
            }
        }
    }
}

fn compact_batches(mut compact: impl FnMut(usize) -> Result<usize>) -> Result<()> {
    for _ in 0..JOURNAL_BATCHES {
        if compact(JOURNAL_BATCH)? < JOURNAL_BATCH {
            break;
        }
    }
    Ok(())
}

pub(crate) async fn run(
    runtime: Runtime,
    clock: Arc<dyn Clock>,
    ticks: Arc<dyn LiveTicks>,
    admitting: Arc<AtomicBool>,
    stopped: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let declared = !runtime.artifact().contract().schedules.is_empty();
    drive(
        Arc::new(NativeWork {
            runtime,
            clock,
            reported: Mutex::new(crate::schedules::Refusals::default()),
        }),
        ticks,
        admitting,
        stopped,
        declared,
    )
    .await
}

async fn drive(
    work: Arc<dyn Work>,
    ticks: Arc<dyn LiveTicks>,
    admitting: Arc<AtomicBool>,
    mut stopped: tokio::sync::watch::Receiver<bool>,
    declared: bool,
) -> Result<()> {
    let mut state = State::new(declared);
    let mut commands = ticks.start(COMMAND_TICK);
    let mut schedules = declared.then(|| ticks.start(SCHEDULE_TICK));
    let mut journal = ticks.start(JOURNAL_TICK);
    let mut jobs = tokio::task::JoinSet::new();
    let mut running = std::collections::HashMap::new();
    loop {
        if *stopped.borrow() || !admitting.load(Ordering::Acquire) {
            admitting.store(false, Ordering::Release);
            state.apply(Event::Stop).map_err(anyhow::Error::msg)?;
            #[cfg(test)]
            work.observe(Event::Stop, &state);
        }
        if state.drained() {
            return Ok(());
        }
        // Stable preference for stop, settlement, commands, schedules, journal.
        // Timers are not polled while their pump runs. On completion the Skip
        // stream may deliver one late tick, never a burst of missed deliveries.
        let event = tokio::select! {
            biased;
            _ = stopped.changed(), if !state.stopping => Event::Stop,
            Some(joined) = jobs.join_next_with_id(), if !jobs.is_empty() => {
                let (id, completion) = match joined {
                    Ok(value) => value,
                    Err(error) => {
                        let pump = running.get(&error.id()).expect("unknown host pump task");
                        match pump {
                            Pump::Commands => eprintln!("command_scheduler_task_failed"),
                            Pump::Schedules => eprintln!("schedule_source_task_failed"),
                            Pump::Journal => eprintln!("journal_compaction_task_failed"),
                        }
                        (error.id(), Completion::Failed)
                    }
                };
                let pump = running.remove(&id).expect("unknown host pump completion");
                Event::Complete(pump, completion)
            }
            _ = commands.next(), if state.poll(Pump::Commands) => Event::Wake(Pump::Commands),
            _ = async { schedules.as_mut().expect("undeclared schedule polled").next().await },
                if state.poll(Pump::Schedules) => Event::Wake(Pump::Schedules),
            _ = journal.next(), if state.poll(Pump::Journal) => Event::Wake(Pump::Journal),
        };
        if event == Event::Stop {
            admitting.store(false, Ordering::Release);
        }
        state.apply(event).map_err(anyhow::Error::msg)?;
        #[cfg(test)]
        work.observe(event, &state);
        while let Some(pump) = state.ready() {
            let dispatch = Event::Dispatch(pump, admitting.load(Ordering::Acquire));
            state.apply(dispatch).map_err(anyhow::Error::msg)?;
            #[cfg(test)]
            work.observe(dispatch, &state);
            if state.stopping {
                break;
            }
            let work = work.clone();
            let admitting = admitting.clone();
            let task = jobs.spawn_blocking(move || {
                // A queued blocking task may not have started when stop arrives.
                // Recheck the shared guard before entering native work. A call
                // already admitted here may commit/send/settle after shutdown;
                // neither abort nor dropping a JoinHandle would interrupt it.
                if accepts_work(false, admitting.load(Ordering::Acquire)) {
                    work.execute(pump)
                } else {
                    Completion::Refused
                }
            });
            running.insert(task.id(), pump);
        }
    }
}

#[cfg(test)]
#[path = "host_loop_tests.rs"]
mod tests;
