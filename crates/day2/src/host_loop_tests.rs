use super::*;
use serde::{Deserialize, Serialize};

#[path = "host_loop_native_tests.rs"]
mod native;

const STEPS: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Snapshot {
    phases: [String; 3],
    stopping: bool,
    ready: Option<usize>,
    poll: [bool; 3],
    drained: bool,
    error: Option<String>,
}

fn snapshot(state: &State, error: Option<&str>) -> Snapshot {
    Snapshot {
        phases: state.phases.map(|phase| format!("{phase:?}")),
        stopping: state.stopping,
        ready: state.ready().map(Pump::index),
        poll: Pump::ALL.map(|pump| state.poll(pump)),
        drained: state.drained(),
        error: error.map(str::to_owned),
    }
}

// Independent history oracle: derive outstanding dispatches and delivered wakes
// from the entire prefix, without calling State, its guard or transition methods.
fn reference(declared: bool, events: &[Event]) -> Snapshot {
    let mut running = [false; 3];
    let mut wakes = [false; 3];
    let enabled = [true, declared, true];
    let mut closed = false;
    let mut error = None;
    for event in events {
        error = None;
        match *event {
            Event::Wake(pump) => {
                let i = pump.index();
                if enabled[i] && !closed && !running[i] {
                    wakes[i] = true;
                }
            }
            Event::Dispatch(pump, admission) => {
                let i = pump.index();
                if !wakes[i] || closed {
                    error = Some("host_pump_not_ready".to_owned());
                } else if !admission {
                    closed = true;
                    wakes = [false; 3];
                } else {
                    wakes[i] = false;
                    running[i] = true;
                }
            }
            Event::Complete(pump, _) => {
                let i = pump.index();
                if running[i] {
                    running[i] = false;
                } else {
                    error = Some("host_pump_not_running".to_owned());
                }
            }
            Event::Stop => {
                closed = true;
                wakes = [false; 3];
            }
        }
    }
    Snapshot {
        phases: std::array::from_fn(|i| {
            if running[i] {
                "Running"
            } else if !enabled[i] || closed {
                "Disabled"
            } else if wakes[i] {
                "Ready"
            } else {
                "Waiting"
            }
            .to_owned()
        }),
        stopping: closed,
        ready: (0..3).find(|i| wakes[*i] && !closed),
        poll: std::array::from_fn(|i| enabled[i] && !closed && !running[i] && !wakes[i]),
        drained: closed && running.iter().all(|value| !value),
        error,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trace {
    format: u8,
    source: String,
    seed: u64,
    declared: bool,
    events: Vec<Event>,
    observations: Vec<Snapshot>,
}

fn decision_source() -> String {
    crate::digest(include_bytes!("host_loop.rs"))
}

fn check(trace: &mut Trace, path: &std::path::Path) {
    assert_eq!(trace.format, 1);
    assert_eq!(
        trace.source,
        decision_source(),
        "replay source identity changed"
    );
    assert!(trace.events.len() <= STEPS + 4, "schedule bound exceeded");
    let mut state = State::new(trace.declared);
    // Save the complete schedule before executing, then every prefix before its
    // assertion. A failed trace is never overwritten by a later campaign.
    std::fs::write(path, serde_json::to_vec_pretty(trace).unwrap()).unwrap();
    for i in 0..trace.events.len() {
        let error = state.apply(trace.events[i]).err();
        let actual = snapshot(&state, error);
        trace.observations.push(actual.clone());
        std::fs::write(path, serde_json::to_vec_pretty(trace).unwrap()).unwrap();
        assert_eq!(
            actual,
            reference(trace.declared, &trace.events[..=i]),
            "seed={} step={i}; complete replay: {}",
            trace.seed,
            path.display()
        );
    }
}

fn replay(path: &std::path::Path) {
    let saved: Trace = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(saved.format, 1);
    assert_eq!(
        saved.source,
        decision_source(),
        "replay source identity changed"
    );
    assert!(saved.events.len() <= STEPS + 4);
    assert!(saved.observations.len() <= saved.events.len());
    let mut state = State::new(saved.declared);
    for (i, event) in saved.events.iter().enumerate() {
        let error = state.apply(*event).err();
        let actual = snapshot(&state, error);
        if let Some(recorded) = saved.observations.get(i) {
            assert_eq!(&actual, recorded);
        }
        assert_eq!(actual, reference(saved.declared, &saved.events[..=i]));
    }
}

#[test]
fn bounded_seeded_schedules_match_independent_history_and_replay() {
    let root = std::path::Path::new("/tmp/dst-platform-host-loops");
    std::fs::create_dir_all(root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("pump-replay-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    let mut witnessed = [false; 7];
    for seed in 0..64_u64 {
        let mut random = seed + 1;
        let mut events = Vec::with_capacity(STEPS + 4);
        for i in 0..STEPS {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let pump = Pump::ALL[((random >> 32) % 3) as usize];
            events.push(match (random >> 40) % 12 {
                0..=4 => Event::Wake(pump),
                5..=7 => Event::Dispatch(pump, (random >> 48) % 8 != 0),
                8 => Event::Complete(pump, Completion::Finished),
                9 => Event::Complete(pump, Completion::Refused),
                10 => Event::Complete(pump, Completion::Failed),
                _ if i > STEPS / 2 => Event::Stop,
                _ => Event::Wake(pump),
            });
        }
        events.push(Event::Stop);
        // Every outstanding call is settled explicitly; bogus completions must
        // fail closed, not silently turn into evidence of successful work.
        events.extend(Pump::ALL.map(|pump| Event::Complete(pump, Completion::Finished)));
        let path = directory.join(format!("seed-{seed}.json"));
        let mut trace = Trace {
            format: 1,
            source: decision_source(),
            seed,
            declared: seed % 2 == 0,
            events,
            observations: Vec::new(),
        };
        check(&mut trace, &path);
        replay(&path);
        assert!(trace.observations.last().unwrap().drained);
        let mut before = reference(trace.declared, &[]);
        for (event, after) in trace.events.iter().zip(&trace.observations) {
            match event {
                Event::Dispatch(_, true) if after.error.is_none() => witnessed[0] = true,
                Event::Dispatch(_, false) if after.error.is_none() => witnessed[1] = true,
                Event::Complete(_, Completion::Failed) if after.error.is_none() => {
                    witnessed[2] = true
                }
                Event::Complete(_, Completion::Refused) if after.error.is_none() => {
                    witnessed[3] = true
                }
                Event::Wake(pump) if before.phases[pump.index()] == "Running" => {
                    witnessed[4] = true
                }
                Event::Stop if !before.stopping => {
                    witnessed[if before.phases.iter().any(|phase| phase == "Running") {
                        5
                    } else {
                        6
                    }] = true;
                }
                _ => {}
            }
            before = after.clone();
        }
    }
    assert_eq!(
        witnessed, [true; 7],
        "generated schedules must make progress and witness each boundary"
    );
}

#[test]
fn proptest_bounded_event_schedules_persist_every_original_and_shrink() {
    use proptest::{
        prelude::*,
        test_runner::{Config, RngSeed, TestRunner},
    };
    const SEED: u64 = 0x5055_4D50;
    let root = std::path::Path::new("/tmp/dst-platform-host-loops");
    std::fs::create_dir_all(root).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("pump-proptest-")
        .tempdir_in(root)
        .unwrap()
        .keep();
    let mut runner = TestRunner::new(Config {
        cases: 32,
        rng_seed: RngSeed::Fixed(SEED),
        max_shrink_iters: 128,
        // Complete schedules and every shrink are saved below, not just seeds.
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(
            &(
                any::<bool>(),
                proptest::collection::vec((0_u8..3, 0_u8..12, any::<bool>()), 0..=STEPS),
            ),
            |(declared, choices)| {
                let mut events = choices
                    .into_iter()
                    .map(|(pump, operation, admission)| {
                        let pump = Pump::ALL[usize::from(pump)];
                        match operation {
                            0..=4 => Event::Wake(pump),
                            5..=7 => Event::Dispatch(pump, admission),
                            8 => Event::Complete(pump, Completion::Finished),
                            9 => Event::Complete(pump, Completion::Refused),
                            10 => Event::Complete(pump, Completion::Failed),
                            _ => Event::Stop,
                        }
                    })
                    .collect::<Vec<_>>();
                events.push(Event::Stop);
                events.extend(Pump::ALL.map(|pump| Event::Complete(pump, Completion::Finished)));
                let (_, path) = tempfile::Builder::new()
                    .prefix("case-")
                    .suffix(".json")
                    .tempfile_in(&directory)
                    .unwrap()
                    .keep()
                    .unwrap();
                let mut trace = Trace {
                    format: 1,
                    source: decision_source(),
                    seed: SEED,
                    declared,
                    events,
                    observations: Vec::new(),
                };
                check(&mut trace, &path);
                replay(&path);
                prop_assert!(trace.observations.last().unwrap().drained);
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn simultaneous_pumps_backpressure_and_stop_have_literal_expectations() {
    let mut state = State::new(true);
    for pump in Pump::ALL {
        state.apply(Event::Wake(pump)).unwrap();
    }
    assert_eq!(state.ready(), Some(Pump::Commands));
    for pump in Pump::ALL {
        assert_eq!(state.ready(), Some(pump));
        state.apply(Event::Dispatch(pump, true)).unwrap();
        state.apply(Event::Wake(pump)).unwrap();
        assert!(!state.poll(pump));
    }
    // A refused or failed native call is finished, not implicitly retried;
    // only another delivered tick can make it runnable again.
    state
        .apply(Event::Complete(Pump::Journal, Completion::Refused))
        .unwrap();
    state
        .apply(Event::Complete(Pump::Schedules, Completion::Failed))
        .unwrap();
    assert_eq!(state.ready(), None);
    state.apply(Event::Wake(Pump::Journal)).unwrap();
    state.apply(Event::Stop).unwrap();
    assert!(!state.drained());
    assert_eq!(state.ready(), None);
    state.apply(Event::Wake(Pump::Commands)).unwrap();
    state
        .apply(Event::Complete(Pump::Commands, Completion::Finished))
        .unwrap();
    assert!(state.drained());
    assert_eq!(state.phases, [Phase::Disabled; 3]);
}

#[test]
fn stop_before_dispatch_and_entry_refusal_share_the_live_guard() {
    assert_eq!(COMMAND_BUDGET, 8);
    assert_eq!(COMMAND_TICK, Duration::from_millis(200));
    assert_eq!(SCHEDULE_TICK, Duration::from_secs(10));
    assert_eq!(JOURNAL_TICK, Duration::from_secs(60));
    assert_eq!(JOURNAL_BATCH, 500);
    assert_eq!(JOURNAL_BATCHES, 20);
    let mut state = State::new(false);
    state.apply(Event::Wake(Pump::Schedules)).unwrap();
    assert_eq!(state.ready(), None);
    state.apply(Event::Wake(Pump::Commands)).unwrap();
    state.apply(Event::Dispatch(Pump::Commands, false)).unwrap();
    assert!(state.drained());
    assert!(!accepts_work(false, false));
    assert!(!accepts_work(true, true));
    assert!(accepts_work(false, true));
    assert_eq!(
        state.apply(Event::Dispatch(Pump::Commands, true)),
        Err("host_pump_not_ready")
    );
    assert_eq!(
        state.apply(Event::Complete(Pump::Commands, Completion::Finished)),
        Err("host_pump_not_running")
    );
}
