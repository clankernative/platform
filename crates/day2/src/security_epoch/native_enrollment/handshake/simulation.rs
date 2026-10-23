//! Controlled adapter observations driving the production DATA reducer. The
//! oracle records an accepted wire prefix, not the production cursor/state.
//! No native enrollment/process/file/permission owner is made in this module.

use super::{
    Actor, Direction, Frame, Observation, PollObservation, Protocol, Transcript, Transport,
    TransportDecision,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, time::Duration};

mod model;

const MAX_EVENTS: usize = 512;
const MAX_QUEUED: usize = 64;
const MAX_BUNDLE: u64 = 8 * 1024 * 1024;

trait Machine: Sized {
    fn new(protocol: Protocol, actor: Actor) -> Self;
    fn next(&self) -> Option<(Direction, Frame)>;
    fn begin(&mut self, direction: Direction, clock: Observation) -> Result<()>;
    fn transport(&mut self, event: Transport, clock: Observation) -> Result<TransportDecision>;
    fn delivered(&mut self, frame: Frame, clock: Observation) -> Result<()>;
    fn current(&mut self, sequence: u64) -> Result<()>;
    fn poll(observation: PollObservation) -> Result<TransportDecision>;
    fn refuse(&mut self);
    fn snapshot(&self) -> serde_json::Value;
}

impl Machine for Transcript {
    fn new(protocol: Protocol, actor: Actor) -> Self {
        Self::new(protocol, actor)
    }

    fn next(&self) -> Option<(Direction, Frame)> {
        self.next()
    }

    fn begin(&mut self, direction: Direction, clock: Observation) -> Result<()> {
        self.begin(direction, clock)
    }

    fn transport(&mut self, event: Transport, clock: Observation) -> Result<TransportDecision> {
        self.transport(event, clock)
    }

    fn delivered(&mut self, frame: Frame, clock: Observation) -> Result<()> {
        self.delivered(frame, clock)
    }

    fn current(&mut self, sequence: u64) -> Result<()> {
        self.begin_current(sequence)
    }

    fn poll(observation: PollObservation) -> Result<TransportDecision> {
        super::poll_decision(observation)
    }

    fn refuse(&mut self) {
        self.refuse();
    }

    fn snapshot(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    version: u32,
    seed: u64,
    protocol: Protocol,
    events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Begin {
        endpoint: usize,
    },
    Call {
        endpoint: usize,
    },
    Postcheck {
        endpoint: usize,
    },
    Transport {
        endpoint: usize,
        observation: Transport,
    },
    Poll {
        endpoint: usize,
        observation: PollObservation,
    },
    Kill {
        endpoint: usize,
    },
    Advance {
        nanos: u64,
    },
    Rewind {
        nanos: u64,
    },
    Lose {
        sender: usize,
    },
    Duplicate {
        sender: usize,
    },
    Substitute {
        sender: usize,
        frame: Frame,
    },
    PartialSend {
        endpoint: usize,
    },
    NativeRefusal {
        endpoint: usize,
    },
    BeginCurrent {
        endpoint: usize,
        sequence: u64,
    },
    ReplaceClock {
        endpoint: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "wire", rename_all = "snake_case", deny_unknown_fields)]
enum Wire {
    Message { frame: Frame },
    Partial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "attempt", rename_all = "snake_case")]
enum Attempt {
    Idle,
    Calling,
    Waiting,
    Returned { packet: Wire },
}

struct Endpoint<M> {
    machine: M,
    clock: Observation,
    // Native adapter observations, not a substitute native capability.
    alive: bool,
    refused: bool,
    attempt: Attempt,
}

struct World<M> {
    endpoints: [Endpoint<M>; 2],
    queues: [VecDeque<Wire>; 2],
    now: Duration,
    seed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Accepted,
    Retry,
    Wait,
    Refused,
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Record {
    outcome: Outcome,
    snapshot: serde_json::Value,
}

impl<M: Machine> World<M> {
    fn new(program: &Program) -> Result<Self> {
        let actors = match program.protocol {
            Protocol::Enrollment => [Actor::Client, Actor::Issuer],
            Protocol::InitialStorage => [Actor::App, Actor::Controller],
            Protocol::InitialServing => [Actor::Shell, Actor::Controller],
            _ => anyhow::bail!("program must begin with an initial protocol"),
        };
        let limit = if program.protocol == Protocol::InitialStorage {
            10
        } else {
            5
        };
        let endpoints = std::array::from_fn(|index| Endpoint {
            machine: M::new(program.protocol, actors[index]),
            clock: Observation {
                domain: Digest::of(&("handshake-simulation", program.seed, index, 0_u64)).unwrap(),
                origin: Duration::from_secs(100),
                deadline: Duration::from_secs(100 + limit),
                now: Duration::from_secs(100),
            },
            alive: true,
            refused: false,
            attempt: Attempt::Idle,
        });
        Ok(Self {
            endpoints,
            queues: Default::default(),
            now: Duration::from_secs(100),
            seed: program.seed,
        })
    }

    fn refuse(&mut self, endpoint: usize) -> Outcome {
        self.endpoints[endpoint].refused = true;
        self.endpoints[endpoint].machine.refuse();
        Outcome::Refused
    }

    // Controlled observations of the guards that remain native. In particular,
    // buffered packets do not survive an observed peer death, and a later fresh
    // scalar interval cannot revive an adapter whose original already refused.
    fn guard(&mut self, endpoint: usize) -> bool {
        let local = &self.endpoints[endpoint];
        if local.refused
            || !local.alive
            || !self.endpoints[1 - endpoint].alive
            || self.now < local.clock.now
            || self.now < local.clock.origin
            || self.now >= local.clock.deadline
        {
            self.refuse(endpoint);
            return false;
        }
        self.endpoints[endpoint].clock.now = self.now;
        true
    }

    fn step(&mut self, event: &Event) -> Result<Record> {
        let outcome = match *event {
            Event::Advance { nanos } => {
                self.now = self
                    .now
                    .checked_add(Duration::from_nanos(nanos))
                    .context("clock overflow")?;
                Outcome::Accepted
            }
            Event::Rewind { nanos } => {
                self.now = self
                    .now
                    .checked_sub(Duration::from_nanos(nanos))
                    .context("clock underflow")?;
                Outcome::Accepted
            }
            Event::Lose { sender } => {
                if self.queues[sender].pop_front().is_some() {
                    Outcome::Accepted
                } else {
                    Outcome::Absent
                }
            }
            Event::Duplicate { sender } => {
                if let Some(packet) = self.queues[sender].front().cloned() {
                    self.queues[sender].push_front(packet);
                    Outcome::Accepted
                } else {
                    Outcome::Absent
                }
            }
            Event::Substitute { sender, frame } => {
                if let Some(packet) = self.queues[sender].front_mut() {
                    *packet = Wire::Message { frame };
                    Outcome::Accepted
                } else {
                    Outcome::Absent
                }
            }
            Event::Kill { endpoint } => {
                self.endpoints[endpoint].alive = false;
                Outcome::Accepted
            }
            Event::NativeRefusal { endpoint } => self.refuse(endpoint),
            Event::ReplaceClock { endpoint } => {
                let clock = &mut self.endpoints[endpoint].clock;
                clock.domain = Digest::of(&("replacement", &clock.domain))?;
                clock.origin = self.now;
                clock.deadline = self.now + Duration::from_secs(5);
                clock.now = self.now;
                Outcome::Accepted
            }
            Event::BeginCurrent { endpoint, sequence } => {
                if !self.endpoints[endpoint].alive
                    || self.endpoints[endpoint].refused
                    || self.endpoints[endpoint].machine.current(sequence).is_err()
                {
                    self.refuse(endpoint)
                } else {
                    self.endpoints[endpoint].clock = Observation {
                        domain: Digest::of(&(
                            "handshake-simulation",
                            self.seed,
                            endpoint,
                            sequence,
                        ))?,
                        origin: self.now,
                        deadline: self.now + Duration::from_secs(5),
                        now: self.now,
                    };
                    Outcome::Accepted
                }
            }
            Event::Begin { endpoint } => {
                if !self.guard(endpoint) {
                    Outcome::Refused
                } else {
                    let local = &mut self.endpoints[endpoint];
                    let direction = local
                        .machine
                        .next()
                        .map_or(Direction::Send, |(direction, _)| direction);
                    if local.machine.begin(direction, local.clock.clone()).is_err() {
                        self.refuse(endpoint)
                    } else {
                        local.attempt = Attempt::Calling;
                        Outcome::Accepted
                    }
                }
            }
            Event::Transport {
                endpoint,
                observation,
            } => {
                if !self.guard(endpoint) {
                    Outcome::Refused
                } else {
                    let local = &mut self.endpoints[endpoint];
                    if !matches!(local.attempt, Attempt::Calling | Attempt::Waiting) {
                        self.refuse(endpoint)
                    } else {
                        match local.machine.transport(observation, local.clock.clone()) {
                            Ok(TransportDecision::Wait) => {
                                local.attempt = Attempt::Waiting;
                                Outcome::Wait
                            }
                            Ok(TransportDecision::Retry) => {
                                local.attempt = Attempt::Calling;
                                Outcome::Retry
                            }
                            Err(_) => self.refuse(endpoint),
                        }
                    }
                }
            }
            Event::Poll {
                endpoint,
                observation,
            } => {
                if !self.guard(endpoint) {
                    Outcome::Refused
                } else if !matches!(self.endpoints[endpoint].attempt, Attempt::Waiting) {
                    self.refuse(endpoint)
                } else {
                    match M::poll(observation) {
                        Ok(TransportDecision::Wait) => Outcome::Wait,
                        Ok(TransportDecision::Retry) => {
                            let local = &mut self.endpoints[endpoint];
                            if local
                                .machine
                                .transport(Transport::Ready, local.clock.clone())
                                .is_err()
                            {
                                self.refuse(endpoint)
                            } else {
                                local.attempt = Attempt::Calling;
                                Outcome::Retry
                            }
                        }
                        Err(_) => self.refuse(endpoint),
                    }
                }
            }
            Event::Call { endpoint } | Event::PartialSend { endpoint } => {
                if !self.guard(endpoint) {
                    Outcome::Refused
                } else if !matches!(self.endpoints[endpoint].attempt, Attempt::Calling) {
                    self.refuse(endpoint)
                } else if let Some((direction, frame)) = self.endpoints[endpoint].machine.next() {
                    match direction {
                        Direction::Send => {
                            if matches!(event, Event::PartialSend { .. }) {
                                self.queues[endpoint].push_back(Wire::Partial);
                                self.refuse(endpoint)
                            } else {
                                let packet = Wire::Message { frame };
                                self.queues[endpoint].push_back(packet.clone());
                                self.endpoints[endpoint].attempt = Attempt::Returned { packet };
                                Outcome::Accepted
                            }
                        }
                        Direction::Receive => {
                            if let Some(packet) = self.queues[1 - endpoint].pop_front() {
                                self.endpoints[endpoint].attempt = Attempt::Returned { packet };
                                Outcome::Accepted
                            } else {
                                let local = &mut self.endpoints[endpoint];
                                match local
                                    .machine
                                    .transport(Transport::WouldBlock, local.clock.clone())
                                {
                                    Ok(TransportDecision::Wait) => {
                                        local.attempt = Attempt::Waiting;
                                        Outcome::Wait
                                    }
                                    _ => self.refuse(endpoint),
                                }
                            }
                        }
                    }
                } else {
                    self.refuse(endpoint)
                }
            }
            Event::Postcheck { endpoint } => {
                if !self.guard(endpoint) {
                    Outcome::Refused
                } else {
                    let local = &mut self.endpoints[endpoint];
                    match local.attempt.clone() {
                        Attempt::Returned {
                            packet: Wire::Message { frame },
                        } => {
                            if local.machine.delivered(frame, local.clock.clone()).is_err() {
                                self.refuse(endpoint)
                            } else {
                                local.attempt = Attempt::Idle;
                                Outcome::Accepted
                            }
                        }
                        _ => self.refuse(endpoint),
                    }
                }
            }
        };
        ensure!(
            self.queues.iter().all(|queue| queue.len() <= MAX_QUEUED),
            "queue bound exceeded"
        );
        Ok(Record {
            outcome,
            snapshot: self.snapshot(),
        })
    }

    fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "now":self.now, "seed":self.seed, "queues":self.queues,
            "endpoints":self.endpoints.iter().map(|local| serde_json::json!({
                "machine":local.machine.snapshot(), "clock":local.clock,
                "alive":local.alive, "refused":local.refused, "attempt":local.attempt,
            })).collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Category {
    Model,
    Replay,
}

#[derive(Debug, Serialize)]
struct Divergence {
    category: Category,
    records: Vec<Record>,
    expected: serde_json::Value,
}

fn run(program: &Program) -> Result<std::result::Result<Vec<Record>, Divergence>> {
    ensure!(
        program.version == 1 && !program.events.is_empty() && program.events.len() <= MAX_EVENTS,
        "history bound/version"
    );
    ensure!(
        program.events.iter().all(|event| match event {
            Event::Begin { endpoint }
            | Event::Call { endpoint }
            | Event::Postcheck { endpoint }
            | Event::Transport { endpoint, .. }
            | Event::Poll { endpoint, .. }
            | Event::Kill { endpoint }
            | Event::PartialSend { endpoint }
            | Event::NativeRefusal { endpoint }
            | Event::BeginCurrent { endpoint, .. }
            | Event::ReplaceClock { endpoint } => *endpoint < 2,
            Event::Lose { sender }
            | Event::Duplicate { sender }
            | Event::Substitute { sender, .. } => *sender < 2,
            _ => true,
        }),
        "endpoint bound"
    );
    let mut production = World::<Transcript>::new(program)?;
    let mut oracle = World::<model::Model>::new(program)?;
    let mut records = Vec::new();
    for event in &program.events {
        let actual = production.step(event)?;
        let expected = oracle.step(event)?;
        records.push(actual.clone());
        if actual != expected {
            return Ok(Err(Divergence {
                category: Category::Model,
                records,
                expected: serde_json::to_value(expected)?,
            }));
        }
    }
    Ok(Ok(records))
}

fn replayed(program: &Program) -> Result<std::result::Result<Vec<Record>, Divergence>> {
    let first = match run(program)? {
        Ok(records) => records,
        Err(failure) => return Ok(Err(failure)),
    };
    let second = match run(program)? {
        Ok(records) => records,
        Err(failure) => return Ok(Err(failure)),
    };
    if first != second {
        return Ok(Err(Divergence {
            category: Category::Replay,
            records: first,
            expected: serde_json::to_value(second)?,
        }));
    }
    Ok(Ok(first))
}

fn implementation() -> Digest {
    Digest::of(&[
        include_str!("../handshake.rs"),
        include_str!("simulation.rs"),
        include_str!("simulation/model.rs"),
        include_str!("../channel.rs"),
        include_str!("../channel/storage.rs"),
        include_str!("../channel/serving.rs"),
        include_str!("../protocol.rs"),
        include_str!("../../native_enrollment.rs"),
        include_str!("../owner.rs"),
        include_str!("../service.rs"),
        include_str!("../storage_peer.rs"),
        include_str!("../storage_peer_wire.rs"),
        include_str!("../serving_peer_wire.rs"),
        include_str!("../storage_peer/continuation.rs"),
        include_str!("../serving_peer.rs"),
        include_str!("../../native_clock.rs"),
    ])
    .unwrap()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: u32,
    implementation: Digest,
    original: Program,
    reduced: Program,
    category: Category,
    // Serialized typed DATA only; never raw errors, certificates or secrets.
    observations: serde_json::Value,
    replay: String,
}

fn check(program: &Program) -> Result<Vec<Record>> {
    match replayed(program)? {
        Ok(records) => Ok(records),
        Err(failure) => {
            let mut reduced = program.clone();
            let mut attempts = 0;
            let mut index = 0;
            while index < reduced.events.len() && attempts < 128 && reduced.events.len() > 1 {
                attempts += 1;
                let mut candidate = reduced.clone();
                candidate.events.remove(index);
                if matches!(replayed(&candidate), Ok(Err(ref error)) if error.category == failure.category)
                {
                    reduced = candidate;
                } else {
                    index += 1;
                }
            }
            let reduced_failure = replayed(&reduced)?;
            let bundle = Bundle {
                version: 1, implementation: implementation(), original: program.clone(), reduced,
                category: failure.category,
                observations: serde_json::json!({"original":failure,"reduced":reduced_failure.err()}),
                replay: "DAY2_NATIVE_HANDSHAKE_REPLAY=<path> cargo test --locked -p day2 --lib security_epoch::native_enrollment::handshake::simulation::replay_saved_native_handshake_history -- --exact".into(),
            };
            let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/native-handshake-simulation");
            std::fs::create_dir_all(&directory)?;
            let path = directory.join(format!(
                "failure-{}-{:?}-{}-{}.json",
                &bundle.implementation.as_str()[7..],
                program.protocol,
                program.seed,
                program.events.len()
            ));
            let bytes = serde_json::to_vec_pretty(&bundle)?;
            ensure!(
                bytes.len() as u64 <= MAX_BUNDLE,
                "failure evidence bound exceeded"
            );
            // Identical reruns retain the first bundle. Never overwrite older
            // evidence, including a different failure under the same source.
            use std::io::Write;
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => file.write_all(&bytes)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            anyhow::bail!(
                "native handshake model/replay divergence; evidence: {}",
                path.display()
            )
        }
    }
}

#[test]
fn replay_saved_native_handshake_history() -> Result<()> {
    use std::io::Read;
    let Some(path) = std::env::var_os("DAY2_NATIVE_HANDSHAKE_REPLAY") else {
        return Ok(());
    };
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_BUNDLE,
        "replay requires a bounded regular file"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_BUNDLE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_BUNDLE, "replay byte bound");
    let bundle: Bundle = crate::json::decode(&bytes)?;
    ensure!(
        bundle.version == 1 && bundle.implementation == implementation(),
        "replay source identity mismatch"
    );
    ensure!(
        replayed(&bundle.reduced)?.is_ok(),
        "saved handshake counterexample still fails"
    );
    Ok(())
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e3779b97f4a7c15);
    let mut value = *seed;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

fn exchange(protocol: Protocol, sequence: u64, random: &mut u64) -> Vec<Event> {
    let mut events = Vec::new();
    for (actor, _) in model::contract(protocol, sequence) {
        let sender = usize::from(matches!(actor, Actor::Controller | Actor::Issuer));
        let receiver = 1 - sender;
        // The receiver is already blocked before the sender's call. Readiness
        // and successful send are separate observations, not remote receipt.
        events.extend([
            Event::Begin { endpoint: receiver },
            Event::Call { endpoint: receiver },
            Event::Begin { endpoint: sender },
        ]);
        if next(random).is_multiple_of(2) {
            events.push(Event::Transport {
                endpoint: sender,
                observation: Transport::Interrupted,
            });
        }
        if next(random).is_multiple_of(2) {
            events.extend([
                Event::Transport {
                    endpoint: sender,
                    observation: Transport::WouldBlock,
                },
                Event::Advance {
                    nanos: next(random) % 20_000_000,
                },
                Event::Poll {
                    endpoint: sender,
                    observation: PollObservation::Interrupted,
                },
                Event::Poll {
                    endpoint: sender,
                    observation: PollObservation::Ready,
                },
            ]);
        }
        events.extend([
            Event::Call { endpoint: sender },
            Event::Advance {
                nanos: next(random) % 20_000_000,
            },
            Event::Postcheck { endpoint: sender },
            Event::Poll {
                endpoint: receiver,
                observation: PollObservation::Interrupted,
            },
            Event::Poll {
                endpoint: receiver,
                observation: PollObservation::Ready,
            },
            Event::Call { endpoint: receiver },
            Event::Postcheck { endpoint: receiver },
        ]);
    }
    events
}

fn successful(seed: u64, protocol: Protocol) -> Program {
    let mut random = seed;
    let mut events = exchange(protocol, 0, &mut random);
    let current = match protocol {
        Protocol::InitialStorage => Some(Protocol::CurrentStorage),
        Protocol::InitialServing => Some(Protocol::CurrentServing),
        _ => None,
    };
    if let Some(current) = current {
        for sequence in 1..=2 {
            // Expired historical handshakes are identity DATA only. Only a
            // fully known/released prior transcript can begin a fresh phase.
            events.push(Event::Advance {
                nanos: 20_000_000_000,
            });
            for endpoint in 0..2 {
                events.push(Event::BeginCurrent { endpoint, sequence });
            }
            events.extend(exchange(current, sequence, &mut random));
        }
    }
    Program {
        version: 1,
        seed,
        protocol,
        events,
    }
}

#[test]
fn seeded_enrollment_storage_and_serving_transcripts_replay_against_independent_model() -> Result<()>
{
    for protocol in [
        Protocol::Enrollment,
        Protocol::InitialStorage,
        Protocol::InitialServing,
    ] {
        for seed in 1..=32 {
            let program = successful(seed, protocol);
            let records = check(&program)?;
            ensure!(
                records
                    .iter()
                    .all(|record| record.outcome != Outcome::Refused),
                "positive transcript refused"
            );
            let last = &records.last().unwrap().snapshot;
            let expected = if protocol == Protocol::Enrollment {
                4
            } else {
                8
            };
            for endpoint in last["endpoints"].as_array().unwrap() {
                ensure!(
                    endpoint["machine"]["position"] == expected
                        && endpoint["machine"]["busy"] == false
                        && endpoint["machine"]["refused"] == false,
                    "positive transcript incomplete"
                );
            }
            ensure!(
                last["queues"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|queue| queue.as_array().unwrap().is_empty()),
                "positive queued remainder"
            );
        }
    }
    Ok(())
}

#[test]
fn every_wire_position_explores_loss_duplicates_death_expiry_and_postcheck_cuts() -> Result<()> {
    let mut seed = 10_000;
    let mut coverage = std::collections::BTreeSet::new();
    for protocol in [
        Protocol::Enrollment,
        Protocol::InitialStorage,
        Protocol::InitialServing,
    ] {
        let base = successful(seed, protocol);
        let mut oracle = World::<model::Model>::new(&base)?;
        // Fault every completed syscall before its final native postcheck,
        // across enrollment, first holder and both current settlement rounds.
        for (index, event) in base.events.iter().enumerate() {
            let direction = match *event {
                Event::Postcheck { endpoint } => oracle.endpoints[endpoint]
                    .machine
                    .next()
                    .map(|(direction, _)| direction),
                _ => None,
            };
            oracle.step(event)?;
            let Event::Postcheck { endpoint } = *event else {
                continue;
            };
            for fault in 0..10 {
                if matches!(fault, 4 | 5 | 9) && direction != Some(Direction::Send) {
                    continue;
                }
                seed += 1;
                let mut program = base.clone();
                program.seed = seed;
                let inserted = match fault {
                    0 => Event::Kill { endpoint },
                    1 => Event::Kill {
                        endpoint: 1 - endpoint,
                    },
                    2 => Event::Advance {
                        nanos: 10_000_000_000,
                    },
                    3 => Event::Rewind {
                        nanos: 1_000_000_000,
                    },
                    4 => Event::Lose { sender: endpoint },
                    5 => Event::Duplicate { sender: endpoint },
                    6 => Event::NativeRefusal { endpoint },
                    7 => Event::ReplaceClock { endpoint },
                    8 => Event::BeginCurrent {
                        endpoint,
                        sequence: 99,
                    },
                    _ => Event::Substitute {
                        sender: endpoint,
                        frame: Frame {
                            protocol: Protocol::Enrollment,
                            step: super::Step::Grant,
                            sequence: None,
                        },
                    },
                };
                program.events.insert(index, inserted);
                if fault == 4 {
                    program.events.truncate(index + 2); // fault, then sender's real postcheck
                    let receiver = 1 - endpoint;
                    program.events.extend([
                        Event::Transport {
                            endpoint: receiver,
                            observation: Transport::Ready,
                        },
                        Event::Call { endpoint: receiver }, // still unavailable, remains waiting
                        Event::Advance {
                            nanos: 10_000_000_000,
                        },
                        Event::Transport {
                            endpoint: receiver,
                            observation: Transport::Ready,
                        },
                    ]);
                }
                // Lost final messages may leave a receiver waiting. Observe its
                // original deadline, then try late/replayed work: no revival.
                program.events.extend([
                    Event::Advance {
                        nanos: 10_000_000_000,
                    },
                    Event::Begin { endpoint: 0 },
                    Event::Call { endpoint: 0 },
                    Event::Postcheck { endpoint: 0 },
                    Event::Begin { endpoint: 1 },
                    Event::Call { endpoint: 1 },
                    Event::Postcheck { endpoint: 1 },
                    Event::ReplaceClock { endpoint: 0 },
                    Event::Begin { endpoint: 0 },
                ]);
                let records = check(&program)?;
                if matches!(fault, 4 | 5 | 9) {
                    ensure!(
                        records[index].outcome == Outcome::Accepted,
                        "wire fault did not affect an actual queued packet"
                    );
                }
                ensure!(
                    records
                        .iter()
                        .any(|record| record.outcome == Outcome::Refused),
                    "fault did not reach refusal"
                );
                // Count executed refusal, not merely a generated fault action.
                coverage.insert((format!("{protocol:?}"), fault));
            }
        }
    }
    ensure!(coverage.len() == 30, "missing executed fault family");
    Ok(())
}

#[test]
fn seeded_adversarial_schedules_keep_complete_bounded_state_and_terminal_refusal() -> Result<()> {
    for protocol in [
        Protocol::Enrollment,
        Protocol::InitialStorage,
        Protocol::InitialServing,
    ] {
        for seed in 100..132 {
            let mut random = seed;
            let mut program = successful(seed, protocol);
            let cut = (next(&mut random) as usize) % program.events.len();
            program.events.truncate(cut + 1);
            for _ in 0..96 {
                let endpoint = (next(&mut random) % 2) as usize;
                let event = match next(&mut random) % 15 {
                    0 => Event::Begin { endpoint },
                    1 => Event::Call { endpoint },
                    2 => Event::Postcheck { endpoint },
                    3 => Event::Transport {
                        endpoint,
                        observation: Transport::Interrupted,
                    },
                    4 => Event::Transport {
                        endpoint,
                        observation: Transport::WouldBlock,
                    },
                    5 => Event::Transport {
                        endpoint,
                        observation: Transport::Ready,
                    },
                    6 => Event::Transport {
                        endpoint,
                        observation: Transport::Failed,
                    },
                    7 => Event::Advance {
                        nanos: next(&mut random) % 6_000_000_000,
                    },
                    8 => Event::Lose { sender: endpoint },
                    9 => Event::Duplicate { sender: endpoint },
                    10 => Event::Kill { endpoint },
                    11 => Event::PartialSend { endpoint },
                    12 => Event::BeginCurrent {
                        endpoint,
                        sequence: next(&mut random) % 5,
                    },
                    13 => Event::NativeRefusal { endpoint },
                    _ => Event::ReplaceClock { endpoint },
                };
                program.events.push(event);
            }
            check(&program)?;
        }
    }
    Ok(())
}

#[test]
fn exact_deadlines_spent_time_and_ambiguous_sends_never_become_remote_acceptance() -> Result<()> {
    for (protocol, sender, seconds) in [
        (Protocol::Enrollment, 0, 5),
        (Protocol::InitialStorage, 1, 10),
        (Protocol::InitialServing, 1, 5),
    ] {
        let receiver = 1 - sender;
        let mut program = Program {
            version: 1,
            seed: 1000 + seconds,
            protocol,
            events: vec![
                Event::Begin { endpoint: sender },
                Event::Call { endpoint: sender },
                Event::Advance {
                    nanos: seconds * 1_000_000_000,
                },
                Event::Postcheck { endpoint: sender },
                Event::Begin { endpoint: receiver },
                Event::Call { endpoint: receiver },
                Event::Postcheck { endpoint: receiver },
            ],
        };
        let records = check(&program)?;
        ensure!(
            records[3].outcome == Outcome::Refused,
            "deadline equality accepted"
        );
        ensure!(
            records.last().unwrap().snapshot["endpoints"][sender]["machine"]["position"] == 0,
            "ambiguous send advanced local transcript"
        );
        program.events = vec![
            Event::Advance {
                nanos: seconds * 1_000_000_000 - 1,
            },
            Event::Begin { endpoint: sender },
            Event::Call { endpoint: sender },
            Event::Postcheck { endpoint: sender },
            Event::Begin { endpoint: receiver },
            Event::Call { endpoint: receiver },
            Event::Postcheck { endpoint: receiver },
        ];
        ensure!(
            check(&program)?
                .iter()
                .all(|record| record.outcome != Outcome::Refused),
            "strictly before deadline refused"
        );
        // Even InitialStorage's ten-second interval does not widen the issuer
        // exchange: enrollment always refuses at five seconds.
    }
    Ok(())
}

#[test]
fn production_reducer_itself_refuses_replaced_rewound_expired_and_widened_clock_data() -> Result<()>
{
    // Exercise the shared production transitions directly, without the world's
    // stand-in native guards rejecting the observation first.
    for (protocol, actor, limit) in [
        (Protocol::Enrollment, Actor::Client, 5),
        (Protocol::InitialStorage, Actor::Controller, 10),
        (Protocol::InitialServing, Actor::Controller, 5),
    ] {
        let original = Observation {
            domain: Digest::new(b"original"),
            origin: Duration::from_secs(100),
            deadline: Duration::from_secs(100 + limit),
            now: Duration::from_secs(101),
        };
        for fault in 0..6 {
            let mut actual = Transcript::new(protocol, actor);
            let mut expected = model::Model::new(protocol, actor);
            actual.begin(Direction::Send, original.clone())?;
            expected.begin(Direction::Send, original.clone())?;
            let mut changed = original.clone();
            match fault {
                0 => changed.now = changed.deadline,
                1 => changed.now -= Duration::from_nanos(1),
                2 => changed.deadline += Duration::from_nanos(1),
                3 => changed.origin -= Duration::from_nanos(1),
                4 => changed.domain = Digest::new(b"replacement"),
                _ => changed.now = changed.origin - Duration::from_nanos(1),
            }
            ensure!(
                actual
                    .transport(Transport::Interrupted, changed.clone())
                    .is_err(),
                "shared reducer accepted bad original"
            );
            ensure!(
                expected.transport(Transport::Interrupted, changed).is_err(),
                "oracle accepted bad original"
            );
            ensure!(
                actual.snapshot() == expected.snapshot(),
                "bad original snapshot"
            );
            ensure!(
                actual
                    .transport(Transport::Interrupted, original.clone())
                    .is_err(),
                "original revived after refusal"
            );
            ensure!(
                actual.begin_current(1).is_err(),
                "new phase revived refusal"
            );
        }
        let mut too_wide = original;
        too_wide.deadline += Duration::from_nanos(1);
        ensure!(
            Transcript::new(protocol, actor)
                .begin(Direction::Send, too_wide)
                .is_err(),
            "first observation widened window"
        );
    }
    Ok(())
}

#[test]
fn partial_packets_and_observed_peer_death_refuse_even_with_buffered_message_data() -> Result<()> {
    for protocol in [
        Protocol::Enrollment,
        Protocol::InitialStorage,
        Protocol::InitialServing,
    ] {
        let sender = usize::from(protocol != Protocol::Enrollment);
        let receiver = 1 - sender;
        for partial in [false, true] {
            let mut events = vec![Event::Begin { endpoint: sender }];
            if partial {
                events.push(Event::PartialSend { endpoint: sender });
            } else {
                events.extend([
                    Event::Call { endpoint: sender },
                    Event::Postcheck { endpoint: sender },
                    Event::Kill { endpoint: sender },
                ]);
            }
            events.extend([
                Event::Begin { endpoint: receiver },
                Event::Call { endpoint: receiver },
                Event::Postcheck { endpoint: receiver },
            ]);
            let records = check(&Program {
                version: 1,
                seed: 7000,
                protocol,
                events,
            })?;
            let last = &records.last().unwrap().snapshot;
            ensure!(
                last["endpoints"][receiver]["machine"]["position"] == 0
                    && last["endpoints"][receiver]["machine"]["refused"] == true,
                "buffered message survived refusal/death"
            );
        }
    }
    Ok(())
}

#[test]
fn interrupted_polls_keep_one_wait_and_timeout_or_unexpected_events_never_resume() -> Result<()> {
    for protocol in [
        Protocol::Enrollment,
        Protocol::InitialStorage,
        Protocol::InitialServing,
    ] {
        let receiver = usize::from(protocol == Protocol::Enrollment);
        for observation in [PollObservation::Timeout, PollObservation::UnexpectedEvents] {
            let program = Program {
                version: 1,
                seed: 8000,
                protocol,
                events: vec![
                    Event::Begin { endpoint: receiver },
                    Event::Call { endpoint: receiver },
                    Event::Advance { nanos: 1_000_000 },
                    Event::Poll {
                        endpoint: receiver,
                        observation: PollObservation::Interrupted,
                    },
                    Event::Poll {
                        endpoint: receiver,
                        observation,
                    },
                    Event::Poll {
                        endpoint: receiver,
                        observation: PollObservation::Ready,
                    },
                    Event::ReplaceClock { endpoint: receiver },
                    Event::Begin { endpoint: receiver },
                ],
            };
            let records = check(&program)?;
            ensure!(
                records[3].outcome == Outcome::Wait
                    && records[4].outcome == Outcome::Refused
                    && records[5].outcome == Outcome::Refused
                    && records[7].outcome == Outcome::Refused,
                "failed poll resumed or interrupted poll advanced"
            );
        }
    }
    Ok(())
}
