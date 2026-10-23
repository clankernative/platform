//! Independent wire-prefix oracle. This deliberately does not call the
//! production message catalog, deadline limits, cursor or transition methods.

use super::{
    Actor, Direction, Frame, Machine, Observation, PollObservation, Protocol, StagePurpose,
    Transport, TransportDecision,
};
use anyhow::{Result, ensure};

pub(super) struct Model {
    protocol: Protocol,
    purpose: StagePurpose,
    actor: Actor,
    sequence: u64,
    accepted: Vec<Frame>,
    // None = no outstanding operation, Some(false) = syscall, Some(true) = poll.
    outstanding: Option<bool>,
    terminal: bool,
    last_clock: Option<Observation>,
}

/// Specification transcripts used by the oracle and history generator. The
/// generator does not ask the implementation what a valid exchange looks like.
pub(super) fn contract(protocol: Protocol, sequence: u64) -> Vec<(Actor, Frame)> {
    use super::super::Step::*;
    use Actor::*;
    let wire: &[(Actor, super::super::Step)] = match protocol {
        Protocol::Enrollment => &[
            (Client, Hello),
            (Issuer, Challenge),
            (Client, Bind),
            (Issuer, Grant),
        ],
        Protocol::InitialStorage => &[
            (Controller, BeginReady),
            (App, Hello),
            (Controller, Offer),
            (App, Confirm),
            (Controller, Complete),
            (App, Accepted),
        ],
        Protocol::CurrentStorage => &[
            (Controller, BeginReady),
            (App, Hello),
            (Controller, Offer),
            (App, Ack),
            (Controller, Ready),
            (Controller, Known),
            (App, Consumed),
            (Controller, Released),
        ],
        Protocol::InitialServing => &[
            (Controller, BeginReady),
            (Shell, Hello),
            (Controller, Offer),
            (Shell, Confirm),
            (Controller, Ready),
        ],
        Protocol::CurrentServing => &[
            (Controller, BeginReady),
            (Shell, Hello),
            (Controller, Offer),
            (Shell, Confirm),
            (Controller, Ready),
            (Controller, Known),
            (Shell, Consumed),
            (Controller, Released),
        ],
    };
    wire.iter()
        .map(|&(actor, step)| {
            let number = match protocol {
                Protocol::CurrentStorage | Protocol::CurrentServing
                    if matches!(step, BeginReady | Hello | Offer) =>
                {
                    Some(sequence)
                }
                _ => None,
            };
            (
                actor,
                Frame {
                    protocol,
                    step,
                    sequence: number,
                },
            )
        })
        .collect()
}

impl Model {
    fn clock(&mut self, clock: Observation) -> Result<()> {
        let limit = if self.protocol == Protocol::InitialStorage {
            10_000_000_000
        } else if self.protocol == Protocol::CurrentStorage
            && self.purpose == StagePurpose::StorageBootstrap
        {
            30_000_000_000
        } else {
            5_000_000_000
        };
        let origin = clock.origin.as_nanos();
        let deadline = clock.deadline.as_nanos();
        let now = clock.now.as_nanos();
        ensure!(
            !self.terminal
                && origin <= now
                && deadline > now
                && deadline > origin
                && deadline - origin <= limit,
            "model interval"
        );
        if let Some(previous) = &self.last_clock {
            ensure!(
                previous.domain == clock.domain
                    && previous.origin == clock.origin
                    && previous.deadline == clock.deadline
                    && previous.now <= clock.now,
                "model original"
            );
        }
        self.last_clock = Some(clock);
        Ok(())
    }

    fn result<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.terminal = true;
        }
        result
    }
}

impl Machine for Model {
    fn new(protocol: Protocol, actor: Actor) -> Self {
        let allowed = match protocol {
            Protocol::Enrollment => [Actor::Client, Actor::Issuer].contains(&actor),
            Protocol::InitialStorage => [Actor::App, Actor::Controller].contains(&actor),
            Protocol::InitialServing => [Actor::Shell, Actor::Controller].contains(&actor),
            _ => false,
        };
        Self {
            protocol,
            purpose: if protocol == Protocol::InitialStorage {
                StagePurpose::InitialFirstHolder
            } else {
                StagePurpose::CurrentRole
            },
            actor,
            sequence: 0,
            accepted: Vec::new(),
            outstanding: None,
            terminal: !allowed,
            last_clock: None,
        }
    }

    fn next(&self) -> Option<(Direction, Frame)> {
        if self.terminal {
            return None;
        }
        let contract = contract(self.protocol, self.sequence);
        let &(sender, frame) = contract.get(self.accepted.len())?;
        Some((
            if sender == self.actor {
                Direction::Send
            } else {
                Direction::Receive
            },
            frame,
        ))
    }

    fn begin(&mut self, direction: Direction, clock: Observation) -> Result<()> {
        let result = (|| {
            ensure!(
                self.outstanding.is_none()
                    && self
                        .next()
                        .is_some_and(|(expected, _)| expected == direction),
                "model outstanding/order"
            );
            self.clock(clock)?;
            self.outstanding = Some(false);
            Ok(())
        })();
        self.result(result)
    }

    fn transport(&mut self, event: Transport, clock: Observation) -> Result<TransportDecision> {
        let result = (|| {
            ensure!(
                self.outstanding.is_some() && event != Transport::Failed,
                "model transport"
            );
            self.clock(clock)?;
            match (self.outstanding, event) {
                (Some(false), Transport::WouldBlock) => {
                    self.outstanding = Some(true);
                    Ok(TransportDecision::Wait)
                }
                (Some(true), Transport::Ready) => {
                    self.outstanding = Some(false);
                    Ok(TransportDecision::Retry)
                }
                (Some(true), Transport::Interrupted) => Ok(TransportDecision::Wait),
                (Some(false), Transport::Interrupted) => Ok(TransportDecision::Retry),
                _ => anyhow::bail!("model poll order"),
            }
        })();
        self.result(result)
    }

    fn delivered(&mut self, frame: Frame, clock: Observation) -> Result<()> {
        let result = (|| {
            ensure!(
                self.outstanding == Some(false)
                    && self.next().is_some_and(|(_, next)| next == frame),
                "model delivered order"
            );
            self.clock(clock)?;
            self.accepted.push(frame);
            self.outstanding = None;
            Ok(())
        })();
        self.result(result)
    }

    fn current(&mut self, sequence: u64, purpose: StagePurpose) -> Result<()> {
        let result = (|| {
            let contract = contract(self.protocol, self.sequence);
            ensure!(
                !self.terminal
                    && self.outstanding.is_none()
                    && self.accepted
                        == contract.iter().map(|(_, frame)| *frame).collect::<Vec<_>>(),
                "model incomplete"
            );
            ensure!(
                self.sequence.checked_add(1) == Some(sequence),
                "model sequence"
            );
            let protocol = match self.protocol {
                Protocol::InitialStorage | Protocol::CurrentStorage => Protocol::CurrentStorage,
                Protocol::InitialServing | Protocol::CurrentServing => Protocol::CurrentServing,
                _ => anyhow::bail!("model enrollment is not renewable"),
            };
            let purpose_allowed = match protocol {
                Protocol::CurrentStorage => matches!(
                    purpose,
                    StagePurpose::CurrentRole | StagePurpose::StorageBootstrap
                ),
                Protocol::CurrentServing => purpose == StagePurpose::CurrentRole,
                _ => false,
            };
            ensure!(purpose_allowed, "model purpose");
            self.protocol = protocol;
            self.purpose = purpose;
            self.sequence = sequence;
            self.accepted.clear();
            self.last_clock = None;
            Ok(())
        })();
        self.result(result)
    }

    fn refuse(&mut self) {
        self.terminal = true;
    }

    fn poll(observation: PollObservation) -> Result<TransportDecision> {
        if observation == PollObservation::Interrupted {
            Ok(TransportDecision::Wait)
        } else if observation == PollObservation::Ready {
            Ok(TransportDecision::Retry)
        } else {
            anyhow::bail!("model poll refused")
        }
    }

    fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "protocol":self.protocol,"purpose":self.purpose,"actor":self.actor,"sequence":self.sequence,
            "position":self.accepted.len(),"busy":self.outstanding.is_some(),
            "waiting":self.outstanding == Some(true),"refused":self.terminal,"clock":self.last_clock,
        })
    }
}
