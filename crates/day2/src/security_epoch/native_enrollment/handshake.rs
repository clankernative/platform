//! Schedulable protocol decisions, exclusively DATA. A completed transcript is
//! not an authenticated sender, enrolled stage, file, holder or serving permit.
//! Native adapters still retain and check every actual kernel/process owner.

use super::protocol::StagePurpose;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Actor {
    Client,
    Issuer,
    Controller,
    App,
    Shell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Protocol {
    Enrollment,
    InitialStorage,
    RestoredStorage,
    CurrentStorage,
    InitialServing,
    CurrentServing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Step {
    Hello,
    Challenge,
    Bind,
    Grant,
    BeginReady,
    Offer,
    Confirm,
    Complete,
    Accepted,
    Ack,
    Ready,
    Known,
    Consumed,
    Released,
    Frozen,
    Drained,
    Fenced,
    FenceConfirmed,
    StopReleased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Direction {
    Send,
    Receive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Frame {
    pub protocol: Protocol,
    pub step: Step,
    // Present on current BeginReady/Hello/Offer; subsequent messages bind the
    // exchange digest instead. The native semantic/signature checks remain.
    pub sequence: Option<u64>,
}

/// Historical clock DATA supplied after a native check, or by a test scheduler.
/// No constructor for NativeAcquisition or any admission owner accepts this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub domain: Digest,
    pub origin: Duration,
    pub deadline: Duration,
    pub now: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Transport {
    Interrupted,
    WouldBlock,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TransportDecision {
    Retry,
    Wait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PollObservation {
    Interrupted,
    Ready,
    Timeout,
    UnexpectedEvents,
}

/// The native poll adapter classifies count/flags without accepting buffered
/// IN together with HUP/ERR. EINTR repeats only the original bounded wait.
pub(super) fn poll_decision(observation: PollObservation) -> Result<TransportDecision> {
    match observation {
        PollObservation::Interrupted => Ok(TransportDecision::Wait),
        PollObservation::Ready => Ok(TransportDecision::Retry),
        PollObservation::Timeout => anyhow::bail!("native_enrollment_socket_poll_timeout"),
        PollObservation::UnexpectedEvents => {
            anyhow::bail!("native_enrollment_socket_unexpected_events")
        }
    }
}

/// Full bounded decision state, also the composition seam for lifecycle DST.
/// There is no DATA-to-native-owner conversion and no ambient I/O here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Transcript {
    protocol: Protocol,
    purpose: StagePurpose,
    actor: Actor,
    sequence: u64,
    position: usize,
    busy: bool,
    waiting: bool,
    refused: bool,
    clock: Option<Observation>,
    storage_tail: StorageTail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StorageTail {
    Ordinary,
    Restore,
}

impl Protocol {
    fn messages(self) -> &'static [(Actor, Step)] {
        use Actor::*;
        use Step::*;
        match self {
            Self::Enrollment => &[
                (Client, Hello),
                (Issuer, Challenge),
                (Client, Bind),
                (Issuer, Grant),
            ],
            Self::InitialStorage => &[
                (Controller, BeginReady),
                (App, Hello),
                (Controller, Offer),
                (App, Confirm),
                (Controller, Complete),
                (App, Accepted),
            ],
            Self::RestoredStorage => &[
                (Controller, BeginReady),
                (App, Hello),
                (Controller, Offer),
                (App, Confirm),
                (Controller, Complete),
                (App, Accepted),
                (Controller, Known),
                (App, Consumed),
                (Controller, Released),
            ],
            Self::CurrentStorage => &[
                (Controller, BeginReady),
                (App, Hello),
                (Controller, Offer),
                (App, Ack),
                (Controller, Ready),
                (Controller, Known),
                (App, Consumed),
                (Controller, Released),
            ],
            Self::InitialServing => &[
                (Controller, BeginReady),
                (Shell, Hello),
                (Controller, Offer),
                (Shell, Confirm),
                (Controller, Ready),
            ],
            Self::CurrentServing => &[
                (Controller, BeginReady),
                (Shell, Hello),
                (Controller, Offer),
                (Shell, Confirm),
                (Controller, Ready),
                (Controller, Known),
                (Shell, Consumed),
                (Controller, Released),
            ],
        }
    }

    fn limit(self, purpose: StagePurpose) -> Result<Duration> {
        ensure!(
            matches!(
                (self, purpose),
                (Self::InitialStorage, StagePurpose::InitialFirstHolder)
                    | (Self::CurrentStorage, StagePurpose::StorageBootstrap)
                    | (
                        Self::Enrollment
                            | Self::RestoredStorage
                            | Self::CurrentStorage
                            | Self::InitialServing
                            | Self::CurrentServing,
                        StagePurpose::CurrentRole
                    )
            ),
            "native_handshake_stage_purpose"
        );
        Ok(purpose.limit())
    }
}

impl Transcript {
    pub(super) fn new(protocol: Protocol, actor: Actor) -> Self {
        let selected = matches!(
            (protocol, actor),
            (Protocol::Enrollment, Actor::Client | Actor::Issuer)
                | (
                    Protocol::InitialStorage | Protocol::RestoredStorage,
                    Actor::App | Actor::Controller
                )
                | (Protocol::InitialServing, Actor::Shell | Actor::Controller)
        );
        Self {
            protocol,
            purpose: if protocol == Protocol::InitialStorage {
                StagePurpose::InitialFirstHolder
            } else {
                StagePurpose::CurrentRole
            },
            actor,
            sequence: 0,
            position: 0,
            busy: false,
            waiting: false,
            refused: !selected,
            clock: None,
            storage_tail: StorageTail::Ordinary,
        }
    }

    /// Only a completely exchanged prior transcript can start another current
    /// transcript. Native disposition/file/consumer final checks are additional
    /// requirements; completing these DATA steps does not settle an operation.
    pub(super) fn begin_current(&mut self, sequence: u64, purpose: StagePurpose) -> Result<()> {
        let result = (|| {
            ensure!(
                self.complete() && self.storage_tail == StorageTail::Ordinary,
                "native_handshake_previous_incomplete"
            );
            ensure!(
                self.sequence.checked_add(1) == Some(sequence),
                "native_handshake_sequence"
            );
            let protocol = match self.protocol {
                Protocol::InitialStorage | Protocol::RestoredStorage | Protocol::CurrentStorage => {
                    Protocol::CurrentStorage
                }
                Protocol::InitialServing | Protocol::CurrentServing => Protocol::CurrentServing,
                Protocol::Enrollment => anyhow::bail!("native_handshake_no_reenrollment"),
            };
            protocol.limit(purpose)?;
            self.protocol = protocol;
            self.purpose = purpose;
            self.sequence = sequence;
            self.position = 0;
            self.clock = None;
            Ok(())
        })();
        self.finish_result(result)
    }

    pub(super) fn next(&self) -> Option<(Direction, Frame)> {
        if self.refused {
            return None;
        }
        let &(sender, step) = self.messages().get(self.position)?;
        let direction = if sender == self.actor {
            Direction::Send
        } else {
            Direction::Receive
        };
        let sequence = if matches!(
            self.protocol,
            Protocol::CurrentStorage | Protocol::CurrentServing
        ) && matches!(step, Step::BeginReady | Step::Hello | Step::Offer)
        {
            Some(self.sequence)
        } else {
            None
        };
        Some((
            direction,
            Frame {
                protocol: self.protocol,
                step,
                sequence,
            },
        ))
    }

    fn messages(&self) -> &'static [(Actor, Step)] {
        if self.protocol == Protocol::CurrentStorage && self.storage_tail == StorageTail::Restore {
            &[
                (Actor::Controller, Step::BeginReady),
                (Actor::App, Step::Hello),
                (Actor::Controller, Step::Offer),
                (Actor::App, Step::Ack),
                (Actor::Controller, Step::Ready),
                (Actor::Controller, Step::Frozen),
                (Actor::App, Step::Drained),
                (Actor::Controller, Step::Fenced),
                (Actor::App, Step::FenceConfirmed),
                (Actor::Controller, Step::StopReleased),
            ]
        } else {
            self.protocol.messages()
        }
    }

    /// The one closed restore branch is selected only at the existing result
    /// slot. This retains the prior clock/sequence and cannot restart a phase.
    /// Senders select before IO; receivers select from the actual delivered
    /// frame after IO. Native signatures and semantic stop checks remain owed.
    pub(super) fn select_frame(&mut self, frame: Frame) -> Result<()> {
        let result = (|| {
            if self.protocol == Protocol::CurrentStorage
                && self.position == 5
                && self.storage_tail == StorageTail::Ordinary
                && frame.protocol == Protocol::CurrentStorage
                && frame.step == Step::Frozen
                && frame.sequence.is_none()
            {
                ensure!(
                    self.purpose == StagePurpose::CurrentRole,
                    "restore_stop_current_original_required"
                );
                self.storage_tail = StorageTail::Restore;
            }
            ensure!(
                self.next().is_some_and(|(_, expected)| expected == frame),
                "native_handshake_message_order"
            );
            Ok(())
        })();
        self.finish_result(result)
    }

    pub(super) fn begin(&mut self, direction: Direction, observation: Observation) -> Result<()> {
        let result = (|| {
            ensure!(!self.busy, "native_handshake_operation_busy");
            ensure!(
                self.next().is_some_and(|(next, _)| next == direction),
                "native_handshake_order"
            );
            self.observe(observation)?;
            self.busy = true;
            Ok(())
        })();
        self.finish_result(result)
    }

    /// Interrupted and unavailable transport never advance the transcript or
    /// replace its clock. The native adapter chooses poll vs syscall retry.
    pub(super) fn transport(
        &mut self,
        transport: Transport,
        observation: Observation,
    ) -> Result<TransportDecision> {
        let result = (|| {
            ensure!(
                self.busy && transport != Transport::Failed,
                "native_handshake_transport"
            );
            self.observe(observation)?;
            match transport {
                Transport::WouldBlock => {
                    ensure!(!self.waiting, "native_handshake_already_waiting");
                    self.waiting = true;
                    Ok(TransportDecision::Wait)
                }
                Transport::Ready => {
                    ensure!(self.waiting, "native_handshake_unexpected_readiness");
                    self.waiting = false;
                    Ok(TransportDecision::Retry)
                }
                Transport::Interrupted => Ok(if self.waiting {
                    TransportDecision::Wait
                } else {
                    TransportDecision::Retry
                }),
                Transport::Failed => unreachable!(),
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Called only after a full packet and all native adapter postchecks. A
    /// successful send alone does not advance the remote endpoint's transcript.
    pub(super) fn delivered(&mut self, frame: Frame, observation: Observation) -> Result<()> {
        let result = (|| {
            self.select_frame(frame)?;
            ensure!(
                self.busy
                    && !self.waiting
                    && self.next().is_some_and(|(_, expected)| expected == frame),
                "native_handshake_message_order"
            );
            self.observe(observation)?;
            self.position += 1;
            self.busy = false;
            Ok(())
        })();
        self.finish_result(result)
    }

    pub(super) fn complete(&self) -> bool {
        !self.refused && !self.busy && self.position == self.messages().len()
    }

    pub(super) fn refuse(&mut self) {
        self.refused = true;
    }

    fn observe(&mut self, observation: Observation) -> Result<()> {
        ensure!(!self.refused, "native_handshake_refused");
        ensure!(
            observation.origin <= observation.now
                && observation.now < observation.deadline
                && observation.deadline > observation.origin
                && observation.deadline - observation.origin
                    <= self.protocol.limit(self.purpose)?,
            "native_handshake_original_interval"
        );
        if let Some(previous) = &self.clock {
            ensure!(
                previous.domain == observation.domain
                    && previous.origin == observation.origin
                    && previous.deadline == observation.deadline
                    && previous.now <= observation.now,
                "native_handshake_original_changed"
            );
        }
        self.clock = Some(observation);
        Ok(())
    }

    fn finish_result(&mut self, result: Result<()>) -> Result<()> {
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

#[cfg(test)]
pub(in crate::security_epoch) mod simulation;

#[cfg(test)]
mod restore_stop_tests {
    use super::*;

    fn clock(tick: u64, current: bool) -> Observation {
        let origin = if current { 20 } else { 0 };
        Observation {
            domain: Digest::new(if current {
                b"stop-original"
            } else {
                b"initial-clock"
            }),
            origin: Duration::from_secs(origin),
            deadline: Duration::from_secs(origin + if current { 5 } else { 10 }),
            now: Duration::from_secs(origin) + Duration::from_micros(tick),
        }
    }

    fn deliver(
        actual: &mut Transcript,
        actor: Actor,
        sender: Actor,
        frame: Frame,
        observation: Observation,
    ) -> Result<()> {
        let direction = if actor == sender {
            Direction::Send
        } else {
            Direction::Receive
        };
        if direction == Direction::Send {
            actual.select_frame(frame)?;
        }
        actual.begin(direction, observation.clone())?;
        actual.transport(Transport::WouldBlock, observation.clone())?;
        actual.transport(Transport::Ready, observation.clone())?;
        actual.delivered(frame, observation)
    }

    fn prefix(actor: Actor, purpose: StagePurpose) -> Transcript {
        let mut actual = Transcript::new(Protocol::InitialStorage, actor);
        for (index, (sender, step)) in [
            (Actor::Controller, Step::BeginReady),
            (Actor::App, Step::Hello),
            (Actor::Controller, Step::Offer),
            (Actor::App, Step::Confirm),
            (Actor::Controller, Step::Complete),
            (Actor::App, Step::Accepted),
        ]
        .into_iter()
        .enumerate()
        {
            deliver(
                &mut actual,
                actor,
                sender,
                Frame {
                    protocol: Protocol::InitialStorage,
                    step,
                    sequence: None,
                },
                clock(index as u64, false),
            )
            .unwrap();
        }
        actual.begin_current(1, purpose).unwrap();
        for (index, (sender, step)) in [
            (Actor::Controller, Step::BeginReady),
            (Actor::App, Step::Hello),
            (Actor::Controller, Step::Offer),
            (Actor::App, Step::Ack),
            (Actor::Controller, Step::Ready),
        ]
        .into_iter()
        .enumerate()
        {
            deliver(
                &mut actual,
                actor,
                sender,
                Frame {
                    protocol: Protocol::CurrentStorage,
                    step,
                    sequence: (index < 3).then_some(1),
                },
                clock(index as u64, true),
            )
            .unwrap();
        }
        actual
    }

    #[test]
    fn stop_transcript_replays_distinct_drain_fence_ack_and_release_against_an_independent_oracle()
    {
        // Specification order is independent of the production message table.
        // No native actor, Stop or known-send owner is made by these frames.
        let required = [
            (Actor::Controller, Step::Frozen),
            (Actor::App, Step::Drained),
            (Actor::Controller, Step::Fenced),
            (Actor::App, Step::FenceConfirmed),
            (Actor::Controller, Step::StopReleased),
        ];
        for actor in [Actor::App, Actor::Controller] {
            let mut actual = prefix(actor, StagePurpose::CurrentRole);
            let original = actual.clock.clone().unwrap();
            for (index, &(sender, step)) in required.iter().enumerate() {
                deliver(
                    &mut actual,
                    actor,
                    sender,
                    Frame {
                        protocol: Protocol::CurrentStorage,
                        step,
                        sequence: None,
                    },
                    clock(10 + index as u64, true),
                )
                .unwrap();
                let current = actual.clock.as_ref().unwrap();
                assert_eq!(
                    (&current.domain, current.origin, current.deadline),
                    (&original.domain, original.origin, original.deadline)
                );
                assert_eq!(actual.complete(), index == required.len() - 1);
            }
            assert!(actual.begin_current(2, StagePurpose::CurrentRole).is_err());
            let mut bootstrap = prefix(actor, StagePurpose::StorageBootstrap);
            assert!(
                deliver(
                    &mut bootstrap,
                    actor,
                    Actor::Controller,
                    Frame {
                        protocol: Protocol::CurrentStorage,
                        step: Step::Frozen,
                        sequence: None
                    },
                    clock(10, true)
                )
                .is_err()
            );
            assert!(bootstrap.next().is_none());
        }
        for seed in 1_u64..=256 {
            for actor in [Actor::App, Actor::Controller] {
                let mut runs = Vec::new();
                for _ in 0..2 {
                    let mut random = seed;
                    let mut actual = prefix(actor, StagePurpose::CurrentRole);
                    let mut outcomes = Vec::new();
                    let mut terminal = false;
                    for (index, &(sender, step)) in required.iter().enumerate() {
                        random ^= random << 13;
                        random ^= random >> 7;
                        random ^= random << 17;
                        let fault = random % 13;
                        let mut frame = Frame {
                            protocol: Protocol::CurrentStorage,
                            step,
                            sequence: None,
                        };
                        let mut observation = clock(10 + index as u64, true);
                        match fault {
                            0 => frame.step = Step::Consumed, // ordinary ACK cannot substitute
                            1 => frame.step = Step::Released, // ordinary release cannot substitute
                            2 => observation.now = observation.deadline,
                            3 => observation.domain = Digest::new(b"replacement-original"),
                            4 => {
                                frame.step = if index == 0 {
                                    Step::Drained
                                } else {
                                    required[index - 1].1
                                }
                            }
                            5 => observation.now = observation.origin,
                            _ => {}
                        }
                        let expected = !terminal && fault >= 6;
                        let result =
                            deliver(&mut actual, actor, sender, frame, observation).is_ok();
                        assert_eq!(
                            result, expected,
                            "seed={seed} actor={actor:?} index={index} fault={fault}"
                        );
                        terminal |= !expected;
                        assert_eq!(actual.complete(), !terminal && index == required.len() - 1);
                        outcomes.push(result);
                        if terminal {
                            // Repaired time/frame cannot recover the same channel.
                            assert!(
                                deliver(
                                    &mut actual,
                                    actor,
                                    sender,
                                    Frame {
                                        protocol: Protocol::CurrentStorage,
                                        step,
                                        sequence: None
                                    },
                                    clock(100 + index as u64, true)
                                )
                                .is_err()
                            );
                        }
                    }
                    // Even known stop completion never starts another ordinary
                    // current transcript on the stopped incumbent channel.
                    assert!(actual.begin_current(2, StagePurpose::CurrentRole).is_err());
                    runs.push(outcomes);
                }
                assert_eq!(runs[0], runs[1], "seed={seed} actor={actor:?}");
            }
        }
    }
}
