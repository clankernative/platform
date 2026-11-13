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
    RestoredRole,
    RestoredDecision,
    RestoredConfirmation,
    RestoredInstallation,
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
    RoleReady,
    RoleDecision,
    AppPrepared,
    PreparedAccepted,
    AppInstalled,
    InstalledAccepted,
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
    // Negative one-shot state for the closed issuer post-Hello bound meet.
    confirmation_bound_spent: bool,
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
            Self::RestoredRole => &[(Controller, RoleReady)],
            Self::RestoredDecision => &[(Controller, RoleDecision)],
            Self::RestoredConfirmation => &[(App, AppPrepared), (Controller, PreparedAccepted)],
            Self::RestoredInstallation => &[(App, AppInstalled), (Controller, InstalledAccepted)],
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
                            | Self::RestoredRole
                            | Self::RestoredDecision
                            | Self::RestoredConfirmation
                            | Self::RestoredInstallation
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
            confirmation_bound_spent: false,
        }
    }

    /// Only a completely exchanged prior transcript can start another current
    /// transcript. Native disposition/file/consumer final checks are additional
    /// requirements; completing these DATA steps does not settle an operation.
    pub(super) fn begin_current(&mut self, sequence: u64, purpose: StagePurpose) -> Result<()> {
        let result = (|| {
            ensure!(
                self.complete() && !self.waiting && self.storage_tail == StorageTail::Ordinary,
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
                Protocol::RestoredInstallation => {
                    self.require_installed_current_data(self.actor)?;
                    ensure!(
                        purpose == StagePurpose::CurrentRole
                            && self.purpose == StagePurpose::CurrentRole,
                        "native_handshake_restored_current_purpose"
                    );
                    Protocol::CurrentStorage
                }
                Protocol::Enrollment => anyhow::bail!("native_handshake_no_reenrollment"),
                Protocol::RestoredRole
                | Protocol::RestoredDecision
                | Protocol::RestoredConfirmation => {
                    anyhow::bail!("native_handshake_role_is_not_current")
                }
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

    /// Historical cursor identity only. The native transfer must separately
    /// own the actual installed peer, same socket and genuinely retired clock.
    /// This never observes old time or grants a future request.
    pub(super) fn require_installed_current_data(&self, actor: Actor) -> Result<()> {
        ensure!(
            self.protocol == Protocol::RestoredInstallation
                && self.purpose == StagePurpose::CurrentRole
                && self.actor == actor
                && matches!(actor, Actor::App | Actor::Controller)
                && self.sequence == 0
                && self.storage_tail == StorageTail::Ordinary
                && self.clock.is_some()
                && !self.waiting
                && self.complete(),
            "native_handshake_installed_current_cursor_required"
        );
        Ok(())
    }

    /// Separate final role-handoff DATA, derived only from the complete restore
    /// exchange. Keep that historical transcript complete with its original
    /// deadline. A narrower handoff may advance its high-water mark, never its
    /// origin or deadline. Native resource checks and actual issuer completion
    /// are additional requirements; this creates no role or Current authority.
    pub(super) fn derive_restored_role(&mut self, observation: Observation) -> Result<Self> {
        self.derive_restore_followup(
            Protocol::RestoredStorage,
            Protocol::RestoredRole,
            observation,
        )
    }

    /// Separate decision delivery DATA from an ACTUAL completed role history.
    /// A native caller must retain the genuine App/Controller owners, issuer
    /// decision and current authority; this grants no cold admission or Current.
    pub(super) fn derive_restored_decision(&mut self, observation: Observation) -> Result<Self> {
        self.derive_restore_followup(
            Protocol::RestoredRole,
            Protocol::RestoredDecision,
            observation,
        )
    }

    /// Prepared acknowledgement and Controller acceptance remain separate
    /// from ordinary installation. Only the actual completed decision history
    /// can derive this DATA transcript, preserving its original and high-water.
    pub(super) fn derive_restored_confirmation(
        &mut self,
        observation: Observation,
    ) -> Result<Self> {
        self.derive_restore_followup(
            Protocol::RestoredDecision,
            Protocol::RestoredConfirmation,
            observation,
        )
    }

    /// Installation acknowledgement DATA only. Native code must additionally
    /// retain the actual prepared runtime/first keeper, sender and full posts.
    /// The old original is preserved; completion grants no ordinary Current.
    pub(super) fn derive_restored_installation(
        &mut self,
        observation: Observation,
    ) -> Result<Self> {
        self.derive_restore_followup(
            Protocol::RestoredConfirmation,
            Protocol::RestoredInstallation,
            observation,
        )
    }

    fn derive_restore_followup(
        &mut self,
        previous_protocol: Protocol,
        next_protocol: Protocol,
        observation: Observation,
    ) -> Result<Self> {
        let result = (|| {
            ensure!(
                matches!(
                    (previous_protocol, next_protocol),
                    (Protocol::RestoredStorage, Protocol::RestoredRole)
                        | (Protocol::RestoredRole, Protocol::RestoredDecision)
                        | (Protocol::RestoredDecision, Protocol::RestoredConfirmation)
                        | (
                            Protocol::RestoredConfirmation,
                            Protocol::RestoredInstallation
                        )
                ),
                "native_handshake_restore_followup_pair"
            );
            ensure!(
                self.protocol == previous_protocol
                    && self.purpose == StagePurpose::CurrentRole
                    && self.storage_tail == StorageTail::Ordinary
                    && self.sequence == 0
                    && self.complete(),
                "native_handshake_restore_role_previous_incomplete"
            );
            let previous = self
                .clock
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_handshake_restore_role_original_missing"))?;
            ensure!(
                previous.domain == observation.domain
                    && previous.origin == observation.origin
                    && previous.deadline >= observation.deadline
                    && previous.now <= observation.now,
                "native_handshake_restore_role_original_changed"
            );
            let mut retained = previous.clone();
            let mut role = Self {
                protocol: next_protocol,
                purpose: StagePurpose::CurrentRole,
                actor: self.actor,
                sequence: 0,
                position: 0,
                busy: false,
                waiting: false,
                refused: false,
                clock: None,
                storage_tail: StorageTail::Ordinary,
                confirmation_bound_spent: false,
            };
            role.observe(observation.clone())?;
            retained.now = observation.now;
            self.clock = Some(retained);
            Ok(role)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Receive-side DATA bound reduction after the actual native adapter has
    /// authenticated the delivered issuer completion. No sender, initial phase,
    /// fresh original or current grant can use this closed transition.
    pub(super) fn narrow_role_receive(&mut self, observation: Observation) -> Result<()> {
        self.narrow_restore_receive(Protocol::RestoredRole, observation)
    }

    pub(super) fn narrow_decision_receive(&mut self, observation: Observation) -> Result<()> {
        self.narrow_restore_receive(Protocol::RestoredDecision, observation)
    }

    pub(super) fn narrow_prepared_receive(&mut self, observation: Observation) -> Result<()> {
        self.narrow_restore_receive(Protocol::RestoredConfirmation, observation)
    }

    pub(super) fn narrow_installed_receive(&mut self, observation: Observation) -> Result<()> {
        self.narrow_restore_receive_at(
            Protocol::RestoredInstallation,
            Actor::Controller,
            0,
            observation,
        )
    }

    pub(super) fn narrow_installed_acceptance(&mut self, observation: Observation) -> Result<()> {
        self.narrow_restore_receive_at(Protocol::RestoredInstallation, Actor::App, 1, observation)
    }

    fn narrow_restore_receive(
        &mut self,
        expected: Protocol,
        observation: Observation,
    ) -> Result<()> {
        let actor = if expected == Protocol::RestoredConfirmation {
            Actor::Controller
        } else {
            Actor::App
        };
        self.narrow_restore_receive_at(expected, actor, 0, observation)
    }

    pub(super) fn narrow_prepared_acceptance(&mut self, observation: Observation) -> Result<()> {
        self.narrow_restore_receive_at(Protocol::RestoredConfirmation, Actor::App, 1, observation)
    }

    fn narrow_restore_receive_at(
        &mut self,
        expected: Protocol,
        actor: Actor,
        position: usize,
        observation: Observation,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                matches!(
                    (expected, actor, position),
                    (
                        Protocol::RestoredRole | Protocol::RestoredDecision,
                        Actor::App,
                        0
                    ) | (Protocol::RestoredConfirmation, Actor::Controller, 0)
                        | (Protocol::RestoredConfirmation, Actor::App, 1)
                        | (Protocol::RestoredInstallation, Actor::Controller, 0)
                        | (Protocol::RestoredInstallation, Actor::App, 1)
                ),
                "native_handshake_restore_receive_purpose"
            );
            ensure!(
                !self.refused
                    && self.protocol == expected
                    && self.purpose == StagePurpose::CurrentRole
                    && self.actor == actor
                    && self.sequence == 0
                    && self.storage_tail == StorageTail::Ordinary
                    && self.position == position
                    && self.busy
                    && !self.waiting,
                "native_handshake_role_receive_narrow_order"
            );
            let previous = self
                .clock
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_handshake_role_receive_original_missing"))?;
            ensure!(
                observation.domain == previous.domain
                    && observation.origin == previous.origin
                    && observation.deadline <= previous.deadline
                    && observation.now >= previous.now
                    && observation.origin <= observation.now
                    && observation.now < observation.deadline
                    && observation.deadline > observation.origin
                    && observation.deadline - observation.origin
                        <= self.protocol.limit(self.purpose)?,
                "native_handshake_role_receive_original_changed"
            );
            self.clock = Some(observation);
            Ok(())
        })();
        self.finish_result(result)
    }

    /// The Controller's first fixed acceptance send may inherit a shorter
    /// actual loan bound after the ACK. Later retries cannot widen or replace
    /// the already signed packet; native code refuses any further shortening.
    pub(super) fn meet_prepared_acceptance_send(&mut self, observation: Observation) -> Result<()> {
        self.meet_restore_acceptance_send(Protocol::RestoredConfirmation, observation)
    }

    /// Same original, shorter current bound only; never a new installed grant.
    pub(super) fn meet_installed_acceptance_send(
        &mut self,
        observation: Observation,
    ) -> Result<()> {
        self.meet_restore_acceptance_send(Protocol::RestoredInstallation, observation)
    }

    fn meet_restore_acceptance_send(
        &mut self,
        expected: Protocol,
        observation: Observation,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.refused
                    && self.protocol == expected
                    && matches!(
                        expected,
                        Protocol::RestoredConfirmation | Protocol::RestoredInstallation
                    )
                    && self.actor == Actor::Controller
                    && self.position == 1
                    && !self.busy
                    && !self.waiting
                    && self.purpose == StagePurpose::CurrentRole
                    && self.sequence == 0
                    && self.storage_tail == StorageTail::Ordinary,
                "native_handshake_prepared_acceptance_send_order"
            );
            let previous = self.clock.as_ref().ok_or_else(|| {
                anyhow::anyhow!("native_handshake_prepared_acceptance_original_missing")
            })?;
            ensure!(
                observation.domain == previous.domain
                    && observation.origin == previous.origin
                    && observation.deadline <= previous.deadline
                    && observation.now >= previous.now
                    && observation.origin <= observation.now
                    && observation.now < observation.deadline
                    && observation.deadline > observation.origin
                    && observation.deadline - observation.origin
                        <= self.protocol.limit(self.purpose)?,
                "native_handshake_prepared_acceptance_original_changed"
            );
            self.clock = Some(observation);
            Ok(())
        })();
        self.finish_result(result)
    }

    /// Only the actual issuer's closed App-confirmation handler may meet its
    /// already received Hello into earlier retained bounds. Preserve cursor,
    /// domain, origin and high-water; ordinary observe remains exact-deadline.
    pub(super) fn narrow_restore_app_confirmation(
        &mut self,
        observation: Observation,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.refused
                    && !self.confirmation_bound_spent
                    && self.protocol == Protocol::Enrollment
                    && self.actor == Actor::Issuer
                    && self.purpose == StagePurpose::CurrentRole
                    && self.sequence == 0
                    && self.position == 1
                    && !self.busy
                    && !self.waiting
                    && self.storage_tail == StorageTail::Ordinary,
                "native_handshake_confirmation_narrow_order"
            );
            self.confirmation_bound_spent = true;
            let previous = self
                .clock
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_handshake_confirmation_original_missing"))?;
            ensure!(
                observation.domain == previous.domain
                    && observation.origin == previous.origin
                    && observation.deadline <= previous.deadline
                    && observation.now >= previous.now
                    && observation.origin <= observation.now
                    && observation.now < observation.deadline
                    && observation.deadline > observation.origin
                    && observation.deadline - observation.origin <= Duration::from_secs(5),
                "native_handshake_confirmation_original_changed"
            );
            self.clock = Some(observation);
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

#[cfg(test)]
mod restore_role_tests {
    use super::*;

    // Independent fixed history, not the production message catalog/cursor.
    const RESTORE: [(Actor, Step); 9] = [
        (Actor::Controller, Step::BeginReady),
        (Actor::App, Step::Hello),
        (Actor::Controller, Step::Offer),
        (Actor::App, Step::Confirm),
        (Actor::Controller, Step::Complete),
        (Actor::App, Step::Accepted),
        (Actor::Controller, Step::Known),
        (Actor::App, Step::Consumed),
        (Actor::Controller, Step::Released),
    ];

    pub(super) fn clock(millis: u64) -> Observation {
        Observation {
            domain: Digest::new(b"restore-role-original"),
            origin: Duration::from_secs(100),
            deadline: Duration::from_secs(105),
            now: Duration::from_millis(millis),
        }
    }

    pub(super) fn history(actor: Actor, count: usize) -> Result<Transcript> {
        let mut transcript = Transcript::new(Protocol::RestoredStorage, actor);
        for &(sender, step) in RESTORE.iter().take(count) {
            let direction = if sender == actor {
                Direction::Send
            } else {
                Direction::Receive
            };
            let frame = Frame {
                protocol: Protocol::RestoredStorage,
                step,
                sequence: None,
            };
            assert_eq!(transcript.next(), Some((direction, frame)));
            transcript.begin(direction, clock(101_000))?;
            transcript.delivered(frame, clock(101_000))?;
        }
        Ok(transcript)
    }

    #[test]
    fn role_handoff_derivation_matches_independent_seeded_prefix_and_clock_model() -> Result<()> {
        for seed in 0_u64..128 {
            for actor in [Actor::Controller, Actor::App] {
                for accepted in 0..=9 {
                    let mut previous = history(actor, accepted)?;
                    let prior = clock(101_000);
                    let mut supplied = clock(101_500 + seed);
                    supplied.deadline = Duration::from_millis(104_800);
                    let fault = seed % 8;
                    match fault {
                        1 => supplied.domain = Digest::new(b"foreign-clock"),
                        2 => supplied.origin += Duration::from_nanos(1),
                        3 => supplied.deadline = Duration::from_secs(106),
                        4 => supplied.now = Duration::from_millis(100_999),
                        5 => supplied.now = supplied.deadline,
                        6 => supplied.deadline = supplied.origin,
                        7 => previous.refuse(),
                        _ => {}
                    }
                    // The reference does not inspect implementation position,
                    // completion, next frame, limits or transition results.
                    let expected = accepted == 9
                        && fault != 7
                        && supplied.domain == prior.domain
                        && supplied.origin == prior.origin
                        && supplied.deadline <= prior.deadline
                        && supplied.deadline > supplied.origin
                        && supplied.deadline - supplied.origin <= Duration::from_secs(5)
                        && supplied.now >= prior.now
                        && supplied.now < supplied.deadline;
                    let result = previous.derive_restored_role(supplied.clone());
                    assert_eq!(
                        result.is_ok(),
                        expected,
                        "replay seed={seed} actor={actor:?} accepted={accepted} observation={supplied:?}"
                    );
                    if let Ok(mut role) = result {
                        assert!(previous.complete());
                        assert_eq!(previous.clock.as_ref().unwrap().deadline, prior.deadline);
                        assert_eq!(previous.clock.as_ref().unwrap().now, supplied.now);
                        assert_eq!(role.clock.as_ref(), Some(&supplied));
                        let direction = if actor == Actor::Controller {
                            Direction::Send
                        } else {
                            Direction::Receive
                        };
                        let ready = Frame {
                            protocol: Protocol::RestoredRole,
                            step: Step::RoleReady,
                            sequence: None,
                        };
                        assert_eq!(role.next(), Some((direction, ready)));
                        role.begin(direction, supplied.clone())?;
                        role.delivered(ready, supplied.clone())?;
                        assert!(role.complete());
                        assert!(previous.complete());
                        // Even a completed role-handoff DATA record cannot
                        // start ordinary Current, re-enrollment or another role.
                        let mut repeated = role.clone();
                        assert!(repeated.derive_restored_role(supplied).is_err());
                        assert!(role.begin_current(1, StagePurpose::CurrentRole).is_err());
                    } else {
                        assert!(!previous.complete());
                        assert!(previous.derive_restored_role(clock(101_500)).is_err());
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn role_handoff_has_no_fresh_or_unrelated_transcript_constructor() -> Result<()> {
        for actor in [
            Actor::Client,
            Actor::Issuer,
            Actor::Controller,
            Actor::App,
            Actor::Shell,
        ] {
            let mut fresh = Transcript::new(Protocol::RestoredRole, actor);
            assert!(fresh.next().is_none());
            assert!(fresh.begin(Direction::Send, clock(101_500)).is_err());
        }
        let mut enrollment = Transcript::new(Protocol::Enrollment, Actor::Client);
        while let Some((direction, frame)) = enrollment.next() {
            enrollment.begin(direction, clock(101_000))?;
            enrollment.delivered(frame, clock(101_000))?;
        }
        assert!(enrollment.complete());
        assert!(enrollment.derive_restored_role(clock(101_500)).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_role_receive_can_only_reduce_its_same_busy_original() -> Result<()> {
        let initial = clock(101_500);
        let mut narrowed = clock(102_000);
        narrowed.deadline = Duration::from_secs(103);
        let mut base = history(Actor::App, 9)?;
        let mut role = base.derive_restored_role(initial.clone())?;
        role.begin(Direction::Receive, initial.clone())?;
        role.narrow_role_receive(narrowed.clone())?;
        assert_eq!(role.clock.as_ref(), Some(&narrowed));
        role.delivered(
            Frame {
                protocol: Protocol::RestoredRole,
                step: Step::RoleReady,
                sequence: None,
            },
            narrowed.clone(),
        )?;
        assert!(role.complete());
        assert_eq!(
            base.clock.as_ref().unwrap().deadline,
            Duration::from_secs(105)
        );
        assert!(role.narrow_role_receive(narrowed.clone()).is_err());
        for fault in 0..8 {
            let actor = if fault == 0 {
                Actor::Controller
            } else {
                Actor::App
            };
            let mut base = history(actor, 9)?;
            let mut role = base.derive_restored_role(initial.clone())?;
            if fault != 1 {
                role.begin(
                    if actor == Actor::App {
                        Direction::Receive
                    } else {
                        Direction::Send
                    },
                    initial.clone(),
                )?;
            }
            if fault == 2 {
                role.transport(Transport::WouldBlock, initial.clone())?;
            }
            let mut bad = narrowed.clone();
            match fault {
                3 => bad.domain = Digest::new(b"foreign-receiver-clock"),
                4 => bad.origin += Duration::from_nanos(1),
                5 => bad.deadline = Duration::from_secs(106),
                6 => bad.now = Duration::from_millis(101_499),
                7 => bad.now = bad.deadline,
                _ => {}
            }
            assert!(role.narrow_role_receive(bad).is_err(), "fault {fault}");
            assert!(
                role.narrow_role_receive(narrowed.clone()).is_err(),
                "repair {fault}"
            );
        }
        let mut other = Transcript::new(Protocol::Enrollment, Actor::Client);
        other.begin(Direction::Send, initial)?;
        assert!(other.narrow_role_receive(narrowed).is_err());
        Ok(())
    }

    #[test]
    fn role_handoff_wait_and_delivery_cannot_extend_or_repair_the_original() -> Result<()> {
        for actor in [Actor::Controller, Actor::App] {
            for fault in 0..4 {
                let mut previous = history(actor, 9)?;
                let supplied = clock(104_000);
                let mut role = previous.derive_restored_role(supplied.clone())?;
                let (direction, frame) = role.next().unwrap();
                role.begin(direction, supplied.clone())?;
                role.transport(Transport::WouldBlock, supplied.clone())?;
                let mut invalid = supplied.clone();
                match fault {
                    0 => invalid.now = invalid.deadline,
                    1 => invalid.now -= Duration::from_nanos(1),
                    2 => invalid.deadline += Duration::from_nanos(1),
                    _ => invalid.domain = Digest::new(b"substituted-clock"),
                }
                assert!(role.transport(Transport::Ready, invalid).is_err());
                assert!(role.transport(Transport::Ready, supplied.clone()).is_err());
                assert!(role.delivered(frame, supplied).is_err());
                assert!(!role.complete());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod restore_decision_tests {
    use super::restore_role_tests::{clock, history};
    use super::*;

    fn received_role(actor: Actor) -> Result<Transcript> {
        let mut base = history(actor, 9)?;
        let mut role = base.derive_restored_role(clock(101_500))?;
        let direction = if actor == Actor::Controller {
            Direction::Send
        } else {
            Direction::Receive
        };
        role.begin(direction, clock(101_500))?;
        role.delivered(
            Frame {
                protocol: Protocol::RestoredRole,
                step: Step::RoleReady,
                sequence: None,
            },
            clock(101_600),
        )?;
        Ok(role)
    }

    #[test]
    fn decision_derivation_matches_independent_original_fault_table_and_refuses_repair()
    -> Result<()> {
        for seed in 0..128u64 {
            for actor in [Actor::Controller, Actor::App] {
                for fault in 0..9 {
                    let mut role = received_role(actor)?;
                    let before = role.clock.clone().unwrap();
                    let mut supplied = clock(102_000 + seed);
                    match fault {
                        0 => {}
                        1 => supplied.domain = Digest::new(b"other-decision-world"),
                        2 => supplied.origin += Duration::from_nanos(1),
                        3 => supplied.deadline += Duration::from_nanos(1),
                        4 => supplied.now = Duration::from_millis(101_599),
                        5 => supplied.now = supplied.deadline,
                        6 => role.purpose = StagePurpose::StorageBootstrap,
                        7 => role.sequence = 1,
                        _ => role.busy = true,
                    }
                    let actual = role.derive_restored_decision(supplied.clone());
                    assert_eq!(
                        actual.is_ok(),
                        fault == 0,
                        "seed{seed}/actor{actor:?}/fault{fault}"
                    );
                    if fault == 0 {
                        let mut decision = actual?;
                        assert_eq!(role.clock.as_ref().unwrap().origin, before.origin);
                        assert_eq!(role.clock.as_ref().unwrap().deadline, before.deadline);
                        assert!(role.complete());
                        let direction = if actor == Actor::Controller {
                            Direction::Send
                        } else {
                            Direction::Receive
                        };
                        let frame = Frame {
                            protocol: Protocol::RestoredDecision,
                            step: Step::RoleDecision,
                            sequence: None,
                        };
                        assert_eq!(decision.next(), Some((direction, frame)));
                        decision.begin(direction, supplied.clone())?;
                        decision.delivered(frame, supplied.clone())?;
                        assert!(decision.complete());
                        assert!(
                            decision
                                .begin_current(1, StagePurpose::CurrentRole)
                                .is_err()
                        );
                    } else {
                        assert!(role.derive_restored_decision(clock(102_500)).is_err());
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn decision_is_not_a_fresh_or_repeat_role_and_only_busy_app_receive_can_tighten() -> Result<()>
    {
        for actor in [Actor::Controller, Actor::App] {
            let mut fresh = Transcript::new(Protocol::RestoredDecision, actor);
            assert!(fresh.begin(Direction::Receive, clock(102_000)).is_err());
            let mut role = received_role(actor)?;
            let mut decision = role.derive_restored_decision(clock(102_000))?;
            let direction = if actor == Actor::Controller {
                Direction::Send
            } else {
                Direction::Receive
            };
            decision.begin(direction, clock(102_000))?;
            let mut reduced = clock(102_100);
            reduced.deadline = Duration::from_secs(103);
            assert_eq!(
                decision.narrow_decision_receive(reduced.clone()).is_ok(),
                actor == Actor::App
            );
            if actor == Actor::App {
                decision.delivered(
                    Frame {
                        protocol: Protocol::RestoredDecision,
                        step: Step::RoleDecision,
                        sequence: None,
                    },
                    reduced,
                )?;
                assert!(decision.complete());
                assert!(decision.derive_restored_decision(clock(102_200)).is_err());
            } else {
                assert!(decision.narrow_decision_receive(clock(102_200)).is_err());
            }
        }
        Ok(())
    }
    fn received_decision(actor: Actor) -> Result<Transcript> {
        let mut role = received_role(actor)?;
        let mut decision = role.derive_restored_decision(clock(102_000))?;
        let (direction, frame) = decision.next().unwrap();
        decision.begin(direction, clock(102_000))?;
        decision.delivered(frame, clock(102_100))?;
        Ok(decision)
    }

    #[test]
    fn prepared_confirmation_requires_both_messages_and_preserves_each_original() -> Result<()> {
        for seed in 0..128u64 {
            for actor in [Actor::Controller, Actor::App] {
                for fault in 0..10 {
                    let mut decision = received_decision(actor)?;
                    let old = decision.clock.clone().unwrap();
                    let mut supplied = clock(102_200 + seed);
                    supplied.deadline = Duration::from_millis(104_500);
                    match fault {
                        0 => {}
                        1 => supplied.domain = Digest::new(b"foreign-prepared-world"),
                        2 => supplied.origin += Duration::from_nanos(1),
                        3 => supplied.deadline = old.deadline + Duration::from_nanos(1),
                        4 => supplied.now = Duration::from_millis(102_099),
                        5 => supplied.now = supplied.deadline,
                        6 => decision.purpose = StagePurpose::StorageBootstrap,
                        7 => decision.sequence = 1,
                        8 => decision.busy = true,
                        _ => decision.storage_tail = StorageTail::Restore,
                    }
                    let actual = decision.derive_restored_confirmation(supplied.clone());
                    assert_eq!(
                        actual.is_ok(),
                        fault == 0,
                        "seed{seed}/actor{actor:?}/fault{fault}"
                    );
                    if fault != 0 {
                        assert!(
                            decision
                                .derive_restored_confirmation(clock(102_500))
                                .is_err()
                        );
                        continue;
                    }
                    let mut prepared = actual?;
                    assert!(decision.complete());
                    assert_eq!(decision.clock.as_ref().unwrap().origin, old.origin);
                    assert_eq!(decision.clock.as_ref().unwrap().deadline, old.deadline);
                    for (sender, step) in [
                        (Actor::App, Step::AppPrepared),
                        (Actor::Controller, Step::PreparedAccepted),
                    ] {
                        let direction = if sender == actor {
                            Direction::Send
                        } else {
                            Direction::Receive
                        };
                        let frame = Frame {
                            protocol: Protocol::RestoredConfirmation,
                            step,
                            sequence: None,
                        };
                        assert_eq!(prepared.next(), Some((direction, frame)));
                        assert!(!prepared.complete());
                        prepared.begin(direction, supplied.clone())?;
                        prepared.delivered(frame, supplied.clone())?;
                    }
                    assert!(prepared.complete());
                    assert!(
                        prepared
                            .begin_current(1, StagePurpose::CurrentRole)
                            .is_err()
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn prepared_ceiling_can_only_meet_actual_busy_controller_ack_receive() -> Result<()> {
        for actor in [Actor::App, Actor::Controller] {
            let mut fresh = Transcript::new(Protocol::RestoredConfirmation, actor);
            assert!(fresh.begin(Direction::Receive, clock(102_200)).is_err());
            for fault in 0..10 {
                let mut decision = received_decision(actor)?;
                let mut prepared = decision.derive_restored_confirmation(clock(102_200))?;
                let direction = if actor == Actor::App {
                    Direction::Send
                } else {
                    Direction::Receive
                };
                if fault != 1 {
                    prepared.begin(direction, clock(102_200))?;
                }
                if fault == 2 {
                    prepared.transport(Transport::WouldBlock, clock(102_200))?;
                }
                let mut supplied = clock(102_300);
                supplied.deadline = Duration::from_secs(104);
                match fault {
                    3 => supplied.domain = Digest::new(b"other-ack-clock"),
                    4 => supplied.origin += Duration::from_nanos(1),
                    5 => supplied.deadline = Duration::from_secs(106),
                    6 => supplied.now = Duration::from_millis(102_199),
                    7 => supplied.now = supplied.deadline,
                    8 => prepared.sequence = 1,
                    9 => prepared.position = 1,
                    _ => {}
                }
                let actual = prepared.narrow_prepared_receive(supplied.clone());
                assert_eq!(
                    actual.is_ok(),
                    actor == Actor::Controller && fault == 0,
                    "actor{actor:?}/fault{fault}"
                );
                if actual.is_err() {
                    assert!(prepared.narrow_prepared_receive(clock(102_400)).is_err());
                } else {
                    prepared.delivered(
                        Frame {
                            protocol: Protocol::RestoredConfirmation,
                            step: Step::AppPrepared,
                            sequence: None,
                        },
                        supplied.clone(),
                    )?;
                    assert!(!prepared.complete());
                    // A delayed acceptance cannot repair or widen this same original.
                    supplied.now = supplied.deadline;
                    assert!(prepared.begin(Direction::Send, supplied).is_err());
                    assert!(!prepared.complete());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn prepared_acceptance_meets_the_app_clock_only_after_its_actual_ack_prefix() -> Result<()> {
        for actor in [Actor::App, Actor::Controller] {
            for fault in 0..10 {
                let mut decision = received_decision(actor)?;
                let mut prepared = decision.derive_restored_confirmation(clock(102_200))?;
                let (direction, frame) = prepared.next().unwrap();
                prepared.begin(direction, clock(102_200))?;
                if fault != 1 {
                    prepared.delivered(frame, clock(102_200))?;
                }
                if fault != 2 && fault != 1 {
                    prepared.begin(
                        if actor == Actor::App {
                            Direction::Receive
                        } else {
                            Direction::Send
                        },
                        clock(102_200),
                    )?;
                }
                if fault == 3 {
                    prepared.transport(Transport::WouldBlock, clock(102_200))?;
                }
                let mut met = clock(102_300);
                met.deadline = Duration::from_millis(102_800);
                match fault {
                    4 => met.domain = Digest::new(b"other-acceptance-world"),
                    5 => met.origin += Duration::from_nanos(1),
                    6 => met.deadline = Duration::from_secs(106),
                    7 => met.now = Duration::from_millis(102_199),
                    8 => met.now = met.deadline,
                    9 => prepared.sequence = 1,
                    _ => {}
                }
                let actual = prepared.narrow_prepared_acceptance(met.clone());
                assert_eq!(
                    actual.is_ok(),
                    actor == Actor::App && fault == 0,
                    "actor{actor:?}/fault{fault}"
                );
                if actual.is_err() {
                    assert!(prepared.narrow_prepared_acceptance(clock(102_400)).is_err());
                } else {
                    prepared.delivered(
                        Frame {
                            protocol: Protocol::RestoredConfirmation,
                            step: Step::PreparedAccepted,
                            sequence: None,
                        },
                        met.clone(),
                    )?;
                    assert!(prepared.complete());
                    assert_eq!(prepared.clock.as_ref(), Some(&met));
                    assert!(
                        prepared
                            .begin_current(1, StagePurpose::CurrentRole)
                            .is_err()
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn prepared_controller_send_meet_requires_idle_ack_prefix_and_never_renews() -> Result<()> {
        let mut decision = received_decision(Actor::Controller)?;
        let mut accepted = decision.derive_restored_confirmation(clock(102_200))?;
        let (direction, frame) = accepted.next().unwrap();
        accepted.begin(direction, clock(102_200))?;
        accepted.delivered(frame, clock(102_200))?;
        let mut met = clock(102_300);
        met.deadline = Duration::from_millis(102_800);
        accepted.meet_prepared_acceptance_send(met.clone())?;
        accepted.begin(Direction::Send, met.clone())?;
        accepted.delivered(
            Frame {
                protocol: Protocol::RestoredConfirmation,
                step: Step::PreparedAccepted,
                sequence: None,
            },
            met.clone(),
        )?;
        assert!(accepted.complete());
        assert_eq!(accepted.clock.as_ref(), Some(&met));
        for actor in [Actor::App, Actor::Controller] {
            for fault in 0..10 {
                let mut decision = received_decision(actor)?;
                let mut prepared = decision.derive_restored_confirmation(clock(102_200))?;
                let (direction, frame) = prepared.next().unwrap();
                prepared.begin(direction, clock(102_200))?;
                if fault != 1 {
                    prepared.delivered(frame, clock(102_200))?;
                }
                if fault == 2 {
                    prepared.begin(
                        if actor == Actor::Controller {
                            Direction::Send
                        } else {
                            Direction::Receive
                        },
                        clock(102_200),
                    )?;
                }
                let mut met = clock(102_300);
                met.deadline = Duration::from_millis(102_800);
                match fault {
                    3 => met.domain = Digest::new(b"other-controller-clock"),
                    4 => met.origin += Duration::from_nanos(1),
                    5 => met.deadline = Duration::from_secs(106),
                    6 => met.now = Duration::from_millis(102_199),
                    7 => met.now = met.deadline,
                    8 => prepared.sequence = 1,
                    9 => prepared.storage_tail = StorageTail::Restore,
                    _ => {}
                }
                let actual = prepared.meet_prepared_acceptance_send(met.clone());
                assert_eq!(
                    actual.is_ok(),
                    actor == Actor::Controller && fault == 0,
                    "actor{actor:?}/fault{fault}"
                );
                if actual.is_err() {
                    assert!(
                        prepared
                            .meet_prepared_acceptance_send(clock(102_400))
                            .is_err()
                    );
                } else {
                    prepared.begin(Direction::Send, met.clone())?;
                    assert!(prepared.meet_prepared_acceptance_send(met.clone()).is_err());
                    assert!(
                        prepared
                            .delivered(
                                Frame {
                                    protocol: Protocol::RestoredConfirmation,
                                    step: Step::PreparedAccepted,
                                    sequence: None
                                },
                                met
                            )
                            .is_err()
                    );
                    assert!(!prepared.complete());
                }
            }
        }
        Ok(())
    }
    fn received_prepared(actor: Actor) -> Result<Transcript> {
        let mut prepared =
            received_decision(actor)?.derive_restored_confirmation(clock(102_200))?;
        for (sender, step) in [
            (Actor::App, Step::AppPrepared),
            (Actor::Controller, Step::PreparedAccepted),
        ] {
            let direction = if sender == actor {
                Direction::Send
            } else {
                Direction::Receive
            };
            prepared.begin(direction, clock(102_250))?;
            prepared.delivered(
                Frame {
                    protocol: Protocol::RestoredConfirmation,
                    step,
                    sequence: None,
                },
                clock(102_250),
            )?;
        }
        Ok(prepared)
    }

    #[test]
    fn installed_controller_send_meets_only_the_same_idle_original_once() -> Result<()> {
        for actor in [Actor::App, Actor::Controller] {
            for fault in 0..11 {
                let mut actual =
                    received_prepared(actor)?.derive_restored_installation(clock(102_300))?;
                let (direction, frame) = actual.next().unwrap();
                actual.begin(direction, clock(102_350))?;
                if fault != 1 {
                    actual.delivered(frame, clock(102_350))?;
                }
                if fault == 2 {
                    actual.begin(
                        if actor == Actor::Controller {
                            Direction::Send
                        } else {
                            Direction::Receive
                        },
                        clock(102_350),
                    )?;
                }
                let mut supplied = clock(102_400);
                supplied.deadline = Duration::from_secs(104);
                match fault {
                    3 => supplied.domain = Digest::new(b"wrong-installed-send-world"),
                    4 => supplied.origin += Duration::from_nanos(1),
                    5 => supplied.deadline = Duration::from_secs(106),
                    6 => supplied.now = Duration::from_millis(102_349),
                    7 => supplied.now = supplied.deadline,
                    8 => actual.sequence = 1,
                    9 => actual.storage_tail = StorageTail::Restore,
                    10 => actual.purpose = StagePurpose::StorageBootstrap,
                    _ => {}
                }
                let result = actual.meet_installed_acceptance_send(supplied.clone());
                assert_eq!(
                    result.is_ok(),
                    actor == Actor::Controller && fault == 0,
                    "{actor:?}/{fault}"
                );
                if result.is_err() {
                    assert!(
                        actual
                            .meet_installed_acceptance_send(clock(102_450))
                            .is_err()
                    );
                } else {
                    assert_eq!(actual.clock.as_ref(), Some(&supplied));
                    actual.begin(Direction::Send, supplied.clone())?;
                    assert!(actual.meet_installed_acceptance_send(supplied).is_err());
                    assert!(!actual.complete());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn installed_transcript_derives_only_from_complete_same_original_and_needs_both_messages()
    -> Result<()> {
        for seed in 0..128u64 {
            for actor in [Actor::App, Actor::Controller] {
                assert!(
                    Transcript::new(Protocol::RestoredInstallation, actor)
                        .begin(Direction::Send, clock(102_300))
                        .is_err()
                );
                for fault in 0..10 {
                    let mut prior = received_prepared(actor)?;
                    let old = prior.clock.clone().unwrap();
                    let mut supplied = clock(102_300 + seed);
                    supplied.deadline = Duration::from_millis(104_500);
                    match fault {
                        0 => {}
                        1 => supplied.domain = Digest::new(b"other-installed-world"),
                        2 => supplied.origin += Duration::from_nanos(1),
                        3 => supplied.deadline = old.deadline + Duration::from_nanos(1),
                        4 => supplied.now = Duration::from_millis(102_249),
                        5 => supplied.now = supplied.deadline,
                        6 => prior.position = 1,
                        7 => prior.busy = true,
                        8 => prior.purpose = StagePurpose::StorageBootstrap,
                        _ => prior.protocol = Protocol::RestoredDecision,
                    }
                    let result = prior.derive_restored_installation(supplied.clone());
                    assert_eq!(
                        result.is_ok(),
                        fault == 0,
                        "seed{seed}/actor{actor:?}/fault{fault}"
                    );
                    if fault != 0 {
                        assert!(prior.derive_restored_installation(clock(102_500)).is_err());
                        continue;
                    }
                    let mut actual = result?;
                    assert!(prior.complete());
                    assert_eq!(prior.clock.as_ref().unwrap().origin, old.origin);
                    assert_eq!(prior.clock.as_ref().unwrap().deadline, old.deadline);
                    // Independent two-message contract, never production.messages().
                    for (sender, step) in [
                        (Actor::App, Step::AppInstalled),
                        (Actor::Controller, Step::InstalledAccepted),
                    ] {
                        let direction = if sender == actor {
                            Direction::Send
                        } else {
                            Direction::Receive
                        };
                        let frame = Frame {
                            protocol: Protocol::RestoredInstallation,
                            step,
                            sequence: None,
                        };
                        assert!(!actual.complete());
                        assert_eq!(actual.next(), Some((direction, frame)));
                        actual.begin(direction, supplied.clone())?;
                        actual.delivered(frame, supplied.clone())?;
                    }
                    assert!(actual.complete());
                    actual.begin_current(1, StagePurpose::CurrentRole)?;
                    assert!(!actual.complete());
                    assert!(actual.clock.is_none());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn final_installed_cursor_moves_to_a_new_current_only_after_both_packets() -> Result<()> {
        for actor in [Actor::App, Actor::Controller] {
            for fault in 0..18 {
                let mut installed =
                    received_prepared(actor)?.derive_restored_installation(clock(102_300))?;
                // Literal independent contract: do not derive the expected
                // prefix from the production protocol message table.
                for (sender, step) in [
                    (Actor::App, Step::AppInstalled),
                    (Actor::Controller, Step::InstalledAccepted),
                ] {
                    let direction = if sender == actor {
                        Direction::Send
                    } else {
                        Direction::Receive
                    };
                    installed.begin(direction, clock(102_350))?;
                    installed.delivered(
                        Frame {
                            protocol: Protocol::RestoredInstallation,
                            step,
                            sequence: None,
                        },
                        clock(102_350),
                    )?;
                }
                assert!(installed.complete());
                match fault {
                    0 => {}
                    1 => installed.position = 0,
                    2 => installed.position = 1,
                    3 => installed.busy = true,
                    4 => installed.waiting = true,
                    5 => installed.refused = true,
                    6 => installed.clock = None,
                    7 => installed.sequence = 1,
                    8 => installed.storage_tail = StorageTail::Restore,
                    9 => installed.purpose = StagePurpose::StorageBootstrap,
                    10 => installed.protocol = Protocol::RestoredStorage,
                    11 => installed.protocol = Protocol::RestoredRole,
                    12 => installed.protocol = Protocol::RestoredConfirmation,
                    13 => installed.actor = Actor::Shell,
                    _ => {}
                }
                let next = (|| -> Result<Transcript> {
                    let sequence = match fault {
                        14 => 0,
                        15 => 2,
                        _ => 1,
                    };
                    let purpose = match fault {
                        16 => StagePurpose::StorageBootstrap,
                        17 => StagePurpose::StorageMetadataObservation,
                        _ => StagePurpose::CurrentRole,
                    };
                    installed.begin_current(sequence, purpose)?;
                    Ok(installed)
                })();
                assert_eq!(next.is_ok(), fault == 0, "{actor:?}/fault{fault}");
                if fault != 0 {
                    continue;
                }
                let mut next = next?;
                assert!(!next.complete());
                assert!(next.clock.is_none());
                assert_eq!(next.sequence, 1);
                assert_eq!(next.purpose, StagePurpose::CurrentRole);
                let direction = if actor == Actor::Controller {
                    Direction::Send
                } else {
                    Direction::Receive
                };
                assert_eq!(
                    next.next(),
                    Some((
                        direction,
                        Frame {
                            protocol: Protocol::CurrentStorage,
                            step: Step::BeginReady,
                            sequence: Some(1),
                        }
                    ))
                );
                // The historical installation deadline is long expired. It
                // supplies no time permission: only this distinct fresh packet
                // observation can enter the new DATA transcript.
                let fresh = Observation {
                    domain: Digest::new(b"fresh-ordinary-request"),
                    origin: Duration::from_secs(900),
                    deadline: Duration::from_secs(905),
                    now: Duration::from_secs(900),
                };
                next.begin(direction, fresh.clone())?;
                assert_eq!(next.clock.as_ref(), Some(&fresh));
                assert!(next.begin_current(2, StagePurpose::CurrentRole).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn installed_receive_ceiling_requires_the_actual_busy_receiver_and_cannot_repair_refusal()
    -> Result<()> {
        for actor in [Actor::App, Actor::Controller] {
            for fault in 0..8 {
                let mut actual =
                    received_prepared(actor)?.derive_restored_installation(clock(102_300))?;
                if actor == Actor::App {
                    let frame = Frame {
                        protocol: Protocol::RestoredInstallation,
                        step: Step::AppInstalled,
                        sequence: None,
                    };
                    actual.begin(Direction::Send, clock(102_300))?;
                    actual.delivered(frame, clock(102_300))?;
                }
                if fault != 1 {
                    actual.begin(Direction::Receive, clock(102_350))?;
                }
                if fault == 2 {
                    actual.transport(Transport::WouldBlock, clock(102_350))?;
                }
                let mut supplied = clock(102_400);
                supplied.deadline = Duration::from_secs(104);
                match fault {
                    3 => supplied.domain = Digest::new(b"foreign-installed-ceiling"),
                    4 => supplied.origin += Duration::from_nanos(1),
                    5 => supplied.deadline = Duration::from_secs(106),
                    6 => supplied.now = supplied.deadline,
                    7 => {
                        actual.actor = if actor == Actor::App {
                            Actor::Controller
                        } else {
                            Actor::App
                        }
                    }
                    _ => {}
                }
                let apply = |actual: &mut Transcript, observation: Observation| {
                    if actor == Actor::App {
                        actual.narrow_installed_acceptance(observation)
                    } else {
                        actual.narrow_installed_receive(observation)
                    }
                };
                assert_eq!(
                    apply(&mut actual, supplied).is_ok(),
                    fault == 0,
                    "actor{actor:?}/fault{fault}"
                );
                if fault != 0 {
                    assert!(apply(&mut actual, clock(102_450)).is_err());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod restore_confirmation_bound_tests {
    use super::*;

    fn clock(now_ms: u64, deadline_ms: u64) -> Observation {
        Observation {
            domain: Digest::new(b"one-confirmation-exchange"),
            origin: Duration::from_secs(3),
            deadline: Duration::from_millis(deadline_ms),
            now: Duration::from_millis(now_ms),
        }
    }

    fn hello(actor: Actor) -> Transcript {
        let mut history = Transcript::new(Protocol::Enrollment, actor);
        let direction = if actor == Actor::Issuer {
            Direction::Receive
        } else {
            Direction::Send
        };
        history.begin(direction, clock(3100, 7500)).unwrap();
        history
            .delivered(
                Frame {
                    protocol: Protocol::Enrollment,
                    step: Step::Hello,
                    sequence: None,
                },
                clock(3100, 7500),
            )
            .unwrap();
        history
    }

    #[test]
    fn strict_confirmation_meet_preserves_hello_history_original_and_remaining_exchange() {
        let mut history = hello(Actor::Issuer);
        let before = history.clock.clone().unwrap();
        history
            .narrow_restore_app_confirmation(clock(3200, 4000))
            .unwrap();
        assert_eq!(history.position, 1);
        assert_eq!(history.sequence, 0);
        let current = history.clock.as_ref().unwrap();
        assert_eq!(
            (&current.domain, current.origin),
            (&before.domain, before.origin)
        );
        assert_eq!(current.now, Duration::from_millis(3200));
        assert_eq!(current.deadline, Duration::from_secs(4));
        for (direction, step, now) in [
            (Direction::Send, Step::Challenge, 3300),
            (Direction::Receive, Step::Bind, 3400),
            (Direction::Send, Step::Grant, 3500),
        ] {
            history.begin(direction, clock(now, 4000)).unwrap();
            history
                .delivered(
                    Frame {
                        protocol: Protocol::Enrollment,
                        step,
                        sequence: None,
                    },
                    clock(now, 4000),
                )
                .unwrap();
        }
        assert!(history.complete());
        // Equal bounds are also valid once; this never permits another meet.
        let mut equal = hello(Actor::Issuer);
        equal
            .narrow_restore_app_confirmation(clock(3200, 7500))
            .unwrap();
        assert!(
            equal
                .narrow_restore_app_confirmation(clock(3250, 7400))
                .is_err()
        );
        assert!(equal.next().is_none());
    }

    #[test]
    fn confirmation_meet_rejects_wrong_world_phase_extension_rewind_and_clock_repair() {
        // Independent fault table over historical DATA, never a native owner.
        for cut in 0..13 {
            let mut history = hello(Actor::Issuer);
            let mut next = clock(3200, 4000);
            match cut {
                0 => next.domain = Digest::new(b"other-original-domain"),
                1 => next.origin = Duration::from_millis(3010),
                2 => next.deadline = Duration::from_secs(8), // valid5s interval, expands prior4.5s
                3 => next.now = Duration::from_millis(3099),
                4 => next.now = next.deadline,
                5 => next.deadline = Duration::from_secs(3),
                6 => history = hello(Actor::Client),
                7 => history = Transcript::new(Protocol::Enrollment, Actor::Issuer),
                8 => {
                    history.begin(Direction::Send, clock(3150, 7500)).unwrap();
                }
                9 => {
                    history.begin(Direction::Send, clock(3150, 7500)).unwrap();
                    history
                        .transport(Transport::WouldBlock, clock(3150, 7500))
                        .unwrap();
                }
                10 => {
                    history.begin(Direction::Send, clock(3150, 7500)).unwrap();
                    history
                        .delivered(
                            Frame {
                                protocol: Protocol::Enrollment,
                                step: Step::Challenge,
                                sequence: None,
                            },
                            clock(3150, 7500),
                        )
                        .unwrap();
                }
                11 => history.protocol = Protocol::InitialStorage,
                12 => history.purpose = StagePurpose::StorageBootstrap,
                _ => unreachable!(),
            }
            assert!(
                history.narrow_restore_app_confirmation(next).is_err(),
                "cut{cut}"
            );
            assert!(
                history
                    .narrow_restore_app_confirmation(clock(3250, 3900))
                    .is_err(),
                "repair{cut}"
            );
            assert!(history.next().is_none());
            assert!(!history.complete());
        }
    }
}
