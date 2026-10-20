//! Retained Shell/Controller identity channel. Binding digests are DATA only.
//! The caller retains physical/epoch/consumer owners through every scoped use.

use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    EnrolledRoleStage, NativeRole, SameEnrolledOwner,
    serving_peer_wire::{Exchange, Statement},
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    channel::{Channel, ServingListener},
    protocol,
    serving_peer_native::Peer,
    serving_peer_wire::Body,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Ready(u64),
    Busy(u64),
    Refused,
}

impl Disposition {
    fn begin(&mut self) -> Result<u64> {
        let previous = match *self {
            Self::Ready(n) => n,
            _ => {
                *self = Self::Refused;
                anyhow::bail!("serving_peer_busy_or_refused")
            }
        };
        let next = previous.checked_add(1).ok_or_else(|| {
            *self = Self::Refused;
            anyhow::anyhow!("serving_peer_sequence_exhausted")
        })?;
        *self = Self::Busy(next);
        Ok(next)
    }

    fn check(&self, sequence: u64) -> Result<()> {
        ensure!(*self == Self::Busy(sequence), "serving_peer_phase_refused");
        Ok(())
    }

    fn complete(&mut self, sequence: u64) -> Result<()> {
        self.check(sequence)?;
        *self = Self::Ready(sequence);
        Ok(())
    }
}

struct Retained {
    same: SameEnrolledOwner,
    latest_local: Statement,
    latest_remote: Statement,
    initial: Digest,
    disposition: Disposition,
    #[cfg(target_os = "linux")]
    channel: Channel,
    #[cfg(target_os = "linux")]
    original_peer: Peer,
}

pub(crate) struct ShellServingPeer {
    owner: Retained,
}
pub(crate) struct ControllerServingPeer {
    owner: Retained,
}

pub(crate) struct ControllerServingListener {
    same: SameEnrolledOwner,
    accepted: bool,
    valid: bool,
    #[cfg(target_os = "linux")]
    listener: ServingListener,
}

/// No file/epoch/P3/consumer permission. The SAME actual stage must be supplied
/// for checks; it remains available to the enclosing physical composite.
pub(crate) struct CurrentServingPeerPhase<'peer> {
    owner: &'peer mut Retained,
    acquisition: NativeAcquisition,
    local: Statement,
    remote: Statement,
    exchange: Exchange,
    completion: Completion,
    #[cfg(target_os = "linux")]
    peer: Peer,
}

impl ShellServingPeer {
    pub(crate) fn connect(stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        let result = (|| {
            // One-way gate belongs to the actual role owner, not a temporary
            // socket object. Failed/uncertain connect cannot obtain a new one.
            stage.begin_serving_attempt(NativeRole::SecurityShell)?;
            let acquisition = stage.narrow_io_acquisition(5)?;
            let local = stage.serving_statement()?;
            let same = stage.capture_same_owner()?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (acquisition, local, same);
                anyhow::bail!("serving_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let mut acquisition = acquisition;
                let mut channel = Channel::connect_serving(stage, &mut acquisition)?;
                let mut session = Session {
                    channel: &mut channel,
                    stage,
                    acquisition: &mut acquisition,
                    original: None,
                };
                let (peer, exchange) = handshake(&mut session, &local, None, 0, None, None)?;
                let remote = peer.statement().clone();
                let owner = Retained {
                    same,
                    latest_local: local,
                    latest_remote: remote,
                    initial: exchange.digest()?,
                    disposition: Disposition::Ready(0),
                    channel,
                    original_peer: peer,
                };
                Ok(Self { owner })
            }
        })();
        if result.is_err() {
            stage.refuse_serving();
        }
        result
    }

    pub(crate) fn begin_current<'peer>(
        &'peer mut self,
        stage: &mut EnrolledRoleStage<'_>,
        binding: Digest,
    ) -> Result<CurrentServingPeerPhase<'peer>> {
        start_current(
            &mut self.owner,
            stage,
            NativeRole::SecurityShell,
            Some(binding),
        )
    }

    pub(crate) fn refuse(&mut self) {
        self.owner.disposition = Disposition::Refused;
    }
}

impl ControllerServingListener {
    pub(crate) fn bind(stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        let result = (|| {
            stage.begin_serving_attempt(NativeRole::EpochController)?;
            let acquisition = stage.narrow_io_acquisition(5)?;
            let same = stage.capture_same_owner()?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (acquisition, same);
                anyhow::bail!("serving_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let mut acquisition = acquisition;
                let listener = ServingListener::bind(stage, &mut acquisition)?;
                Ok(Self {
                    same,
                    accepted: false,
                    valid: true,
                    listener,
                })
            }
        })();
        if result.is_err() {
            stage.refuse_serving();
        }
        result
    }

    /// No fresh role stage, request or permission is created by readiness.
    pub(crate) fn idle_ready(&mut self) -> Result<bool> {
        let result = (|| {
            ensure!(self.valid, "serving_peer_listener_refused");
            if self.accepted {
                return Ok(false);
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("serving_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.listener.pending()
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    pub(crate) fn accept(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<ControllerServingPeer> {
        let result = (|| {
            ensure!(self.valid && !self.accepted, "serving_peer_no_reconnect");
            self.accepted = true;
            self.same.check(stage)?;
            ensure!(
                stage.serving_role()? == NativeRole::EpochController,
                "serving_peer_controller_role"
            );
            let acquisition = stage.narrow_io_acquisition(5)?;
            let local = stage.serving_statement()?;
            let same = stage.capture_same_owner()?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (acquisition, local, same);
                anyhow::bail!("serving_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let mut acquisition = acquisition;
                let mut channel = self.listener.accept(stage, &mut acquisition)?;
                let mut session = Session {
                    channel: &mut channel,
                    stage,
                    acquisition: &mut acquisition,
                    original: None,
                };
                let (peer, exchange) = handshake(&mut session, &local, None, 0, None, None)?;
                let remote = peer.statement().clone();
                Ok(ControllerServingPeer {
                    owner: Retained {
                        same,
                        latest_local: local,
                        latest_remote: remote,
                        initial: exchange.digest()?,
                        disposition: Disposition::Ready(0),
                        channel,
                        original_peer: peer,
                    },
                })
            }
        })();
        if result.is_err() {
            self.valid = false;
            stage.refuse_serving();
        }
        result
    }
}

impl ControllerServingPeer {
    pub(crate) fn idle_ready(&mut self) -> Result<bool> {
        let result = (|| {
            ensure!(
                matches!(self.owner.disposition, Disposition::Ready(_)),
                "serving_peer_not_idle"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("serving_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.owner.channel.pending_serving()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn accept_current<'peer>(
        &'peer mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<CurrentServingPeerPhase<'peer>> {
        start_current(&mut self.owner, stage, NativeRole::EpochController, None)
    }

    pub(crate) fn refuse(&mut self) {
        self.owner.disposition = Disposition::Refused;
    }
}

impl Retained {
    fn check_resources(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        self.same.check(stage)?;
        ensure!(
            self.latest_local
                .same_enrollment(&stage.serving_statement()?),
            "serving_peer_local_enrollment_changed"
        );
        #[cfg(not(target_os = "linux"))]
        {
            let _ = acquisition;
            anyhow::bail!("serving_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.channel.check_serving_open(stage, acquisition)?;
            self.original_peer.check_continuity(stage, acquisition)?;
            self.channel.check_serving_open(stage, acquisition)
        }
    }
}

struct Started {
    acquisition: NativeAcquisition,
    local: Statement,
    remote: Statement,
    exchange: Exchange,
    #[cfg(target_os = "linux")]
    peer: Peer,
}

fn begin(
    owner: &mut Retained,
    stage: &mut EnrolledRoleStage<'_>,
    role: NativeRole,
    binding: Option<Digest>,
) -> Result<Started> {
    // Busy BEFORE any fallible clock/role/identity/packet work. Dropping the
    // borrowed phase leaves this latch closed: only consuming finish_checked
    // can return the parent to Ready, and no replacement phase can be created.
    let sequence = owner.disposition.begin()?;
    owner.same.check(stage)?;
    ensure!(stage.serving_role()? == role, "serving_peer_phase_role");
    let mut acquisition = stage.narrow_io_acquisition(5)?;
    let local = stage.serving_statement()?;
    local.require_fresh(&owner.latest_local)?;
    owner.check_resources(stage, &mut acquisition)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sequence, acquisition, local, binding);
        anyhow::bail!("serving_peer_platform_unsupported");
    }
    #[cfg(target_os = "linux")]
    {
        let mut session = Session {
            channel: &mut owner.channel,
            stage,
            acquisition: &mut acquisition,
            original: Some(&mut owner.original_peer),
        };
        let (peer, exchange) = handshake(
            &mut session,
            &local,
            Some(&owner.initial),
            sequence,
            binding,
            Some(&owner.latest_remote),
        )?;
        let remote = peer.statement().clone();
        owner.check_resources(stage, &mut acquisition)?;
        Ok(Started {
            acquisition,
            local,
            remote,
            exchange,
            peer,
        })
    }
}

fn start_current<'peer>(
    owner: &'peer mut Retained,
    stage: &mut EnrolledRoleStage<'_>,
    role: NativeRole,
    binding: Option<Digest>,
) -> Result<CurrentServingPeerPhase<'peer>> {
    let started = match begin(owner, stage, role, binding) {
        Ok(started) => started,
        Err(error) => {
            owner.disposition = Disposition::Refused;
            stage.refuse_serving();
            return Err(error);
        }
    };
    let mut phase = CurrentServingPeerPhase {
        owner,
        acquisition: started.acquisition,
        local: started.local,
        remote: started.remote,
        exchange: started.exchange,
        completion: Completion::Waiting,
        #[cfg(target_os = "linux")]
        peer: started.peer,
    };
    phase.check(stage)?;
    Ok(phase)
}

#[cfg(target_os = "linux")]
struct Session<'io, 'role> {
    channel: &'io mut Channel,
    stage: &'io mut EnrolledRoleStage<'role>,
    acquisition: &'io mut NativeAcquisition,
    original: Option<&'io mut Peer>,
}

#[cfg(target_os = "linux")]
impl Session<'_, '_> {
    fn check(&mut self) -> Result<()> {
        self.channel
            .check_serving_open(self.stage, self.acquisition)?;
        if let Some(original) = &mut self.original {
            original.check_continuity(self.stage, self.acquisition)?;
        }
        self.channel
            .check_serving_open(self.stage, self.acquisition)
    }

    fn send(&mut self, body: Body, mut peer: Option<&mut Peer>) -> Result<()> {
        self.check()?;
        if let Some(peer) = peer.as_deref_mut() {
            peer.check(self.stage, self.acquisition)?;
        }
        let message = self.stage.sign_serving_message(body)?;
        self.channel
            .send_serving(&message, self.stage, self.acquisition)?;
        if let Some(peer) = peer {
            peer.check(self.stage, self.acquisition)?;
        }
        self.check()
    }

    fn receive(
        &mut self,
    ) -> Result<(
        super::serving_peer_wire::Message,
        super::channel::ServingSender,
    )> {
        self.check()?;
        let packet = self.channel.receive_serving(self.stage, self.acquisition)?;
        self.check()?;
        Ok(packet)
    }
}

#[cfg(target_os = "linux")]
fn handshake(
    session: &mut Session<'_, '_>,
    local: &Statement,
    initial: Option<&Digest>,
    sequence: u64,
    binding: Option<Digest>,
    previous: Option<&Statement>,
) -> Result<(Peer, Exchange)> {
    let current = initial.is_some();
    if local.stage.data.role == NativeRole::SecurityShell {
        let nonce = protocol::nonce("serving-shell")?;
        let hello = match initial {
            None => Body::Hello {
                shell: Box::new(local.clone()),
                nonce: nonce.clone(),
            },
            Some(initial) => Body::CurrentHello {
                shell: Box::new(local.clone()),
                initial: initial.clone(),
                sequence,
                binding: binding
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("serving_peer_binding_missing"))?,
                nonce: nonce.clone(),
            },
        };
        session.send(hello, None)?;
        let (offer, process) = session.receive()?;
        let (remote, exchange) = match &offer.body {
            Body::Offer {
                controller,
                exchange,
            } if !current => (controller.as_ref().clone(), exchange.clone()),
            Body::CurrentOffer {
                controller,
                exchange,
            } if current => (controller.as_ref().clone(), exchange.clone()),
            _ => anyhow::bail!("serving_peer_offer_order"),
        };
        if let Some(previous) = previous {
            remote.require_fresh(previous)?;
        }
        let mut peer =
            Peer::authenticate(&offer, remote, process, session.stage, session.acquisition)?;
        ensure!(
            exchange.initial.as_ref() == initial
                && exchange.sequence == sequence
                && exchange.binding == binding
                && exchange.shell_stage == local.digest()?
                && exchange.controller_stage == peer.statement().digest()?
                && exchange.shell_nonce == nonce,
            "serving_peer_offer_transcript"
        );
        let digest = exchange.digest()?;
        session.send(
            if current {
                Body::CurrentConfirm {
                    exchange: digest.clone(),
                }
            } else {
                Body::Confirm {
                    exchange: digest.clone(),
                }
            },
            Some(&mut peer),
        )?;
        let (ready, process) = session.receive()?;
        peer.accept_message(&ready, process, session.stage, session.acquisition)?;
        ensure!(
            matches!(&ready.body, Body::Ready { exchange } if !current && *exchange == digest)
                || matches!(&ready.body, Body::CurrentReady { exchange } if current && *exchange == digest),
            "serving_peer_ready_transcript"
        );
        peer.check(session.stage, session.acquisition)?;
        session.check()?;
        Ok((peer, exchange))
    } else {
        ensure!(
            local.stage.data.role == NativeRole::EpochController,
            "serving_peer_controller_role"
        );
        let (hello, process) = session.receive()?;
        let (remote, nonce, binding) = match &hello.body {
            Body::Hello { shell, nonce } if !current => {
                (shell.as_ref().clone(), nonce.clone(), None)
            }
            Body::CurrentHello {
                shell,
                initial: actual,
                sequence: number,
                binding,
                nonce,
            } if current && Some(actual) == initial && *number == sequence => {
                (shell.as_ref().clone(), nonce.clone(), Some(binding.clone()))
            }
            _ => anyhow::bail!("serving_peer_hello_order_or_sequence"),
        };
        if let Some(previous) = previous {
            remote.require_fresh(previous)?;
        }
        let mut peer =
            Peer::authenticate(&hello, remote, process, session.stage, session.acquisition)?;
        let exchange = Exchange {
            initial: initial.cloned(),
            sequence,
            binding,
            shell_stage: peer.statement().digest()?,
            controller_stage: local.digest()?,
            shell_nonce: nonce,
            controller_nonce: protocol::nonce("serving-controller")?,
        };
        let digest = exchange.digest()?;
        session.send(
            if current {
                Body::CurrentOffer {
                    controller: Box::new(local.clone()),
                    exchange: exchange.clone(),
                }
            } else {
                Body::Offer {
                    controller: Box::new(local.clone()),
                    exchange: exchange.clone(),
                }
            },
            Some(&mut peer),
        )?;
        let (confirm, process) = session.receive()?;
        peer.accept_message(&confirm, process, session.stage, session.acquisition)?;
        ensure!(
            matches!(&confirm.body, Body::Confirm { exchange } if !current && *exchange == digest)
                || matches!(&confirm.body, Body::CurrentConfirm { exchange } if current && *exchange == digest),
            "serving_peer_confirm_transcript"
        );
        session.send(
            if current {
                Body::CurrentReady { exchange: digest }
            } else {
                Body::Ready { exchange: digest }
            },
            Some(&mut peer),
        )?;
        peer.check(session.stage, session.acquisition)?;
        session.check()?;
        Ok((peer, exchange))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion {
    Waiting,
    Known,
    Consumed,
    Released,
    Refused,
}

impl CurrentServingPeerPhase<'_> {
    pub(crate) fn request_binding(&self) -> &Digest {
        // Native constructors guarantee current sequence/binding shape.
        self.exchange
            .binding
            .as_ref()
            .expect("current serving request binding")
    }

    pub(crate) fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            self.owner.disposition.check(self.exchange.sequence)?;
            self.owner.check_resources(stage, &mut self.acquisition)?;
            ensure!(
                self.local == stage.serving_statement()?,
                "serving_peer_actual_stage_replaced"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("serving_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                self.peer.check(stage, &mut self.acquisition)?;
                self.owner
                    .channel
                    .check_serving_open(stage, &mut self.acquisition)
            }
        })();
        if result.is_err() {
            self.refuse();
            stage.refuse_serving();
        }
        result
    }

    fn packet(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        role: NativeRole,
        expected: Completion,
        next: Completion,
        send: bool,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.local.stage.data.role == role && self.completion == expected,
                "serving_peer_completion_order_or_role"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (next, send);
                anyhow::bail!("serving_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let digest = self.exchange.digest()?;
                if send {
                    let body = match next {
                        Completion::Known => Body::Known { exchange: digest },
                        Completion::Consumed => Body::Consumed { exchange: digest },
                        Completion::Released => Body::Released { exchange: digest },
                        _ => anyhow::bail!("serving_peer_completion_send_state"),
                    };
                    let message = stage.sign_serving_message(body)?;
                    self.owner
                        .channel
                        .send_serving(&message, stage, &mut self.acquisition)?;
                } else {
                    let (message, process) = self
                        .owner
                        .channel
                        .receive_serving(stage, &mut self.acquisition)?;
                    self.peer
                        .accept_message(&message, process, stage, &mut self.acquisition)?;
                    ensure!(
                        matches!(&message.body, Body::Known { exchange } if next == Completion::Known && *exchange == digest)
                            || matches!(&message.body, Body::Consumed { exchange } if next == Completion::Consumed && *exchange == digest)
                            || matches!(&message.body, Body::Released { exchange } if next == Completion::Released && *exchange == digest),
                        "serving_peer_completion_transcript"
                    );
                }
                self.check(stage)?;
                self.completion = next;
                Ok(())
            }
        })();
        if result.is_err() {
            self.refuse();
            stage.refuse_serving();
        }
        result
    }

    pub(crate) fn announce_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.packet(
            stage,
            NativeRole::EpochController,
            Completion::Waiting,
            Completion::Known,
            true,
        )
    }

    pub(crate) fn await_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.packet(
            stage,
            NativeRole::SecurityShell,
            Completion::Waiting,
            Completion::Known,
            false,
        )
    }

    pub(crate) fn await_consumed(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.packet(
            stage,
            NativeRole::EpochController,
            Completion::Known,
            Completion::Consumed,
            false,
        )
    }

    pub(crate) fn release(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.packet(
            stage,
            NativeRole::EpochController,
            Completion::Consumed,
            Completion::Released,
            true,
        )
    }

    /// Shell's known consumer performs final local checks before acknowledging.
    /// Controller calls only after its release and final physical postchecks.
    /// The parent keeps the original socket alive after either side finishes.
    pub(crate) fn finish_checked(mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        if self.local.stage.data.role == NativeRole::SecurityShell {
            self.packet(
                stage,
                NativeRole::SecurityShell,
                Completion::Known,
                Completion::Consumed,
                true,
            )?;
            self.packet(
                stage,
                NativeRole::SecurityShell,
                Completion::Consumed,
                Completion::Released,
                false,
            )?;
        }
        self.check(stage)?;
        ensure!(
            self.completion == Completion::Released,
            "serving_peer_completion_not_released"
        );
        self.owner.latest_local = self.local.clone();
        self.owner.latest_remote = self.remote.clone();
        self.owner.disposition.complete(self.exchange.sequence)?;
        Ok(())
    }

    /// Terminal, local-only refusal. No network, clock or replacement stage.
    pub(crate) fn refuse(&mut self) {
        self.completion = Completion::Refused;
        self.owner.disposition = Disposition::Refused;
        self.acquisition.refuse();
    }
}

#[cfg(test)]
mod tests {
    use super::Disposition;

    #[test]
    fn abandoned_or_busy_operation_never_reopens_from_a_later_begin_or_finish() {
        let mut owner = Disposition::Ready(0);
        let first = owner.begin().unwrap();
        assert_eq!(first, 1);
        assert!(owner.begin().is_err());
        assert_eq!(owner, Disposition::Refused);
        assert!(owner.complete(first).is_err());
        assert!(owner.begin().is_err());
    }

    #[test]
    fn late_completion_cannot_settle_a_different_operation() {
        let mut owner = Disposition::Ready(0);
        let first = owner.begin().unwrap();
        owner.complete(first).unwrap();
        let next = owner.begin().unwrap();
        assert!(owner.complete(first).is_err());
        assert_eq!(owner, Disposition::Busy(next));
        owner.complete(next).unwrap();
        assert_eq!(owner, Disposition::Ready(next));
    }

    #[test]
    fn sequence_exhaustion_and_explicit_refusal_are_terminal() {
        let mut owner = Disposition::Ready(u64::MAX);
        assert!(owner.begin().is_err());
        assert_eq!(owner, Disposition::Refused);
        assert!(owner.complete(0).is_err());
        let mut owner = Disposition::Refused;
        assert!(owner.begin().is_err());
        assert!(owner.complete(1).is_err());
    }
}
