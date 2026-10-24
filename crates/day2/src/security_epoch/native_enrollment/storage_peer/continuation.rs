//! Preserve the actual authenticated channel/handles across KNOWN initial
//! completion. Historical grants remain identity DATA, never later permission.
//! Each new phase exchanges fresh signed stages on that SAME retained socket.

use super::{AuthenticatedAppFirstHolder, AuthenticatedControllerFirstHolder};
use crate::security_epoch::native_enrollment::storage_peer_wire::{
    CurrentExchange, StageStatement,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    channel::Channel, protocol, storage_peer_native::Peer, storage_peer_wire::Body,
};
use crate::security_epoch::{
    AppFileContinuity, PreparedFileProjection,
    native_clock::{NativeAcquisition, STORAGE_BOOTSTRAP_LIMIT},
    native_enrollment::{
        EnrolledRoleStage, NativeRole, SameEnrolledOwner, StoragePeerPurpose, StoragePeerRequest,
    },
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;

/// Local socket replay/disposition state only, not a distributed permit
/// journal, storage authority, P3 proof or native owner constructor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Disposition {
    Ready(u64),
    Pending(u64),
    Busy(u64),
    Refused,
}

impl Disposition {
    fn notify(&mut self) -> Result<u64> {
        let sequence = self.begin()?;
        *self = Self::Pending(sequence);
        Ok(sequence)
    }

    fn begin_notified(&mut self, sequence: u64) -> Result<()> {
        if *self != Self::Pending(sequence) {
            self.refuse();
            anyhow::bail!("storage_peer_notification_changed_or_spent");
        }
        *self = Self::Busy(sequence);
        Ok(())
    }

    fn begin(&mut self) -> Result<u64> {
        let Self::Ready(previous) = *self else {
            anyhow::bail!("storage_peer_continuation_busy_or_refused");
        };
        let Some(sequence) = previous.checked_add(1) else {
            self.refuse();
            anyhow::bail!("storage_peer_sequence_exhausted");
        };
        *self = Self::Busy(sequence);
        Ok(sequence)
    }

    fn check(&self, sequence: u64) -> Result<()> {
        ensure!(
            *self == Self::Busy(sequence),
            "storage_peer_current_phase_refused"
        );
        Ok(())
    }

    fn complete(&mut self, sequence: u64) -> Result<()> {
        self.check(sequence)?;
        *self = Self::Ready(sequence);
        Ok(())
    }

    fn refuse(&mut self) {
        *self = Self::Refused;
    }
}

struct RetainedPeer {
    same: SameEnrolledOwner,
    local: StageStatement,
    initial: Digest,
    projection: PreparedFileProjection,
    last_local_grant: Digest,
    last_remote_grant: Digest,
    first_holder: crate::security_epoch::kernel::Holder,
    disposition: Disposition,
    #[cfg(target_os = "linux")]
    peer: Peer,
    #[cfg(target_os = "linux")]
    channel: Channel,
}

pub(crate) struct AppHolderPeerContinuity {
    owner: RetainedPeer,
}

pub(crate) struct ControllerHolderPeerContinuity {
    owner: RetainedPeer,
}

/// A single sent wakeup and the same retained peer. No role, clock, file or
/// action permission is live while this waits for signed readiness DATA.
pub(crate) struct PendingAppCurrentPeer<'peer> {
    owner: &'peer mut RetainedPeer,
    sequence: u64,
}

/// Queued notification DATA only. The actual retained peer, fresh role and
/// original Ready transcript must still be joined before any current phase.
pub(crate) struct QueuedAppCurrentPeer {
    initial: Digest,
    sequence: u64,
}

/// The actual Controller stage and channel stay bound to this readiness
/// transcript while its caller acquires the physical/provider phase.
pub(crate) struct ControllerCurrentRendezvous<'peer> {
    owner: &'peer mut RetainedPeer,
    acquisition: NativeAcquisition,
    local: StageStatement,
    sequence: u64,
    nonce: Digest,
    purpose: StoragePeerPurpose,
}

/// Identity/channel phase only. This owns no active file, P3, epoch, writer,
/// original human phase or consumer permission. The real narrowed acquisition
/// remains bound to the exact initial stage domain/origin and signed grant.
/// Each check requires that SAME actual stage as a temporary borrow, so the
/// physical/provider owner can run its own checks without aliased borrows.
/// The storage composite must
/// retain/recheck all those other owners around every use of this same stage.
pub(crate) struct CurrentStoragePeerPhase<'peer> {
    owner: &'peer mut RetainedPeer,
    acquisition: NativeAcquisition,
    local: StageStatement,
    exchange: CurrentExchange,
    remote_grant: Digest,
    completion: Completion,
    #[cfg(target_os = "linux")]
    peer: Peer,
}

impl AuthenticatedAppFirstHolder<'_, '_> {
    pub(crate) fn retain_for_activation(
        mut self,
    ) -> Result<(AppFileContinuity, AppHolderPeerContinuity)> {
        self.check()?;
        let same = self.file.app_stage()?.capture_same_owner()?;
        let projection = self.file.projection()?;
        self.check()?;
        let initial = self.offer.exchange.digest()?;
        let last_local_grant = self.offer.local.grant_digest()?;
        let last_remote_grant = self.offer.remote.grant_digest()?;
        let first_holder = self.offer.local.app_holder()?;
        // The storage owner moves the SAME descriptors after its own final
        // original checks. No file/key/channel is reopened or reconstructed.
        let file = self.file.retain_physical()?;
        Ok((
            file,
            AppHolderPeerContinuity {
                owner: RetainedPeer {
                    same,
                    local: self.offer.local,
                    initial,
                    projection,
                    last_local_grant,
                    last_remote_grant,
                    first_holder,
                    disposition: Disposition::Ready(0),
                    #[cfg(target_os = "linux")]
                    peer: self.offer.peer,
                    #[cfg(target_os = "linux")]
                    channel: self.offer.channel,
                },
            },
        ))
    }
}

impl AuthenticatedControllerFirstHolder<'_, '_> {
    pub(crate) fn retain_for_activation(mut self) -> Result<ControllerHolderPeerContinuity> {
        self.check()?;
        let same = self.phase.controller_stage()?.capture_same_owner()?;
        let projection = self.phase.projection()?;
        self.check()?;
        let initial = self.exchange.digest()?;
        let last_local_grant = self.local.grant_digest()?;
        let last_remote_grant = self.remote.grant_digest()?;
        let first_holder = self.remote.app_holder()?;
        // Only known initial exchange completion closes this original phase.
        // Its caller still owns the SAME PreparedFileContinuity; it may now
        // move that owner into its storage composite. This peer is not a file.
        self.phase.finish_checked()?;
        Ok(ControllerHolderPeerContinuity {
            owner: RetainedPeer {
                same,
                local: self.local,
                initial,
                projection,
                last_local_grant,
                last_remote_grant,
                first_holder,
                disposition: Disposition::Ready(0),
                #[cfg(target_os = "linux")]
                peer: self.peer,
                #[cfg(target_os = "linux")]
                channel: self.channel,
            },
        })
    }
}

impl RetainedPeer {
    fn start(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        role: NativeRole,
        purpose: StoragePeerPurpose,
    ) -> Result<(NativeAcquisition, StageStatement, u64)> {
        // Close before ANY fallible current work. No destructor, timeout or
        // later role can rearm an abandoned/unknown exchange.
        let sequence = self.disposition.begin()?;
        self.start_phase(stage, role, sequence, purpose)
    }

    fn start_phase(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        role: NativeRole,
        sequence: u64,
        purpose: StoragePeerPurpose,
    ) -> Result<(NativeAcquisition, StageStatement, u64)> {
        stage.require_purpose(purpose.stage_purpose())?;
        self.same.check(stage)?;
        ensure!(
            self.local.stage.data.role == role,
            "storage_peer_local_role"
        );
        let mut acquisition = match purpose {
            StoragePeerPurpose::CurrentServing => stage.narrow_io_acquisition(5)?,
            StoragePeerPurpose::BootstrapCreate | StoragePeerPurpose::BootstrapComplete => {
                stage.storage()?.narrow_storage_bootstrap_io_acquisition(
                    STORAGE_BOOTSTRAP_LIMIT.as_secs().try_into()?,
                )?
            }
        };
        let local = stage.storage()?.storage_statement()?;
        ensure!(
            self.local.same_enrollment(&local),
            "storage_peer_enrollment_changed"
        );
        local.require_new_grant(&self.last_local_grant)?;
        self.check_resources(stage, &mut acquisition)?;
        // The actual signed stage matched this purpose above, and the
        // purpose-specific clock/peer guards just succeeded. The DATA reducer
        // records that checked class; it never guesses from a scalar deadline.
        #[cfg(target_os = "linux")]
        self.channel.begin_current_handshake(
            sequence,
            purpose.stage_purpose(),
            &mut acquisition,
        )?;
        Ok((acquisition, local, sequence))
    }

    fn check_resources(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        self.same.check(stage)?;
        {
            // One lexical facade; each operation still performs its own full
            // native checks. No message/process I/O occurs between these calls.
            let mut storage = stage.storage()?;
            let local = storage.storage_statement()?;
            ensure!(
                self.local.same_enrollment(&local),
                "storage_peer_enrollment_changed"
            );
            storage.check_storage_acquisition(acquisition)?;
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("storage_peer_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            self.channel.check_storage_open(stage, acquisition)?;
            // Only original identity/liveness here. NEW grant validation is
            // mandatory in the fresh Peer below, not historical-stage replay.
            self.peer.check_continuity(stage, acquisition)?;
            self.channel.check_storage_open(stage, acquisition)
        }
    }
}

impl AppHolderPeerContinuity {
    pub(in crate::security_epoch) fn first_holder(&self) -> &crate::security_epoch::kernel::Holder {
        &self.owner.first_holder
    }

    /// This is the original selection DATA, not a refreshed image or permission.
    pub(crate) fn initial_projection(&self) -> &PreparedFileProjection {
        &self.owner.projection
    }

    pub(crate) fn refuse(&mut self) {
        self.owner.disposition.refuse();
    }

    pub(crate) fn notify_current(&mut self) -> Result<PendingAppCurrentPeer<'_>> {
        let sequence = self.owner.disposition.notify()?;
        #[cfg(not(target_os = "linux"))]
        {
            self.refuse();
            let _ = sequence;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            if let Err(error) = self.owner.channel.notify_idle(
                super::super::peer_idle::PeerChannel::Storage,
                &self.owner.initial,
                sequence,
            ) {
                self.refuse();
                return Err(error);
            }
            Ok(PendingAppCurrentPeer {
                owner: &mut self.owner,
                sequence,
            })
        }
    }

    pub(crate) fn begin_current<'peer>(
        &'peer mut self,
        queued: QueuedAppCurrentPeer,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        if queued.initial != self.owner.initial {
            self.refuse();
            anyhow::bail!("storage_peer_notification_original_changed");
        }
        PendingAppCurrentPeer {
            owner: &mut self.owner,
            sequence: queued.sequence,
        }
        .begin_current(stage, request)
    }
}

impl<'peer> PendingAppCurrentPeer<'peer> {
    pub(crate) fn wait(mut self) -> Result<QueuedAppCurrentPeer> {
        while !self.idle_ready()? {
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
        Ok(QueuedAppCurrentPeer {
            initial: self.owner.initial.clone(),
            sequence: self.sequence,
        })
    }

    pub(crate) fn idle_ready(&mut self) -> Result<bool> {
        let result = (|| {
            ensure!(
                self.owner.disposition == Disposition::Pending(self.sequence),
                "storage_peer_notification_changed_or_spent"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.owner.channel.storage_pending()
        })();
        if result.is_err() {
            self.owner.disposition.refuse();
        }
        result
    }

    pub(crate) fn begin_current(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        self.owner.disposition.begin_notified(self.sequence)?;
        let (acquisition, local, sequence) =
            self.owner
                .start_phase(stage, NativeRole::AppHost, self.sequence, request.purpose)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (acquisition, local, sequence, request);
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut acquisition = acquisition;
            let (ready, process) = self
                .owner
                .channel
                .receive_storage(stage, &mut acquisition)?;
            let (remote, controller_nonce) = match &ready.body {
                Body::CurrentBeginReady {
                    controller,
                    initial,
                    sequence: selected,
                    nonce,
                } if *initial == self.owner.initial && *selected == sequence => {
                    (controller.as_ref().clone(), nonce.clone())
                }
                _ => anyhow::bail!("storage_peer_current_begin_ready_changed"),
            };
            ensure!(
                self.owner.peer.statement().same_enrollment(&remote),
                "storage_peer_remote_enrollment_changed"
            );
            remote.require_new_grant(&self.owner.last_remote_grant)?;
            let mut peer = Peer::authenticate(&ready, remote, process, stage, &mut acquisition)?;
            let nonce = protocol::nonce("current-storage-peer-app")?;
            self.owner.check_resources(stage, &mut acquisition)?;
            let hello = stage.storage()?.sign_storage_message(Body::CurrentHello {
                app: Box::new(local.clone()),
                initial: self.owner.initial.clone(),
                sequence,
                request: request.clone(),
                nonce: nonce.clone(),
                controller_nonce: controller_nonce.clone(),
            })?;
            self.owner
                .channel
                .send_storage(&hello, stage, &mut acquisition)?;
            self.owner.check_resources(stage, &mut acquisition)?;
            let (offer, process) = self
                .owner
                .channel
                .receive_storage(stage, &mut acquisition)?;
            let (remote, exchange) = match &offer.body {
                Body::CurrentOffer {
                    controller,
                    exchange,
                } => (controller.as_ref().clone(), exchange.clone()),
                _ => anyhow::bail!("storage_peer_expected_current_offer"),
            };
            ensure!(
                self.owner.peer.statement().same_enrollment(&remote),
                "storage_peer_remote_enrollment_changed"
            );
            exchange.require_begin_ready(peer.statement(), &controller_nonce, &remote)?;
            peer.accept_message(&offer, process, stage, &mut acquisition)?;
            ensure!(
                exchange.initial == self.owner.initial
                    && exchange.sequence == sequence
                    && exchange.request == request
                    && exchange.app_stage == local.digest()?
                    && exchange.controller_stage == peer.statement().digest()?
                    && exchange.app_nonce == nonce,
                "storage_peer_current_offer_changed"
            );
            self.owner.check_resources(stage, &mut acquisition)?;
            peer.check(stage, &mut acquisition)?;
            let digest = exchange.digest()?;
            let ack = stage.storage()?.sign_storage_message(Body::CurrentAck {
                exchange: digest.clone(),
            })?;
            self.owner
                .channel
                .send_storage(&ack, stage, &mut acquisition)?;
            self.owner.check_resources(stage, &mut acquisition)?;
            let (ready, process) = self
                .owner
                .channel
                .receive_storage(stage, &mut acquisition)?;
            peer.accept_message(&ready, process, stage, &mut acquisition)?;
            ensure!(
                matches!(&ready.body, Body::CurrentReady { exchange } if *exchange == digest),
                "storage_peer_current_ready_changed"
            );
            let mut phase = CurrentStoragePeerPhase {
                completion: Completion::Waiting,
                remote_grant: peer.statement().grant_digest()?,
                owner: self.owner,
                acquisition,
                local,
                exchange,
                peer,
            };
            phase.check(stage)?;
            Ok(phase)
        }
    }
}

impl ControllerHolderPeerContinuity {
    /// Candidate DATA captured from the actual initial App participant.
    pub(in crate::security_epoch) fn first_holder(&self) -> &crate::security_epoch::kernel::Holder {
        &self.owner.first_holder
    }

    pub(crate) fn initial_projection(&self) -> &PreparedFileProjection {
        &self.owner.projection
    }

    pub(crate) fn refuse(&mut self) {
        self.owner.disposition.refuse();
    }

    pub(in crate::security_epoch) fn pending(&mut self) -> Result<bool> {
        ensure!(
            matches!(self.owner.disposition, Disposition::Ready(_)),
            "storage_peer_retained_busy_or_refused"
        );
        #[cfg(not(target_os = "linux"))]
        {
            self.refuse();
            anyhow::bail!("storage_peer_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            let result = self.owner.channel.storage_pending();
            if result.is_err() {
                self.refuse();
            }
            result
        }
    }

    /// Identity/liveness of the original App holder only. This deliberately
    /// grants no fresh App role/file possession or serving authority.
    pub(in crate::security_epoch) fn check_retained_identity(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                matches!(self.owner.disposition, Disposition::Ready(_)),
                "storage_peer_retained_busy_or_refused"
            );
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            self.owner.check_resources(stage, &mut acquisition)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn prepare_current(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        purpose: StoragePeerPurpose,
    ) -> Result<ControllerCurrentRendezvous<'_>> {
        let (acquisition, local, sequence) =
            self.owner
                .start(stage, NativeRole::EpochController, purpose)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (acquisition, local, sequence);
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut acquisition = acquisition;
            self.owner.channel.receive_idle(
                super::super::peer_idle::PeerChannel::Storage,
                &self.owner.initial,
                sequence,
                &mut acquisition,
            )?;
            self.owner.check_resources(stage, &mut acquisition)?;
            let nonce = protocol::nonce("current-storage-peer-controller")?;
            let ready = stage
                .storage()?
                .sign_storage_message(Body::CurrentBeginReady {
                    controller: Box::new(local.clone()),
                    initial: self.owner.initial.clone(),
                    sequence,
                    nonce: nonce.clone(),
                })?;
            self.owner
                .channel
                .send_storage(&ready, stage, &mut acquisition)?;
            self.owner.check_resources(stage, &mut acquisition)?;
            Ok(ControllerCurrentRendezvous {
                owner: &mut self.owner,
                acquisition,
                local,
                sequence,
                nonce,
                purpose,
            })
        }
    }
}

impl<'peer> ControllerCurrentRendezvous<'peer> {
    pub(crate) fn accept_current(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        expected: Option<&StoragePeerRequest>,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        self.owner.disposition.check(self.sequence)?;
        stage.require_purpose(self.purpose.stage_purpose())?;
        ensure!(
            expected.is_none_or(|request| request.purpose == self.purpose)
                && (self.purpose == StoragePeerPurpose::CurrentServing || expected.is_some()),
            "storage_peer_current_expected_request_required"
        );
        // Keep exactly the already-spent Ready acquisition. A different
        // actual stage cannot satisfy the original-origin and statement checks.
        let mut acquisition = self.acquisition;
        self.owner.check_resources(stage, &mut acquisition)?;
        let local = self.local;
        let sequence = self.sequence;
        ensure!(
            local == stage.storage()?.storage_statement()?,
            "storage_peer_current_ready_stage_changed"
        );
        stage
            .storage()?
            .check_storage_acquisition(&mut acquisition)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (acquisition, local, sequence, expected);
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let (hello, process) = self
                .owner
                .channel
                .receive_storage(stage, &mut acquisition)?;
            let (remote, nonce, request) =
                hello.current_hello(&self.owner.initial, sequence, &self.nonce, expected)?;
            let (remote, nonce, request) = (remote.clone(), nonce.clone(), request.clone());
            ensure!(
                request.purpose == self.purpose,
                "storage_peer_current_purpose_changed"
            );
            ensure!(
                self.owner.peer.statement().same_enrollment(&remote),
                "storage_peer_remote_enrollment_changed"
            );
            remote.require_new_grant(&self.owner.last_remote_grant)?;
            let mut peer = Peer::authenticate(&hello, remote, process, stage, &mut acquisition)?;
            let exchange = CurrentExchange {
                initial: self.owner.initial.clone(),
                sequence,
                request,
                app_stage: peer.statement().digest()?,
                controller_stage: local.digest()?,
                app_nonce: nonce,
                controller_nonce: self.nonce,
            };
            self.owner.check_resources(stage, &mut acquisition)?;
            peer.check(stage, &mut acquisition)?;
            let offer = stage.storage()?.sign_storage_message(Body::CurrentOffer {
                controller: Box::new(local.clone()),
                exchange: exchange.clone(),
            })?;
            self.owner
                .channel
                .send_storage(&offer, stage, &mut acquisition)?;
            self.owner.check_resources(stage, &mut acquisition)?;
            let (ack, process) = self
                .owner
                .channel
                .receive_storage(stage, &mut acquisition)?;
            peer.accept_message(&ack, process, stage, &mut acquisition)?;
            let digest = exchange.digest()?;
            ensure!(
                matches!(&ack.body, Body::CurrentAck { exchange } if *exchange == digest),
                "storage_peer_current_ack_changed"
            );
            self.owner.check_resources(stage, &mut acquisition)?;
            peer.check(stage, &mut acquisition)?;
            let ready = stage
                .storage()?
                .sign_storage_message(Body::CurrentReady { exchange: digest })?;
            self.owner
                .channel
                .send_storage(&ready, stage, &mut acquisition)?;
            let mut phase = CurrentStoragePeerPhase {
                completion: Completion::Waiting,
                remote_grant: peer.statement().grant_digest()?,
                owner: self.owner,
                acquisition,
                local,
                exchange,
                peer,
            };
            phase.check(stage)?;
            Ok(phase)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Waiting,
    ControllerAnnounced,
    AppObserved,
    AppAcknowledged,
    ControllerAcknowledged,
    AppReleased,
    ControllerReleased,
    Refused,
}

impl CurrentStoragePeerPhase<'_> {
    /// Close before the actual packet operation. An uncertain send/receive
    /// cannot be repeated or converted into a completion by time or DATA.
    fn completion_packet(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        expected: Completion,
        next: Completion,
        role: NativeRole,
        send: bool,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.completion == expected && self.local.stage.data.role == role,
                "storage_peer_completion_order_or_role"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (next, send);
                anyhow::bail!("storage_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let digest = self.exchange.digest()?;
                if send {
                    let body = if next == Completion::ControllerReleased {
                        Body::CurrentReleased { exchange: digest }
                    } else if role == NativeRole::EpochController {
                        Body::CurrentResult { exchange: digest }
                    } else {
                        Body::CurrentConsumed { exchange: digest }
                    };
                    let message = stage.storage()?.sign_storage_message(body)?;
                    self.owner
                        .channel
                        .send_storage(&message, stage, &mut self.acquisition)?;
                } else {
                    let (message, process) = self
                        .owner
                        .channel
                        .receive_storage(stage, &mut self.acquisition)?;
                    self.peer
                        .accept_message(&message, process, stage, &mut self.acquisition)?;
                    let kind = match next {
                        Completion::AppObserved => {
                            super::super::storage_peer_wire::CompletionKind::Result
                        }
                        Completion::ControllerAcknowledged => {
                            super::super::storage_peer_wire::CompletionKind::Consumed
                        }
                        Completion::AppReleased => {
                            super::super::storage_peer_wire::CompletionKind::Released
                        }
                        _ => anyhow::bail!("storage_peer_completion_receive_state"),
                    };
                    ensure!(
                        message.body.matches_completion(&digest, kind),
                        "storage_peer_completion_transcript_changed"
                    );
                }
                self.check(stage)?;
                self.completion = next;
                Ok(())
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn announce_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.completion_packet(
            stage,
            Completion::Waiting,
            Completion::ControllerAnnounced,
            NativeRole::EpochController,
            true,
        )
    }

    pub(crate) fn await_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.completion_packet(
            stage,
            Completion::Waiting,
            Completion::AppObserved,
            NativeRole::AppHost,
            false,
        )
    }

    pub(crate) fn acknowledge_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.completion_packet(
            stage,
            Completion::AppObserved,
            Completion::AppAcknowledged,
            NativeRole::AppHost,
            true,
        )
    }

    pub(crate) fn await_acknowledgement(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.completion_packet(
            stage,
            Completion::ControllerAnnounced,
            Completion::ControllerAcknowledged,
            NativeRole::EpochController,
            false,
        )
    }

    pub(crate) fn release_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.completion_packet(
            stage,
            Completion::ControllerAcknowledged,
            Completion::ControllerReleased,
            NativeRole::EpochController,
            true,
        )
    }

    pub(crate) fn await_release(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.completion_packet(
            stage,
            Completion::AppAcknowledged,
            Completion::AppReleased,
            NativeRole::AppHost,
            false,
        )
    }

    pub(crate) fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            self.owner.disposition.check(self.exchange.sequence)?;
            stage.require_purpose(self.exchange.request.purpose.stage_purpose())?;
            self.owner.check_resources(stage, &mut self.acquisition)?;
            ensure!(
                self.local == stage.storage()?.storage_statement()?,
                "storage_peer_current_stage_replaced"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.peer.check(stage, &mut self.acquisition)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn request(&self) -> &StoragePeerRequest {
        &self.exchange.request
    }

    /// Call only AFTER the storage composite's known result and ALL final
    /// physical/provider/original/consumer checks. This is NOT finish_known of
    /// a consumer: it releases the peer scope and must follow those postchecks.
    pub(crate) fn finish_checked(mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.check(stage)?;
        ensure!(
            matches!(
                (self.local.stage.data.role, self.completion),
                (NativeRole::AppHost, Completion::AppReleased)
                    | (NativeRole::EpochController, Completion::ControllerReleased)
            ),
            "storage_peer_completion_not_consumed"
        );
        self.owner.last_local_grant = self.local.grant_digest()?;
        self.owner.last_remote_grant = self.remote_grant.clone();
        self.owner.disposition.complete(self.exchange.sequence)
    }

    /// Terminal refusal has no live clock, stage check, network or replacement.
    pub(crate) fn refuse(&mut self) {
        self.completion = Completion::Refused;
        self.owner.disposition.refuse();
        self.acquisition.refuse();
    }
}

#[cfg(test)]
mod disposition_tests {
    use super::Disposition;

    #[test]
    fn notification_is_not_a_phase_and_only_its_exact_sequence_can_begin() {
        let mut state = Disposition::Ready(0);
        assert_eq!(state.notify().unwrap(), 1);
        assert_eq!(state, Disposition::Pending(1));
        assert!(state.complete(1).is_err());
        assert!(state.begin().is_err());
        assert_eq!(state, Disposition::Pending(1));
        state.begin_notified(1).unwrap();
        state.check(1).unwrap();
        assert!(state.begin_notified(1).is_err());
        assert_eq!(state, Disposition::Refused);
        assert!(state.complete(1).is_err());

        let mut changed = Disposition::Ready(7);
        assert_eq!(changed.notify().unwrap(), 8);
        assert!(changed.begin_notified(7).is_err());
        assert_eq!(changed, Disposition::Refused);
        assert!(changed.begin_notified(8).is_err());
    }

    #[test]
    fn only_known_current_completion_allows_a_later_notification() {
        let mut state = Disposition::Ready(0);
        state.notify().unwrap();
        state.begin_notified(1).unwrap();
        state.complete(1).unwrap();
        assert_eq!(state.notify().unwrap(), 2);
        assert!(state.complete(1).is_err());
        state.refuse();
        assert!(state.begin_notified(2).is_err());
        assert!(state.notify().is_err());
    }

    #[test]
    fn unknown_or_abandoned_phase_never_reopens_from_time_or_another_begin() {
        let mut state = Disposition::Ready(0);
        assert_eq!(state.begin().unwrap(), 1);
        assert!(state.begin().is_err());
        assert_eq!(state, Disposition::Busy(1));
        assert!(state.complete(2).is_err());
        assert_eq!(state, Disposition::Busy(1));
        state.refuse();
        assert!(state.complete(1).is_err());
        assert!(state.begin().is_err());
        assert_eq!(state, Disposition::Refused);
    }

    #[test]
    fn late_known_completion_cannot_settle_a_different_paused_phase() {
        let mut state = Disposition::Ready(0);
        let first = state.begin().unwrap();
        state.complete(first).unwrap();
        let second = state.begin().unwrap();
        assert!(state.complete(first).is_err());
        assert!(state.begin().is_err());
        assert_eq!(state, Disposition::Busy(second));
        state.complete(second).unwrap();
        assert_eq!(state, Disposition::Ready(second));
    }

    #[test]
    fn refusal_after_known_result_stays_terminal() {
        let mut state = Disposition::Ready(0);
        let sequence = state.begin().unwrap();
        state.complete(sequence).unwrap();
        state.refuse();
        assert!(state.complete(sequence).is_err());
        assert!(state.begin().is_err());
        assert_eq!(state, Disposition::Refused);
    }

    #[test]
    fn sequence_exhaustion_refuses_before_another_exchange() {
        let mut state = Disposition::Ready(u64::MAX);
        assert!(state.begin().is_err());
        assert_eq!(state, Disposition::Refused);
        assert!(state.complete(0).is_err());
    }
}
