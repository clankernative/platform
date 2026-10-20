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
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, NativeRole, SameEnrolledOwner, StoragePeerRequest},
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;

/// Local socket replay/disposition state only, not a distributed permit
/// journal, storage authority, P3 proof or native owner constructor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Disposition {
    Ready(u64),
    Busy(u64),
    Refused,
}

impl Disposition {
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
    ) -> Result<(NativeAcquisition, StageStatement, u64)> {
        // Close before ANY fallible current work. No destructor, timeout or
        // later role can rearm an abandoned/unknown exchange.
        let sequence = self.disposition.begin()?;
        self.same.check(stage)?;
        ensure!(
            self.local.stage.data.role == role,
            "storage_peer_local_role"
        );
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let local = stage.storage_statement()?;
        ensure!(
            self.local.same_enrollment(&local),
            "storage_peer_enrollment_changed"
        );
        self.check_resources(stage, &mut acquisition)?;
        Ok((acquisition, local, sequence))
    }

    fn check_resources(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        self.same.check(stage)?;
        let local = stage.storage_statement()?;
        ensure!(
            self.local.same_enrollment(&local),
            "storage_peer_enrollment_changed"
        );
        stage.check_storage_acquisition(acquisition)?;
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
    /// This is the original selection DATA, not a refreshed image or permission.
    pub(crate) fn initial_projection(&self) -> &PreparedFileProjection {
        &self.owner.projection
    }

    pub(crate) fn refuse(&mut self) {
        self.owner.disposition.refuse();
    }

    pub(crate) fn begin_current<'peer>(
        &'peer mut self,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        let (acquisition, local, sequence) = self.owner.start(stage, NativeRole::AppHost)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (acquisition, local, sequence, request);
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut acquisition = acquisition;
            let nonce = protocol::nonce("current-storage-peer-app")?;
            self.owner.check_resources(stage, &mut acquisition)?;
            let hello = stage.sign_storage_message(Body::CurrentHello {
                app: Box::new(local.clone()),
                initial: self.owner.initial.clone(),
                sequence,
                request: request.clone(),
                nonce: nonce.clone(),
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
            let mut peer = Peer::authenticate(&offer, remote, process, stage, &mut acquisition)?;
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
            let ack = stage.sign_storage_message(Body::CurrentAck {
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
                owner: &mut self.owner,
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
    pub(crate) fn initial_projection(&self) -> &PreparedFileProjection {
        &self.owner.projection
    }

    pub(crate) fn refuse(&mut self) {
        self.owner.disposition.refuse();
    }

    pub(crate) fn accept_current<'peer>(
        &'peer mut self,
        stage: &mut EnrolledRoleStage<'_>,
        expected: &StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        let (acquisition, local, sequence) =
            self.owner.start(stage, NativeRole::EpochController)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (acquisition, local, sequence, expected);
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut acquisition = acquisition;
            let (hello, process) = self
                .owner
                .channel
                .receive_storage(stage, &mut acquisition)?;
            let (remote, nonce) = match &hello.body {
                Body::CurrentHello {
                    app,
                    initial,
                    sequence: selected,
                    request,
                    nonce,
                } => {
                    ensure!(
                        *initial == self.owner.initial
                            && *selected == sequence
                            && request == expected,
                        "storage_peer_current_request_changed"
                    );
                    (app.as_ref().clone(), nonce.clone())
                }
                _ => anyhow::bail!("storage_peer_expected_current_hello"),
            };
            ensure!(
                self.owner.peer.statement().same_enrollment(&remote),
                "storage_peer_remote_enrollment_changed"
            );
            let mut peer = Peer::authenticate(&hello, remote, process, stage, &mut acquisition)?;
            let exchange = CurrentExchange {
                initial: self.owner.initial.clone(),
                sequence,
                request: expected.clone(),
                app_stage: peer.statement().digest()?,
                controller_stage: local.digest()?,
                app_nonce: nonce,
                controller_nonce: protocol::nonce("current-storage-peer-controller")?,
            };
            self.owner.check_resources(stage, &mut acquisition)?;
            peer.check(stage, &mut acquisition)?;
            let offer = stage.sign_storage_message(Body::CurrentOffer {
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
            let ready = stage.sign_storage_message(Body::CurrentReady { exchange: digest })?;
            self.owner
                .channel
                .send_storage(&ready, stage, &mut acquisition)?;
            let mut phase = CurrentStoragePeerPhase {
                owner: &mut self.owner,
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

impl CurrentStoragePeerPhase<'_> {
    pub(crate) fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            self.owner.disposition.check(self.exchange.sequence)?;
            self.owner.check_resources(stage, &mut self.acquisition)?;
            ensure!(
                self.local == stage.storage_statement()?,
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
        self.owner.disposition.complete(self.exchange.sequence)
    }

    /// Terminal refusal has no live clock, stage check, network or replacement.
    pub(crate) fn refuse(&mut self) {
        self.owner.disposition.refuse();
        self.acquisition.refuse();
    }
}

#[cfg(test)]
mod disposition_tests {
    use super::Disposition;

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
