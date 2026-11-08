//! Preserve the actual authenticated channel/handles across KNOWN initial
//! completion. Historical grants remain identity DATA, never later permission.
//! Each new phase exchanges fresh signed stages on that SAME retained socket.

use super::super::{RestoredCurrentPeerPort, RestoredPeerTail};
use super::{AuthenticatedAppFirstHolder, AuthenticatedControllerFirstHolder};
use crate::security_epoch::native_enrollment::storage_peer_wire::{
    CurrentExchange, StageStatement,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    channel::Channel,
    protocol,
    storage_peer_native::{Peer, PeerAnchor},
    storage_peer_wire::Body,
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

/// Closed provenance of the single operational cursor, never request permission.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionOrigin {
    Initial,
    RestoredFirst,
    RestoredCurrent,
}

impl ConnectionOrigin {
    fn require_purpose(self, purpose: StoragePeerPurpose) -> Result<()> {
        ensure!(
            self == Self::Initial
                || matches!(
                    purpose,
                    StoragePeerPurpose::CurrentServing | StoragePeerPurpose::AdminRead
                ),
            "restore_current_initial_purpose_refused"
        );
        Ok(())
    }

    fn require_interval(
        self,
        current: &super::super::storage_peer_wire::OriginalInterval,
        previous: &super::super::storage_peer_wire::OriginalInterval,
    ) -> Result<()> {
        if self == Self::RestoredFirst {
            current.require_later_request(previous)
        } else {
            current.require_request_continuity(previous)
        }
    }
}

struct RetainedPeer {
    same: SameEnrolledOwner,
    local: StageStatement,
    initial: Digest,
    last_local_request: super::super::storage_peer_wire::OriginalInterval,
    last_remote_request: super::super::storage_peer_wire::OriginalInterval,
    disposition: Disposition,
    origin: ConnectionOrigin,
    #[cfg(target_os = "linux")]
    peer: PeerAnchor,
    #[cfg(target_os = "linux")]
    channel: Channel,
}

pub(crate) struct AppHolderPeerContinuity {
    owner: RetainedPeer,
    projection: PreparedFileProjection,
    first_holder: crate::security_epoch::kernel::Holder,
}

pub(crate) struct ControllerHolderPeerContinuity {
    owner: RetainedPeer,
    projection: PreparedFileProjection,
    first_holder: crate::security_epoch::kernel::Holder,
}

/// A single sent wakeup and the same retained peer. No role, clock, file or
/// action permission is live while this waits for signed readiness DATA.
pub(crate) struct PendingAppCurrentPeer<'peer> {
    owner: PeerPhaseOwner<'peer>,
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
    owner: PeerPhaseOwner<'peer>,
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
    owner: PeerPhaseOwner<'peer>,
    acquisition: NativeAcquisition,
    local: StageStatement,
    exchange: CurrentExchange,
    remote_request: super::super::storage_peer_wire::OriginalInterval,
    completion: Completion,
    stopped: Option<super::super::AuthorityStopData>,
    fence: Option<crate::security_epoch::firestore::ReservationConfirmation>,
    #[cfg(target_os = "linux")]
    peer: Peer,
}

/// The same engine either borrows its existing connection or temporarily owns
/// a genuinely transferred restore connection. Neither branch creates socket,
/// native role, file or epoch authority. Only the closed restore producer may
/// construct the owning branch; it must also retain the complete old tail.
enum PeerPhaseOwner<'peer> {
    Borrowed(&'peer mut RetainedPeer),
    Restored(Box<RestoredPeerConnection<'peer>>),
}

impl std::ops::Deref for PeerPhaseOwner<'_> {
    type Target = RetainedPeer;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(owner) => owner,
            Self::Restored(owner) => &owner.owner,
        }
    }
}

impl std::ops::DerefMut for PeerPhaseOwner<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Borrowed(owner) => owner,
            Self::Restored(owner) => &mut owner.owner,
        }
    }
}

/// Whole historical owner tail plus the sole operational cursor. A lexical
/// Controller connection cannot outlive its real Installed owners. The App
/// form retains its whole original keeper/history through the actual Rc loan.
pub(in crate::security_epoch) struct RestoredPeerConnection<'tail> {
    owner: RetainedPeer,
    tail: RestoredPeerTail<'tail>,
    #[cfg(target_os = "linux")]
    original: Option<NativeAcquisition>,
    #[cfg(target_os = "linux")]
    native_refusal: crate::security_epoch::native_clock::NativeOriginalRefusal,
    #[cfg(target_os = "linux")]
    channel_refusal: std::rc::Rc<std::cell::Cell<bool>>,
}

impl Drop for RestoredPeerConnection<'_> {
    fn drop(&mut self) {
        self.owner.disposition.refuse();
        self.tail.refuse();
        #[cfg(target_os = "linux")]
        {
            self.channel_refusal.set(true);
            self.native_refusal.refuse();
            if let Some(original) = &mut self.original {
                original.refuse();
            }
        }
    }
}

impl<'tail> RestoredPeerConnection<'tail> {
    fn from_port(
        mut input: RestoredCurrentPeerPort<'tail>,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&mut input, stage);
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let channel = Channel::take_restored(&mut input, stage, &mut acquisition)?;
            let peer = PeerAnchor::from_restored(&mut input, stage, &mut acquisition)?;
            let same = input.same.take().context("restore_current_owner_missing")?;
            let original = input
                .original
                .take()
                .context("restore_current_original_missing")?;
            let native_refusal = input
                .native_refusal
                .take()
                .context("restore_current_refusal_missing")?;
            let tail = input.tail.take().context("restore_current_tail_missing")?;
            let mut connection = Self {
                owner: RetainedPeer {
                    same,
                    local: input.local.clone(),
                    initial: input.binding.clone(),
                    last_local_request: input.local.original.clone(),
                    last_remote_request: input.remote.original.clone(),
                    disposition: Disposition::Ready(0),
                    origin: ConnectionOrigin::RestoredFirst,
                    peer,
                    channel,
                },
                tail,
                original: Some(original),
                native_refusal,
                channel_refusal: std::rc::Rc::clone(&input.channel_refusal),
            };
            // The entire negative tail is already installed before any final
            // fallible post. Only this complete ownership move disarms input.
            let requested = connection.check_resources(stage, &mut acquisition);
            let checked = stage.check();
            requested?;
            checked?;
            input.completed = true;
            Ok(connection)
        }
    }

    fn check_resources(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            #[cfg(target_os = "linux")]
            {
                let original = self
                    .original
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
                self.owner.same.meet_current_read_view(stage, original)?;
                original.exchange_current_views(acquisition)?;
            }
            self.owner.check_resources(stage, acquisition)?;
            #[cfg(target_os = "linux")]
            self.owner.channel.check_restored_source(
                &mut self.tail,
                &self.owner.local,
                self.owner.peer.statement(),
                &self.owner.initial,
                stage,
                acquisition,
            )?;
            Ok(())
        })();
        let tail = self
            .tail
            .check_current(&self.owner.initial, stage, acquisition);
        let checked = stage.check();
        if requested.is_err() || tail.is_err() || checked.is_err() {
            self.owner.disposition.refuse();
            self.tail.refuse();
            acquisition.refuse();
            stage.refuse_serving();
        }
        requested?;
        tail?;
        checked
    }

    /// Only the genuine whole App history can supply this connection. Raw
    /// transfer parts never cross the private accepting factory boundary.
    pub(in crate::security_epoch::native_enrollment) fn from_app_history(
        history: &std::rc::Rc<super::super::restored::RestoredAppHistory>,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<RestoredPeerConnection<'static>> {
        let port = history.take_current_peer(stage)?;
        RestoredPeerConnection::from_port(port, stage)
    }

    /// Readiness DATA only. No stage, original, packet decode or permission is
    /// created while the actual retained Controller waits for an App wakeup.
    pub(in crate::security_epoch) fn pending(&mut self) -> Result<bool> {
        let requested = (|| {
            ensure!(
                matches!(self.owner.disposition, Disposition::Ready(_)),
                "storage_peer_retained_busy_or_refused"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.owner.channel.storage_pending()
        })();
        if requested.is_err() {
            self.owner.disposition.refuse();
            self.tail.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn prepare_controller(
        peer: &'tail mut super::super::owner::RestoredWriterPeer,
        installed: &'tail mut super::super::owner::InstalledRestoredAppConfirmation,
        stage: &mut EnrolledRoleStage<'_>,
        purpose: StoragePeerPurpose,
    ) -> Result<ControllerCurrentRendezvous<'tail>> {
        let port = peer.take_current_peer(installed, stage)?;
        Self::from_port(port, stage)?.prepare_current(stage, purpose)
    }

    pub(in crate::security_epoch) fn prepare_current(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        purpose: StoragePeerPurpose,
    ) -> Result<ControllerCurrentRendezvous<'tail>> {
        ControllerCurrentRendezvous::prepare(
            PeerPhaseOwner::Restored(Box::new(self)),
            stage,
            purpose,
        )
    }

    pub(in crate::security_epoch::native_enrollment) fn begin_app(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'tail>> {
        let mut owner = PeerPhaseOwner::Restored(Box::new(self));
        #[cfg(target_os = "linux")]
        if let PeerPhaseOwner::Restored(connection) = &mut owner {
            if connection.original.is_none() {
                connection.original = Some(stage.narrow_io_acquisition(5)?);
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = &request;
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        owner.check_resources(stage, &mut acquisition)?;
        let mut pending = PendingAppCurrentPeer::notify(owner)?;
        // The wakeup itself is real transport and gets its own posts.
        pending.owner.check_resources(stage, &mut acquisition)?;
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("storage_peer_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            let requested = pending
                .owner
                .channel
                .wait_storage_pending(stage, &mut acquisition);
            let checked = pending.owner.check_resources(stage, &mut acquisition);
            requested?;
            checked?;
            pending.begin_current(stage, request)
        }
    }
}

impl<'peer> PeerPhaseOwner<'peer> {
    fn check_resources(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        match self {
            Self::Borrowed(owner) => owner.check_resources(stage, acquisition),
            Self::Restored(owner) => owner.check_resources(stage, acquisition),
        }
    }

    fn start(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        role: NativeRole,
        purpose: StoragePeerPurpose,
    ) -> Result<(NativeAcquisition, StageStatement, u64)> {
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
        #[cfg(target_os = "linux")]
        if let Self::Restored(owner) = self {
            if owner.original.is_none() {
                owner.original = Some(stage.narrow_io_acquisition(5)?);
            }
        }
        let (mut acquisition, local, sequence) = match self {
            Self::Borrowed(owner) => owner.start_phase(stage, role, sequence, purpose)?,
            Self::Restored(owner) => owner.owner.start_phase(stage, role, sequence, purpose)?,
        };
        // start_phase advances only cursor DATA. The full historical native
        // tail is checked before the first actual receive, send or signature.
        self.check_resources(stage, &mut acquisition)?;
        Ok((acquisition, local, sequence))
    }
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
        let last_local_request = self.offer.local.original.clone();
        let last_remote_request = self.offer.remote.original.clone();
        let first_holder = self.offer.local.app_holder()?;
        // The storage owner moves the SAME descriptors after its own final
        // original checks. No file/key/channel is reopened or reconstructed.
        let file = self.file.retain_physical()?;
        Ok((
            file,
            AppHolderPeerContinuity {
                projection,
                first_holder,
                owner: RetainedPeer {
                    same,
                    local: self.offer.local,
                    initial,
                    last_local_request,
                    last_remote_request,
                    disposition: Disposition::Ready(0),
                    origin: ConnectionOrigin::Initial,
                    #[cfg(target_os = "linux")]
                    peer: self.offer.peer.into_anchor(),
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
        let last_local_request = self.local.original.clone();
        let last_remote_request = self.remote.original.clone();
        let first_holder = self.remote.app_holder()?;
        // Only known initial exchange completion closes this original phase.
        // Its caller still owns the SAME PreparedFileContinuity; it may now
        // move that owner into its storage composite. This peer is not a file.
        self.phase.finish_checked()?;
        Ok(ControllerHolderPeerContinuity {
            projection,
            first_holder,
            owner: RetainedPeer {
                same,
                local: self.local,
                initial,
                last_local_request,
                last_remote_request,
                disposition: Disposition::Ready(0),
                origin: ConnectionOrigin::Initial,
                #[cfg(target_os = "linux")]
                peer: self.peer.into_anchor(),
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
        self.origin.require_purpose(purpose)?;
        stage.require_purpose(purpose.stage_purpose())?;
        self.same.check(stage)?;
        ensure!(
            self.local.stage.data.role == role,
            "storage_peer_local_role"
        );
        let mut acquisition = match purpose {
            StoragePeerPurpose::CurrentServing | StoragePeerPurpose::AdminRead => {
                stage.narrow_io_acquisition(5)?
            }
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
        self.origin
            .require_interval(&local.original, &self.last_local_request)?;
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

    fn notify_current(&mut self) -> Result<PendingAppCurrentPeer<'_>> {
        PendingAppCurrentPeer::notify(PeerPhaseOwner::Borrowed(self))
    }

    fn begin_current<'peer>(
        &'peer mut self,
        queued: QueuedAppCurrentPeer,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        if queued.initial != self.initial {
            self.disposition.refuse();
            anyhow::bail!("storage_peer_notification_original_changed");
        }
        PendingAppCurrentPeer {
            owner: PeerPhaseOwner::Borrowed(self),
            sequence: queued.sequence,
        }
        .begin_current(stage, request)
    }

    fn prepare_current(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        purpose: StoragePeerPurpose,
    ) -> Result<ControllerCurrentRendezvous<'_>> {
        ControllerCurrentRendezvous::prepare(PeerPhaseOwner::Borrowed(self), stage, purpose)
    }
}

impl AppHolderPeerContinuity {
    /// Rejoin the original admitted App owner and peer without starting a
    /// packet exchange or issuing request/serving authority.
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

    pub(in crate::security_epoch) fn first_holder(&self) -> &crate::security_epoch::kernel::Holder {
        &self.first_holder
    }

    /// This is the original selection DATA, not a refreshed image or permission.
    pub(crate) fn initial_projection(&self) -> &PreparedFileProjection {
        &self.projection
    }

    pub(crate) fn refuse(&mut self) {
        self.owner.disposition.refuse();
    }

    pub(crate) fn notify_current(&mut self) -> Result<PendingAppCurrentPeer<'_>> {
        self.owner.notify_current()
    }

    pub(crate) fn begin_current<'peer>(
        &'peer mut self,
        queued: QueuedAppCurrentPeer,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        self.owner.begin_current(queued, stage, request)
    }
}

impl<'peer> PendingAppCurrentPeer<'peer> {
    fn notify(mut owner: PeerPhaseOwner<'peer>) -> Result<Self> {
        let sequence = owner.disposition.notify()?;
        #[cfg(not(target_os = "linux"))]
        {
            owner.disposition.refuse();
            let _ = sequence;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let initial = owner.initial.clone();
            if let Err(error) = owner.channel.notify_idle(
                super::super::peer_idle::PeerChannel::Storage,
                &initial,
                sequence,
            ) {
                owner.disposition.refuse();
                return Err(error);
            }
            Ok(PendingAppCurrentPeer { owner, sequence })
        }
    }

    pub(crate) fn wait(mut self) -> Result<QueuedAppCurrentPeer> {
        if !matches!(&self.owner, PeerPhaseOwner::Borrowed(_)) {
            self.owner.disposition.refuse();
            anyhow::bail!("storage_peer_owned_notification_requires_parent");
        }
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
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        self.owner.disposition.begin_notified(self.sequence)?;
        let (acquisition, local, sequence) =
            self.owner
                .start_phase(stage, NativeRole::AppHost, self.sequence, request.purpose())?;
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
            self.owner
                .origin
                .require_interval(&remote.original, &self.owner.last_remote_request)?;
            let mut peer = Peer::authenticate_request(
                &mut self.owner.peer,
                &ready,
                remote,
                process,
                stage,
                &mut acquisition,
            )?;
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
                stopped: None,
                fence: None,
                remote_request: peer.statement().original.clone(),
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
        &self.first_holder
    }

    pub(crate) fn initial_projection(&self) -> &PreparedFileProjection {
        &self.projection
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
        self.owner.prepare_current(stage, purpose)
    }
}

impl<'peer> ControllerCurrentRendezvous<'peer> {
    fn prepare(
        mut owner: PeerPhaseOwner<'peer>,
        stage: &mut EnrolledRoleStage<'_>,
        purpose: StoragePeerPurpose,
    ) -> Result<Self> {
        let (acquisition, local, sequence) =
            owner.start(stage, NativeRole::EpochController, purpose)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (acquisition, local, sequence);
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut acquisition = acquisition;
            let initial = owner.initial.clone();
            owner.channel.receive_idle(
                super::super::peer_idle::PeerChannel::Storage,
                &initial,
                sequence,
                &mut acquisition,
            )?;
            owner.check_resources(stage, &mut acquisition)?;
            let nonce = protocol::nonce("current-storage-peer-controller")?;
            let ready = stage
                .storage()?
                .sign_storage_message(Body::CurrentBeginReady {
                    controller: Box::new(local.clone()),
                    initial: owner.initial.clone(),
                    sequence,
                    nonce: nonce.clone(),
                })?;
            owner
                .channel
                .send_storage(&ready, stage, &mut acquisition)?;
            owner.check_resources(stage, &mut acquisition)?;
            Ok(ControllerCurrentRendezvous {
                owner,
                acquisition,
                local,
                sequence,
                nonce,
                purpose,
            })
        }
    }

    pub(crate) fn accept_current(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        expected: Option<&StoragePeerRequest>,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        let expected = expected.map_or(
            super::super::storage_peer_wire::CurrentExpectation::Serving,
            super::super::storage_peer_wire::CurrentExpectation::Exact,
        );
        self.accept_expected(stage, expected)
    }

    pub(crate) fn accept_admin_read(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        binding: &Digest,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        self.accept_expected(
            stage,
            super::super::storage_peer_wire::CurrentExpectation::AdminRead(binding),
        )
    }

    fn accept_expected(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        expected: super::super::storage_peer_wire::CurrentExpectation<'_>,
    ) -> Result<CurrentStoragePeerPhase<'peer>> {
        self.owner.disposition.check(self.sequence)?;
        stage.require_purpose(self.purpose.stage_purpose())?;
        ensure!(
            expected.purpose() == self.purpose,
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
            let (remote, nonce, request) = hello.current_hello_expected(
                &self.owner.initial,
                sequence,
                &self.nonce,
                &expected,
            )?;
            let (remote, nonce, request) = (remote.clone(), nonce.clone(), request.clone());
            ensure!(
                request.purpose() == self.purpose,
                "storage_peer_current_purpose_changed"
            );
            ensure!(
                self.owner.peer.statement().same_enrollment(&remote),
                "storage_peer_remote_enrollment_changed"
            );
            self.owner
                .origin
                .require_interval(&remote.original, &self.owner.last_remote_request)?;
            let mut peer = Peer::authenticate_request(
                &mut self.owner.peer,
                &hello,
                remote,
                process,
                stage,
                &mut acquisition,
            )?;
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
                stopped: None,
                fence: None,
                remote_request: peer.statement().original.clone(),
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
    ControllerStopAnnounced,
    AppStopObserved,
    AppStopAcknowledged,
    ControllerStopped,
    AppFenceObserved,
    ControllerFenceAnnounced,
    AppFenceAcknowledged,
    ControllerFenceConfirmed,
    AppStoppedTerminal,
    ControllerStoppedTerminal,
    Refused,
}

impl CurrentStoragePeerPhase<'_> {
    pub(in crate::security_epoch) fn freeze_restore_issuer(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        stop: &crate::security_epoch::kernel::restore::StopSelection,
    ) -> Result<super::super::FrozenRoleIssuer> {
        let requested = (|| {
            self.check(stage)?;
            ensure!(
                matches!(
                    self.exchange.request,
                    super::super::storage_peer_wire::StoragePeerRequest::AdminRead { .. }
                ) && self.completion == Completion::Waiting
                    && self.local.stage.data.role == NativeRole::EpochController,
                "native_restore_same_admin_peer_required"
            );
            self.exchange
                .request
                .admin_action_data()?
                .require_restore_operation_data(&stop.restore_operation)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = stop;
                anyhow::bail!("native_restore_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                // The statement comes ONLY from this actual authenticated,
                // retained App peer, not from an operator/caller projection.
                let app = self.peer.statement().clone();
                super::super::FrozenRoleIssuer::capture_restore(
                    &mut stage.storage()?,
                    &app,
                    self.exchange.request.binding(),
                    stop,
                )
            }
        })();
        let checked = self.check(stage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let frozen = requested?;
        checked?;
        Ok(frozen)
    }

    pub(in crate::security_epoch) fn announce_restore_stop(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        issuer: &mut super::super::FrozenRoleIssuer,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.completion == Completion::Waiting
                    && self.exchange.request.purpose() == StoragePeerPurpose::AdminRead,
                "native_restore_stop_peer_order"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = issuer;
                anyhow::bail!("native_restore_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let body = issuer.stop_message(&mut stage.storage()?, &self.exchange)?;
                let Body::CurrentStop {
                    frozen, signature, ..
                } = &body
                else {
                    anyhow::bail!("native_restore_stop_message_required");
                };
                let data = stop_data(&self.exchange, frozen, signature)?;
                let message = stage.storage()?.sign_storage_message(body)?;
                self.owner
                    .channel
                    .send_storage(&message, stage, &mut self.acquisition)?;
                self.check(stage)?;
                issuer.check(&mut stage.storage()?)?;
                self.stopped = Some(data);
                self.completion = Completion::ControllerStopAnnounced;
                Ok(())
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn await_admin_result(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<super::super::AdminPeerResult> {
        let result = (|| {
            ensure!(
                self.completion == Completion::Waiting
                    && self.local.stage.data.role == NativeRole::AppHost
                    && self.exchange.request.purpose() == StoragePeerPurpose::AdminRead,
                "native_restore_admin_peer_required"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let (message, process) = self
                    .owner
                    .channel
                    .receive_storage(stage, &mut self.acquisition)?;
                self.peer
                    .accept_message(&message, process, stage, &mut self.acquisition)?;
                self.check(stage)?;
                let digest = self.exchange.digest()?;
                match message.body {
                    Body::CurrentResult { exchange } if exchange == digest => {
                        self.completion = Completion::AppObserved;
                        Ok(super::super::AdminPeerResult::Known)
                    }
                    Body::CurrentStop {
                        exchange,
                        frozen,
                        signature,
                    } if exchange == digest => {
                        ensure!(
                            frozen.selection.app == self.local
                                && &frozen.selection.controller == self.peer.statement()
                                && frozen.policy == self.local.stage.data.policy
                                && frozen.issuer == self.local.certificate.digest()?
                                && frozen.cohort == frozen.selection.history_digest()?,
                            "native_restore_stop_actor_changed"
                        );
                        super::super::protocol::verify(
                            &self.local.certificate.data.public_key,
                            "restore-issuer-frozen",
                            &*frozen,
                            &signature,
                        )?;
                        let data = stop_data(&self.exchange, &frozen, &signature)?;
                        self.stopped = Some(data.clone());
                        self.completion = Completion::AppStopObserved;
                        Ok(super::super::AdminPeerResult::Stop(data))
                    }
                    _ => anyhow::bail!("native_restore_admin_result_changed"),
                }
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    // All stop packets use the existing SAME-original current transcript but
    // distinct signed bodies/states. Ordinary known/ACK/release cannot settle it.
    fn stop_packet(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
        expected: Completion,
        next: Completion,
        send: bool,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.completion == expected && self.stopped.as_ref() == Some(data),
                "native_restore_stop_changed_or_spent"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (next, send);
                anyhow::bail!("native_restore_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let exchange = self.exchange.digest()?;
                if send {
                    let body = if next == Completion::ControllerStoppedTerminal {
                        Body::CurrentStopReleased {
                            exchange,
                            stopped: data.stopped.clone(),
                        }
                    } else {
                        Body::CurrentStopped {
                            exchange,
                            stopped: data.stopped.clone(),
                        }
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
                    ensure!(
                        match message.body {
                            Body::CurrentStopped {
                                exchange: actual,
                                stopped,
                            } if next == Completion::ControllerStopped =>
                                actual == exchange && stopped == data.stopped,
                            Body::CurrentStopReleased {
                                exchange: actual,
                                stopped,
                            } if next == Completion::AppStoppedTerminal =>
                                actual == exchange && stopped == data.stopped,
                            _ => false,
                        },
                        "native_restore_stop_packet_changed"
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

    pub(in crate::security_epoch) fn acknowledge_restore_stop(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
    ) -> Result<()> {
        self.stop_packet(
            stage,
            data,
            Completion::AppStopObserved,
            Completion::AppStopAcknowledged,
            true,
        )
    }
    pub(in crate::security_epoch) fn await_restore_stopped(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<super::super::AuthorityStopData> {
        let data = self
            .stopped
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native_restore_stop_missing"))?;
        self.stop_packet(
            stage,
            &data,
            Completion::ControllerStopAnnounced,
            Completion::ControllerStopped,
            false,
        )?;
        Ok(data)
    }
    /// A distinct message AFTER the Controller's actual known reservation.
    /// This projection never supplies the native known-send owner itself.
    pub(in crate::security_epoch) fn announce_restore_fence(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
        confirmation: &crate::security_epoch::firestore::ReservationConfirmation,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.completion == Completion::ControllerStopped
                    && self.stopped.as_ref() == Some(data)
                    && self.fence.is_none()
                    && self.local.stage.data.role == NativeRole::EpochController,
                "native_restore_fence_peer_order"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = confirmation;
                anyhow::bail!("native_restore_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let message = stage.storage()?.sign_storage_message(Body::CurrentFence {
                    exchange: self.exchange.digest()?,
                    stopped: data.stopped.clone(),
                    confirmation: Box::new(confirmation.clone()),
                })?;
                self.owner
                    .channel
                    .send_storage(&message, stage, &mut self.acquisition)?;
                self.check(stage)?;
                self.fence = Some(confirmation.clone());
                self.completion = Completion::ControllerFenceAnnounced;
                Ok(())
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// The App remains drained and owns the same exclusion while it waits.
    pub(in crate::security_epoch) fn await_restore_fence(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
    ) -> Result<crate::security_epoch::firestore::ReservationConfirmation> {
        let result = (|| {
            ensure!(
                self.completion == Completion::AppStopAcknowledged
                    && self.stopped.as_ref() == Some(data)
                    && self.fence.is_none()
                    && self.local.stage.data.role == NativeRole::AppHost,
                "native_restore_fence_peer_order"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let (message, process) = self
                    .owner
                    .channel
                    .receive_storage(stage, &mut self.acquisition)?;
                self.peer
                    .accept_message(&message, process, stage, &mut self.acquisition)?;
                self.check(stage)?;
                let Body::CurrentFence {
                    exchange,
                    stopped,
                    confirmation,
                } = message.body
                else {
                    anyhow::bail!("native_restore_fence_message_required");
                };
                ensure!(
                    exchange == self.exchange.digest()? && stopped == data.stopped,
                    "native_restore_fence_peer_changed"
                );
                self.fence = Some((*confirmation).clone());
                self.completion = Completion::AppFenceObserved;
                Ok(*confirmation)
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Only the fixed App caller, after its independent complete fresh read
    /// and cohort check, reaches this distinct acknowledgement operation.
    pub(in crate::security_epoch) fn acknowledge_restore_fence(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
        confirmation: &crate::security_epoch::firestore::ReservationConfirmation,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.completion == Completion::AppFenceObserved
                    && self.stopped.as_ref() == Some(data)
                    && self.fence.as_ref() == Some(confirmation)
                    && self.local.stage.data.role == NativeRole::AppHost,
                "native_restore_fence_ack_order"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let message =
                    stage
                        .storage()?
                        .sign_storage_message(Body::CurrentFenceConfirmed {
                            exchange: self.exchange.digest()?,
                            stopped: data.stopped.clone(),
                            confirmation: confirmation.digest_data()?,
                        })?;
                self.owner
                    .channel
                    .send_storage(&message, stage, &mut self.acquisition)?;
                self.check(stage)?;
                self.completion = Completion::AppFenceAcknowledged;
                Ok(())
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn await_restore_fence_confirmed(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
        confirmation: &crate::security_epoch::firestore::ReservationConfirmation,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.completion == Completion::ControllerFenceAnnounced
                    && self.stopped.as_ref() == Some(data)
                    && self.fence.as_ref() == Some(confirmation)
                    && self.local.stage.data.role == NativeRole::EpochController,
                "native_restore_fence_ack_order"
            );
            self.completion = Completion::Refused;
            self.check(stage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let (message, process) = self
                    .owner
                    .channel
                    .receive_storage(stage, &mut self.acquisition)?;
                self.peer
                    .accept_message(&message, process, stage, &mut self.acquisition)?;
                self.check(stage)?;
                ensure!(
                    matches!(message.body, Body::CurrentFenceConfirmed { exchange, stopped, confirmation: actual }
                    if exchange == self.exchange.digest()? && stopped == data.stopped && actual == confirmation.digest_data()?),
                    "native_restore_fence_ack_changed"
                );
                self.completion = Completion::ControllerFenceConfirmed;
                Ok(())
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn require_restore_stopped(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                self.completion == Completion::ControllerFenceConfirmed
                    && self.stopped.as_ref() == Some(data)
                    && self.fence.is_some(),
                "native_restore_stop_not_retained"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
    pub(in crate::security_epoch) fn release_restore_stop(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
    ) -> Result<()> {
        self.stop_packet(
            stage,
            data,
            Completion::ControllerFenceConfirmed,
            Completion::ControllerStoppedTerminal,
            true,
        )
    }
    pub(in crate::security_epoch) fn await_restore_release(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        data: &super::super::AuthorityStopData,
    ) -> Result<()> {
        self.stop_packet(
            stage,
            data,
            Completion::AppFenceAcknowledged,
            Completion::AppStoppedTerminal,
            false,
        )
    }
    pub(in crate::security_epoch) fn finish_restore_stopped(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        ensure!(
            matches!(
                self.completion,
                Completion::AppStoppedTerminal | Completion::ControllerStoppedTerminal
            ),
            "native_restore_stop_not_terminal"
        );
        // Closing old authority never makes this old first-holder reusable.
        self.owner.disposition.refuse();
        Ok(())
    }

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
            stage.require_purpose(self.exchange.request.purpose().stage_purpose())?;
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
        if !matches!(&self.owner, PeerPhaseOwner::Borrowed(_)) {
            self.refuse();
            anyhow::bail!("storage_peer_owned_completion_requires_parent_return");
        }
        self.finish_owner(stage).map(|_| ())
    }

    /// Terminal refusal has no live clock, stage check, network or replacement.
    pub(crate) fn refuse(&mut self) {
        self.completion = Completion::Refused;
        self.owner.disposition.refuse();
        self.acquisition.refuse();
    }
}

impl<'peer> CurrentStoragePeerPhase<'peer> {
    fn finish_owner(mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<PeerPhaseOwner<'peer>> {
        self.check(stage)?;
        ensure!(
            matches!(
                (self.local.stage.data.role, self.completion),
                (NativeRole::AppHost, Completion::AppReleased)
                    | (NativeRole::EpochController, Completion::ControllerReleased)
            ),
            "storage_peer_completion_not_consumed"
        );
        self.owner.last_local_request = self.local.original.clone();
        self.owner.last_remote_request = self.remote_request.clone();
        self.owner.disposition.complete(self.exchange.sequence)?;
        if self.owner.origin == ConnectionOrigin::RestoredFirst {
            self.owner.origin = ConnectionOrigin::RestoredCurrent;
        }
        #[cfg(target_os = "linux")]
        if let PeerPhaseOwner::Restored(owner) = &mut self.owner {
            owner.original = None;
        }
        Ok(self.owner)
    }

    /// Identity/channel return only, after real completion. Its enclosing
    /// restore parent must run all S3 file/counter/original posts before it
    /// restores its private slot. No external parts or permission are returned.
    pub(in crate::security_epoch) fn finish_restored(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<RestoredPeerConnection<'peer>> {
        if !matches!(&self.owner, PeerPhaseOwner::Restored(_)) {
            self.refuse();
            anyhow::bail!("storage_peer_restored_owner_required");
        }
        match self.finish_owner(stage)? {
            PeerPhaseOwner::Restored(owner) => Ok(*owner),
            PeerPhaseOwner::Borrowed(_) => unreachable!("checked restored owner"),
        }
    }
}

#[cfg(target_os = "linux")]
fn stop_data(
    exchange: &super::super::storage_peer_wire::CurrentExchange,
    frozen: &super::super::protocol::FrozenIssuance,
    signature: &str,
) -> Result<super::super::AuthorityStopData> {
    ensure!(
        frozen.selection.admin_binding == *exchange.request.binding()
            && frozen.selection.app.digest()? == exchange.app_stage
            && frozen.selection.controller.digest()? == exchange.controller_stage,
        "native_restore_stop_exchange_changed"
    );
    Ok(super::super::AuthorityStopData {
        admin_binding: frozen.selection.admin_binding.clone(),
        selection: frozen.selection.stop.clone(),
        stopped: Digest::of(&(
            "day2-native-stopped-peer-v1",
            exchange.digest()?,
            frozen,
            signature,
        ))?,
    })
}

#[cfg(test)]
mod restored_origin_tests {
    use super::{ConnectionOrigin, StoragePeerPurpose};
    use crate::security_epoch::native_enrollment::{
        protocol::StagePurpose, storage_peer_wire::OriginalInterval,
    };
    use day2_capabilities::Digest;

    #[test]
    fn restored_connections_admit_only_current_purposes_and_a_strictly_new_first_original() {
        let old = OriginalInterval {
            purpose: StagePurpose::CurrentRole,
            domain: Digest::of(&"old").unwrap(),
            origin_ns: 100,
            deadline_ns: 105,
        };
        let fresh = OriginalInterval {
            domain: Digest::of(&"fresh").unwrap(),
            origin_ns: 900,
            deadline_ns: 905,
            ..old.clone()
        };
        for origin in [
            ConnectionOrigin::Initial,
            ConnectionOrigin::RestoredFirst,
            ConnectionOrigin::RestoredCurrent,
        ] {
            for purpose in [
                StoragePeerPurpose::AdminRead,
                StoragePeerPurpose::CurrentServing,
                StoragePeerPurpose::BootstrapCreate,
                StoragePeerPurpose::BootstrapComplete,
            ] {
                let expected = origin == ConnectionOrigin::Initial
                    || matches!(
                        purpose,
                        StoragePeerPurpose::AdminRead | StoragePeerPurpose::CurrentServing
                    );
                assert_eq!(origin.require_purpose(purpose).is_ok(), expected);
            }
            assert!(origin.require_interval(&fresh, &old).is_ok());
            assert_eq!(
                origin.require_interval(&old, &old).is_ok(),
                origin != ConnectionOrigin::RestoredFirst
            );
        }
        for bad in [
            old.clone(),
            OriginalInterval {
                origin_ns: 100,
                ..fresh.clone()
            },
            OriginalInterval {
                origin_ns: 99,
                ..fresh.clone()
            },
            OriginalInterval {
                domain: old.domain.clone(),
                ..fresh.clone()
            },
        ] {
            assert!(
                ConnectionOrigin::RestoredFirst
                    .require_interval(&bad, &old)
                    .is_err()
            );
        }
        let narrowed = OriginalInterval {
            deadline_ns: 904,
            ..fresh.clone()
        };
        assert!(
            ConnectionOrigin::RestoredCurrent
                .require_interval(&narrowed, &fresh)
                .is_ok()
        );
        let expanded = OriginalInterval {
            deadline_ns: 906,
            ..fresh.clone()
        };
        assert!(
            ConnectionOrigin::RestoredCurrent
                .require_interval(&expanded, &fresh)
                .is_err()
        );
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

#[cfg(test)]
mod restored_transfer_source_tests {
    use quote::ToTokens;

    fn method(source: &str, owner: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(source).unwrap();
        let found=file.items.iter().filter_map(|item|match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(),syn::Type::Path(path) if path.path.segments.last().is_some_and(|p|p.ident==owner))=>Some(item),
            _=>None,
        }).flat_map(|item|item.items.iter()).filter_map(|item|match item {
            syn::ImplItem::Fn(item) if item.sig.ident==name=>Some(item.clone()),_=>None,
        }).collect::<Vec<_>>();
        assert_eq!(found.len(), 1);
        found.into_iter().next().unwrap()
    }

    fn normalized(item: &syn::ImplItemFn) -> String {
        item.to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    fn ordered(text: &str, parts: &[&str]) -> bool {
        let mut tail = text;
        for part in parts {
            let Some((_, after)) = tail.split_once(part) else {
                return false;
            };
            tail = after;
        }
        true
    }

    fn private_input(item: &syn::ImplItemFn) -> bool {
        matches!(item.vis, syn::Visibility::Inherited)
            && normalized(item).contains("input:RestoredCurrentPeerPort<'tail>")
    }

    fn app_factory(text: &str) -> bool {
        ordered(
            text,
            &[
                "history.take_current_peer(stage)?",
                "RestoredPeerConnection::from_port(port,stage)",
            ],
        )
    }

    fn leaf_source(text: &str) -> bool {
        text.contains("original.exchange_current_views(acquisition)?")
            && ordered(
                text,
                &[
                    "self.owner.check_resources(stage,acquisition)?",
                    "self.owner.channel.check_restored_source(",
                    "self.tail.check_current(",
                    "letchecked=stage.check()",
                    "requested?",
                    "tail?",
                    "checked",
                ],
            )
    }

    fn source_fields(item: &syn::ImplItemFn) -> Option<&syn::ExprStruct> {
        item.block.stmts.iter().find_map(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let syn::Pat::Ident(name) = &local.pat else {
                return None;
            };
            if name.ident != "source" {
                return None;
            }
            let syn::Expr::Struct(value) = local.init.as_ref()?.expr.as_ref() else {
                return None;
            };
            Some(value)
        })
    }

    fn source_shape(value: &syn::ExprStruct) -> bool {
        if !value.path.is_ident("RestoredPeerSource") || value.rest.is_some() {
            return false;
        }
        let actual = value
            .fields
            .iter()
            .map(|field| {
                let name = field.member.to_token_stream().to_string();
                let expression = field
                    .expr
                    .to_token_stream()
                    .to_string()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>();
                (name, expression)
            })
            .collect::<Vec<_>>();
        let expected = [
            ("socket", "&self.socket"),
            ("refusal", "&self.refused"),
            ("local", "local"),
            ("remote", "remote"),
            ("binding", "binding"),
        ]
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .to_vec();
        actual == expected
    }

    fn controller_source(text: &str) -> bool {
        [
            "Rc::ptr_eq(retained,source.socket)",
            "Rc::ptr_eq(&state.refused,source.refusal)",
            "state.socket.is_none()",
            "self.transcript.is_none()",
            "Some(source.local)==state.controller.as_ref()",
            "app.as_ref()==source.remote",
        ]
        .iter()
        .all(|part| text.matches(part).count() == 1)
    }

    #[test]
    fn transient_transfer_drop_keeps_all_actual_negative_roots_without_positive_work() {
        let actual = method(
            include_str!("../../native_enrollment.rs"),
            "RestoredCurrentPeerPort",
            "drop",
        );
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed {
                #[cfg(target_os = "linux")]
                {
                    self.channel_refusal.set(true);
                    if let Some(original) = &self.native_refusal {
                        original.refuse();
                    }
                }
                if let Some(tail) = &mut self.tail {
                    tail.refuse();
                }
            }
        });
        let guarded = |item: &syn::ImplItemFn| {
            item.block.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual));
        let mut missing = actual.clone();
        missing.block.stmts.clear();
        assert!(!guarded(&missing));
        let mut disarmed = actual.clone();
        let syn::Stmt::Expr(syn::Expr::If(condition), _) = &mut disarmed.block.stmts[0] else {
            panic!("actual drop condition");
        };
        *condition.cond = syn::parse_quote!(false);
        assert!(!guarded(&disarmed));
        for removed in 0..2 {
            let mut changed = actual.clone();
            let syn::Stmt::Expr(syn::Expr::If(condition), _) = &mut changed.block.stmts[0] else {
                unreachable!();
            };
            let syn::Stmt::Expr(syn::Expr::Block(linux), _) = &mut condition.then_branch.stmts[0]
            else {
                unreachable!();
            };
            linux.block.stmts.remove(removed);
            assert!(!guarded(&changed));
        }
    }

    #[test]
    fn accepting_factories_are_leaf_private_for_parts_and_join_actual_historical_owners() {
        let source = include_str!("continuation.rs");
        let input = method(source, "RestoredPeerConnection", "from_port");
        assert!(private_input(&input));
        let mut public = input.clone();
        public.vis = syn::parse_quote!(pub(in crate::security_epoch::native_enrollment));
        assert!(!private_input(&public));
        let app = normalized(&method(
            source,
            "RestoredPeerConnection",
            "from_app_history",
        ));
        assert!(app_factory(&app));
        let controller = normalized(&method(
            source,
            "RestoredPeerConnection",
            "prepare_controller",
        ));
        assert!(ordered(
            &controller,
            &[
                "peer.take_current_peer(installed,stage)?",
                "Self::from_port(port,stage)?",
                "prepare_current(stage,purpose)"
            ]
        ));
        assert!(!app_factory(&app.replace(
            "history.take_current_peer(stage)?",
            "foreign_port()?"
        )));
        let leaf = method(source, "RestoredPeerConnection", "check_resources");
        // Parse the actual native source; a portable fake owner is not evidence
        // for this Linux resource boundary.
        let text = normalized(&leaf);
        assert!(leaf_source(&text));
        let target = "self.owner.channel.check_restored_source(";
        assert_eq!(text.matches(target).count(), 1);
        let missing = text.replacen(target, "bypassed_source(", 1);
        assert!(!leaf_source(&missing));
    }

    #[test]
    fn actual_socket_provenance_and_one_shot_controller_takes_are_bound_to_the_negative_loan() {
        let source = include_str!("../owner/restore_receiver.rs");
        let transfer = normalized(&method(source, "RestoredWriterPeer", "take_current_peer"));
        assert!(ordered(
            &transfer,
            &[
                "RestoredControllerPortTransfer{",
                "current_transfer_binding(peer,attempt.stage,&mutoriginal)?",
                "current_socket.is_none()",
                "socket.take()",
                "current_socket=Some(Rc::clone(&socket))",
                "transcript.take()",
                "attempt.peer.take()",
                "letchecked=attempt.stage.check()",
                "checked?",
                "attempt.done=true"
            ]
        ));
        assert!(transfer.contains("Rc::clone(&peer.receiver.receiver.refused)"));
        let check = normalized(&method(
            source,
            "InstalledRestoredAppConfirmation",
            "check_current_source",
        ));
        assert!(controller_source(&check));
        for exact in [
            "Rc::ptr_eq(retained,source.socket)",
            "Rc::ptr_eq(&state.refused,source.refusal)",
            "state.socket.is_none()",
            "self.transcript.is_none()",
            "Some(source.local)==state.controller.as_ref()",
            "app.as_ref()==source.remote",
        ] {
            assert!(check.contains(exact), "missing actual source join: {exact}");
            assert_eq!(check.matches(exact).count(), 1);
            assert!(!controller_source(&check.replacen(exact, "unrelated()", 1)));
        }
        let channel_method = method(
            include_str!("../channel.rs"),
            "Channel",
            "check_restored_source",
        );
        let actual = source_fields(&channel_method).unwrap();
        assert!(source_shape(actual));
        for omitted in 0..actual.fields.len() {
            let mut changed = actual.clone();
            changed.fields = changed
                .fields
                .into_iter()
                .enumerate()
                .filter_map(|(index, field)| (index != omitted).then_some(field))
                .collect();
            assert!(!source_shape(&changed));
        }
        let mut foreign = actual.clone();
        foreign.fields[0].expr = syn::parse_quote!(&unrelated.socket);
        assert!(!source_shape(&foreign));
        let channel = normalized(&channel_method);
        assert!(ordered(
            &channel,
            &[
                "tail.check_source(&source)",
                "self.check_storage_open(stage,acquisition)",
                "requested?",
                "checked"
            ]
        ));
    }
}
