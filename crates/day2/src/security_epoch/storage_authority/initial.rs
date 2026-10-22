//! Own the SAME joined durable initial file and authenticated App peer. This
//! is conditional PD/ext4 durability, not effective IAM or active writer proof.

use super::preparation::PendingPhysicalFilePhase;
use super::{
    AppFileContinuity, CurrentPhysicalFilePhase, CurrentPreparedFilePhase, PreparedFileContinuity,
};
use crate::security_epoch::{
    authenticated_reads::{AuthenticatedReads, ControllerEpochReads},
    controller::{
        bootstrap_timing::BootstrapTiming,
        evidence::{PreparationFailure, PreparationStep},
        preparation_timing::{Operation, Timings},
    },
    kernel::{Bootstrap, Holder, Request},
    native_enrollment::{
        AppHolderPeerContinuity, AuthenticatedAppFirstHolder, ControllerHolderPeerContinuity,
        CurrentStoragePeerPhase, EnrolledRoleStage, InitialHolderListener, QueuedAppCurrentPeer,
        StoragePeerPurpose, StoragePeerRequest,
    },
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{InitialBootstrapPolicy, NativeRole},
    },
};

/// Failure retains the actual file/volume owners, including an uncertain
/// exchange or synchronization. There is no retry/adoption conversion.
pub(crate) enum InitialStorageOutcome {
    Established(Box<InitialStorageContinuity>),
    Refused {
        file: Box<PreparedFileContinuity>,
        error: anyhow::Error,
    },
}

pub(crate) struct InitialStorageContinuity {
    file: PreparedFileContinuity,
    peer: ControllerHolderPeerContinuity,
    ready: bool,
}

/// The actual initial App file and same connected peer stay together. This is
/// the unprivileged participant, not a Controller, provider or counter writer.
pub(crate) struct AppInitialStorageContinuity {
    file: AppFileContinuity,
    peer: AppHolderPeerContinuity,
    ready: AppContinuation,
}

enum AppContinuation {
    Ready,
    Queued(QueuedAppCurrentPeer),
    Busy,
    Refused,
}

#[cfg(test)]
mod app_continuation_tests {
    use super::AppContinuation;

    #[test]
    fn absent_queue_and_unknown_completion_cannot_restore_file_continuity() {
        let mut state = AppContinuation::Ready;
        assert!(state.complete().is_err());
        assert!(state.begin().is_err());
        assert!(matches!(state, AppContinuation::Refused));
        assert!(!state.data_available());
        assert!(state.begin().is_err());
        assert!(state.complete().is_err());
        let mut busy = AppContinuation::Busy;
        assert!(!busy.data_available());
        busy.complete().unwrap();
        assert!(busy.data_available());
        assert!(busy.begin().is_err());
        assert!(!busy.data_available());
    }
}

impl AppContinuation {
    fn begin(&mut self) -> Result<QueuedAppCurrentPeer> {
        let Self::Queued(queued) = std::mem::replace(self, Self::Refused) else {
            anyhow::bail!("app_storage_notification_missing_or_spent");
        };
        *self = Self::Busy;
        Ok(queued)
    }

    fn check(&self) -> Result<()> {
        ensure!(
            matches!(self, Self::Busy),
            "app_storage_current_phase_refused"
        );
        Ok(())
    }

    fn complete(&mut self) -> Result<()> {
        self.check()?;
        *self = Self::Ready;
        Ok(())
    }

    fn data_available(&self) -> bool {
        matches!(self, Self::Ready | Self::Queued(_))
    }
}

pub(crate) struct CurrentAppStorageBootstrapPhase<'storage> {
    file: &'storage mut AppFileContinuity,
    peer: CurrentStoragePeerPhase<'storage>,
    continuation: &'storage mut AppContinuation,
}

/// The actual fresh role is owned by the physical phase. The peer retains its
/// own actual narrowed acquisition and received sender handles on the same
/// channel. Dropping either cannot rearm the enclosing continuation.
pub(crate) struct CurrentStorageBootstrapPhase<'storage, 'role> {
    file: CurrentPreparedFilePhase<'storage, 'role>,
    peer: CurrentStoragePeerPhase<'storage>,
    continuation: &'storage mut bool,
    request: Request,
}

/// Physical inputs only. Active admission additionally requires the genuine
/// active owner, exact current provider observation and purpose-bound scope.
pub(crate) struct CurrentAppStoragePhase<'storage> {
    file: &'storage mut AppFileContinuity,
    peer: CurrentStoragePeerPhase<'storage>,
    continuation: &'storage mut AppContinuation,
}

pub(crate) struct CurrentControllerStoragePhase<'storage, 'role> {
    file: CurrentPhysicalFilePhase<'storage, 'role>,
    peer: PeerFence<'storage>,
    continuation: &'storage mut bool,
}

/// Closed original file/parent continuity before Shell readiness I/O. No
/// native role or provider permission is constructed until acquire consumes it.
pub(in crate::security_epoch) struct PendingControllerStoragePhase<'storage> {
    file: PendingPhysicalFilePhase<'storage>,
    peer: &'storage mut ControllerHolderPeerContinuity,
    continuation: &'storage mut bool,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(PendingControllerStoragePhase<'static>, Clone);
    assert_not_impl!(PendingControllerStoragePhase<'static>, Copy);
    assert_not_impl!(PendingControllerStoragePhase<'static>, Default);
    assert_not_impl!(PendingControllerStoragePhase<'static>, Send);
    assert_not_impl!(PendingControllerStoragePhase<'static>, Sync);
    assert_not_impl!(PendingControllerStoragePhase<'static>, serde::Serialize);
    assert_not_impl!(
        PendingControllerStoragePhase<'static>,
        serde::Deserialize<'static>
    );
};

enum PeerFence<'storage> {
    Current(Box<CurrentStoragePeerPhase<'storage>>),
    Retained(&'storage mut ControllerHolderPeerContinuity),
}

impl InitialStorageContinuity {
    /// This fixed native operation performs the real first-holder exchange,
    /// selected PD/ext4 checks, file+directory synchronization and readback.
    /// No caller assertion, descriptor, projection or completed receipt enters
    /// as a substitute. A filesystem fixture cannot supply the required phase.
    pub(in crate::security_epoch) fn establish(
        mut file: PreparedFileContinuity,
        listener: InitialHolderListener,
        mut stage: EnrolledRoleStage<'_>,
        timings: &Timings,
    ) -> InitialStorageOutcome {
        let result = (|| {
            let pending = file.begin_pending_initial_phase()?;
            // The file is already closed to any other phase. Readiness opens
            // no file and grants no P3; the SAME actual stage remains live.
            let rendezvous = timings
                .measure(Operation::FirstReady, || listener.prepare(&mut stage))
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstReady, error))?;
            let phase = timings
                .measure(Operation::FirstFile, || pending.acquire_first_holder(stage))
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstFile, error))?;
            timings.measure(Operation::FirstExchange, || {
                let server = rendezvous
                    .start(phase)
                    .map_err(|error| PreparationFailure::at(PreparationStep::FirstStart, error))?;
                let mut holder = server.exchange().map_err(|error| {
                    PreparationFailure::at(PreparationStep::FirstExchange, error)
                })?;
                holder.check_initial_durability().map_err(|error| {
                    PreparationFailure::at(PreparationStep::FirstDurability, error)
                })?;
                holder
                    .retain_for_activation()
                    .map_err(|error| PreparationFailure::at(PreparationStep::FirstRetain, error))
            })
        })();
        match result {
            Ok(peer) => InitialStorageOutcome::Established(Box::new(Self {
                file,
                peer,
                ready: true,
            })),
            Err(error) => InitialStorageOutcome::Refused {
                file: Box::new(file),
                error,
            },
        }
    }

    /// Each bootstrap operation needs a NEW actual Controller stage and fresh
    /// peer handshake. The historical durability completion never renews a
    /// grant. Request DATA must match the original seed and actual first App.
    pub(in crate::security_epoch) fn begin_bootstrap<'storage, 'role>(
        &'storage mut self,
        mut stage: EnrolledRoleStage<'role>,
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        request: &Request,
        trace: &BootstrapTiming,
    ) -> Result<(
        CurrentStorageBootstrapPhase<'storage, 'role>,
        ControllerEpochReads,
    )> {
        ensure!(self.ready, "initial_storage_continuation_refused");
        self.ready = false;
        let expected = self.peer.initial_projection().clone();
        let binding = request_binding(
            &expected.initial_core().bootstrap()?,
            self.peer.first_holder(),
            selection,
            request,
        )?;
        let pending = self.file.begin_pending_initial_phase()?;
        let rendezvous = trace
            .measure(Operation::BootstrapReady, || {
                self.peer.prepare_current(&mut stage)
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapReady, error))?;
        // Read-only authentication overlaps the App's fresh role acquisition
        // after the real Ready message. It retains THIS already-spent original
        // stage; neither these reads nor their material can dispatch a write.
        // The fixed writer is installed only after the file and peer join below.
        let (reads, provider) = trace.measure(Operation::BootstrapAuthentication, || {
            let retained = AuthenticatedReads::acquire(
                policy,
                selection,
                NativeRole::EpochController,
                &mut stage,
            )
            .and_then(AuthenticatedReads::retain_current)
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapTransport, error))?;
            retained
                .into_controller(&mut stage, policy, selection, trace.timings())
                .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapTransport, error))
        })?;
        let mut file = trace
            .measure(Operation::BootstrapFile, || {
                pending.acquire_authenticated(stage, provider, trace)
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapFile, error))?;
        ensure!(
            trace.measure(Operation::BootstrapProjection, || file.projection())? == expected,
            "initial_storage_file_projection_changed"
        );
        // The historical establishment is not a current configuration lease.
        // Rejoin/check and synchronize under THIS already-spent fresh stage,
        // before the new peer transcript can advertise a bootstrap phase.
        trace
            .measure(Operation::BootstrapDurability, || {
                file.check_initial_durability()
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapDurability, error))?;
        let peer = trace
            .measure(Operation::BootstrapPeer, || {
                rendezvous.accept_current(file.controller_stage()?, Some(&binding))
            })
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapPeer, error))?;
        let mut phase = CurrentStorageBootstrapPhase {
            file,
            peer,
            continuation: &mut self.ready,
            request: request.clone(),
        };
        trace
            .measure(Operation::BootstrapPeerCheck, || phase.check())
            .map_err(|error| PreparationFailure::at(PreparationStep::BootstrapPeerCheck, error))?;
        Ok((phase, reads))
    }

    pub(in crate::security_epoch) fn app_pending(&mut self) -> Result<bool> {
        ensure!(self.ready, "controller_storage_continuation_refused");
        self.peer.pending()
    }

    pub(in crate::security_epoch) fn begin_current_app<'storage, 'role>(
        &'storage mut self,
        mut stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentControllerStoragePhase<'storage, 'role>> {
        ensure!(self.ready, "controller_storage_continuation_refused");
        self.ready = false;
        let pending = self.file.begin_pending_physical_phase()?;
        let rendezvous = self.peer.prepare_current(&mut stage)?;
        let mut file = pending.acquire(stage)?;
        file.check_current_durability()?;
        let peer = rendezvous.accept_current(file.controller_stage()?, None)?;
        let mut phase = CurrentControllerStoragePhase {
            file,
            peer: PeerFence::Current(Box::new(peer)),
            continuation: &mut self.ready,
        };
        phase.check()?;
        Ok(phase)
    }

    /// Historical first-App identity is not a fresh App role/file permission.
    /// Shell gets its OWN role/channel and only a current Controller fence.
    pub(in crate::security_epoch) fn begin_pending_current_controller(
        &mut self,
    ) -> Result<PendingControllerStoragePhase<'_>> {
        ensure!(self.ready, "controller_storage_continuation_refused");
        self.ready = false;
        let file = self.file.begin_pending_physical_phase()?;
        Ok(PendingControllerStoragePhase {
            file,
            peer: &mut self.peer,
            continuation: &mut self.ready,
        })
    }

    pub(in crate::security_epoch) fn bootstrap_core(
        &self,
    ) -> Result<crate::security_epoch::seed_core::OriginalSeedCore> {
        ensure!(self.ready, "initial_storage_continuation_refused");
        Ok(self.peer.initial_projection().initial_core().clone())
    }

    pub(in crate::security_epoch) fn first_holder_data(&self) -> Result<Holder> {
        ensure!(self.ready, "initial_storage_continuation_refused");
        Ok(self.peer.first_holder().clone())
    }

    pub(crate) fn refuse(&mut self) {
        self.ready = false;
        self.peer.refuse();
    }
}

impl<'storage> PendingControllerStoragePhase<'storage> {
    pub(in crate::security_epoch) fn acquire<'role>(
        self,
        stage: EnrolledRoleStage<'role>,
    ) -> Result<CurrentControllerStoragePhase<'storage, 'role>> {
        ensure!(!*self.continuation, "controller_storage_phase_released");
        let mut file = self.file.acquire(stage)?;
        file.check_current_durability()?;
        self.peer
            .check_retained_identity(file.controller_stage()?)?;
        let mut phase = CurrentControllerStoragePhase {
            file,
            peer: PeerFence::Retained(self.peer),
            continuation: self.continuation,
        };
        phase.check()?;
        Ok(phase)
    }
}

/// Request-selection DATA only. This cannot construct the native file, peer,
/// phase, durability owner or an epoch dispatch context.
fn request_binding(
    expected: &Bootstrap,
    first: &Holder,
    selection: &EpochStore,
    request: &Request,
) -> Result<StoragePeerRequest> {
    request.validate(selection)?;
    ensure!(
        *request.bootstrap() == *expected,
        "initial_storage_request_seed_changed"
    );
    let purpose = match request {
        Request::CreateInitialAuthority { .. } => StoragePeerPurpose::BootstrapCreate,
        Request::CompleteInitialFirstActivation { holder, .. } => {
            ensure!(holder == first, "initial_storage_first_holder_changed");
            StoragePeerPurpose::BootstrapComplete
        }
    };
    Ok(StoragePeerRequest {
        purpose,
        binding: request.digest()?,
    })
}

impl<'role> CurrentStorageBootstrapPhase<'_, 'role> {
    pub(in crate::security_epoch) fn check_authenticated_reads(
        &mut self,
        reads: &ControllerEpochReads,
    ) -> Result<()> {
        self.check()?;
        self.file.check_authenticated_reads(reads)
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(
                !*self.continuation,
                "initial_storage_phase_already_released"
            );
            self.file.check()?;
            ensure!(
                self.peer.request().binding == self.request.digest()?,
                "initial_storage_peer_request_changed"
            );
            self.peer.check(self.file.controller_stage()?)?;
            self.file.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn controller_stage(
        &mut self,
    ) -> Result<&mut EnrolledRoleStage<'role>> {
        self.check()?;
        self.file.controller_stage()
    }

    pub(in crate::security_epoch) fn request_digest(&self) -> Result<Digest> {
        self.request.digest()
    }

    /// This releases only the storage scope, after a known operation and ALL
    /// composite postchecks. It grants no epoch/write/serving permission. The
    /// enclosing ready gate stays false if either final owner check fails,
    /// including after the peer has recorded its own known completion.
    pub(in crate::security_epoch) fn announce_known(&mut self) -> Result<()> {
        self.check()?;
        self.peer.announce_known(self.file.controller_stage()?)?;
        self.check()
    }

    pub(in crate::security_epoch) fn finish_checked(mut self) -> Result<()> {
        self.check()?;
        self.peer
            .await_acknowledgement(self.file.controller_stage()?)?;
        self.check()?;
        self.peer.release_known(self.file.controller_stage()?)?;
        self.peer.finish_checked(self.file.controller_stage()?)?;
        self.file.finish_checked()?;
        *self.continuation = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn finish_activated(mut self) -> Result<()> {
        self.check()?;
        self.peer
            .await_acknowledgement(self.file.controller_stage()?)?;
        self.check()?;
        // The App remains blocked on release until this last initial-byte
        // check. Once released, only physical identity is required here.
        let mut physical = self.file.into_physical_checked()?;
        self.peer.release_known(physical.controller_stage()?)?;
        self.peer.finish_checked(physical.controller_stage()?)?;
        physical.finish_checked()?;
        *self.continuation = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        *self.continuation = false;
        self.file.refuse();
        self.peer.refuse();
    }
}

impl AppInitialStorageContinuity {
    /// Complete only a fixed wakeup and readiness wait before the caller
    /// acquires its fresh role. This never opens the file or grants permission.
    pub(in crate::security_epoch) fn prepare_current(&mut self) -> Result<()> {
        ensure!(
            matches!(self.ready, AppContinuation::Ready),
            "app_storage_continuation_refused"
        );
        self.ready = AppContinuation::Refused;
        let queued = self.peer.notify_current()?.wait()?;
        self.ready = AppContinuation::Queued(queued);
        Ok(())
    }

    pub(in crate::security_epoch) fn begin_current<'storage>(
        &'storage mut self,
        stage: &mut EnrolledRoleStage<'_>,
        request: StoragePeerRequest,
    ) -> Result<CurrentAppStoragePhase<'storage>> {
        let queued = self.ready.begin()?;
        ensure!(
            request.purpose == StoragePeerPurpose::CurrentServing,
            "app_storage_serving_purpose_required"
        );
        self.file.check_current(stage)?;
        let peer = self.peer.begin_current(queued, stage, request)?;
        let mut phase = CurrentAppStoragePhase {
            file: &mut self.file,
            peer,
            continuation: &mut self.ready,
        };
        phase.check(stage)?;
        Ok(phase)
    }

    pub(in crate::security_epoch) fn bootstrap_core(
        &self,
    ) -> Result<crate::security_epoch::seed_core::OriginalSeedCore> {
        ensure!(
            self.ready.data_available(),
            "app_initial_storage_continuation_refused"
        );
        Ok(self.peer.initial_projection().initial_core().clone())
    }

    pub(in crate::security_epoch) fn first_holder_data(&self) -> Result<Holder> {
        ensure!(
            self.ready.data_available(),
            "app_initial_storage_continuation_refused"
        );
        Ok(self.peer.first_holder().clone())
    }

    pub(crate) fn retain(holder: AuthenticatedAppFirstHolder<'_, '_>) -> Result<Self> {
        let (file, peer) = holder.retain_for_activation()?;
        Ok(Self {
            file,
            peer,
            ready: AppContinuation::Ready,
        })
    }

    /// This side validates its own SAME retained read-only image before/after
    /// the fresh handshake. It neither borrows the Controller's stage nor uses
    /// a caller projection in place of the original file or participant.
    pub(in crate::security_epoch) fn begin_bootstrap<'storage>(
        &'storage mut self,
        stage: &mut EnrolledRoleStage<'_>,
        selection: &EpochStore,
        request: &Request,
    ) -> Result<CurrentAppStorageBootstrapPhase<'storage>> {
        let queued = self.ready.begin()?;
        let binding = request_binding(
            &self.peer.initial_projection().initial_core().bootstrap()?,
            self.peer.first_holder(),
            selection,
            request,
        )?;
        self.file.check_initial(stage)?;
        let peer = self.peer.begin_current(queued, stage, binding)?;
        let mut phase = CurrentAppStorageBootstrapPhase {
            file: &mut self.file,
            peer,
            continuation: &mut self.ready,
        };
        phase.check(stage)?;
        Ok(phase)
    }

    pub(crate) fn refuse(&mut self) {
        self.ready = AppContinuation::Refused;
        self.file.refuse();
        self.peer.refuse();
    }
}

impl CurrentAppStorageBootstrapPhase<'_> {
    pub(in crate::security_epoch) fn await_known(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        self.peer.await_known(stage)?;
        self.check(stage)
    }

    pub(crate) fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            self.continuation.check()?;
            self.file.check_initial(stage)?;
            self.peer.check(stage)?;
            self.file.check_initial(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn finish_checked(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        self.peer.acknowledge_known(stage)?;
        self.check(stage)?;
        self.peer.await_release(stage)?;
        self.peer.finish_checked(stage)?;
        self.file.check_initial(stage)?;
        self.continuation.complete()?;
        Ok(())
    }

    pub(in crate::security_epoch) fn finish_activated(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        self.peer.acknowledge_known(stage)?;
        self.peer.await_release(stage)?;
        // The Controller may now finalize activation. Future writes need
        // their own active serving fence; initial bytes are never re-adopted.
        self.peer.finish_checked(stage)?;
        self.file.check_current(stage)?;
        self.continuation.complete()?;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        *self.continuation = AppContinuation::Refused;
        self.file.refuse();
        self.peer.refuse();
    }
}

impl CurrentAppStoragePhase<'_> {
    pub(in crate::security_epoch) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let result = (|| {
            self.continuation.check()?;
            self.file.check_current(stage)?;
            self.peer.check(stage)?;
            self.file.check_current(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn await_known(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        self.peer.await_known(stage)?;
        self.check(stage)
    }

    pub(in crate::security_epoch) fn finish_checked(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        self.peer.acknowledge_known(stage)?;
        self.peer.await_release(stage)?;
        self.check(stage)?;
        self.peer.finish_checked(stage)?;
        self.file.check_current(stage)?;
        self.continuation.complete()?;
        Ok(())
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        *self.continuation = AppContinuation::Refused;
        self.file.refuse();
        self.peer.refuse();
    }
}

impl<'role> CurrentControllerStoragePhase<'_, 'role> {
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(!*self.continuation, "controller_storage_phase_released");
            self.file.check_current_durability()?;
            match &mut self.peer {
                PeerFence::Current(peer) => peer.check(self.file.controller_stage()?)?,
                PeerFence::Retained(peer) => {
                    peer.check_retained_identity(self.file.controller_stage()?)?
                }
            }
            self.file.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn controller_stage(
        &mut self,
    ) -> Result<&mut EnrolledRoleStage<'role>> {
        self.check()?;
        self.file.controller_stage()
    }

    pub(in crate::security_epoch) fn app_request(&self) -> Result<&StoragePeerRequest> {
        match &self.peer {
            PeerFence::Current(peer) => Ok(peer.request()),
            PeerFence::Retained(_) => anyhow::bail!("controller_storage_has_no_app_request"),
        }
    }

    pub(in crate::security_epoch) fn announce_app_known(&mut self) -> Result<()> {
        self.check()?;
        match &mut self.peer {
            PeerFence::Current(peer) => peer.announce_known(self.file.controller_stage()?)?,
            PeerFence::Retained(_) => anyhow::bail!("controller_storage_has_no_app_request"),
        }
        self.check()
    }

    pub(in crate::security_epoch) fn await_app_consumed(&mut self) -> Result<()> {
        self.check()?;
        match &mut self.peer {
            PeerFence::Current(peer) => {
                peer.await_acknowledgement(self.file.controller_stage()?)?
            }
            PeerFence::Retained(_) => anyhow::bail!("controller_storage_has_no_app_request"),
        }
        self.check()
    }

    pub(in crate::security_epoch) fn finish_app_known(mut self) -> Result<()> {
        self.check()?;
        let PeerFence::Current(mut peer) = self.peer else {
            anyhow::bail!("controller_storage_has_no_app_request")
        };
        self.file.check_current_durability()?;
        peer.release_known(self.file.controller_stage()?)?;
        peer.finish_checked(self.file.controller_stage()?)?;
        self.file.finish_checked()?;
        *self.continuation = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn finish_controller_known(mut self) -> Result<()> {
        self.check()?;
        ensure!(
            matches!(self.peer, PeerFence::Retained(_)),
            "controller_storage_app_scope_requires_peer_settlement"
        );
        self.file.finish_checked()?;
        *self.continuation = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        *self.continuation = false;
        self.file.refuse();
        match &mut self.peer {
            PeerFence::Current(peer) => peer.refuse(),
            PeerFence::Retained(peer) => peer.refuse(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::{kernel::Versions, tests as epoch_tests};

    fn first() -> Holder {
        Holder {
            principal: Digest::new(b"actual participant fixture principal"),
            pod_uid: "a6b27e63-16d8-4b99-92f6-2437e5b20f43".into(),
            process_incarnation: Digest::new(b"actual participant fixture process"),
            ephemeral_key: Digest::new(b"actual participant fixture key"),
        }
    }

    #[test]
    fn bootstrap_request_data_rejects_other_seed_artifact_and_selection() {
        let selection = epoch_tests::selection();
        let create = epoch_tests::create();
        let expected = create.bootstrap().clone();
        let binding = request_binding(&expected, &first(), &selection, &create).unwrap();
        assert!(binding.purpose == StoragePeerPurpose::BootstrapCreate);
        assert_eq!(binding.binding, create.digest().unwrap());
        let mut changed = expected.clone();
        changed.manifest.artifact = Digest::new(b"other artifact");
        assert!(
            request_binding(
                &expected,
                &first(),
                &selection,
                &Request::CreateInitialAuthority { bootstrap: changed }
            )
            .is_err()
        );
        let mut changed = expected.clone();
        changed.record_incarnation = Digest::new(b"other seed");
        assert!(
            request_binding(
                &expected,
                &first(),
                &selection,
                &Request::CreateInitialAuthority { bootstrap: changed }
            )
            .is_err()
        );
        let mut other_store = selection;
        other_store.key_set = Digest::new(b"other keys");
        assert!(request_binding(&expected, &first(), &other_store, &create).is_err());
    }

    #[test]
    fn completion_request_data_must_keep_the_exact_initial_native_participant() {
        let selection = epoch_tests::selection();
        let create = epoch_tests::create();
        let holder = first();
        let request = Request::CompleteInitialFirstActivation {
            bootstrap: create.bootstrap().clone(),
            operation: Digest::new(b"complete operation"),
            parent_receipt: create.receipt().unwrap().digest().unwrap(),
            before: Versions {
                root: "2026-10-20T07:00:00Z".to_owned().try_into().unwrap(),
                sentinel: "2026-10-20T07:00:00Z".to_owned().try_into().unwrap(),
            },
            holder: holder.clone(),
        };
        let binding = request_binding(create.bootstrap(), &holder, &selection, &request).unwrap();
        assert!(binding.purpose == StoragePeerPurpose::BootstrapComplete);
        assert_eq!(binding.binding, request.digest().unwrap());
        let mut other = holder.clone();
        other.ephemeral_key = Digest::new(b"other process key");
        assert!(request_binding(create.bootstrap(), &other, &selection, &request).is_err());
        let mut other = holder.clone();
        other.process_incarnation = Digest::new(b"restarted process");
        assert!(request_binding(create.bootstrap(), &other, &selection, &request).is_err());
        let mut changed = request;
        let Request::CompleteInitialFirstActivation { parent_receipt, .. } = &mut changed else {
            unreachable!()
        };
        *parent_receipt = Digest::new(b"unrelated receipt");
        assert!(request_binding(create.bootstrap(), &holder, &selection, &changed).is_err());
    }
}
