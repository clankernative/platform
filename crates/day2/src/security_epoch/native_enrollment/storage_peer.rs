//! Closed initial-holder exchange. Wire statements remain DATA; only the
//! native channel/process/file composition below constructs holder owners.
//! A successful exchange alone is neither provider P3 nor a serving writer.

mod continuation;
pub(crate) use continuation::{
    AppHolderPeerContinuity, ControllerCurrentRendezvous, ControllerHolderPeerContinuity,
    CurrentStoragePeerPhase, PendingAppCurrentPeer, QueuedAppCurrentPeer,
};

#[cfg(target_os = "linux")]
use super::storage_peer_native::Peer;
#[cfg(target_os = "linux")]
use super::{
    channel::{Channel, StorageListener},
    protocol,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::controller::evidence::{PreparationFailure, PreparationStep};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::storage_peer_wire::Body;
use crate::security_epoch::native_enrollment::storage_peer_wire::{Exchange, StageStatement};
use crate::security_epoch::{
    AppPreparedFile, CurrentPreparedFilePhase, PreparedFileProjection,
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, SameEnrolledOwner},
};
use anyhow::{Result, ensure};
use day2_capabilities::security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy};

/// A bound endpoint and original ownership identity, never a retained role or
/// first-holder/P3 permit. Idle readiness DATA may outlive its completed bind
/// phase; actual exchange needs a new SAME-owner current file/role phase.
pub(crate) struct InitialHolderListener {
    owner: SameEnrolledOwner,
    projection: PreparedFileProjection,
    valid: bool,
    #[cfg(target_os = "linux")]
    listener: StorageListener,
}

/// A completed same-owner connection, without a live old stage or permission.
/// Readiness polling is DATA only; consuming it requires a fresh actual stage.
pub(crate) struct InitialHolderConnection {
    owner: SameEnrolledOwner,
    setup_grant: day2_capabilities::Digest,
    valid: bool,
    #[cfg(target_os = "linux")]
    channel: Channel,
}

/// Retains the exact accepted channel and original stage's narrowed interval
/// after sending readiness. This alone supplies no file, holder or P3 proof.
pub(crate) struct InitialHolderRendezvous {
    owner: SameEnrolledOwner,
    projection: PreparedFileProjection,
    acquisition: NativeAcquisition,
    local: StageStatement,
    controller_nonce: day2_capabilities::Digest,
    valid: bool,
    #[cfg(target_os = "linux")]
    channel: Channel,
}

// Completed transport DATA still owns real nontransferable resources. It is
// not an application-serializable or clonable supplier for another executor.
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
    assert_not_impl!(InitialHolderConnection, Clone);
    assert_not_impl!(InitialHolderConnection, Copy);
    assert_not_impl!(InitialHolderConnection, Default);
    assert_not_impl!(InitialHolderConnection, Send);
    assert_not_impl!(InitialHolderConnection, Sync);
    assert_not_impl!(InitialHolderConnection, serde::Serialize);
    assert_not_impl!(InitialHolderConnection, serde::Deserialize<'static>);
    assert_not_impl!(InitialHolderRendezvous, Clone);
    assert_not_impl!(InitialHolderRendezvous, Copy);
    assert_not_impl!(InitialHolderRendezvous, Default);
    assert_not_impl!(InitialHolderRendezvous, Send);
    assert_not_impl!(InitialHolderRendezvous, Sync);
    assert_not_impl!(InitialHolderRendezvous, serde::Serialize);
    assert_not_impl!(InitialHolderRendezvous, serde::Deserialize<'static>);
};

pub(crate) struct InitialHolderServer<'file, 'role> {
    phase: CurrentPreparedFilePhase<'file, 'role>,
    acquisition: NativeAcquisition,
    local: StageStatement,
    controller_nonce: day2_capabilities::Digest,
    #[cfg(target_os = "linux")]
    channel: Channel,
}

/// The controller authenticates this offer BEFORE an App may open/parse the
/// projected SQLite file. It owns the exact channel, sender handles and original
/// acquisition, without storing a self-referential borrow of the App stage.
pub(crate) struct AuthenticatedInitialHolderOffer {
    local: StageStatement,
    remote: StageStatement,
    exchange: Exchange,
    projection: PreparedFileProjection,
    acquisition: NativeAcquisition,
    valid: bool,
    #[cfg(target_os = "linux")]
    peer: Peer,
    #[cfg(target_os = "linux")]
    channel: Channel,
}

pub(crate) struct AuthenticatedAppFirstHolder<'stage, 'role> {
    file: AppPreparedFile<'stage, 'role>,
    offer: AuthenticatedInitialHolderOffer,
}

/// Still owns the original file phase and all actual App sender handles. It
/// does not release that phase or manufacture a P3/counter/current-writer permit.
pub(crate) struct AuthenticatedControllerFirstHolder<'file, 'role> {
    phase: CurrentPreparedFilePhase<'file, 'role>,
    acquisition: NativeAcquisition,
    local: StageStatement,
    remote: StageStatement,
    exchange: Exchange,
    #[cfg(target_os = "linux")]
    peer: Peer,
    #[cfg(target_os = "linux")]
    channel: Channel,
    valid: bool,
}

impl InitialHolderConnection {
    /// Complete transport setup under THIS actual stage. No old acquisition
    /// survives the return, and the one-way owner gate closes before connect.
    pub(crate) fn connect(stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stage;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            stage.begin_initial_holder_attempt()?;
            let mut owner = stage.capture_same_owner()?;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let mut channel = Channel::connect_storage(stage, &mut acquisition)?;
            let setup_grant = stage.storage_statement()?.grant_digest()?;
            owner.check(stage)?;
            channel.check_storage_open(stage, &mut acquisition)?;
            stage.check_storage_acquisition(&mut acquisition)?;
            Ok(Self {
                owner,
                setup_grant,
                valid: true,
                channel,
            })
        }
    }

    /// Queued readiness is DATA, never authentication or a retained stage.
    pub(crate) fn idle_ready(&mut self) -> Result<bool> {
        let result = (|| {
            ensure!(self.valid, "storage_peer_connection_refused");
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.channel.storage_pending()
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }
}

impl InitialHolderListener {
    pub(crate) fn bind(mut phase: CurrentPreparedFilePhase<'_, '_>) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut phase;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            phase
                .check()
                .map_err(|error| PreparationFailure::at(PreparationStep::HolderFilePhase, error))?;
            let owner = phase
                .controller_stage()
                .and_then(|stage| stage.capture_same_owner())
                .map_err(|error| PreparationFailure::at(PreparationStep::HolderOwner, error))?;
            let projection = phase.projection().map_err(|error| {
                PreparationFailure::at(PreparationStep::HolderProjection, error)
            })?;
            let mut acquisition = phase
                .controller_stage()
                .and_then(|stage| stage.narrow_io_acquisition(5))
                .map_err(|error| PreparationFailure::at(PreparationStep::HolderInterval, error))?;
            let stage = phase
                .controller_stage()
                .map_err(|error| PreparationFailure::at(PreparationStep::HolderFilePhase, error))?;
            let listener = StorageListener::bind(stage, &mut acquisition)
                .map_err(|error| PreparationFailure::at(PreparationStep::HolderTransport, error))?;
            phase.check().map_err(|error| {
                PreparationFailure::at(PreparationStep::HolderFinalCheck, error)
            })?;
            // Binding is a completed atomic operation, NOT a first-holder
            // exchange. No signed offer or durable activation has occurred.
            phase.finish_checked().map_err(|error| {
                PreparationFailure::at(PreparationStep::HolderFinalCheck, error)
            })?;
            Ok(Self {
                owner,
                projection,
                valid: true,
                listener,
            })
        }
    }

    pub(crate) fn idle_ready(&mut self) -> Result<bool> {
        let result = (|| {
            ensure!(self.valid, "storage_peer_listener_refused");
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.listener.pending()
        })();
        if result.is_err() {
            self.valid = false;
        }
        result
    }

    /// Consume this one original listener BEFORE any fallible exchange work.
    /// Its completed old bind stage cannot authorize a packet or renew time.
    pub(crate) fn prepare(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<InitialHolderRendezvous> {
        ensure!(self.valid, "storage_peer_listener_refused");
        self.valid = false;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stage;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.owner.check(stage)?;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let mut channel = self
                .listener
                .accept(stage, &mut acquisition)
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstAccept, error))?;
            let local = stage.storage_statement()?;
            let controller_nonce = protocol::nonce("initial-holder-controller")?;
            let ready = stage.sign_storage_message(Body::InitialReady {
                controller: Box::new(local.clone()),
                nonce: controller_nonce.clone(),
            })?;
            channel.send_storage(&ready, stage, &mut acquisition)?;
            self.owner.check(stage)?;
            channel.check_storage_open(stage, &mut acquisition)?;
            Ok(InitialHolderRendezvous {
                owner: self.owner,
                projection: self.projection,
                acquisition,
                local,
                controller_nonce,
                valid: true,
                channel,
            })
        }
    }
}

impl InitialHolderRendezvous {
    pub(crate) fn start<'file, 'role>(
        mut self,
        mut phase: CurrentPreparedFilePhase<'file, 'role>,
    ) -> Result<InitialHolderServer<'file, 'role>> {
        ensure!(self.valid, "storage_peer_rendezvous_refused");
        self.valid = false;
        self.owner.check(phase.controller_stage()?)?;
        phase.check()?;
        ensure!(
            phase.projection()? == self.projection,
            "storage_peer_listener_original_changed"
        );
        phase
            .controller_stage()?
            .check_storage_acquisition(&mut self.acquisition)?;
        ensure!(
            phase.controller_stage()?.storage_statement()? == self.local,
            "storage_peer_ready_stage_changed"
        );
        self.owner.check(phase.controller_stage()?)?;
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("storage_peer_platform_unsupported");
        #[cfg(target_os = "linux")]
        Ok(InitialHolderServer {
            phase,
            acquisition: self.acquisition,
            local: self.local,
            controller_nonce: self.controller_nonce,
            channel: self.channel,
        })
    }
}

impl<'file, 'role> InitialHolderServer<'file, 'role> {
    fn check(&mut self) -> Result<()> {
        self.phase.check()?;
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("storage_peer_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            let stage = self.phase.controller_stage()?;
            stage.check_storage_acquisition(&mut self.acquisition)?;
            ensure!(
                stage.storage_statement()? == self.local,
                "storage_peer_local_stage_changed"
            );
            Ok(())
        }
    }

    pub(crate) fn exchange(mut self) -> Result<AuthenticatedControllerFirstHolder<'file, 'role>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            let (hello, process) = (|| {
                self.channel
                    .receive_storage(self.phase.controller_stage()?, &mut self.acquisition)
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstHello, error))?;
            let (app, app_nonce) = hello.initial_hello(&self.controller_nonce)?;
            let (app, app_nonce) = (app.clone(), app_nonce.clone());
            hello.verify(&app)?;
            let mut peer = (|| {
                Peer::authenticate(
                    &hello,
                    app,
                    process,
                    self.phase.controller_stage()?,
                    &mut self.acquisition,
                )
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstPeer, error))?;
            self.check()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            let projection = self
                .phase
                .projection()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstProjection, error))?;
            let exchange = Exchange {
                app_stage: peer.statement().digest()?,
                controller_stage: self.local.digest()?,
                app_nonce,
                controller_nonce: self.controller_nonce.clone(),
                projection: projection.digest()?,
            };
            self.check()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            (|| peer.check(self.phase.controller_stage()?, &mut self.acquisition))()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstPeer, error))?;
            let offer = (|| {
                self.phase
                    .controller_stage()?
                    .sign_storage_message(Body::Offer {
                        controller: Box::new(self.local.clone()),
                        exchange: exchange.clone(),
                        projection: Box::new(projection),
                    })
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstOffer, error))?;
            (|| {
                self.channel.send_storage(
                    &offer,
                    self.phase.controller_stage()?,
                    &mut self.acquisition,
                )
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstOffer, error))?;
            self.check()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            (|| peer.check(self.phase.controller_stage()?, &mut self.acquisition))()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstPeer, error))?;
            let (confirm, process) = (|| {
                self.channel
                    .receive_storage(self.phase.controller_stage()?, &mut self.acquisition)
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstConfirm, error))?;
            (|| {
                peer.accept_message(
                    &confirm,
                    process,
                    self.phase.controller_stage()?,
                    &mut self.acquisition,
                )
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstConfirm, error))?;
            let exchange_digest = exchange.digest()?;
            ensure!(
                matches!(&confirm.body, Body::Confirm { exchange: selected, projection } if *selected == exchange_digest && *projection == exchange.projection),
                "storage_peer_confirmation_changed"
            );
            self.check()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            (|| peer.check(self.phase.controller_stage()?, &mut self.acquisition))()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstPeer, error))?;
            let complete = (|| {
                self.phase
                    .controller_stage()?
                    .sign_storage_message(Body::Complete {
                        exchange: exchange_digest.clone(),
                    })
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstComplete, error))?;
            (|| {
                self.channel.send_storage(
                    &complete,
                    self.phase.controller_stage()?,
                    &mut self.acquisition,
                )
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstComplete, error))?;
            self.check()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            (|| peer.check(self.phase.controller_stage()?, &mut self.acquisition))()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstPeer, error))?;
            // A successful send is not an App receipt. Wait for its signed
            // acceptance after it received Complete and rechecked its real file.
            let (accepted, process) = (|| {
                self.channel
                    .receive_storage(self.phase.controller_stage()?, &mut self.acquisition)
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstAccepted, error))?;
            (|| {
                peer.accept_message(
                    &accepted,
                    process,
                    self.phase.controller_stage()?,
                    &mut self.acquisition,
                )
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstAccepted, error))?;
            ensure!(
                matches!(&accepted.body, Body::Accepted { exchange: selected } if *selected == exchange_digest),
                "storage_peer_acceptance_changed"
            );
            self.check()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            (|| peer.check(self.phase.controller_stage()?, &mut self.acquisition))()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstPeer, error))?;
            (|| peer.check(self.phase.controller_stage()?, &mut self.acquisition))()
                .map_err(|error| PreparationFailure::at(PreparationStep::FirstPeer, error))?;
            (|| {
                self.channel
                    .check_storage_open(self.phase.controller_stage()?, &mut self.acquisition)
            })()
            .map_err(|error| PreparationFailure::at(PreparationStep::FirstCheck, error))?;
            Ok(AuthenticatedControllerFirstHolder {
                remote: peer.statement().clone(),
                phase: self.phase,
                acquisition: self.acquisition,
                local: self.local,
                exchange,
                peer,
                channel: self.channel,
                valid: true,
            })
        }
    }
}

impl AuthenticatedInitialHolderOffer {
    pub(crate) fn receive(
        mut connection: InitialHolderConnection,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<Self> {
        ensure!(connection.valid, "storage_peer_connection_refused");
        connection.valid = false;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stage;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            connection.owner.check(stage)?;
            let local = stage.storage_statement()?;
            local.require_new_grant(&connection.setup_grant)?;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let mut channel = connection.channel;
            let (ready, process) = channel.receive_storage(stage, &mut acquisition)?;
            let (controller, controller_nonce) = match &ready.body {
                Body::InitialReady { controller, nonce } => {
                    (controller.as_ref().clone(), nonce.clone())
                }
                _ => anyhow::bail!("storage_peer_expected_initial_ready"),
            };
            ready.verify(&controller)?;
            let mut peer =
                Peer::authenticate(&ready, controller, process, stage, &mut acquisition)?;
            let app_nonce = protocol::nonce("initial-holder-app")?;
            let hello = stage.sign_storage_message(Body::Hello {
                app: Box::new(local.clone()),
                nonce: app_nonce.clone(),
                controller_nonce: controller_nonce.clone(),
            })?;
            channel.send_storage(&hello, stage, &mut acquisition)?;
            let (offer, process) = channel.receive_storage(stage, &mut acquisition)?;
            let (controller, exchange, projection) = match &offer.body {
                Body::Offer {
                    controller,
                    exchange,
                    projection,
                } => (
                    controller.as_ref().clone(),
                    exchange.clone(),
                    projection.as_ref().clone(),
                ),
                _ => anyhow::bail!("storage_peer_expected_offer"),
            };
            offer.verify(&controller)?;
            exchange.require_initial_ready(peer.statement(), &controller_nonce, &controller)?;
            peer.accept_message(&offer, process, stage, &mut acquisition)?;
            ensure!(
                exchange.app_stage == local.digest()?
                    && exchange.controller_stage == peer.statement().digest()?
                    && exchange.app_nonce == app_nonce
                    && exchange.controller_nonce == controller_nonce
                    && exchange.projection == projection.digest()?,
                "storage_peer_offer_changed"
            );
            let mut owner = Self {
                remote: peer.statement().clone(),
                local,
                exchange,
                projection,
                acquisition,
                valid: true,
                peer,
                channel,
            };
            owner.check(stage)?;
            Ok(owner)
        }
    }

    pub(crate) fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "storage_peer_offer_refused");
            #[cfg(not(target_os = "linux"))]
            {
                let _ = stage;
                anyhow::bail!("storage_peer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                stage.check_storage_acquisition(&mut self.acquisition)?;
                ensure!(
                    stage.storage_statement()? == self.local,
                    "storage_peer_local_stage_changed"
                );
                self.channel
                    .check_storage_open(stage, &mut self.acquisition)?;
                self.peer.check(stage, &mut self.acquisition)?;
                self.channel
                    .check_storage_open(stage, &mut self.acquisition)
            }
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }

    pub(crate) fn projection(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<PreparedFileProjection> {
        let result = (|| {
            self.check(stage)?;
            self.projection.validate_selection(policy, store)?;
            stage.check_selection(policy, store, super::NativeRole::AppHost)?;
            self.check(stage)?;
            Ok(self.projection.clone())
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }

    fn check_file(&mut self, file: &mut AppPreparedFile<'_, '_>) -> Result<()> {
        file.check_original()?;
        self.check(file.app_stage()?)?;
        ensure!(
            file.projection()? == self.projection,
            "storage_peer_app_file_changed"
        );
        file.check_original()?;
        self.check(file.app_stage()?)
    }

    pub(crate) fn finish<'stage, 'role>(
        mut self,
        mut file: AppPreparedFile<'stage, 'role>,
    ) -> Result<AuthenticatedAppFirstHolder<'stage, 'role>> {
        let result: Result<()> = (|| {
            self.check_file(&mut file)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let exchange = self.exchange.digest()?;
                let confirm = file.app_stage()?.sign_storage_message(Body::Confirm {
                    exchange: exchange.clone(),
                    projection: self.exchange.projection.clone(),
                })?;
                self.channel
                    .send_storage(&confirm, file.app_stage()?, &mut self.acquisition)?;
                self.check_file(&mut file)?;
                let (complete, process) = self
                    .channel
                    .receive_storage(file.app_stage()?, &mut self.acquisition)?;
                self.peer.accept_message(
                    &complete,
                    process,
                    file.app_stage()?,
                    &mut self.acquisition,
                )?;
                ensure!(
                    matches!(&complete.body, Body::Complete { exchange: selected } if *selected == exchange),
                    "storage_peer_completion_changed"
                );
                self.check_file(&mut file)?;
                let accepted = file
                    .app_stage()?
                    .sign_storage_message(Body::Accepted { exchange })?;
                self.channel
                    .send_storage(&accepted, file.app_stage()?, &mut self.acquisition)?;
                self.check_file(&mut file)
            }
        })();
        if let Err(error) = result {
            self.valid = false;
            self.acquisition.refuse();
            file.refuse();
            return Err(error);
        }
        Ok(AuthenticatedAppFirstHolder { file, offer: self })
    }
}

impl AuthenticatedAppFirstHolder<'_, '_> {
    pub(crate) fn check(&mut self) -> Result<()> {
        let result = self.offer.check_file(&mut self.file);
        if result.is_err() {
            self.offer.valid = false;
            self.offer.acquisition.refuse();
            self.file.refuse();
        }
        result
    }
}

impl AuthenticatedControllerFirstHolder<'_, '_> {
    /// Spend this SAME authenticated holder and physical phase on the joined
    /// initial durability operation. This returns no transferable P3 witness.
    pub(crate) fn check_initial_durability(&mut self) -> Result<()> {
        self.check()?;
        self.phase.check_initial_durability()?;
        self.check()
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "storage_peer_controller_holder_refused");
            self.phase.check()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("storage_peer_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let stage = self.phase.controller_stage()?;
                stage.check_storage_acquisition(&mut self.acquisition)?;
                ensure!(
                    stage.storage_statement()? == self.local,
                    "storage_peer_local_stage_changed"
                );
                self.channel
                    .check_storage_open(stage, &mut self.acquisition)?;
                self.peer.check(stage, &mut self.acquisition)?;
                self.channel
                    .check_storage_open(stage, &mut self.acquisition)
            }
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
            self.phase.refuse();
        }
        result
    }
}
