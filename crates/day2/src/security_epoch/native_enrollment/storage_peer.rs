//! Closed initial-holder exchange. Wire statements remain DATA; only the
//! native channel/process/file composition below constructs holder owners.
//! A successful exchange alone is neither provider P3 nor a serving writer.

#[cfg(target_os = "linux")]
use super::storage_peer_native::Peer;
#[cfg(target_os = "linux")]
use super::{
    channel::{Channel, StorageListener},
    protocol,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::storage_peer_wire::Body;
use crate::security_epoch::native_enrollment::storage_peer_wire::{Exchange, StageStatement};
use crate::security_epoch::{
    AppPreparedFile, CurrentPreparedFilePhase, PreparedFileProjection,
    native_clock::NativeAcquisition, native_enrollment::EnrolledRoleStage,
};
use anyhow::{Result, ensure};
use day2_capabilities::security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy};

pub(crate) struct InitialHolderServer<'file, 'role> {
    phase: CurrentPreparedFilePhase<'file, 'role>,
    acquisition: NativeAcquisition,
    local: StageStatement,
    #[cfg(target_os = "linux")]
    listener: StorageListener,
}

/// The controller authenticates this offer BEFORE an App may open/parse the
/// projected SQLite file. It owns the exact channel, sender handles and original
/// acquisition, without storing a self-referential borrow of the App stage.
pub(crate) struct AuthenticatedInitialHolderOffer {
    local: StageStatement,
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
    exchange: Exchange,
    #[cfg(target_os = "linux")]
    peer: Peer,
    #[cfg(target_os = "linux")]
    channel: Channel,
    valid: bool,
}

impl<'file, 'role> InitialHolderServer<'file, 'role> {
    pub(crate) fn bind(mut phase: CurrentPreparedFilePhase<'file, 'role>) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut phase;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            phase.check()?;
            let mut acquisition = phase.controller_stage()?.narrow_io_acquisition(5)?;
            let local = phase.controller_stage()?.storage_statement()?;
            let listener = StorageListener::bind(phase.controller_stage()?, &mut acquisition)?;
            phase.check()?;
            Ok(Self {
                phase,
                acquisition,
                local,
                listener,
            })
        }
    }

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
            self.check()?;
            let mut channel = self
                .listener
                .accept(self.phase.controller_stage()?, &mut self.acquisition)?;
            let (hello, process) =
                channel.receive_storage(self.phase.controller_stage()?, &mut self.acquisition)?;
            let (app, app_nonce) = match &hello.body {
                Body::Hello { app, nonce } => (app.as_ref().clone(), nonce.clone()),
                _ => anyhow::bail!("storage_peer_expected_hello"),
            };
            hello.verify(&app)?;
            let mut peer = Peer::authenticate(
                &hello,
                app,
                process,
                self.phase.controller_stage()?,
                &mut self.acquisition,
            )?;
            self.check()?;
            let projection = self.phase.projection()?;
            let exchange = Exchange {
                app_stage: peer.statement().digest()?,
                controller_stage: self.local.digest()?,
                app_nonce,
                controller_nonce: protocol::nonce("initial-holder-controller")?,
                projection: projection.digest()?,
            };
            self.check()?;
            peer.check(self.phase.controller_stage()?, &mut self.acquisition)?;
            let offer = self
                .phase
                .controller_stage()?
                .sign_storage_message(Body::Offer {
                    controller: Box::new(self.local.clone()),
                    exchange: exchange.clone(),
                    projection: Box::new(projection),
                })?;
            channel.send_storage(
                &offer,
                self.phase.controller_stage()?,
                &mut self.acquisition,
            )?;
            self.check()?;
            peer.check(self.phase.controller_stage()?, &mut self.acquisition)?;
            let (confirm, process) =
                channel.receive_storage(self.phase.controller_stage()?, &mut self.acquisition)?;
            peer.accept_message(
                &confirm,
                process,
                self.phase.controller_stage()?,
                &mut self.acquisition,
            )?;
            let exchange_digest = exchange.digest()?;
            ensure!(
                matches!(&confirm.body, Body::Confirm { exchange: selected, projection } if *selected == exchange_digest && *projection == exchange.projection),
                "storage_peer_confirmation_changed"
            );
            self.check()?;
            peer.check(self.phase.controller_stage()?, &mut self.acquisition)?;
            let complete = self
                .phase
                .controller_stage()?
                .sign_storage_message(Body::Complete {
                    exchange: exchange_digest.clone(),
                })?;
            channel.send_storage(
                &complete,
                self.phase.controller_stage()?,
                &mut self.acquisition,
            )?;
            self.check()?;
            peer.check(self.phase.controller_stage()?, &mut self.acquisition)?;
            // A successful send is not an App receipt. Wait for its signed
            // acceptance after it received Complete and rechecked its real file.
            let (accepted, process) =
                channel.receive_storage(self.phase.controller_stage()?, &mut self.acquisition)?;
            peer.accept_message(
                &accepted,
                process,
                self.phase.controller_stage()?,
                &mut self.acquisition,
            )?;
            ensure!(
                matches!(&accepted.body, Body::Accepted { exchange: selected } if *selected == exchange_digest),
                "storage_peer_acceptance_changed"
            );
            self.check()?;
            peer.check(self.phase.controller_stage()?, &mut self.acquisition)?;
            peer.check(self.phase.controller_stage()?, &mut self.acquisition)?;
            channel.check_storage_open(self.phase.controller_stage()?, &mut self.acquisition)?;
            Ok(AuthenticatedControllerFirstHolder {
                phase: self.phase,
                acquisition: self.acquisition,
                local: self.local,
                exchange,
                peer,
                channel,
                valid: true,
            })
        }
    }
}

impl AuthenticatedInitialHolderOffer {
    pub(crate) fn receive(stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stage;
            anyhow::bail!("storage_peer_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            stage.begin_initial_holder_attempt()?;
            let local = stage.storage_statement()?;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let mut channel = Channel::connect_storage(stage, &mut acquisition)?;
            let app_nonce = protocol::nonce("initial-holder-app")?;
            let hello = stage.sign_storage_message(Body::Hello {
                app: Box::new(local.clone()),
                nonce: app_nonce.clone(),
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
            let peer = Peer::authenticate(&offer, controller, process, stage, &mut acquisition)?;
            ensure!(
                exchange.app_stage == local.digest()?
                    && exchange.controller_stage == peer.statement().digest()?
                    && exchange.app_nonce == app_nonce
                    && exchange.projection == projection.digest()?,
                "storage_peer_offer_changed"
            );
            let mut owner = Self {
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
