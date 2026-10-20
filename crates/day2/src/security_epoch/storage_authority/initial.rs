//! Own the SAME joined durable initial file and authenticated App peer. This
//! is conditional PD/ext4 durability, not effective IAM or active writer proof.

use super::{AppFileContinuity, CurrentPreparedFilePhase, PreparedFileContinuity};
use crate::security_epoch::{
    kernel::{Bootstrap, Holder, Request},
    native_enrollment::{
        AppHolderPeerContinuity, AuthenticatedAppFirstHolder, ControllerHolderPeerContinuity,
        CurrentStoragePeerPhase, EnrolledRoleStage, InitialHolderServer, StoragePeerPurpose,
        StoragePeerRequest,
    },
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};

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
    ready: bool,
}

pub(crate) struct CurrentAppStorageBootstrapPhase<'storage> {
    file: &'storage mut AppFileContinuity,
    peer: CurrentStoragePeerPhase<'storage>,
    continuation: &'storage mut bool,
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

impl InitialStorageContinuity {
    /// This fixed native operation performs the real first-holder exchange,
    /// selected PD/ext4 checks, file+directory synchronization and readback.
    /// No caller assertion, descriptor, projection or completed receipt enters
    /// as a substitute. A filesystem fixture cannot supply the required phase.
    pub(crate) fn establish(
        mut file: PreparedFileContinuity,
        stage: EnrolledRoleStage<'_>,
    ) -> InitialStorageOutcome {
        let result = (|| {
            let phase = file.begin_initial_phase(stage)?;
            let mut holder = InitialHolderServer::bind(phase)?.exchange()?;
            holder.check_initial_durability()?;
            holder.retain_for_activation()
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
        stage: EnrolledRoleStage<'role>,
        selection: &EpochStore,
        request: &Request,
    ) -> Result<CurrentStorageBootstrapPhase<'storage, 'role>> {
        ensure!(self.ready, "initial_storage_continuation_refused");
        self.ready = false;
        let expected = self.peer.initial_projection();
        let binding = request_binding(
            &expected.initial_core().bootstrap()?,
            self.peer.first_holder(),
            selection,
            request,
        )?;
        let mut file = self.file.begin_initial_phase(stage)?;
        ensure!(
            file.projection()? == *expected,
            "initial_storage_file_projection_changed"
        );
        // The historical establishment is not a current configuration lease.
        // Rejoin/check and synchronize under THIS already-spent fresh stage,
        // before the new peer transcript can advertise a bootstrap phase.
        file.check_initial_durability()?;
        let peer = self
            .peer
            .accept_current(file.controller_stage()?, &binding)?;
        let mut phase = CurrentStorageBootstrapPhase {
            file,
            peer,
            continuation: &mut self.ready,
            request: request.clone(),
        };
        phase.check()?;
        Ok(phase)
    }

    pub(crate) fn refuse(&mut self) {
        self.ready = false;
        self.peer.refuse();
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
    pub(in crate::security_epoch) fn finish_checked(mut self) -> Result<()> {
        self.check()?;
        self.peer.finish_checked(self.file.controller_stage()?)?;
        self.file.finish_checked()?;
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
    pub(crate) fn retain(holder: AuthenticatedAppFirstHolder<'_, '_>) -> Result<Self> {
        let (file, peer) = holder.retain_for_activation()?;
        Ok(Self {
            file,
            peer,
            ready: true,
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
        ensure!(self.ready, "app_initial_storage_continuation_refused");
        self.ready = false;
        let binding = request_binding(
            &self.peer.initial_projection().initial_core().bootstrap()?,
            self.peer.first_holder(),
            selection,
            request,
        )?;
        self.file.check_initial(stage)?;
        let peer = self.peer.begin_current(stage, binding)?;
        let mut phase = CurrentAppStorageBootstrapPhase {
            file: &mut self.file,
            peer,
            continuation: &mut self.ready,
        };
        phase.check(stage)?;
        Ok(phase)
    }

    pub(crate) fn refuse(&mut self) {
        self.ready = false;
        self.file.refuse();
        self.peer.refuse();
    }
}

impl CurrentAppStorageBootstrapPhase<'_> {
    pub(crate) fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            ensure!(!*self.continuation, "app_initial_storage_phase_released");
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
        self.peer.finish_checked(stage)?;
        self.file.check_initial(stage)?;
        *self.continuation = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        *self.continuation = false;
        self.file.refuse();
        self.peer.refuse();
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
