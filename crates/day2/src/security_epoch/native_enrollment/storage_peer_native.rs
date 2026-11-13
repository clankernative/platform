//! Retained actual per-message sender handles, not reconstructed numeric PIDs.

use super::storage_peer_wire::{Message, StageStatement};
use super::{RestoredCurrentPeerPort, RestoredPeerAnchor};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::issuer_costs::HashCosts;
use crate::security_epoch::native_enrollment::{
    EnrolledRoleStage, channel::StorageSender, process::MessageProcess,
};
use anyhow::{Result, ensure};

pub(super) struct Peer {
    statement: StageStatement,
    processes: Vec<StorageSender>,
    valid: bool,
}

impl Peer {
    /// A current grant requires an actual retained anchor AND a new signed
    /// packet with its real kernel sender. An identity/liveness check alone
    /// cannot turn historical grant DATA into this fresh Peer.
    pub(super) fn authenticate_request(
        anchor: &mut PeerAnchor,
        message: &Message,
        statement: StageStatement,
        mut process: StorageSender,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Peer> {
        let result = (|| {
            anchor.check_continuity(stage, acquisition)?;
            message.verify(&statement)?;
            stage.storage()?.check_admitted_storage_statement(
                &statement,
                &anchor.statement,
                acquisition,
            )?;
            match &mut process {
                StorageSender::App(process) => {
                    ensure!(
                        process.data() == &anchor.statement.stage.data.process,
                        "storage_peer_message_sender_changed"
                    );
                    process.check_identity(acquisition, &HashCosts::disabled())?;
                }
                StorageSender::Controller(receipt) => match &mut anchor.source {
                    AnchorSource::Admitted(processes) => {
                        let original = processes
                            .iter_mut()
                            .find_map(|sender| match sender {
                                StorageSender::Controller(original) => Some(original),
                                StorageSender::App(_) => None,
                            })
                            .ok_or_else(|| {
                                anyhow::anyhow!("storage_peer_original_controller_missing")
                            })?;
                        receipt.bind_admitted(
                            &statement,
                            original,
                            &anchor.statement,
                            stage,
                            acquisition,
                        )?;
                    }
                    AnchorSource::RestoredController(original) => {
                        receipt.bind_restored(
                            &statement,
                            original,
                            &anchor.statement,
                            stage,
                            acquisition,
                        )?;
                    }
                },
            }
            anchor.check_continuity(stage, acquisition)?;
            let mut request = Peer {
                statement,
                processes: vec![process],
                valid: true,
            };
            request.check(stage, acquisition)?;
            Ok(request)
        })();
        if result.is_err() {
            anchor.valid = false;
            acquisition.refuse();
        }
        result
    }

    /// Consume an actually authenticated peer as identity/liveness only.
    /// The resulting anchor cannot check or grant a later request: only its
    /// fresh-message factory may produce another current Peer.
    pub(super) fn into_anchor(self) -> PeerAnchor {
        PeerAnchor {
            statement: self.statement,
            source: AnchorSource::Admitted(self.processes),
            valid: self.valid,
        }
    }

    pub(super) fn authenticate(
        message: &Message,
        statement: StageStatement,
        process: StorageSender,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        message.verify(&statement)?;
        let mut owner = Self {
            statement,
            processes: vec![process],
            valid: true,
        };
        match &mut owner.processes[0] {
            StorageSender::App(process) => stage.storage()?.check_storage_app_statement(
                &owner.statement,
                process.data(),
                acquisition,
            )?,
            StorageSender::Controller(receipt) => {
                receipt.bind(&owner.statement, stage, acquisition)?
            }
        }
        // No peer escapes before this new, complete native sender observation.
        owner.check(stage, acquisition)?;
        Ok(owner)
    }

    pub(super) fn statement(&self) -> &StageStatement {
        &self.statement
    }

    pub(super) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.valid && !self.processes.is_empty() && self.processes.len() <= 5,
                "storage_peer_retained_process_refused"
            );
            stage.storage()?.check_storage_acquisition(acquisition)?;
            ensure!(
                acquisition.sample()?.elapsed
                    < std::time::Duration::from_nanos(self.statement.original.deadline_ns),
                "storage_peer_remote_stage_expired"
            );
            let mut same_actor = Vec::new();
            for sender in &mut self.processes {
                match sender {
                    StorageSender::App(process) => {
                        ensure!(
                            process.data() == &self.statement.stage.data.process,
                            "storage_peer_message_sender_changed"
                        );
                        same_actor.push(process.as_mut());
                    }
                    StorageSender::Controller(receipt) => {
                        receipt.check(&self.statement, stage, acquisition)?
                    }
                }
            }
            if !same_actor.is_empty() {
                MessageProcess::check_same_actor(
                    &mut same_actor,
                    acquisition,
                    &HashCosts::disabled(),
                )?;
            }
            stage.storage()?.check_storage_acquisition(acquisition)
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }

    pub(super) fn accept_message(
        &mut self,
        message: &Message,
        process: StorageSender,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            // A current App phase receives BeginReady, Offer, CurrentReady,
            // Result and Released. Each is checked and retained separately.
            ensure!(self.processes.len() < 5, "storage_peer_message_count");
            // Retain the actual newly received handle before fallible checks.
            self.processes.push(process);
            ensure!(self.valid, "storage_peer_retained_process_refused");
            acquisition.remaining()?;
            let (received, originals) = self.processes.split_last_mut().unwrap();
            if let StorageSender::Controller(receipt) = received {
                let original = originals
                    .iter_mut()
                    .find_map(|sender| match sender {
                        StorageSender::Controller(original) => Some(original),
                        StorageSender::App(_) => None,
                    })
                    .ok_or_else(|| anyhow::anyhow!("storage_peer_original_controller_missing"))?;
                receipt.bind_admitted(
                    &self.statement,
                    original,
                    &self.statement,
                    stage,
                    acquisition,
                )?;
            }
            // Verification is bounded public DATA work, with no signing,
            // I/O or publication. The one final retained observation joins ALL
            // retained sender handles after verification before returning.
            super::storage_peer_wire::verify_message_then_observe(
                self,
                message,
                |owner| &owner.statement,
                |owner| owner.check(stage, acquisition),
            )
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }
}

/// Retained historical identity, deliberately distinct from a fresh grant.
/// No DATA constructor, current check or native-resource getter exists here.
pub(super) struct PeerAnchor {
    statement: StageStatement,
    source: AnchorSource,
    valid: bool,
}

enum AnchorSource {
    Admitted(Vec<StorageSender>),
    RestoredController(super::restored::RestoredControllerReceipt),
}

impl PeerAnchor {
    pub(super) fn from_restored(
        input: &mut RestoredCurrentPeerPort<'_>,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let requested = (|| {
            use anyhow::Context;
            ensure!(
                !input.completed,
                "restore_current_transfer_already_consumed"
            );
            stage.require_current_role()?;
            let original = input
                .original
                .as_mut()
                .context("restore_current_original_missing")?;
            input
                .same
                .as_mut()
                .context("restore_current_owner_missing")?
                .meet_current_read_view(stage, original)?;
            original.exchange_current_views(acquisition)?;
            let source = match input
                .anchor
                .take()
                .context("restore_current_anchor_already_spent")?
            {
                RestoredPeerAnchor::App(process) => {
                    ensure!(
                        input.local.stage.data.role == super::NativeRole::EpochController
                            && input.remote.stage.data.role == super::NativeRole::AppHost,
                        "restore_current_anchor_role"
                    );
                    AnchorSource::Admitted(vec![StorageSender::App(process)])
                }
                RestoredPeerAnchor::Controller(receipt) => {
                    ensure!(
                        input.local.stage.data.role == super::NativeRole::AppHost
                            && input.remote.stage.data.role == super::NativeRole::EpochController,
                        "restore_current_anchor_role"
                    );
                    AnchorSource::RestoredController(receipt)
                }
            };
            let mut anchor = Self {
                statement: input.remote.clone(),
                source,
                valid: true,
            };
            anchor.check_continuity(stage, acquisition)?;
            Ok(anchor)
        })();
        let checked = stage
            .storage()
            .and_then(|mut storage| storage.check_storage_acquisition(acquisition));
        if requested.is_err() || checked.is_err() {
            input.channel_refusal.set(true);
            if let Some(original) = &input.native_refusal {
                original.refuse();
            }
            if let Some(tail) = &mut input.tail {
                tail.refuse();
            }
            acquisition.refuse();
            stage.refuse_serving();
        }
        let anchor = requested?;
        checked?;
        Ok(anchor)
    }

    pub(super) fn statement(&self) -> &StageStatement {
        &self.statement
    }

    /// Original peer identity/liveness only, never permission for a request.
    /// A new exchange must authenticate its own signed request and interval.
    pub(super) fn check_continuity(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "storage_peer_retained_process_refused");
            {
                let mut storage = stage.storage()?;
                storage.check_storage_acquisition(acquisition)?;
                let local = storage.storage_statement()?;
                ensure!(
                    self.statement.certificate == local.certificate
                        && self.statement.stage.data.policy == local.stage.data.policy
                        && self.statement.stage.data.role == storage.storage_peer_role()?,
                    "storage_peer_original_issuer_or_role_changed"
                );
            }
            let mut same_actor = Vec::new();
            match &mut self.source {
                AnchorSource::Admitted(processes) => {
                    ensure!(
                        !processes.is_empty() && processes.len() <= 5,
                        "storage_peer_retained_process_refused"
                    );
                    for sender in processes {
                        match sender {
                            StorageSender::App(process) => {
                                ensure!(
                                    process.data() == &self.statement.stage.data.process,
                                    "storage_peer_message_sender_changed"
                                );
                                same_actor.push(process.as_mut());
                            }
                            StorageSender::Controller(receipt) => {
                                receipt.check_continuity(&self.statement, stage, acquisition)?;
                            }
                        }
                    }
                }
                AnchorSource::RestoredController(receipt) => {
                    receipt.check_current_anchor(&self.statement, stage, acquisition)?;
                }
            }
            if !same_actor.is_empty() {
                MessageProcess::check_same_actor(
                    &mut same_actor,
                    acquisition,
                    &HashCosts::disabled(),
                )?;
            }
            stage.storage()?.check_storage_acquisition(acquisition)
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <PeerAnchor as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
};
