//! Retained actual per-message sender handles, not reconstructed numeric PIDs.

use super::storage_peer_wire::{Message, StageStatement};
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

    /// A fresh request can only borrow an actual fully admitted peer. A saved
    /// statement cannot enter this factory or replace any original handle.
    pub(super) fn authenticate_request(
        &mut self,
        message: &Message,
        statement: StageStatement,
        mut process: StorageSender,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            self.check_continuity(stage, acquisition)?;
            message.verify(&statement)?;
            stage.storage()?.check_admitted_storage_statement(
                &statement,
                &self.statement,
                acquisition,
            )?;
            match &mut process {
                StorageSender::App(process) => {
                    ensure!(
                        process.data() == &self.statement.stage.data.process,
                        "storage_peer_message_sender_changed"
                    );
                    process.check_identity(acquisition, &HashCosts::disabled())?;
                }
                StorageSender::Controller(receipt) => {
                    let original = self
                        .processes
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
                        &self.statement,
                        stage,
                        acquisition,
                    )?;
                }
            }
            self.check_continuity(stage, acquisition)?;
            let mut request = Self {
                statement,
                processes: vec![process],
                valid: true,
            };
            request.check(stage, acquisition)?;
            Ok(request)
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }

    /// Original peer identity/liveness only, never permission for a request.
    /// A new exchange must authenticate its own signed request and interval.
    pub(super) fn check_continuity(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.valid && !self.processes.is_empty() && self.processes.len() <= 5,
                "storage_peer_retained_process_refused"
            );
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
                        receipt.check_continuity(&self.statement, stage, acquisition)?;
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
            self.check(stage, acquisition)?;
            message.verify(&self.statement)?;
            self.check(stage, acquisition)
        })();
        if result.is_err() {
            self.valid = false;
            acquisition.refuse();
        }
        result
    }
}
