//! Retained actual per-message sender handles, not reconstructed numeric PIDs.

use super::serving_peer_wire::{Message, Statement};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::issuer_costs::HashCosts;
use crate::security_epoch::native_enrollment::{
    EnrolledRoleStage, channel::ServingSender, process::MessageProcess,
};
use anyhow::{Result, ensure};

pub(super) struct Peer {
    statement: Statement,
    processes: Vec<ServingSender>,
    valid: bool,
}

impl Peer {
    pub(super) fn authenticate(
        message: &Message,
        statement: Statement,
        process: ServingSender,
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
            ServingSender::Shell(process) => stage.check_serving_shell_statement(
                &owner.statement,
                process.data(),
                acquisition,
            )?,
            ServingSender::Controller(receipt) => {
                receipt.bind(&owner.statement, stage, acquisition)?
            }
        }
        // No peer escapes before this new, complete native sender observation.
        owner.check(stage, acquisition)?;
        Ok(owner)
    }

    pub(super) fn statement(&self) -> &Statement {
        &self.statement
    }

    /// Borrow actual admission, not historical issuer DATA, for one new signed
    /// request. Every packet still supplies its original kernel sender handle.
    pub(super) fn authenticate_request(
        &mut self,
        message: &Message,
        statement: Statement,
        mut process: ServingSender,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Self> {
        let result = (|| {
            self.check_continuity(stage, acquisition)?;
            message.verify(&statement)?;
            stage.check_admitted_serving_statement(&statement, &self.statement, acquisition)?;
            match &mut process {
                ServingSender::Shell(process) => {
                    ensure!(
                        process.data() == &self.statement.stage.data.process,
                        "serving_peer_message_sender_changed"
                    );
                    process.check_identity(acquisition, &HashCosts::disabled())?;
                }
                ServingSender::Controller(receipt) => {
                    let original = self
                        .processes
                        .iter_mut()
                        .find_map(|sender| match sender {
                            ServingSender::Controller(original) => Some(original),
                            ServingSender::Shell(_) => None,
                        })
                        .ok_or_else(|| {
                            anyhow::anyhow!("serving_peer_original_controller_missing")
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

    /// Original peer identity/liveness only, never request permission.
    pub(super) fn check_continuity(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                self.valid && !self.processes.is_empty() && self.processes.len() <= 5,
                "serving_peer_retained_process_refused"
            );
            stage.check_serving_acquisition(acquisition)?;
            let local = stage.serving_statement()?;
            ensure!(
                self.statement.certificate == local.certificate
                    && self.statement.stage.data.policy == local.stage.data.policy
                    && self.statement.stage.data.role == stage.serving_peer_role()?,
                "serving_peer_original_issuer_or_role_changed"
            );
            let mut same_actor = Vec::new();
            for sender in &mut self.processes {
                match sender {
                    ServingSender::Shell(process) => {
                        ensure!(
                            process.data() == &self.statement.stage.data.process,
                            "serving_peer_message_sender_changed"
                        );
                        same_actor.push(process.as_mut());
                    }
                    ServingSender::Controller(receipt) => {
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
            stage.check_serving_acquisition(acquisition)
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
                "serving_peer_retained_process_refused"
            );
            stage.check_serving_acquisition(acquisition)?;
            ensure!(
                acquisition.sample()?.elapsed
                    < std::time::Duration::from_nanos(self.statement.original.deadline_ns),
                "serving_peer_remote_stage_expired"
            );
            let mut same_actor = Vec::new();
            for sender in &mut self.processes {
                match sender {
                    ServingSender::Shell(process) => {
                        ensure!(
                            process.data() == &self.statement.stage.data.process,
                            "serving_peer_message_sender_changed"
                        );
                        same_actor.push(process.as_mut());
                    }
                    ServingSender::Controller(receipt) => {
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
            stage.check_serving_acquisition(acquisition)
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
        process: ServingSender,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            // BeginReady, Offer, CurrentReady, Known and Released each retain
            // the actual authenticated sender throughout a current Shell use.
            ensure!(self.processes.len() < 5, "serving_peer_message_count");
            // Retain the actual newly received handle before fallible checks.
            self.processes.push(process);
            let (received, originals) = self.processes.split_last_mut().unwrap();
            if let ServingSender::Controller(receipt) = received {
                let original = originals
                    .iter_mut()
                    .find_map(|sender| match sender {
                        ServingSender::Controller(original) => Some(original),
                        ServingSender::Shell(_) => None,
                    })
                    .ok_or_else(|| anyhow::anyhow!("serving_peer_original_controller_missing"))?;
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
