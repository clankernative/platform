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
            ServingSender::Shell(process) => {
                process.check_identity(acquisition, &HashCosts::disabled())?;
                stage.check_serving_shell_statement(
                    &owner.statement,
                    process.data(),
                    acquisition,
                )?;
                process.check_identity(acquisition, &HashCosts::disabled())?
            }
            ServingSender::Controller(receipt) => {
                receipt.bind(&owner.statement, stage, acquisition)?
            }
        }
        owner.check(stage, acquisition)?;
        Ok(owner)
    }

    pub(super) fn statement(&self) -> &Statement {
        &self.statement
    }

    /// Original peer identity/liveness only. Deliberately does NOT renew or
    /// accept the old signed stage as current. A new exchange must authenticate
    /// fresh grants before CurrentServingPeerPhase can be constructed.
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
                        receipt.bind(&self.statement, stage, acquisition)?
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
