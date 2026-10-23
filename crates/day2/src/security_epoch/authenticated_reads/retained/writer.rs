//! Fixed Controller counter transport. It retains the SAME native physical and
//! authenticated peer phase throughout each request; read credentials or parsed
//! policy DATA alone cannot install this port.

use super::{ControllerEpochReads, ReadScope, RetainedEpochReads};
use crate::security_epoch::CurrentStorageBootstrapPhase;
use crate::security_epoch::{
    controller::preparation_timing::{Operation, Timings},
    firestore::{Budget, EpochReply, Port, Sample},
    transport::Route,
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{InitialBootstrapPolicy, NativeRole},
    },
};
use std::{cell::RefCell, rc::Rc, time::Duration};

pub(crate) struct ControllerPort<'storage, 'role> {
    owner: Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
    reads: ControllerEpochReads,
    selection: Digest,
    valid: bool,
    timings: Timings,
}

/// A short-lived borrow only; it cannot outlive or reconstruct the actual
/// owning material and grants no generic adapter API to that owner.
pub(in crate::security_epoch) struct ControllerBorrow<'io, 'storage, 'role> {
    owner: &'io mut ControllerPort<'storage, 'role>,
}

impl<'storage, 'role> ControllerPort<'storage, 'role> {
    pub(in crate::security_epoch) fn borrow(&mut self) -> ControllerBorrow<'_, 'storage, 'role> {
        ControllerBorrow { owner: self }
    }

    pub(in crate::security_epoch) fn acquire(
        owner: Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        reads: ControllerEpochReads,
        timings: Timings,
    ) -> Result<Self> {
        let state = Rc::clone(&reads.state);
        let guard = state.gate.guard()?;
        let result = (|| {
            let mut phase = owner.try_borrow_mut()?;
            // Resolve the actual phase BEFORE borrowing shared material:
            // phase checks themselves reborrow that same provider context.
            timings.measure(Operation::BootstrapWriterPhase, || {
                phase.check_authenticated_reads(&reads)
            })?;
            let stage = phase.controller_stage()?;
            let borrow = state.gate.enter()?;
            let mut material = state.material.try_borrow_mut()?;
            timings.measure(Operation::BootstrapWriterMaterial, || {
                material.check_bootstrap(stage, policy, store)
            })?;
            let selection = material.selection.clone();
            drop(material);
            borrow.complete()?;
            drop(phase);
            let mut port = Self {
                owner: Rc::clone(&owner),
                reads,
                selection,
                valid: true,
                timings: timings.clone(),
            };
            port.sample()?;
            guard.complete()?;
            Ok(port)
        })();
        if result.is_err() {
            state.refuse();
            if let Ok(mut phase) = owner.try_borrow_mut() {
                phase.refuse();
            }
        }
        result
    }

    pub(in crate::security_epoch) fn context_interval(
        &mut self,
        owner: &Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
        selection: &EpochStore,
    ) -> Result<(Sample, Duration)> {
        let result = (|| {
            ensure!(
                Rc::ptr_eq(owner, &self.owner),
                "epoch_writer_original_owner_changed"
            );
            ensure!(
                self.selection == Digest::of(selection)?,
                "epoch_writer_selection_changed"
            );
            let sample = self.sample()?;
            let guard = self.reads.state.gate.enter()?;
            let (_, deadline) = self
                .reads
                .state
                .material
                .try_borrow_mut()?
                .acquisition
                .interval_data()?;
            guard.complete()?;
            Ok((sample, deadline))
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn budget(&mut self) -> Result<Budget> {
        self.sample()?;
        let guard = self.reads.state.gate.enter()?;
        let result = self
            .reads
            .state
            .material
            .try_borrow_mut()?
            .acquisition
            .budget()?;
        guard.complete()?;
        Ok(result)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.valid = false;
        self.reads.refuse();
        if let Ok(mut phase) = self.owner.try_borrow_mut() {
            phase.refuse();
        }
    }
}

impl ControllerPort<'_, '_> {
    /// Pure decoding consumes THIS retained acquisition, not a reconstructed
    /// clock or successful native-check cache. The same local owners and shared
    /// refusal gate stay borrowed; full sample/post/transfer guards are separate.
    fn decoding_sample(&mut self) -> Result<Sample> {
        let result = (|| {
            let guard = self.reads.state.gate.guard()?;
            ensure!(self.valid, "epoch_writer_refused");
            let phase = self.owner.try_borrow()?;
            phase.check_budget_liveness()?;
            let borrow = self.reads.state.gate.enter()?;
            let mut material = self.reads.state.material.try_borrow_mut()?;
            ensure!(
                material.valid
                    && material.scope == ReadScope::StorageBootstrap
                    && material.purpose == NativeRole::EpochController,
                "epoch_bootstrap_read_purpose_changed"
            );
            material.acquisition.require_storage_bootstrap()?;
            let sample = material.acquisition.sample()?;
            drop(material);
            borrow.complete()?;
            drop(phase);
            guard.complete()?;
            Ok(sample)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn sample(&mut self) -> Result<Sample> {
        // Count every full composite observation, not just acquisition's
        // first one. These inclusive timings do not grant or cache authority.
        let timings = self.timings.clone();
        let result = timings.measure(Operation::BootstrapWriterSample, || {
            let guard = self.reads.state.gate.guard()?;
            ensure!(self.valid, "epoch_writer_refused");
            self.owner.try_borrow_mut()?.check()?;
            let mut phase = self.owner.try_borrow_mut()?;
            let stage = phase.controller_stage()?;
            let borrow = self.reads.state.gate.enter()?;
            let mut material = self.reads.state.material.try_borrow_mut()?;
            let sample = material.sample(stage)?;
            drop(material);
            borrow.complete()?;
            drop(phase);
            self.owner.try_borrow_mut()?.check()?;
            guard.complete()?;
            Ok(sample)
        });
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        let result = (|| {
            let guard = self.reads.state.gate.guard()?;
            self.sample()?;
            ensure!(
                max_bytes == 65_536
                    && body.len() <= 65_536
                    && !timeout.is_zero()
                    && timeout <= Duration::from_secs(5),
                "epoch_writer_budget"
            );
            let mut phase = self.owner.try_borrow_mut()?;
            let stage = phase.controller_stage()?;
            let borrow = self.reads.state.gate.enter()?;
            let mut material = self.reads.state.material.try_borrow_mut()?;
            material.sample(stage)?;
            let (route, operation) = writer_route(url)?;
            ensure!(
                material.http.matches(&route, url)?,
                "epoch_writer_recipient_changed"
            );
            let RetainedEpochReads {
                http,
                credential,
                acquisition,
                ..
            } = &mut *material;
            // Keep this fallible evaluation outside the diagnostic closure:
            // failure must exit before both request and post-request sampling.
            let authorization = credential.authorization()?;
            let requested = self.timings.measure(operation, || {
                http.request_with_ceiling(route, &authorization, Some(body), acquisition, timeout)
            });
            let checked = material.sample(stage);
            let bytes = requested?;
            checked?;
            drop(material);
            borrow.complete()?;
            drop(phase);
            self.sample()?;
            guard.complete()?;
            Ok(EpochReply {
                status: 200,
                body: bytes,
            })
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

impl<'storage, 'role> ControllerBorrow<'_, 'storage, 'role> {
    pub(in crate::security_epoch) fn context_interval(
        &mut self,
        owner: &Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
        selection: &EpochStore,
    ) -> Result<(Sample, Duration)> {
        self.owner.context_interval(owner, selection)
    }

    pub(in crate::security_epoch) fn budget(&mut self) -> Result<Budget> {
        self.owner.budget()
    }
}

impl Port for ControllerBorrow<'_, '_, '_> {
    fn sample(&mut self) -> Result<Sample> {
        self.owner.sample()
    }

    fn decoding_sample(&mut self) -> Result<Sample> {
        self.owner.decoding_sample()
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        self.owner.post(url, body, timeout, max_bytes)
    }
}

// Route selection is DATA; NativeHttp additionally requires the exact selected
// project/database URL. This function cannot issue a request or mint a writer.
fn writer_route(url: &str) -> Result<(Route<'static>, Operation)> {
    if url.ends_with("/documents:batchGet") {
        Ok((Route::EpochRead, Operation::BootstrapFirestoreRead))
    } else if url.ends_with("/documents:rollback") {
        Ok((Route::EpochRollback, Operation::BootstrapFirestoreRollback))
    } else if url.ends_with("/documents:commit") {
        Ok((Route::EpochCommit, Operation::BootstrapFirestoreCommit))
    } else {
        anyhow::bail!("epoch_writer_route_refused")
    }
}

#[cfg(test)]
mod tests {
    use super::writer_route;

    #[test]
    fn counter_routes_are_closed_and_transport_checks_the_selected_recipient() {
        for operation in ["batchGet", "rollback", "commit"] {
            assert!(writer_route(&format!("https://firestore.googleapis.com/v1/projects/p/databases/d/documents:{operation}")).is_ok());
        }
        for url in [
            "https://other/commit",
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:commit?x=1",
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:delete",
        ] {
            assert!(writer_route(url).is_err());
        }
    }
}
