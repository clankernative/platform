//! Fixed Controller counter transport. It retains the SAME native physical and
//! authenticated peer phase throughout each request; read credentials or parsed
//! policy DATA alone cannot install this port.

use super::RetainedEpochReads;
use crate::security_epoch::CurrentStorageBootstrapPhase;
use crate::security_epoch::{
    credential_material::CredentialMaterial,
    firestore::{Budget, EpochReply, Port, Sample},
    native_clock::NativeAcquisition,
    native_identity::NativeProcessObservation,
    transport::{NativeHttp, Route},
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};
use std::{cell::RefCell, rc::Rc, time::Duration};

pub(crate) struct ControllerPort<'storage, 'role> {
    owner: Rc<RefCell<CurrentStorageBootstrapPhase<'storage, 'role>>>,
    http: NativeHttp,
    credential: CredentialMaterial,
    acquisition: NativeAcquisition,
    process: NativeProcessObservation,
    selection: Digest,
    valid: bool,
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
        mut reads: RetainedEpochReads,
    ) -> Result<Self> {
        let result = (|| {
            let mut phase = owner.try_borrow_mut()?;
            reads.check_bootstrap(phase.controller_stage()?, policy, store)?;
            // Move the actual read-only material acquired before the peer
            // join. The SAME original role/clock/material is checked above;
            // only THIS genuine file/peer owner installs the fixed writer.
            let RetainedEpochReads {
                http,
                credential,
                acquisition,
                process,
                selection,
                ..
            } = reads;
            drop(phase);
            let mut port = Self {
                owner: Rc::clone(&owner),
                http,
                credential,
                acquisition,
                process,
                selection,
                valid: true,
            };
            port.sample()?;
            Ok(port)
        })();
        if result.is_err()
            && let Ok(mut phase) = owner.try_borrow_mut()
        {
            phase.refuse();
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
            let (_, deadline) = self.acquisition.interval_data()?;
            Ok((sample, deadline))
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn budget(&mut self) -> Result<Budget> {
        self.sample()?;
        self.acquisition.budget()
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.valid = false;
        self.acquisition.refuse();
        if let Ok(mut phase) = self.owner.try_borrow_mut() {
            phase.refuse();
        }
    }
}

impl ControllerPort<'_, '_> {
    fn sample(&mut self) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "epoch_writer_refused");
            self.owner.try_borrow_mut()?.check()?;
            self.process.check(&mut self.acquisition)?;
            let sample = self.acquisition.sample()?;
            self.owner.try_borrow_mut()?.check()?;
            Ok(sample)
        })();
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
            self.sample()?;
            ensure!(
                max_bytes == 65_536
                    && body.len() <= 65_536
                    && !timeout.is_zero()
                    && timeout <= Duration::from_secs(5),
                "epoch_writer_budget"
            );
            let route = writer_route(url)?;
            ensure!(
                self.http.matches(&route, url)?,
                "epoch_writer_recipient_changed"
            );
            let bytes = self.http.request_with_ceiling(
                route,
                &self.credential.authorization()?,
                Some(body),
                &mut self.acquisition,
                timeout,
            )?;
            self.sample()?;
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
fn writer_route(url: &str) -> Result<Route<'static>> {
    if url.ends_with("/documents:batchGet") {
        Ok(Route::EpochRead)
    } else if url.ends_with("/documents:rollback") {
        Ok(Route::EpochRollback)
    } else if url.ends_with("/documents:commit") {
        Ok(Route::EpochCommit)
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
