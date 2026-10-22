//! Same-stage read material retained independently of a long mutable stage
//! borrow. Every use reborrows the SAME actual enrollment and original clock.
//! No parsed identity, renewed role, token alone or mutable caller callback can
//! construct this owner. Its short I/O borrow remains read-only.

use super::AuthenticatedReads;
use crate::security_epoch::{
    credential_material::CredentialMaterial,
    firestore::{self, EpochObservation, EpochReply, Names, Port, Sample},
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, SameEnrolledOwner},
    native_identity::NativeProcessObservation,
    transport::{NativeHttp, Route},
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{InitialBootstrapPolicy, NativeRole},
    },
};
use std::time::Duration;

pub(crate) struct RetainedEpochReads {
    owner: SameEnrolledOwner,
    policy: InitialBootstrapPolicy,
    purpose: NativeRole,
    store: EpochStore,
    // Movable only inside the private authenticated-reads implementation. No
    // transport/credential accessor or ownerless writer factory is exposed.
    pub(super) http: NativeHttp,
    pub(super) credential: CredentialMaterial,
    pub(super) acquisition: NativeAcquisition,
    pub(super) process: NativeProcessObservation,
    pub(super) selection: Digest,
    valid: bool,
}

impl AuthenticatedReads<'_, '_> {
    pub(in crate::security_epoch) fn retain_current(mut self) -> Result<RetainedEpochReads> {
        self.sample()?;
        let owner = self.stage.capture_same_owner()?;
        self.sample()?;
        let Self {
            policy,
            purpose,
            store,
            http,
            credential,
            acquisition,
            process,
            selection,
            ..
        } = self;
        Ok(RetainedEpochReads {
            owner,
            policy,
            purpose,
            store,
            http,
            credential,
            acquisition,
            process,
            selection,
            valid: true,
        })
    }
}

impl RetainedEpochReads {
    /// The fixed writer must consume the SAME original read material after
    /// the actual current file/peer join, never a later stage of the same owner.
    pub(super) fn check_bootstrap(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<()> {
        let result = (|| {
            stage.check_selection(policy, store, NativeRole::EpochController)?;
            ensure!(
                self.purpose == NativeRole::EpochController
                    && self.policy == *policy
                    && self.store == *store
                    && self.selection == Digest::of(store)?,
                "epoch_bootstrap_read_selection_changed"
            );
            self.check(stage)?;
            let same = stage.narrow_io_acquisition(store.max_lease_seconds)?;
            self.acquisition.join_current_view(same)?;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.sample(stage).map(|_| ())
    }

    fn sample(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "epoch_retained_read_refused");
            self.owner.check(stage)?;
            stage.check_selection(&self.policy, &self.store, self.purpose)?;
            // This child samples THIS actual stage's original domain; it
            // neither begins a new interval nor renews our retained owner.
            let mut same_stage = stage.narrow_io_acquisition(self.store.max_lease_seconds)?;
            let supplied = same_stage.sample()?;
            let sample = self.acquisition.sample()?;
            ensure!(
                supplied.domain == sample.domain,
                "epoch_retained_read_stage_replaced"
            );
            self.process.check(&mut self.acquisition)?;
            self.owner.check(stage)?;
            Ok(sample)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn read(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        selection: &EpochStore,
        names: &Names,
    ) -> Result<EpochObservation> {
        let result = (|| {
            ensure!(
                self.selection == Digest::of(selection)? && names.matches_selection(selection),
                "epoch_retained_read_selection_changed"
            );
            self.check(stage)?;
            let budget = self.acquisition.budget()?;
            let observed = firestore::read_with_budget(
                &mut CurrentReadPort { owner: self, stage },
                names,
                budget,
            )?;
            self.check(stage)?;
            Ok(observed)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check_observation(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        observation: &mut EpochObservation,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            let selection = self.store.clone();
            observation.remaining(&selection, &mut CurrentReadPort { owner: self, stage })?;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.valid = false;
        self.acquisition.refuse();
    }

    fn post(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        url: &str,
        body: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        let result = (|| {
            self.check(stage)?;
            ensure!(
                max_bytes == 65536
                    && body.len() <= 65536
                    && !timeout.is_zero()
                    && timeout <= Duration::from_secs(5),
                "epoch_retained_read_budget"
            );
            let route = if url.ends_with("/documents:batchGet") {
                Route::EpochRead
            } else if url.ends_with("/documents:rollback") {
                Route::EpochRollback
            } else {
                anyhow::bail!("epoch_retained_read_write_or_route_refused")
            };
            ensure!(
                self.http.matches(&route, url)?,
                "epoch_retained_read_recipient_changed"
            );
            let bytes = self.http.request_with_ceiling(
                route,
                &self.credential.authorization()?,
                Some(body),
                &mut self.acquisition,
                timeout,
            )?;
            self.check(stage)?;
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

struct CurrentReadPort<'io, 'stage, 'role> {
    owner: &'io mut RetainedEpochReads,
    stage: &'stage mut EnrolledRoleStage<'role>,
}

impl Port for CurrentReadPort<'_, '_, '_> {
    fn sample(&mut self) -> Result<Sample> {
        self.owner.sample(self.stage)
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        self.owner.post(self.stage, url, body, timeout, max_bytes)
    }
}
