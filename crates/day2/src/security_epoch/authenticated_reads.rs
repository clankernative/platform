//! Authenticated epoch READ acquisition. No counter mutation, current bootstrap
//! authority or original-file/app-holder capability is installed by this module.
//! This trusted-native path still needs actual Linux/GKE deployment qualification.

use super::{
    credential_material::CredentialMaterial,
    firestore::{self, EpochObservation, EpochReply, Names, Port, Sample},
    identity_protocol,
    native_clock::NativeAcquisition,
    native_enrollment::EnrolledRoleStage,
    native_identity::NativeProcessObservation,
    transport::{NativeHttp, Route},
};
use crate::security_epoch::native_enrollment::issuer_costs::HashCosts;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{InitialBootstrapPolicy, NativeRole, WorkloadKind},
    },
};
use std::{collections::BTreeMap, io::Read, time::Duration};
use zeroize::Zeroizing;

mod retained;
pub(in crate::security_epoch) use retained::ControllerBorrow;
pub(crate) use retained::{ControllerPort, RetainedEpochReads};

pub(crate) struct AuthenticatedReads<'stage, 'role> {
    stage: &'stage mut EnrolledRoleStage<'role>,
    policy: InitialBootstrapPolicy,
    purpose: NativeRole,
    store: EpochStore,
    http: NativeHttp,
    credential: CredentialMaterial,
    acquisition: NativeAcquisition,
    process: NativeProcessObservation,
    selection: Digest,
    valid: bool,
}

struct RoleGuard<'stage, 'role, 'selection> {
    stage: &'stage mut EnrolledRoleStage<'role>,
    policy: &'selection InitialBootstrapPolicy,
    selection: &'selection EpochStore,
    purpose: NativeRole,
}

impl RoleGuard<'_, '_, '_> {
    fn check(&mut self) -> Result<()> {
        self.stage
            .check_selection(self.policy, self.selection, self.purpose)
    }

    fn request(
        &mut self,
        http: &NativeHttp,
        route: Route<'_>,
        authorization: &reqwest::header::HeaderValue,
        body: Option<&[u8]>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<Vec<u8>> {
        self.check()?;
        let result = http.request(route, authorization, body, acquisition);
        self.check()?;
        result
    }
}

pub(super) fn reader_selection(
    policy: &InitialBootstrapPolicy,
    purpose: NativeRole,
) -> Result<day2_capabilities::security_epoch::bootstrap::NativeRoleSelection<'_>> {
    ensure!(
        purpose != NativeRole::SecurityShell,
        "epoch_native_shell_reader_refused"
    );
    Ok(policy.native_role(purpose))
}

impl<'stage, 'role> AuthenticatedReads<'stage, 'role> {
    pub(super) fn acquire(
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        purpose: NativeRole,
        stage: &'stage mut EnrolledRoleStage<'role>,
    ) -> Result<Self> {
        policy.validate(&BTreeMap::from([(
            policy.epoch_store.id.clone(),
            selection.clone(),
        )]))?;
        let selected = reader_selection(policy, purpose)?;
        let mut guard = RoleGuard {
            stage,
            policy,
            selection,
            purpose,
        };
        guard.check()?;
        let role = selected.workload;
        // The native executable pin must come from the selected admitted profile;
        // matching it alone does not qualify the full deployment/profile/image.
        let mut acquisition = guard
            .stage
            .narrow_io_acquisition(selection.max_lease_seconds)?;
        let process = NativeProcessObservation::acquire(
            selected.code,
            &mut acquisition,
            &HashCosts::disabled(),
        )?;
        guard.check()?;
        let mut ca = Vec::new();
        acquisition.remaining()?;
        let ca_file = std::fs::File::from(rustix::fs::open(
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        ensure!(
            ca_file.metadata()?.is_file(),
            "epoch_native_projection_not_regular"
        );
        ca_file.take(65_537).read_to_end(&mut ca)?;
        guard.check()?;
        acquisition.remaining()?;
        let mut http = NativeHttp::new(selection, &policy.cluster, &ca)?;
        acquisition.remaining()?;
        guard.check()?;
        let source = CredentialMaterial::metadata_source(&mut acquisition)?;
        guard.check()?;
        identity_protocol::project(
            selection,
            &guard.request(
                &http,
                Route::Project,
                &source.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        // Establish the authenticated current recipient before reading or
        // sending either Kubernetes projection. Transport enforces this order.
        http.verify_cluster(&ca, &source.authorization()?, &mut acquisition)?;
        guard.check()?;
        let api = CredentialMaterial::kubernetes_api(&mut acquisition)?;
        guard.check()?;
        let subject = CredentialMaterial::subject(&mut acquisition)?;
        guard.check()?;
        let request = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
            "apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
            "spec":{"token":subject.subject_text()?,"audiences":[role.token_review_audience]}
        }))?);
        let response = Zeroizing::new(guard.request(
            &http,
            Route::TokenReview,
            &api.authorization()?,
            Some(&request),
            &mut acquisition,
        )?);
        let reviewed = identity_protocol::token_review(role, &response)?;
        let ns = &role.namespace.name;
        identity_protocol::namespace(
            role,
            &guard.request(
                &http,
                Route::Namespace(ns),
                &api.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        identity_protocol::service_account(
            role,
            &guard.request(
                &http,
                Route::ServiceAccount {
                    namespace: ns,
                    name: &role.kubernetes_service_account.name,
                },
                &api.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        let owner = identity_protocol::pod(
            role,
            &reviewed,
            &guard.request(
                &http,
                Route::Pod {
                    namespace: ns,
                    name: &reviewed.pod_name,
                },
                &api.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        let replica = match role.workload_kind {
            WorkloadKind::DeploymentV1 => Some(
                guard.request(
                    &http,
                    Route::ReplicaSet {
                        namespace: ns,
                        name: owner
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .context("epoch_identity_replica_set_name")?,
                    },
                    &api.authorization()?,
                    None,
                    &mut acquisition,
                )?,
            ),
            WorkloadKind::StatefulSetV1 => None,
        };
        let route = match role.workload_kind {
            WorkloadKind::DeploymentV1 => Route::Deployment {
                namespace: ns,
                name: &role.workload.name,
            },
            WorkloadKind::StatefulSetV1 => Route::StatefulSet {
                namespace: ns,
                name: &role.workload.name,
            },
        };
        identity_protocol::workload(
            role,
            &owner,
            replica.as_deref(),
            &guard.request(&http, route, &api.authorization()?, None, &mut acquisition)?,
        )?;
        identity_protocol::google_service_account(
            &role.google_service_account,
            &policy.cluster.project,
            &guard.request(
                &http,
                Route::GoogleAccount(&role.google_service_account),
                &source.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        let credential = CredentialMaterial::mint_target(
            &source,
            &role.google_service_account,
            &http,
            &mut acquisition,
        )?;
        guard.check()?;
        identity_protocol::database(
            selection,
            &guard.request(
                &http,
                Route::Database,
                &credential.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        let mut reads = Self {
            stage: guard.stage,
            policy: policy.clone(),
            purpose,
            store: selection.clone(),
            http,
            credential,
            acquisition,
            process,
            selection: Digest::of(selection)?,
            valid: true,
        };
        reads.process.check(&mut reads.acquisition)?;
        reads.stage.check_selection(policy, selection, purpose)?;
        Ok(reads)
    }

    pub(super) fn read(
        &mut self,
        selection: &EpochStore,
        names: &Names,
    ) -> Result<EpochObservation> {
        let result = (|| {
            ensure!(
                self.valid && self.selection == Digest::of(selection)?,
                "epoch_native_read_selection_changed"
            );
            ensure!(
                names.matches_selection(selection),
                "epoch_native_read_names_selection_changed"
            );
            let budget = self.acquisition.budget()?;
            firestore::read_with_budget(&mut ReadPort { owner: self }, names, budget)
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }
    pub(super) fn read_slot(
        &mut self,
        selection: &EpochStore,
        core: &super::control_slot::LogicalCore,
    ) -> Result<super::control_slot_io::SlotObservation> {
        let result = (|| {
            ensure!(
                self.selection == Digest::of(selection)?,
                "epoch_native_read_selection_changed"
            );
            self.sample()?;
            let budget = self.acquisition.budget()?;
            super::control_slot_io::read_with_budget(
                selection,
                core,
                &mut ReadPort { owner: self },
                budget,
            )
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }

    fn sample(&mut self) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "epoch_native_read_refused");
            self.stage
                .check_selection(&self.policy, &self.store, self.purpose)?;
            self.process.check(&mut self.acquisition)?;
            let sample = self.acquisition.sample()?;
            self.stage
                .check_selection(&self.policy, &self.store, self.purpose)?;
            Ok(sample)
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
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
            ensure!(
                self.valid
                    && max_bytes == 65_536
                    && !timeout.is_zero()
                    && timeout <= Duration::from_secs(5),
                "epoch_native_read_budget"
            );
            // Only the two fixed read-only transaction routes exist here. This
            // adapter cannot dispatch the counter writer or construct its permit.
            let route = if url.ends_with("/documents:batchGet") {
                Route::EpochRead
            } else if url.ends_with("/documents:rollback") {
                Route::EpochRollback
            } else {
                anyhow::bail!("epoch_native_read_write_or_route_refused")
            };
            ensure!(
                self.http.matches(&route, url)?,
                "epoch_native_read_route_mismatch"
            );
            self.stage
                .check_selection(&self.policy, &self.store, self.purpose)?;
            self.process.check(&mut self.acquisition)?;
            let bytes = self.http.request_with_ceiling(
                route,
                &self.credential.authorization()?,
                Some(body),
                &mut self.acquisition,
                timeout,
            )?;
            self.process.check(&mut self.acquisition)?;
            self.stage
                .check_selection(&self.policy, &self.store, self.purpose)?;
            Ok(EpochReply {
                status: 200,
                body: bytes,
            })
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }
}

/// This short-lived I/O borrow has no constructor outside the owning read
/// method and cannot outlive the opaque acquisition. The owning material does
/// not implement callback/transport traits or gain their default APIs.
struct ReadPort<'a, 'stage, 'role> {
    owner: &'a mut AuthenticatedReads<'stage, 'role>,
}

impl Port for ReadPort<'_, '_, '_> {
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
