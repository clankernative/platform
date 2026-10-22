//! Authenticated epoch READ acquisition. No counter mutation, current bootstrap
//! authority or original-file/app-holder capability is installed by this module.
//! This trusted-native path still needs actual Linux/GKE deployment qualification.

use super::{
    credential_material::CredentialMaterial,
    firestore::Sample,
    identity_protocol,
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, StagePurpose},
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
use std::{collections::BTreeMap, io::Read};
use zeroize::Zeroizing;

mod retained;
pub(in crate::security_epoch) use retained::ControllerBorrow;
pub(in crate::security_epoch) use retained::RefusalGuard;
pub(in crate::security_epoch) use retained::StorageMetadataRead;
pub(crate) use retained::{
    ControllerEpochReads, ControllerPort, ProviderEpochReads, RetainedEpochReads,
};

pub(crate) struct AuthenticatedReads<'stage, 'role> {
    scope: ReadScope,
    stage: &'stage mut EnrolledRoleStage<'role>,
    policy: InitialBootstrapPolicy,
    purpose: NativeRole,
    store: EpochStore,
    http: NativeHttp,
    credential: CredentialMaterial,
    source: CredentialMaterial,
    kubernetes: CredentialMaterial,
    acquisition: NativeAcquisition,
    process: NativeProcessObservation,
    selection: Digest,
    valid: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadScope {
    Current,
    StorageBootstrap,
    StorageMetadataObservation,
}

impl ReadScope {
    fn require(self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        stage.require_purpose(match self {
            Self::Current => StagePurpose::CurrentRole,
            Self::StorageBootstrap => StagePurpose::StorageBootstrap,
            Self::StorageMetadataObservation => StagePurpose::StorageMetadataObservation,
        })
    }

    fn authentication(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        self.require(stage)?;
        match self {
            Self::Current => stage.narrow_io_acquisition(max_lease_seconds),
            Self::StorageBootstrap | Self::StorageMetadataObservation => {
                let mut child = stage.storage()?.narrow_storage_authentication()?;
                let (_, ceiling) = child.interval_data()?;
                child.narrow(max_lease_seconds, ceiling)
            }
        }
    }

    fn io(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        self.require(stage)?;
        match self {
            Self::Current => stage.narrow_io_acquisition(max_lease_seconds),
            Self::StorageBootstrap => stage
                .storage()?
                .narrow_storage_bootstrap_io_acquisition(max_lease_seconds),
            Self::StorageMetadataObservation => stage
                .storage()?
                .narrow_storage_metadata_observation_io_acquisition(max_lease_seconds),
        }
    }

    fn join(self, retained: &mut NativeAcquisition, actual: NativeAcquisition) -> Result<()> {
        match self {
            Self::Current => retained.join_current_view(actual),
            Self::StorageBootstrap => retained.join_storage_bootstrap_view(actual),
            Self::StorageMetadataObservation => {
                retained.join_storage_metadata_observation_view(actual)
            }
        }
    }

    fn exchange(
        self,
        retained: &mut NativeAcquisition,
        actual: &mut NativeAcquisition,
    ) -> Result<()> {
        match self {
            Self::Current => retained.exchange_current_views(actual),
            Self::StorageBootstrap => retained.exchange_storage_bootstrap_views(actual),
            Self::StorageMetadataObservation => {
                retained.exchange_storage_metadata_observation_views(actual)
            }
        }
    }
}

struct RoleGuard<'stage, 'role, 'selection> {
    scope: ReadScope,
    stage: &'stage mut EnrolledRoleStage<'role>,
    policy: &'selection InitialBootstrapPolicy,
    selection: &'selection EpochStore,
    purpose: NativeRole,
}

impl RoleGuard<'_, '_, '_> {
    fn check(&mut self) -> Result<()> {
        self.stage
            .check_selection(self.policy, self.selection, self.purpose)?;
        self.scope.require(self.stage)
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
        // Always retain the original postcheck and its terminal refusal. If
        // BOTH failed, report the first request failure, including its bounded
        // request-window DATA, rather than the later spent-stage consequence.
        let checked = self.check();
        let bytes = result?;
        checked?;
        Ok(bytes)
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
        Self::acquire_scoped(policy, selection, purpose, stage, ReadScope::Current)
    }

    pub(super) fn acquire_storage_bootstrap(
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        purpose: NativeRole,
        stage: &'stage mut EnrolledRoleStage<'role>,
    ) -> Result<Self> {
        Self::acquire_scoped(
            policy,
            selection,
            purpose,
            stage,
            ReadScope::StorageBootstrap,
        )
    }

    pub(super) fn acquire_storage_metadata_observation(
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        stage: &'stage mut EnrolledRoleStage<'role>,
    ) -> Result<Self> {
        Self::acquire_scoped(
            policy,
            selection,
            NativeRole::EpochController,
            stage,
            ReadScope::StorageMetadataObservation,
        )
    }

    fn acquire_scoped(
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        purpose: NativeRole,
        stage: &'stage mut EnrolledRoleStage<'role>,
        scope: ReadScope,
    ) -> Result<Self> {
        policy.validate(&BTreeMap::from([(
            policy.epoch_store.id.clone(),
            selection.clone(),
        )]))?;
        let selected = reader_selection(policy, purpose)?;
        let mut guard = RoleGuard {
            scope,
            stage,
            policy,
            selection,
            purpose,
        };
        guard.check()?;
        let role = selected.workload;
        // The native executable pin must come from the selected admitted profile;
        // matching it alone does not qualify the full deployment/profile/image.
        let mut acquisition = scope.authentication(guard.stage, selection.max_lease_seconds)?;
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
            scope,
            stage: guard.stage,
            policy: policy.clone(),
            purpose,
            store: selection.clone(),
            http,
            credential,
            source,
            kubernetes: api,
            acquisition,
            process,
            selection: Digest::of(selection)?,
            valid: true,
        };
        reads.process.check(&mut reads.acquisition)?;
        reads.stage.check_selection(policy, selection, purpose)?;
        reads.scope.require(reads.stage)?;
        Ok(reads)
    }

    fn sample(&mut self) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "epoch_native_read_refused");
            self.stage
                .check_selection(&self.policy, &self.store, self.purpose)?;
            self.scope.require(self.stage)?;
            self.process.check(&mut self.acquisition)?;
            let sample = self.acquisition.sample()?;
            self.stage
                .check_selection(&self.policy, &self.store, self.purpose)?;
            self.scope.require(self.stage)?;
            Ok(sample)
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.refuse();
        }
        result
    }
}
