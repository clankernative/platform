//! Authenticated epoch READ acquisition. No counter mutation, current bootstrap
//! authority or original-file/app-holder capability is installed by this module.
//! This trusted-native path still needs actual Linux/GKE deployment qualification.

use super::{
    credential_material::CredentialMaterial,
    firestore::Sample,
    identity_protocol,
    native_clock::{AppAuthentication, NativeAcquisition},
    native_enrollment::{EnrolledRoleStage, EnrolledStorageStage, StagePurpose},
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
    acquisition: ProviderAcquisition,
    process: NativeProcessObservation,
    selection: Digest,
    valid: bool,
}

// Internal clock carrier only. An App work window cannot be converted into an
// owned I/O clock here: only its actual stage may consume its opaque marker.
pub(super) struct ProviderAcquisition {
    clock: ProviderClock,
}

enum ProviderClock {
    Native(NativeAcquisition),
    App(AppAuthentication),
}

impl ProviderAcquisition {
    pub(super) fn native(acquisition: NativeAcquisition) -> Self {
        Self {
            clock: ProviderClock::Native(acquisition),
        }
    }

    pub(super) fn app(authentication: AppAuthentication) -> Self {
        Self {
            clock: ProviderClock::App(authentication),
        }
    }

    pub(super) fn acquisition(&mut self) -> &mut NativeAcquisition {
        match &mut self.clock {
            ProviderClock::Native(acquisition) => acquisition,
            ProviderClock::App(authentication) => authentication.acquisition(),
        }
    }

    pub(super) fn complete_app(
        self,
        mut stage: EnrolledStorageStage<'_, '_>,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        match self.clock {
            ProviderClock::App(authentication) => {
                stage.complete_app_authentication(authentication, max_lease_seconds)
            }
            ProviderClock::Native(mut acquisition) => {
                acquisition.refuse();
                stage.refuse_app_authentication();
                anyhow::bail!("epoch_native_app_authentication_provenance_changed")
            }
        }
    }

    pub(super) fn into_native(self) -> Result<NativeAcquisition> {
        match self.clock {
            ProviderClock::Native(acquisition) => Ok(acquisition),
            ProviderClock::App(mut authentication) => {
                authentication.acquisition().refuse();
                anyhow::bail!("epoch_native_authentication_provenance_changed")
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadScope {
    Current,
    AppServing,
    StorageBootstrap,
    StorageMetadataObservation,
}

impl ReadScope {
    fn check_selection(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        purpose: NativeRole,
    ) -> Result<()> {
        match self {
            Self::Current => {
                stage.check_current_selection(policy, selection, purpose, StagePurpose::CurrentRole)
            }
            Self::AppServing => {
                stage.check_current_selection(policy, selection, purpose, StagePurpose::AppServing)
            }
            Self::StorageBootstrap | Self::StorageMetadataObservation => {
                stage.check_selection(policy, selection, purpose)?;
                self.require(stage)
            }
        }
    }

    fn require(self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        stage.require_purpose(match self {
            Self::Current => StagePurpose::CurrentRole,
            Self::AppServing => StagePurpose::AppServing,
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
            Self::AppServing => {
                anyhow::bail!("epoch_app_authentication_must_start_at_entry")
            }
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
            Self::AppServing => stage
                .storage()?
                .narrow_app_serving_io_acquisition(max_lease_seconds),
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
            Self::Current | Self::AppServing => retained.join_current_view(actual),
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
            Self::Current | Self::AppServing => retained.exchange_current_views(actual),
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
        self.scope
            .check_selection(self.stage, self.policy, self.selection, self.purpose)
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

    pub(super) fn acquire_app_serving(
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        purpose: NativeRole,
        stage: &'stage mut EnrolledRoleStage<'role>,
    ) -> Result<Self> {
        Self::acquire_scoped(policy, selection, purpose, stage, ReadScope::AppServing)
            .context("epoch_app_provider_authentication")
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
        // Capture before policy validation, the first native guard, or any
        // credential/provider work. The opaque window keeps the original App
        // parent and selected ceilings; starting it cannot renew an old grant.
        let app_authentication = if scope == ReadScope::AppServing {
            Some(
                stage
                    .begin_app_authentication(selection.max_lease_seconds)
                    .context("epoch_app_provider_authentication_begin")?,
            )
        } else {
            None
        };
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
        let mut acquisition = match app_authentication {
            Some(authentication) => ProviderAcquisition::app(authentication),
            None => ProviderAcquisition::native(
                scope.authentication(guard.stage, selection.max_lease_seconds)?,
            ),
        };
        let process = NativeProcessObservation::acquire(
            selected.code,
            acquisition.acquisition(),
            &HashCosts::disabled(),
        )?;
        guard.check()?;
        let mut ca = Vec::new();
        acquisition.acquisition().remaining()?;
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
        acquisition.acquisition().remaining()?;
        let mut http = NativeHttp::new(selection, &policy.cluster, &ca)?;
        acquisition.acquisition().remaining()?;
        guard.check()?;
        let source = CredentialMaterial::metadata_source(acquisition.acquisition())?;
        guard.check()?;
        identity_protocol::project(
            selection,
            &guard.request(
                &http,
                Route::Project,
                &source.authorization()?,
                None,
                acquisition.acquisition(),
            )?,
        )?;
        // Establish the authenticated current recipient before reading or
        // sending either Kubernetes projection. Transport enforces this order.
        http.verify_cluster(&ca, &source.authorization()?, acquisition.acquisition())?;
        guard.check()?;
        let api = CredentialMaterial::kubernetes_api(acquisition.acquisition())?;
        guard.check()?;
        let subject = CredentialMaterial::subject(acquisition.acquisition())?;
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
            acquisition.acquisition(),
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
                acquisition.acquisition(),
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
                acquisition.acquisition(),
            )?,
        )?;
        let (_, owner) = identity_protocol::pod(
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
                acquisition.acquisition(),
            )?,
        )?
        .into_parts();
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
                    acquisition.acquisition(),
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
            &guard.request(
                &http,
                route,
                &api.authorization()?,
                None,
                acquisition.acquisition(),
            )?,
        )?;
        identity_protocol::google_service_account(
            &role.google_service_account,
            &policy.cluster.project,
            &guard.request(
                &http,
                Route::GoogleAccount(&role.google_service_account),
                &source.authorization()?,
                None,
                acquisition.acquisition(),
            )?,
        )?;
        let credential = CredentialMaterial::mint_target(
            &source,
            &role.google_service_account,
            &http,
            acquisition.acquisition(),
        )?;
        guard.check()?;
        identity_protocol::database(
            selection,
            &guard.request(
                &http,
                Route::Database,
                &credential.authorization()?,
                None,
                acquisition.acquisition(),
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
        reads.process.check(reads.acquisition.acquisition())?;
        reads
            .scope
            .check_selection(reads.stage, policy, selection, purpose)?;
        Ok(reads)
    }

    fn sample(&mut self) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "epoch_native_read_refused");
            self.scope
                .check_selection(self.stage, &self.policy, &self.store, self.purpose)?;
            self.process.check(self.acquisition.acquisition())?;
            let sample = self.acquisition.acquisition().sample()?;
            self.scope
                .check_selection(self.stage, &self.policy, &self.store, self.purpose)?;
            Ok(sample)
        })();
        if result.is_err() {
            self.valid = false;
            self.acquisition.acquisition().refuse();
        }
        result
    }
}
