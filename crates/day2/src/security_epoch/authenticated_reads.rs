//! Authenticated epoch READ acquisition. No counter mutation, current bootstrap
//! authority or original-file/app-holder capability is installed by this module.
//! This trusted-native path still needs actual Linux/GKE deployment qualification.

use super::{
    credential_material::CredentialMaterial,
    firestore::{self, EpochObservation, EpochReply, Names, Port, Sample},
    identity_protocol,
    native_clock::NativeAcquisition,
    native_identity::NativeProcessObservation,
    transport::{NativeHttp, Route},
};
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

pub(crate) struct AuthenticatedReads {
    http: NativeHttp,
    credential: CredentialMaterial,
    acquisition: NativeAcquisition,
    process: NativeProcessObservation,
    selection: Digest,
    valid: bool,
}

impl AuthenticatedReads {
    pub(super) fn acquire(
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        purpose: NativeRole,
    ) -> Result<Self> {
        policy.validate(&BTreeMap::from([(
            policy.epoch_store.id.clone(),
            selection.clone(),
        )]))?;
        match purpose {
            NativeRole::EpochController => {}
            NativeRole::AppHost => {
                anyhow::bail!("epoch_native_app_executable_profile_producer_unavailable")
            }
            NativeRole::SecurityShell => {
                anyhow::bail!("epoch_native_shell_executable_profile_producer_unavailable")
            }
        }
        let selected = policy.native_role(purpose);
        let role = selected.workload;
        // The native executable pin must come from the selected admitted profile;
        // matching it alone does not qualify the full deployment/profile/image.
        let mut acquisition = NativeAcquisition::begin(selection.max_lease_seconds)?;
        let process = NativeProcessObservation::acquire(selected.code, &mut acquisition)?;
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
        acquisition.remaining()?;
        let mut http = NativeHttp::new(selection, &policy.cluster, &ca)?;
        acquisition.remaining()?;
        let source = CredentialMaterial::metadata_source(&mut acquisition)?;
        identity_protocol::project(
            selection,
            &http.request(
                Route::Project,
                &source.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        // Establish the authenticated current recipient before reading or
        // sending either Kubernetes projection. Transport enforces this order.
        http.verify_cluster(&ca, &source.authorization()?, &mut acquisition)?;
        let api = CredentialMaterial::kubernetes_api(&mut acquisition)?;
        let subject = CredentialMaterial::subject(&mut acquisition)?;
        let request = Zeroizing::new(serde_json::to_vec(&serde_json::json!({
            "apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
            "spec":{"token":subject.subject_text()?,"audiences":[role.token_review_audience]}
        }))?);
        let response = Zeroizing::new(http.request(
            Route::TokenReview,
            &api.authorization()?,
            Some(&request),
            &mut acquisition,
        )?);
        let reviewed = identity_protocol::token_review(role, &response)?;
        let ns = &role.namespace.name;
        identity_protocol::namespace(
            role,
            &http.request(
                Route::Namespace(ns),
                &api.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        identity_protocol::service_account(
            role,
            &http.request(
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
            &http.request(
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
                http.request(
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
            &http.request(route, &api.authorization()?, None, &mut acquisition)?,
        )?;
        identity_protocol::google_service_account(
            &role.google_service_account,
            &policy.cluster.project,
            &http.request(
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
        identity_protocol::database(
            selection,
            &http.request(
                Route::Database,
                &credential.authorization()?,
                None,
                &mut acquisition,
            )?,
        )?;
        let mut reads = Self {
            http,
            credential,
            acquisition,
            process,
            selection: Digest::of(selection)?,
            valid: true,
        };
        reads.process.check(&mut reads.acquisition)?;
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
    fn sample(&mut self) -> Result<Sample> {
        let result = (|| {
            ensure!(self.valid, "epoch_native_read_refused");
            self.process.check(&mut self.acquisition)?;
            self.acquisition.sample()
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
            self.process.check(&mut self.acquisition)?;
            let bytes = self.http.request_with_ceiling(
                route,
                &self.credential.authorization()?,
                Some(body),
                &mut self.acquisition,
                timeout,
            )?;
            self.process.check(&mut self.acquisition)?;
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
struct ReadPort<'a> {
    owner: &'a mut AuthenticatedReads,
}

impl Port for ReadPort<'_> {
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
