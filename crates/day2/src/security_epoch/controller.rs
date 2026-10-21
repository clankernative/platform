//! Fixed initial-only protocol executor. All native owners remain on THIS OS
//! thread. Idle probes create DATA, never a role lease or action permission.
use crate::artifact::Instance;
use crate::security_epoch::{
    bootstrap::{self, ControllerActivationOutcome},
    native_enrollment::{
        ControllerServingListener, ControllerServingPeer, EnrolledProcessRoleOwner,
        InitialHolderListener, NativeRole,
    },
    storage_authority::{self, InitialStorageContinuity, InitialStorageOutcome},
};
use anyhow::{Context, Result, ensure};
use std::{path::Path, time::Duration};

pub(in crate::security_epoch) mod evidence;
mod health;
pub(in crate::security_epoch) mod preparation_timing;
use evidence::{Evidence, FailurePhase, PreparationFailure, PreparationStep, ServingRole};
use preparation_timing::{Operation, Timings};

pub(crate) fn run(instance_path: &Path, app: &str) -> Result<()> {
    run_mode(instance_path, app, false)
}

/// Read-only diagnosis on an actually enrolled Controller. It cannot reach
/// private-directory creation, initial-file creation or any provider mutation.
pub(crate) fn observe_preparation(instance_path: &Path, app: &str) -> Result<()> {
    run_mode(instance_path, app, true)
}

fn run_mode(instance_path: &Path, app: &str, read_only: bool) -> Result<()> {
    let mut evidence = Evidence::new();
    let result = run_inner(instance_path, app, &mut evidence, read_only);
    let recorded = match &result {
        Err(error) => evidence.refuse(Some(error)),
        Ok(()) => Ok(()),
    };
    preserve_native_failure(result, recorded)
}

fn preserve_native_failure(result: Result<()>, recorded: Result<()>) -> Result<()> {
    match result {
        Err(error) if recorded.is_err() => Err(error.context("native_evidence_export_failed")),
        Err(error) => Err(error),
        Ok(()) => recorded,
    }
}

fn run_inner(
    instance_path: &Path,
    app: &str,
    evidence: &mut Evidence,
    read_only: bool,
) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "native_controller_platform_unsupported"
    );
    let instance = Instance::load(instance_path)?;
    let policy = instance
        .native_bootstrap_for(app)?
        .context("native_controller_explicit_profile_required")?
        .clone();
    let store = instance
        .control
        .as_ref()
        .context("native_controller_catalog_required")?
        .security_epochs
        .get(&policy.epoch_store.id)
        .context("native_controller_epoch_required")?
        .clone();
    evidence.select(&policy, &store)?;
    // Artifact/instance admission produces desired DATA, not a role, storage
    // owner or prepared image. Do its worker exchanges before creating any
    // native acquisition; the original phase still rechecks this selection.
    evidence.enter(FailurePhase::Preparation);
    let metadata = crate::store::InitialStoreMetadata::load(instance_path, app)
        .and_then(|metadata| {
            metadata.require_native_selection(
                &store,
                &policy.runtime_profile.app_artifact,
                &policy,
            )?;
            Ok(metadata)
        })
        .map_err(|error| PreparationFailure::at(PreparationStep::ImageAdmission, error))?;
    evidence.enter(FailurePhase::Enrollment);
    let mut role = EnrolledProcessRoleOwner::enroll_current_thread(
        &policy.scope,
        NativeRole::EpochController,
    )?;
    evidence.enrolled(role.historical_incarnation_data())?;
    evidence.enter(FailurePhase::Preparation);
    let timings = Timings::new();
    if read_only {
        let result = timings
            .measure(Operation::RoleStage, || role.begin_current_stage())
            .map_err(|error| PreparationFailure::at(PreparationStep::RoleStage, error))
            .and_then(|stage| {
                storage_authority::observe_preparation_read_only(stage, &policy, &store, &timings)
            });
        // The actual stage/resources have unwound. This record grants nothing;
        // returning here unconditionally excludes every creation/serving path.
        if result.is_err() {
            // The ordinary single refusal exports both timing and the original
            // native boundary, without a preceding potentially partial record.
            evidence.preparation_timings(timings.summary());
            return result;
        }
        return evidence.preparation_read_only(timings.summary(), true);
    }
    let result = timings
        .measure(Operation::RoleStage, || role.begin_current_stage())
        .map_err(|error| PreparationFailure::at(PreparationStep::RoleStage, error))
        .and_then(|stage| {
            storage_authority::prepare_controller_initial(
                &metadata, stage, &policy, &store, &timings,
            )
        });
    // Cache only DATA; no logging while the original phase remains live. A
    // later first-holder/refusal record includes completed diagnostic rows.
    evidence.preparation_timings(timings.summary());
    let mut file = result?;
    evidence.enter(FailurePhase::HolderListener);
    let result = timings
        .measure(Operation::HolderRole, || role.begin_current_stage())
        .map_err(|error| PreparationFailure::at(PreparationStep::HolderRoleStage, error))
        .and_then(|stage| {
            timings.measure(Operation::HolderListener, || {
                let phase = file.begin_initial_phase(stage).map_err(|error| {
                    PreparationFailure::at(PreparationStep::HolderFilePhase, error)
                })?;
                InitialHolderListener::bind(phase).map_err(|error| {
                    PreparationFailure::at(PreparationStep::HolderListenerBind, error)
                })
            })
        });
    // The file phase has completed/unwound before the ending measurement.
    // Cache both outcomes without logging or returning a permission here.
    evidence.preparation_timings(timings.summary());
    let mut holder_listener = result?;
    while !holder_listener.idle_ready()? {
        // No role/file permission remains live while waiting for Kubernetes
        // startup. Start a fresh same-owner phase only after actual pending DATA.
        std::thread::park_timeout(Duration::from_millis(5));
    }
    evidence.enter(FailurePhase::FirstHolder);
    let stage = timings
        .measure(Operation::FirstRole, || role.begin_current_stage())
        .map_err(|error| PreparationFailure::at(PreparationStep::FirstRole, error));
    evidence.preparation_timings(timings.summary());
    let result = InitialStorageContinuity::establish(file, holder_listener, stage?, &timings);
    // The holder operation has returned; its failed resources have unwound or
    // its actual continuity is retained. Diagnostic DATA grants no permission.
    evidence.preparation_timings(timings.summary());
    let storage = match result {
        InitialStorageOutcome::Established(storage) => *storage,
        InitialStorageOutcome::Refused { file, error } => {
            let _refused_original = file;
            return Err(error);
        }
    };
    evidence.first_holder(&storage.bootstrap_core()?, &storage.first_holder_data()?)?;
    let mut active =
        match bootstrap::activate_controller(storage, &mut role, &policy, &store, evidence) {
            ControllerActivationOutcome::Active(active) => active,
            ControllerActivationOutcome::Refused { storage, error } => {
                let _refused_original = storage;
                return Err(error);
            }
        };
    evidence.enter(FailurePhase::ServingListener);
    let mut listener = ControllerServingListener::bind(&mut role.begin_current_stage()?)?;
    let mut shell: Option<ControllerServingPeer> = None;
    // Health is idle process/lifecycle DATA, not evidence of a current provider
    // observation or serving permission. It owns no native material.
    evidence.enter(FailurePhase::Health);
    let health = health::Health::bind()?;
    let result = (|| -> Result<()> {
        loop {
            // Only acquire a role after actual pending work. An idle wait must
            // not renew or silently spend a previously issued five-second stage.
            evidence.enter(FailurePhase::AppPending);
            if active.app_pending()? {
                evidence.enter(FailurePhase::AppServing);
                let observed = active.serve_app_current(role.begin_current_stage()?)?;
                evidence.serving(ServingRole::App, observed)?;
            }
            if let Some(peer) = &mut shell {
                evidence.enter(FailurePhase::ShellPending);
                if peer.idle_ready()? {
                    evidence.enter(FailurePhase::ShellServing);
                    let observed = active.serve_shell_current(role.begin_current_stage()?, peer)?;
                    evidence.serving(ServingRole::Shell, observed)?;
                }
            } else {
                evidence.enter(FailurePhase::ShellPending);
                if listener.idle_ready()? {
                    evidence.enter(FailurePhase::ShellAccept);
                    shell = Some(listener.accept(&mut role.begin_current_stage()?)?);
                }
            }
            evidence.enter(FailurePhase::Health);
            health.serve_one()?;
            // Dispatch pacing only; no expiry cleanup, permit regrant, retry,
            // provider polling, role refresh or holder change happens here.
            std::thread::park_timeout(Duration::from_millis(5));
        }
    })();
    active.refuse();
    if let Some(peer) = &mut shell {
        peer.refuse();
    }
    // Failure stops this process. A restarted executor encounters existing
    // original objects and refuses; it cannot adopt or recreate authority.
    result
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn interrupted_diagnostic_export_retains_original_native_failure_and_stays_terminal() {
        let native = PreparationFailure::at(
            PreparationStep::DiskBinding,
            anyhow::anyhow!("storage_provider_disk_binding"),
        );
        let error =
            preserve_native_failure(Err(native), Err(anyhow::anyhow!("private output failure")))
                .unwrap_err();
        assert!(error.downcast_ref::<PreparationFailure>().is_some());
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string() == "storage_provider_disk_binding")
        );
        assert_eq!(error.to_string(), "native_evidence_export_failed");
        assert!(preserve_native_failure(Ok(()), Err(anyhow::anyhow!("output failed"))).is_err());
    }
}
