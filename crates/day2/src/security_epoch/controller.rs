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
use evidence::{Evidence, FailurePhase, PreparationFailure, PreparationStep, ServingRole};

pub(crate) fn run(instance_path: &Path, app: &str) -> Result<()> {
    let mut evidence = Evidence::new();
    let result = run_inner(instance_path, app, &mut evidence);
    if let Err(error) = &result {
        evidence.refuse(Some(error))?;
    }
    result
}

fn run_inner(instance_path: &Path, app: &str, evidence: &mut Evidence) -> Result<()> {
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
    evidence.enter(FailurePhase::Enrollment);
    let mut role = EnrolledProcessRoleOwner::enroll_current_thread(
        &policy.scope,
        NativeRole::EpochController,
    )?;
    evidence.enrolled(role.historical_incarnation_data())?;
    evidence.enter(FailurePhase::Preparation);
    let mut file = storage_authority::prepare_controller_initial(
        instance_path,
        role.begin_current_stage()
            .map_err(|error| PreparationFailure::at(PreparationStep::RoleStage, error))?,
        &policy,
        &store,
    )?;
    evidence.enter(FailurePhase::HolderListener);
    let mut holder_listener =
        InitialHolderListener::bind(file.begin_initial_phase(role.begin_current_stage()?)?)?;
    while !holder_listener.idle_ready()? {
        // No role/file permission remains live while waiting for Kubernetes
        // startup. Start a fresh same-owner phase only after actual pending DATA.
        std::thread::park_timeout(Duration::from_millis(5));
    }
    evidence.enter(FailurePhase::FirstHolder);
    let storage = match InitialStorageContinuity::establish(
        file,
        holder_listener,
        role.begin_current_stage()?,
    ) {
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
