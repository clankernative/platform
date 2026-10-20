//! Fixed initial-only protocol executor. All native owners remain on THIS OS
//! thread. Idle probes create DATA, never a role lease or action permission.
use crate::artifact::Instance;
use crate::security_epoch::{
    bootstrap::{self, ControllerActivationOutcome},
    native_enrollment::{
        ControllerServingListener, ControllerServingPeer, EnrolledProcessRoleOwner, NativeRole,
    },
    storage_authority::{self, InitialStorageContinuity, InitialStorageOutcome},
};
use anyhow::{Context, Result, ensure};
use std::{path::Path, time::Duration};

mod health;

pub(crate) fn run(instance_path: &Path, app: &str) -> Result<()> {
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
    let mut role = EnrolledProcessRoleOwner::enroll_current_thread(
        &policy.scope,
        NativeRole::EpochController,
    )?;
    let file = storage_authority::prepare_controller_initial(
        instance_path,
        role.begin_current_stage()?,
        &policy,
        &store,
    )?;
    let storage = match InitialStorageContinuity::establish(file, role.begin_current_stage()?) {
        InitialStorageOutcome::Established(storage) => *storage,
        InitialStorageOutcome::Refused { file, error } => {
            let _refused_original = file;
            return Err(error);
        }
    };
    let mut active = match bootstrap::activate_controller(storage, &mut role, &policy, &store) {
        ControllerActivationOutcome::Active(active) => active,
        ControllerActivationOutcome::Refused { storage, error } => {
            let _refused_original = storage;
            return Err(error);
        }
    };
    let mut listener = ControllerServingListener::bind(&mut role.begin_current_stage()?)?;
    let mut shell: Option<ControllerServingPeer> = None;
    // Health is idle process/lifecycle DATA, not evidence of a current provider
    // observation or serving permission. It owns no native material.
    let health = health::Health::bind()?;
    let result = (|| -> Result<()> {
        loop {
            // Only acquire a role after actual pending work. An idle wait must
            // not renew or silently spend a previously issued five-second stage.
            if active.app_pending()? {
                active.serve_app_current(role.begin_current_stage()?)?;
            }
            if let Some(peer) = &mut shell {
                if peer.idle_ready()? {
                    active.serve_shell_current(role.begin_current_stage()?, peer)?;
                }
            } else if listener.idle_ready()? {
                shell = Some(listener.accept(&mut role.begin_current_stage()?)?);
            }
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
