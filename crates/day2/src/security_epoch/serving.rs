//! Scoped native serving composition. An App needs the genuine activated file,
//! fresh role/Controller peer and current coherent epoch. Shell gets its own
//! supplier, never the App's file or database identity. Live qualification is
//! separate; no configuration or earlier receipt can construct these owners.

use crate::security_epoch::bootstrap::CurrentAppServingPhase;
use crate::{oauth::fresh_auth::FreshIntent, security_epoch::native_enrollment::EnrolledRoleStage};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::Serialize;
use std::rc::Rc;

mod shell;

/// Purpose selection DATA, not execution permission. Each later irreversible
/// phase needs its own genuine same-stage serving fence.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum ServingUse {
    Claim,
    Publication,
    StartCommit,
    DispatchCommit,
    ProviderSend,
    FinishCommit,
    DisconnectCommit,
    Session,
    Signature,
    Verification,
    Callback,
    Response,
    AppResponseComplete,
    ShellResponseComplete,
}

mod sealed {
    pub trait NativeServingOwner {}
}

/// A scoped borrow of genuine native material, never a DTO or transferable
/// permission. Sealing prevents consumer/simulator code from supplying a mock
/// native implementation. Only the narrow mutable borrow below implements it.
pub(crate) trait CurrentServingPhase: sealed::NativeServingOwner {
    fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()>;

    fn check_runtime_selection(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()>;

    fn admit_runtime_database(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
        db: &rusqlite::Connection,
    ) -> Result<()>;

    /// Before the actual mutation/send attempt, not after its possibly lost
    /// result. Failure must leave the actual owner permanently refused.
    fn arm(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()>;

    /// Known result plus current fences. This must not rearm an unknown result
    /// or restore an owner that a previous physical/current check refused.
    /// Recording the known result DOES NOT release the callback's scope: all
    /// subsequent original checks must finish before another consumer enters.
    fn finish_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()>;

    /// Only a known exclusion BEFORE arming, such as a rejected MAC or pure
    /// input. It cannot clear a previously refused owner or attempted effect.
    fn finish_excluded(&mut self) -> Result<()>;

    /// Terminal/unknown disposition works even after expiry or unwinding.
    /// It must require no still-live role, clock or provider request, and must
    /// remain terminal even if finish_known was already recorded.
    fn refuse(&mut self);
}

/// Connection identity DATA only. Allocate once in the actual Sink constructor;
/// clones represent that SAME connection. There is no serialized/scalar identity
/// factory, permission, original or native material inside it.
#[derive(Clone)]
pub(crate) struct ResponseIdentity(Rc<()>);

impl ResponseIdentity {
    pub(crate) fn new() -> Self {
        Self(Rc::new(()))
    }

    pub(crate) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum RuntimeServingUse {
    InitialStorage,
    PendingCapture,
    Read,
    Refresh,
}

#[derive(Clone, Copy)]
pub(super) enum ScopePurpose {
    Human(ServingUse),
    Runtime(RuntimeServingUse),
}

struct ResponseHold {
    identity: ResponseIdentity,
    intent: Digest,
    refused: bool,
}

/// Connection ownership/disposition DATA only, not an epoch or execution owner.
#[derive(Default)]
struct ResponseHolds {
    current: Option<ResponseHold>,
}

impl ResponseHolds {
    fn prepare(
        &mut self,
        intent: &Digest,
        purpose: ServingUse,
        identity: Option<&ResponseIdentity>,
    ) -> Result<bool> {
        if !matches!(
            purpose,
            ServingUse::Response
                | ServingUse::AppResponseComplete
                | ServingUse::ShellResponseComplete
        ) {
            ensure!(
                identity.is_none(),
                "native_serving_unexpected_response_identity"
            );
            return Ok(false);
        }
        let identity =
            identity.ok_or_else(|| anyhow::anyhow!("native_serving_response_identity_required"))?;
        if let Some(hold) = &self.current {
            ensure!(
                !hold.refused && hold.identity.same(identity) && hold.intent == *intent,
                "native_serving_different_or_refused_response_hold"
            );
            return Ok(false);
        }
        ensure!(
            purpose == ServingUse::Response,
            "native_serving_response_hold_missing"
        );
        self.current = Some(ResponseHold {
            identity: identity.clone(),
            intent: intent.clone(),
            refused: false,
        });
        Ok(true)
    }

    fn require_bound(
        &mut self,
        intent: &Digest,
        purpose: ServingUse,
        identity: Option<&ResponseIdentity>,
    ) -> Result<()> {
        if matches!(
            purpose,
            ServingUse::Response
                | ServingUse::AppResponseComplete
                | ServingUse::ShellResponseComplete
        ) {
            ensure!(
                self.current.is_some(),
                "native_serving_response_not_bound_at_creator"
            );
        }
        self.prepare(intent, purpose, identity)?;
        Ok(())
    }

    fn refuse_exact(&mut self, intent: &Digest, identity: &ResponseIdentity) -> Result<()> {
        let hold = self
            .current
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("native_serving_response_hold_missing"))?;
        ensure!(
            hold.intent == *intent && hold.identity.same(identity),
            "native_serving_different_response_hold"
        );
        hold.refused = true;
        Ok(())
    }
}

/// Real active material; connection DATA cannot construct native permission.
pub(crate) struct ServingParticipant {
    native: ParticipantOwner,
    response: ResponseHolds,
}

enum ParticipantOwner {
    App(Box<super::ActiveAppStorageContinuity>),
    Shell(Box<super::native_enrollment::ShellServingPeer>),
}

pub(crate) struct CurrentShellServingPhase<'peer> {
    peer: super::native_enrollment::CurrentServingPeerPhase<'peer>,
    disposition: super::bootstrap::ServingDisposition,
}

impl ServingParticipant {
    pub(crate) fn app(app: super::ActiveAppStorageContinuity) -> Self {
        Self {
            native: ParticipantOwner::App(Box::new(app)),
            response: ResponseHolds::default(),
        }
    }

    pub(crate) fn shell(peer: super::native_enrollment::ShellServingPeer) -> Self {
        Self {
            native: ParticipantOwner::Shell(Box::new(peer)),
            response: ResponseHolds::default(),
        }
    }

    pub(crate) fn refuse(&mut self) {
        if let Some(hold) = &mut self.response.current {
            hold.refused = true;
        }
        match &mut self.native {
            ParticipantOwner::App(app) => app.refuse(),
            ParticipantOwner::Shell(shell) => shell.refuse(),
        }
    }
}

/// Reserve only the exact actual Sink's negative/ownership hold before its
/// first poll. This performs no action, native acquisition or provider I/O.
/// A different paused connection is rejected without modifying its hold.
pub(crate) fn bind_response(
    participant: &mut ServingParticipant,
    intent: &FreshIntent,
    identity: &ResponseIdentity,
) -> Result<()> {
    intent.require_oauth_management()?;
    participant
        .response
        .prepare(&intent.commitment()?, ServingUse::Response, Some(identity))?;
    Ok(())
}

/// Same actual role and storage scope through the original consumer callback.
/// Commitment/identity are protocol DATA; neither can construct this scope.
pub(crate) fn with_current_serving<'role, T>(
    participant: &mut ServingParticipant,
    stage: &mut EnrolledRoleStage<'role>,
    intent: &FreshIntent,
    purpose: ServingUse,
    response: Option<&ResponseIdentity>,
    operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
) -> Result<T> {
    intent.require_oauth_management()?;
    match &participant.native {
        ParticipantOwner::App(_) => ensure!(
            !matches!(
                purpose,
                ServingUse::Session | ServingUse::Signature | ServingUse::ShellResponseComplete
            ),
            "native_serving_shell_participant_required"
        ),
        ParticipantOwner::Shell(_) => ensure!(
            matches!(
                purpose,
                ServingUse::Session
                    | ServingUse::Signature
                    | ServingUse::Response
                    | ServingUse::ShellResponseComplete
            ),
            "native_serving_app_participant_required"
        ),
    }
    let commitment = intent.commitment()?;
    // A duplicate loser fails BEFORE taking the paused winner's native scope.
    participant
        .response
        .require_bound(&commitment, purpose, response)?;
    let binding = Digest::of(&("day2-native-human-serving-v1", &commitment, purpose))?;
    let outcome = match &mut participant.native {
        ParticipantOwner::App(app) => {
            app.with_serving(stage, binding, ScopePurpose::Human(purpose), operation)
        }
        ParticipantOwner::Shell(peer) => shell::with_current(peer, stage, binding, operation),
    };
    match outcome {
        ScopeOutcome::Known(value) => {
            if matches!(
                purpose,
                ServingUse::AppResponseComplete | ServingUse::ShellResponseComplete
            ) {
                participant.response.current = None;
            }
            Ok(value)
        }
        ScopeOutcome::Excluded(error) => Err(error),
        ScopeOutcome::Refused(error) => {
            participant.refuse();
            Err(error)
        }
    }
}

pub(crate) fn with_current_runtime_serving<'role, T>(
    participant: &mut ServingParticipant,
    stage: &mut EnrolledRoleStage<'role>,
    purpose: RuntimeServingUse,
    operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
) -> Result<T> {
    let binding = Digest::of(&("day2-native-runtime-serving-v1", purpose))?;
    let ParticipantOwner::App(app) = &mut participant.native else {
        anyhow::bail!("native_runtime_app_participant_required");
    };
    match app.with_serving(stage, binding, ScopePurpose::Runtime(purpose), operation) {
        ScopeOutcome::Known(value) => Ok(value),
        ScopeOutcome::Excluded(error) => Err(error),
        ScopeOutcome::Refused(error) => {
            participant.refuse();
            Err(error)
        }
    }
}

/// The real active App participant and SAME already acquired stage remain
/// borrowed through fixed existing-file admission. No ordinary load fallback.
pub(crate) fn load_native_runtime(
    participant: &mut ServingParticipant,
    stage: &mut EnrolledRoleStage<'_>,
    metadata: crate::store::InitialStoreMetadata,
) -> Result<crate::store::Runtime> {
    with_current_runtime_serving(
        participant,
        stage,
        RuntimeServingUse::InitialStorage,
        |current, same| crate::store::Runtime::load_native_storage(metadata, current, same),
    )
}

/// Negative disposition only of the EXISTING exact connection hold. A late or
/// different connection cannot settle/refuse the paused winner or replacement.
/// No current role, clock, provider request or new hold is acquired.
pub(crate) fn refuse_current_serving(
    participant: &mut ServingParticipant,
    intent: &FreshIntent,
    purpose: ServingUse,
    identity: &ResponseIdentity,
) -> Result<()> {
    ensure!(
        purpose == ServingUse::Response,
        "native_serving_terminal_purpose"
    );
    let commitment = intent.commitment()?;
    participant.response.refuse_exact(&commitment, identity)?;
    participant.refuse();
    Ok(())
}

pub(super) enum ScopeOutcome<T> {
    Known(T),
    Excluded(anyhow::Error),
    Refused(anyhow::Error),
}

pub(super) fn borrow_current<'phase, 'storage>(
    owner: &'phase mut CurrentAppServingPhase<'storage>,
) -> ServingBorrow<'phase, 'storage> {
    ServingBorrow { owner }
}

pub(super) struct ServingBorrow<'phase, 'storage> {
    owner: &'phase mut CurrentAppServingPhase<'storage>,
}
impl sealed::NativeServingOwner for ServingBorrow<'_, '_> {}
impl CurrentServingPhase for ServingBorrow<'_, '_> {
    fn check_runtime_selection(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
    ) -> Result<()> {
        self.owner.check_runtime_selection(stage, metadata)
    }

    fn admit_runtime_database(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        metadata: &crate::store::InitialStoreMetadata,
        db: &rusqlite::Connection,
    ) -> Result<()> {
        self.owner.admit_runtime_database(stage, metadata, db)
    }

    fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.owner.check(stage)
    }
    fn arm(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.owner.arm(stage)
    }
    fn finish_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.owner.finish_known(stage)
    }
    fn finish_excluded(&mut self) -> Result<()> {
        self.owner.finish_excluded()
    }
    fn refuse(&mut self) {
        self.owner.refuse();
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn pre_poll_abort_and_loser_completion_cannot_burn_a_paused_winner() {
        let mut holds = ResponseHolds::default();
        let intent = Digest::new(b"same-real-intent-data");
        let a = ResponseIdentity::new();
        let a_clone = a.clone();
        let b = ResponseIdentity::new();
        assert!(
            holds
                .prepare(&intent, ServingUse::Response, Some(&a))
                .unwrap()
        );
        assert!(
            !holds
                .prepare(&intent, ServingUse::Response, Some(&a_clone))
                .unwrap()
        );
        assert!(
            holds
                .prepare(&intent, ServingUse::Response, Some(&b))
                .is_err()
        );
        assert!(
            holds
                .prepare(&intent, ServingUse::AppResponseComplete, Some(&b))
                .is_err()
        );
        assert!(holds.refuse_exact(&intent, &b).is_err());
        let hold = holds.current.as_ref().unwrap();
        assert!(!hold.refused && hold.identity.same(&a));
        // The real owner may abort before any poll/stage has existed.
        holds.refuse_exact(&intent, &a).unwrap();
        assert!(
            holds
                .prepare(&intent, ServingUse::AppResponseComplete, Some(&a))
                .is_err()
        );
        assert!(
            holds
                .prepare(&intent, ServingUse::Response, Some(&a))
                .is_err()
        );
    }

    #[test]
    fn late_old_abort_never_refuses_a_replacement_or_creates_a_missing_hold() {
        let mut holds = ResponseHolds::default();
        let intent = Digest::new(b"intent");
        let a = ResponseIdentity::new();
        let b = ResponseIdentity::new();
        assert!(holds.refuse_exact(&intent, &a).is_err());
        assert!(
            holds
                .require_bound(&intent, ServingUse::Response, Some(&a))
                .is_err()
        );
        assert!(holds.current.is_none());
        assert!(
            holds
                .prepare(&intent, ServingUse::AppResponseComplete, Some(&a))
                .is_err()
        );
        holds
            .prepare(&intent, ServingUse::Response, Some(&a))
            .unwrap();
        holds
            .prepare(&intent, ServingUse::AppResponseComplete, Some(&a))
            .unwrap();
        // Only a known actual serving/connection completion may perform this
        // removal in production. This is a DATA state-machine control only.
        holds.current = None;
        holds
            .prepare(&intent, ServingUse::Response, Some(&b))
            .unwrap();
        assert!(holds.refuse_exact(&intent, &a).is_err());
        assert!(
            holds
                .prepare(
                    &Digest::new(b"foreign-intent"),
                    ServingUse::Response,
                    Some(&b)
                )
                .is_err()
        );
        assert!(!holds.current.as_ref().unwrap().refused);
    }
}

#[cfg(test)]
mod native_admission_tests {
    use crate::store::Runtime;
    fn selected_profile_instance() -> anyhow::Result<crate::artifact::Instance> {
        use anyhow::Context;
        let mut instance = crate::oauth::clients::tests::security_instance("workspace", true)?;
        let control = instance.control.as_mut().context("fixture control")?;
        let (alias, store) = control
            .security_epochs
            .iter()
            .find(|(_, store)| store.scope.app.as_str() == "workspace")
            .map(|(alias, store)| (alias.clone(), store.clone()))
            .context("fixture epoch")?;
        let mut policy = crate::security_epoch::control_slot_tests::policy(&store);
        let day2_capabilities::security_epoch::EpochProvider::FirestoreNativeV1 { project, .. } =
            &store.provider;
        policy.cluster.project = project.clone();
        policy.epoch_store.id = alias;
        policy.control_store.epoch_store = policy.epoch_store.clone();
        control
            .security_bootstraps
            .insert("native".to_owned().try_into()?, policy);
        crate::artifact::Instance::from_bytes(&serde_json::to_vec(&instance)?)
    }

    #[test]
    fn ordinary_runtime_refuses_selected_native_before_creating_state_or_loading_an_artifact()
    -> anyhow::Result<()> {
        let instance = selected_profile_instance()?;
        assert!(instance.native_bootstrap_for("workspace")?.is_some());
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        std::fs::write(&path, serde_json::to_vec(&instance)?)?;
        let error = Runtime::load(&path, "workspace")
            .err()
            .expect("ordinary native load refused");
        assert!(format!("{error:#}").contains("native_runtime_current_serving_required"));
        assert!(!directory.path().join(".state").exists());
        assert!(instance.native_bootstrap_for("unknown-app").is_err());
        for mutation in [
            "wrong_scope",
            "duplicate_policy",
            "missing_epoch",
            "duplicate_epoch",
        ] {
            let mut invalid = instance.clone();
            let control = invalid.control.as_mut().unwrap();
            match mutation {
                "wrong_scope" => {
                    control
                        .security_bootstraps
                        .values_mut()
                        .next()
                        .unwrap()
                        .scope
                        .environment = "foreign".to_owned().try_into()?
                }
                "duplicate_policy" => {
                    let policy = control.security_bootstraps.values().next().unwrap().clone();
                    control
                        .security_bootstraps
                        .insert("second".to_owned().try_into()?, policy);
                }
                "missing_epoch" => control.security_epochs.clear(),
                "duplicate_epoch" => {
                    let epoch = control.security_epochs.values().next().unwrap().clone();
                    control
                        .security_epochs
                        .insert("second".to_owned().try_into()?, epoch);
                }
                _ => unreachable!(),
            }
            assert!(
                invalid.native_bootstrap_for("workspace").is_err(),
                "{mutation}"
            );
        }
        let mut prerequisite = instance;
        prerequisite
            .control
            .as_mut()
            .unwrap()
            .security_bootstraps
            .clear();
        assert!(prerequisite.native_bootstrap_for("workspace")?.is_none());
        // Epoch catalog alone does not select native mode or create authority.
        assert!(
            !prerequisite
                .control
                .as_ref()
                .unwrap()
                .security_epochs
                .is_empty()
        );
        Ok(())
    }
}
