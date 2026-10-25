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
    Pending,
    Claim,
    Publication,
    StartCommit,
    DispatchCommit,
    ProviderSend,
    FinishCommit,
    DisconnectCommit,
    Authentication,
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

    /// A response spanning socket polls retains its original authentication,
    /// but still needs the fresh counter observations supplied by the former
    /// per-poll scopes. Checking a retained observation is not another read.
    fn reobserve(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()>;

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
    Registration,
    Read,
    Refresh,
    Response,
    ResponseComplete,
}

#[derive(Clone, Copy, Serialize)]
pub(super) enum ScopePurpose {
    Human(ServingUse),
    Runtime(RuntimeServingUse),
}

// Historical DATA only. These capped private log records are never parsed as
// readiness, native material or permission. Shell has no App provider snapshot
// and cannot manufacture one from a matching binding.
#[derive(Clone)]
pub(in crate::security_epoch) struct ConsumerScopeEvidence {
    role: super::native_enrollment::NativeRole,
    selection: Option<Digest>,
    incarnation: Digest,
    binding: Option<Digest>,
    purpose: Option<ScopePurpose>,
    snapshot: Option<Digest>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum ConsumerScopeResult {
    ExecutorEnrolled,
    #[serde(rename = "scope_completed")]
    Completed,
    OperationRefused,
    FinalScopeRefused,
    Unsettled,
    Panicked,
}

#[derive(Serialize)]
struct ConsumerEvidenceRecord<'a> {
    format: &'static str,
    sequence: u8,
    observation: ConsumerScopeResult,
    role: super::native_enrollment::NativeRole,
    selection: &'a Option<Digest>,
    consumer_incarnation: &'a Digest,
    binding: &'a Option<Digest>,
    purpose: &'a Option<ScopePurpose>,
    snapshot: &'a Option<Digest>,
}

const CONSUMER_EVIDENCE_PREFIX: &str = "day2-native-consumer-evidence ";
const CONSUMER_EVIDENCE_LIMIT: u8 = 128;
const CONSUMER_EVIDENCE_BYTES: usize = 2048;
static CONSUMER_EVIDENCE_RECORDS: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn next_consumer_evidence_sequence(records: &std::sync::atomic::AtomicU8) -> Option<u8> {
    use std::sync::atomic::Ordering;
    records
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
            (previous < CONSUMER_EVIDENCE_LIMIT).then(|| previous + 1)
        })
        .ok()
        .map(|previous| previous + 1)
}

impl ConsumerScopeEvidence {
    pub(in crate::security_epoch) fn app(
        selection: Digest,
        incarnation: Digest,
        binding: Digest,
        purpose: ScopePurpose,
    ) -> Self {
        Self {
            role: super::native_enrollment::NativeRole::AppHost,
            selection: Some(selection),
            incarnation,
            binding: Some(binding),
            purpose: Some(purpose),
            snapshot: None,
        }
    }

    pub(in crate::security_epoch) fn shell(incarnation: Digest, binding: Digest) -> Self {
        Self {
            role: super::native_enrollment::NativeRole::SecurityShell,
            selection: None,
            incarnation,
            binding: Some(binding),
            purpose: None,
            snapshot: None,
        }
    }

    pub(in crate::security_epoch) fn snapshot(&mut self, snapshot: Digest) {
        self.snapshot = Some(snapshot);
    }

    fn line(&self, sequence: u8, observation: ConsumerScopeResult) -> Option<Vec<u8>> {
        if !(1..=CONSUMER_EVIDENCE_LIMIT).contains(&sequence) {
            return None;
        }
        let record = ConsumerEvidenceRecord {
            format: "day2_native_consumer_evidence_v1",
            sequence,
            observation,
            role: self.role,
            selection: &self.selection,
            consumer_incarnation: &self.incarnation,
            binding: &self.binding,
            purpose: &self.purpose,
            snapshot: &self.snapshot,
        };
        let json = serde_json::to_string(&record).ok()?;
        let line = format!("{CONSUMER_EVIDENCE_PREFIX}{json}\n");
        (line.len() <= CONSUMER_EVIDENCE_BYTES).then(|| line.into_bytes())
    }

    pub(in crate::security_epoch) fn record(&self, observation: ConsumerScopeResult) {
        use std::io::Write;
        let Some(sequence) = next_consumer_evidence_sequence(&CONSUMER_EVIDENCE_RECORDS) else {
            return;
        };
        let Some(line) = self.line(sequence, observation) else {
            return;
        };
        // Export failure cannot change a completed native result. Missing or
        // truncated diagnostics remain missing evidence, never a positive claim.
        let _ = std::io::stderr().lock().write_all(&line);
    }
}

/// Only the actual final HTTP executor calls this after genuine enrollment and
/// its checked App/Shell stage. This reports no file, P3, consumer or readiness
/// success; Shell still needs a real human request to enter a serving scope.
pub(crate) fn record_executor_enrollment(
    stage: &mut EnrolledRoleStage<'_>,
    policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
    store: &day2_capabilities::security_epoch::EpochStore,
    role: super::native_enrollment::NativeRole,
) -> Result<()> {
    ensure!(
        matches!(
            role,
            super::native_enrollment::NativeRole::AppHost
                | super::native_enrollment::NativeRole::SecurityShell
        ),
        "native HTTP enrollment role refused"
    );
    stage.check_selection(policy, store, role)?;
    let evidence = ConsumerScopeEvidence {
        role,
        selection: Some(Digest::of(&(
            "day2-controller-evidence-selection-v1",
            policy,
            store,
        ))?),
        incarnation: stage.incarnation_data()?,
        binding: None,
        purpose: None,
        snapshot: None,
    };
    stage.check_selection(policy, store, role)?;
    evidence.record(ConsumerScopeResult::ExecutorEnrolled);
    Ok(())
}

#[derive(Clone, PartialEq, Eq)]
enum HoldContext {
    Human(Digest),
    Runtime(Digest),
}

struct ResponseHold {
    identity: ResponseIdentity,
    context: HoldContext,
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
        context: &HoldContext,
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
                !hold.refused && hold.identity.same(identity) && hold.context == *context,
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
            context: context.clone(),
            refused: false,
        });
        Ok(true)
    }

    fn require_bound(
        &mut self,
        context: &HoldContext,
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
        self.prepare(context, purpose, identity)?;
        Ok(())
    }

    fn refuse_exact(&mut self, context: &HoldContext, identity: &ResponseIdentity) -> Result<()> {
        let hold = self
            .current
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("native_serving_response_hold_missing"))?;
        ensure!(
            hold.context == *context && hold.identity.same(identity),
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
    evidence: ConsumerScopeEvidence,
}

impl ServingParticipant {
    /// Only wakeup/readiness DATA is exchanged here. The caller acquires its
    /// real fresh role afterwards; no provider or consumer scope is returned.
    pub(crate) fn prepare_current(&mut self) -> Result<()> {
        match &mut self.native {
            ParticipantOwner::App(app) => app.prepare_current(),
            ParticipantOwner::Shell(peer) => peer.prepare_current(),
        }
    }

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
    participant.response.prepare(
        &HoldContext::Human(intent.commitment()?),
        ServingUse::Response,
        Some(identity),
    )?;
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
                ServingUse::Authentication
                    | ServingUse::Session
                    | ServingUse::Signature
                    | ServingUse::ShellResponseComplete
            ),
            "native_serving_shell_participant_required"
        ),
        ParticipantOwner::Shell(_) => ensure!(
            matches!(
                purpose,
                ServingUse::Authentication
                    | ServingUse::Session
                    | ServingUse::Signature
                    | ServingUse::Response
                    | ServingUse::ShellResponseComplete
            ),
            "native_serving_app_participant_required"
        ),
    }
    let commitment = intent.commitment()?;
    // A duplicate loser fails BEFORE taking the paused winner's native scope.
    participant.response.require_bound(
        &HoldContext::Human(commitment.clone()),
        purpose,
        response,
    )?;
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
    require_runtime_operation(purpose)?;
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

fn require_runtime_operation(purpose: RuntimeServingUse) -> Result<()> {
    ensure!(
        !matches!(
            purpose,
            RuntimeServingUse::Response | RuntimeServingUse::ResponseComplete
        ),
        "native_runtime_response_requires_exact_hold"
    );
    Ok(())
}

fn runtime_response_context(
    scope: &day2_capabilities::security_epoch::AuthorityScope,
) -> Result<HoldContext> {
    Ok(HoldContext::Runtime(Digest::of(&(
        "day2-native-runtime-response-v1",
        scope,
    ))?))
}

/// Connection ownership DATA, never an autonomous operation permission. Bind
/// only the actual socket identity before its first poll; a human hold cannot
/// be reclassified as runtime even with equal digest/identity bytes.
pub(crate) fn bind_runtime_response(
    participant: &mut ServingParticipant,
    scope: &day2_capabilities::security_epoch::AuthorityScope,
    identity: &ResponseIdentity,
) -> Result<()> {
    ensure!(
        matches!(participant.native, ParticipantOwner::App(_)),
        "native_runtime_app_participant_required"
    );
    participant.response.prepare(
        &runtime_response_context(scope)?,
        ServingUse::Response,
        Some(identity),
    )?;
    Ok(())
}

/// Pure exclusion before the caller acquires a new role stage. It cannot make
/// a hold, consume native permission or repair a missing/foreign connection.
pub(crate) fn require_runtime_response(
    participant: &mut ServingParticipant,
    scope: &day2_capabilities::security_epoch::AuthorityScope,
    identity: &ResponseIdentity,
) -> Result<()> {
    ensure!(
        matches!(participant.native, ParticipantOwner::App(_)),
        "native_runtime_app_participant_required"
    );
    participant.response.require_bound(
        &runtime_response_context(scope)?,
        ServingUse::Response,
        Some(identity),
    )
}

pub(crate) fn with_current_runtime_response<'role, T>(
    participant: &mut ServingParticipant,
    stage: &mut EnrolledRoleStage<'role>,
    scope: &day2_capabilities::security_epoch::AuthorityScope,
    purpose: RuntimeServingUse,
    identity: &ResponseIdentity,
    operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
) -> Result<T> {
    ensure!(
        matches!(
            purpose,
            RuntimeServingUse::Response | RuntimeServingUse::ResponseComplete
        ),
        "native_runtime_response_purpose_required"
    );
    require_runtime_response(participant, scope, identity)?;
    stage.check_for(scope, super::native_enrollment::NativeRole::AppHost)?;
    let binding = Digest::of(&("day2-native-runtime-response-scope-v1", scope, purpose))?;
    let ParticipantOwner::App(app) = &mut participant.native else {
        anyhow::bail!("native_runtime_app_participant_required")
    };
    match app.with_serving(stage, binding, ScopePurpose::Runtime(purpose), operation) {
        ScopeOutcome::Known(value) => {
            if purpose == RuntimeServingUse::ResponseComplete {
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

/// One actual App response, including all Pending waits, retains one stage,
/// physical peer, authentication and original five-second interval. This is
/// not the Shell supplier: Shell needs its own Controller observation protocol.
pub(crate) async fn with_app_response<'role, T>(
    participant: &mut ServingParticipant,
    stage: &mut EnrolledRoleStage<'role>,
    scope: &day2_capabilities::security_epoch::AuthorityScope,
    intent: Option<&FreshIntent>,
    identity: &ResponseIdentity,
    operation: impl AsyncFnOnce(
        &mut dyn CurrentServingPhase,
        &mut EnrolledRoleStage<'role>,
    ) -> Result<T>,
) -> Result<T> {
    let (context, purpose, binding) = match intent {
        Some(intent) => {
            intent.require_oauth_management()?;
            let commitment = intent.commitment()?;
            (
                HoldContext::Human(commitment.clone()),
                ScopePurpose::Human(ServingUse::Response),
                Digest::of(&(
                    "day2-native-human-serving-v1",
                    &commitment,
                    ServingUse::Response,
                ))?,
            )
        }
        None => (
            runtime_response_context(scope)?,
            ScopePurpose::Runtime(RuntimeServingUse::Response),
            Digest::of(&(
                "day2-native-runtime-response-scope-v1",
                scope,
                RuntimeServingUse::Response,
            ))?,
        ),
    };
    participant
        .response
        .require_bound(&context, ServingUse::Response, Some(identity))?;
    stage.check_for(scope, super::native_enrollment::NativeRole::AppHost)?;
    let ParticipantOwner::App(app) = &mut participant.native else {
        anyhow::bail!("native_response_requires_App_participant")
    };
    match app
        .with_serving_async(stage, binding, purpose, operation)
        .await
    {
        ScopeOutcome::Known(value) => {
            participant.response.current = None;
            Ok(value)
        }
        ScopeOutcome::Excluded(error) => Err(error),
        ScopeOutcome::Refused(error) => {
            participant.refuse();
            Err(error)
        }
    }
}

pub(crate) fn require_app_response(
    participant: &mut ServingParticipant,
    scope: &day2_capabilities::security_epoch::AuthorityScope,
    intent: Option<&FreshIntent>,
    identity: &ResponseIdentity,
) -> Result<()> {
    ensure!(
        matches!(participant.native, ParticipantOwner::App(_)),
        "native_response_requires_App_participant"
    );
    let context = match intent {
        Some(intent) => HoldContext::Human(intent.commitment()?),
        None => runtime_response_context(scope)?,
    };
    participant
        .response
        .require_bound(&context, ServingUse::Response, Some(identity))
}

/// Stage-free terminal disposition of only the existing exact runtime hold.
/// A human/retired/losing context never changes the rightful native owner.
pub(crate) fn refuse_runtime_response(
    participant: &mut ServingParticipant,
    scope: &day2_capabilities::security_epoch::AuthorityScope,
    identity: &ResponseIdentity,
) -> Result<()> {
    ensure!(
        matches!(participant.native, ParticipantOwner::App(_)),
        "native_runtime_app_participant_required"
    );
    participant
        .response
        .refuse_exact(&runtime_response_context(scope)?, identity)?;
    participant.refuse();
    Ok(())
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
    participant
        .response
        .refuse_exact(&HoldContext::Human(commitment), identity)?;
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
    fn reobserve(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        self.owner.reobserve(stage)
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
    fn enrollment_observation_does_not_invent_a_serving_binding_or_snapshot() {
        for role in [
            super::super::native_enrollment::NativeRole::AppHost,
            super::super::native_enrollment::NativeRole::SecurityShell,
        ] {
            // Format DATA only. This fixture never constructs a native stage or
            // calls the actual checked enrollment-observation producer.
            let evidence = ConsumerScopeEvidence {
                role,
                selection: Some(Digest::new(b"selected policy DATA")),
                incarnation: Digest::new(b"historical incarnation DATA"),
                binding: None,
                purpose: None,
                snapshot: None,
            };
            let line = String::from_utf8(
                evidence
                    .line(1, ConsumerScopeResult::ExecutorEnrolled)
                    .unwrap(),
            )
            .unwrap();
            let value: serde_json::Value =
                serde_json::from_str(line.strip_prefix(CONSUMER_EVIDENCE_PREFIX).unwrap()).unwrap();
            assert_eq!(value["observation"], "executor_enrolled");
            for field in ["binding", "purpose", "snapshot"] {
                assert!(value[field].is_null());
            }
            assert!(value["selection"].is_string());
            assert!(value["consumer_incarnation"].is_string());
        }
    }

    #[test]
    fn consumer_diagnostic_budget_cannot_wrap_or_reopen_after_exhaustion() {
        let records = std::sync::atomic::AtomicU8::new(0);
        for expected in 1..=128 {
            assert_eq!(next_consumer_evidence_sequence(&records), Some(expected));
        }
        for _ in 0..1024 {
            assert_eq!(next_consumer_evidence_sequence(&records), None);
        }
        assert_eq!(records.load(std::sync::atomic::Ordering::Relaxed), 128);
    }

    #[test]
    fn historical_consumer_records_are_bounded_redacted_and_keep_shell_snapshot_absent() {
        let private = "PRIVATE_token_subject_callback_url";
        let digest = Digest::new(private.as_bytes());
        let mut app = ConsumerScopeEvidence::app(
            digest.clone(),
            digest.clone(),
            digest.clone(),
            ScopePurpose::Runtime(RuntimeServingUse::Registration),
        );
        app.snapshot(digest.clone());
        let shell = ConsumerScopeEvidence::shell(digest.clone(), digest.clone());
        for (record, has_snapshot) in [(&app, true), (&shell, false)] {
            assert!(record.line(0, ConsumerScopeResult::Completed).is_none());
            assert!(record.line(129, ConsumerScopeResult::Completed).is_none());
            for (result, expected) in [
                (ConsumerScopeResult::Completed, "scope_completed"),
                (ConsumerScopeResult::OperationRefused, "operation_refused"),
                (
                    ConsumerScopeResult::FinalScopeRefused,
                    "final_scope_refused",
                ),
                (ConsumerScopeResult::Unsettled, "unsettled"),
                (ConsumerScopeResult::Panicked, "panicked"),
            ] {
                let bytes = record.line(128, result).unwrap();
                assert!(bytes.len() <= CONSUMER_EVIDENCE_BYTES);
                let line = String::from_utf8(bytes).unwrap();
                assert_eq!(line.lines().count(), 1);
                assert!(!line.contains(private));
                let json: serde_json::Value =
                    serde_json::from_str(line.strip_prefix(CONSUMER_EVIDENCE_PREFIX).unwrap())
                        .unwrap();
                assert_eq!(json["observation"], expected);
                assert_eq!(json["binding"], digest.as_str());
                assert_eq!(json["snapshot"].is_string(), has_snapshot);
                assert_eq!(json["selection"].is_string(), has_snapshot);
            }
        }
    }

    #[test]
    fn equal_digest_and_identity_cannot_cross_human_and_runtime_holds() {
        let digest = Digest::new(b"deliberately equal context bytes");
        let human = HoldContext::Human(digest.clone());
        let runtime = HoldContext::Runtime(digest);
        for (owner, foreign) in [(human.clone(), runtime.clone()), (runtime, human)] {
            let mut holds = ResponseHolds::default();
            let identity = ResponseIdentity::new();
            holds
                .prepare(&owner, ServingUse::Response, Some(&identity))
                .unwrap();
            assert!(
                holds
                    .require_bound(&foreign, ServingUse::AppResponseComplete, Some(&identity))
                    .is_err()
            );
            assert!(holds.refuse_exact(&foreign, &identity).is_err());
            assert!(!holds.current.as_ref().unwrap().refused);
            holds
                .require_bound(&owner, ServingUse::AppResponseComplete, Some(&identity))
                .unwrap();
            // Model only the known actual completion branch; no native factory
            // or completed operation is manufactured by this DATA control.
            holds.current = None;
            holds
                .prepare(&foreign, ServingUse::Response, Some(&identity))
                .unwrap();
            assert!(holds.refuse_exact(&owner, &identity).is_err());
            assert!(!holds.current.as_ref().unwrap().refused);
        }
    }

    #[test]
    fn runtime_response_cannot_use_the_generic_operation_purpose() {
        for purpose in [
            RuntimeServingUse::Response,
            RuntimeServingUse::ResponseComplete,
        ] {
            assert!(require_runtime_operation(purpose).is_err());
        }
        for purpose in [
            RuntimeServingUse::InitialStorage,
            RuntimeServingUse::PendingCapture,
            RuntimeServingUse::Registration,
            RuntimeServingUse::Read,
            RuntimeServingUse::Refresh,
        ] {
            require_runtime_operation(purpose).unwrap();
        }
    }

    #[test]
    fn pre_poll_abort_and_loser_completion_cannot_burn_a_paused_winner() {
        let mut holds = ResponseHolds::default();
        let intent = HoldContext::Human(Digest::new(b"same-real-intent-data"));
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
        let intent = HoldContext::Human(Digest::new(b"intent"));
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
                    &HoldContext::Human(Digest::new(b"foreign-intent")),
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

/// The ordinary database path cannot adopt or initialize storage selected for
/// native bootstrap. Check this BEFORE `.state` metadata, directory creation,
/// active-authority reads or SQLite open. Desired policy and an old SQL row do
/// not recreate a current physical holder after executor/process loss.
///
/// There is no successful native Runtime admission constructor yet. A future
/// path must consume the actual activated same-file/current-owner composition;
/// it must not replace this refusal with a boolean or a stored receipt. Apps
/// without a native bootstrap selection retain their ordinary storage path.
pub(crate) fn require_runtime_admission(
    instance: &crate::artifact::Instance,
    app: &str,
) -> Result<()> {
    let Some(control) = &instance.control else {
        return Ok(());
    };
    if control
        .security_bootstraps
        .values()
        .any(|policy| policy.scope.app.as_str() == app)
    {
        anyhow::bail!("native runtime storage authority unavailable");
    }
    Ok(())
}

#[cfg(test)]
mod runtime_admission_tests {
    use super::*;
    use anyhow::Context;

    fn selected_profile_instance() -> Result<crate::artifact::Instance> {
        let mut instance = crate::oauth::clients::tests::security_instance("workspace", true)?;
        let control = instance.control.as_mut().context("fixture control")?;
        let (alias, store) = control
            .security_epochs
            .iter()
            .find(|(_, store)| store.scope.app.as_str() == "workspace")
            .map(|(alias, store)| (alias.clone(), store.clone()))
            .context("fixture epoch")?;
        let mut policy = super::super::control_slot_tests::policy(&store);
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
    fn explicit_native_profile_selection_cannot_downgrade_invalid_metadata() -> Result<()> {
        let instance = selected_profile_instance()?;
        let policy = instance
            .native_bootstrap_for("workspace")?
            .context("explicit native profile")?;
        let scope = policy.scope.clone();
        assert_eq!(
            crate::oauth::native_management::selected_scopes(&instance, Some("workspace"))?,
            vec![scope]
        );
        for mutation in [
            "foreign_installation",
            "foreign_environment",
            "duplicate_policy",
            "missing_epoch",
            "ambiguous_epoch",
        ] {
            let mut invalid = instance.clone();
            let control = invalid.control.as_mut().unwrap();
            match mutation {
                "foreign_installation" => {
                    control
                        .security_bootstraps
                        .values_mut()
                        .next()
                        .unwrap()
                        .scope
                        .installation = "foreign".to_owned().try_into()?;
                }
                "foreign_environment" => {
                    control
                        .security_bootstraps
                        .values_mut()
                        .next()
                        .unwrap()
                        .scope
                        .environment = "foreign".to_owned().try_into()?;
                }
                "duplicate_policy" => {
                    let copy = control.security_bootstraps.values().next().unwrap().clone();
                    control
                        .security_bootstraps
                        .insert("second".to_owned().try_into()?, copy);
                }
                "missing_epoch" => {
                    control.security_epochs.remove(&policy.epoch_store.id);
                }
                "ambiguous_epoch" => {
                    let copy = control.security_epochs[&policy.epoch_store.id].clone();
                    control
                        .security_epochs
                        .insert("second".to_owned().try_into()?, copy);
                }
                _ => unreachable!(),
            }
            assert!(
                invalid.native_bootstrap_for("workspace").is_err(),
                "{mutation}"
            );
            assert!(
                crate::oauth::native_management::selected_scopes(&invalid, Some("workspace"))
                    .is_err(),
                "{mutation} became prerequisite-only startup"
            );
        }
        let mut prerequisite_only = instance.clone();
        prerequisite_only
            .control
            .as_mut()
            .unwrap()
            .security_bootstraps
            .clear();
        let prerequisite_only =
            crate::artifact::Instance::from_bytes(&serde_json::to_vec(&prerequisite_only)?)?;
        assert!(
            prerequisite_only
                .native_bootstrap_for("workspace")?
                .is_none()
        );
        assert!(
            crate::oauth::native_management::selected_scopes(&prerequisite_only, None)?.is_empty()
        );
        Ok(())
    }

    #[test]
    fn selected_native_bootstrap_refuses_before_state_creation_metadata_or_database_open()
    -> Result<()> {
        let mut instance = crate::oauth::clients::tests::security_instance("workspace", false)?;
        let control = instance.control.as_mut().context("fixture control")?;
        let (alias, store) = control
            .security_epochs
            .iter()
            .find(|(_, store)| store.scope.app.as_str() == "workspace")
            .map(|(alias, store)| (alias.clone(), store.clone()))
            .context("fixture epoch")?;
        let mut policy = super::super::control_slot_tests::policy(&store);
        let day2_capabilities::security_epoch::EpochProvider::FirestoreNativeV1 { project, .. } =
            &store.provider;
        policy.cluster.project = project.clone();
        policy.epoch_store.id = alias;
        policy.control_store.epoch_store = policy.epoch_store.clone();
        control
            .security_bootstraps
            .insert("native".to_owned().try_into()?, policy);
        // Pass the ACTUAL strict operator loader, not a fixture-only relaxed
        // decoder or a fabricated permission/supplier matrix.
        let bytes = serde_json::to_vec(&instance)?;
        crate::artifact::Instance::from_bytes(&bytes)?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("instance.json");
        std::fs::write(&path, bytes)?;
        let state = directory.path().join(".state");
        let refused = || -> Result<()> {
            let error = crate::store::Runtime::load(&path, "workspace")
                .err()
                .context("native Runtime unexpectedly admitted")?;
            assert_eq!(error.to_string(), "native_runtime_current_serving_required");
            Ok(())
        };
        refused()?;
        assert!(
            !state.exists(),
            "startup created ordinary state before native admission"
        );
        // Even querying/chmodding the ordinary state directory is too early.
        std::fs::write(&state, b"must not inspect this as a directory")?;
        refused()?;
        assert_eq!(
            std::fs::read(&state)?,
            b"must not inspect this as a directory"
        );
        std::fs::remove_file(&state)?;
        std::fs::create_dir(&state)?;
        let database = state.join("workspace.sqlite");
        std::fs::write(
            &database,
            b"old copied authority/receipt is not a native owner",
        )?;
        refused()?;
        assert_eq!(
            std::fs::read(&database)?,
            b"old copied authority/receipt is not a native owner"
        );
        assert_eq!(std::fs::read_dir(&state)?.count(), 1);
        Ok(())
    }
}
