use crate::security_epoch::native_enrollment::{
    NativeRole,
    policy::{EnrollmentPolicy, decode_key},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use day2_capabilities::Digest;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc};

#[cfg(test)]
#[path = "protocol/restore_tests.rs"]
mod restore_tests;

pub(super) const MAX_PACKET: usize = 8192;

/// Historical process binding, never an owning process handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessData {
    pub process: u32,
    pub start_ticks: u64,
    pub code: Digest,
    pub boot: String,
    pub namespaces: BTreeMap<String, (u64, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuerData {
    pub policy: Digest,
    pub root_version: String,
    pub nonce: Digest,
    pub public_key: String,
    pub process: ProcessData,
    pub provisioner: ProcessData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IssuerCertificate {
    pub data: IssuerData,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StageData {
    pub issuer: Digest,
    pub policy: Digest,
    pub role: NativeRole,
    pub purpose: StagePurpose,
    pub public_key: String,
    pub challenge: Digest,
    pub request: Digest,
    pub process: ProcessData,
    pub runtime: RuntimeBinding,
    pub origin_ns: u64,
    pub deadline_ns: u64,
}

/// Signed closed stage purpose. Each producer and consumer requires its exact
/// purpose; a longer bootstrap/observation interval is never ordinary Current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::security_epoch) enum StagePurpose {
    CurrentRole,
    InitialFirstHolder,
    StorageBootstrap,
    StorageMetadataObservation,
}

impl StagePurpose {
    pub(super) fn limit(self) -> std::time::Duration {
        match self {
            Self::CurrentRole => std::time::Duration::from_secs(5),
            Self::InitialFirstHolder => {
                crate::security_epoch::native_clock::INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT
            }
            Self::StorageBootstrap => crate::security_epoch::native_clock::STORAGE_BOOTSTRAP_LIMIT,
            Self::StorageMetadataObservation => {
                crate::security_epoch::native_clock::STORAGE_METADATA_OBSERVATION_LIMIT
            }
        }
    }

    pub(super) fn require_role(self, role: NativeRole) -> Result<()> {
        let allowed = match self {
            Self::CurrentRole => true,
            Self::InitialFirstHolder | Self::StorageBootstrap => {
                matches!(role, NativeRole::EpochController | NativeRole::AppHost)
            }
            Self::StorageMetadataObservation => role == NativeRole::EpochController,
        };
        ensure!(allowed, "native_enrollment_stage_purpose_role");
        Ok(())
    }

    /// DATA comparison used by the actual native stage gate. Success here
    /// neither constructs nor checks a native stage, clock or permission.
    pub(super) fn require_exact(self, expected: Self) -> Result<()> {
        ensure!(self == expected, "native_enrollment_stage_purpose_changed");
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeBinding {
    pub container: crate::security_epoch::runtime_profile::ContainerFacts,
    pub node_uid: String,
    pub boot: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedStage {
    pub data: StageData,
    pub signature: String,
}

/// Selection DATA for one irreversible issuer-closure attempt. The real
/// requester still needs its retained role key, native message process and
/// original. A signed statement alone is NOT business-rights Stop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FreezeSelection {
    pub admin_binding: Digest,
    pub stop: crate::security_epoch::kernel::restore::StopSelection,
    pub app: super::storage_peer_wire::StageStatement,
    pub controller: super::storage_peer_wire::StageStatement,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenIssuance {
    pub selection: FreezeSelection,
    pub policy: Digest,
    pub issuer: Digest,
    pub cohort: Digest,
    pub request: Digest,
    pub challenge: Digest,
}

/// Fixed Controller preparation DATA. Only the retained restore driver's
/// authorizer can obtain a Controller signature over this exact binding. A
/// decoded object never supplies the native parent or any file/keeper owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::security_epoch) struct RestoreAuthorizationData {
    pub issuer: Digest,
    pub policy: Digest,
    pub frozen: Digest,
    pub controller: Digest,
    pub operation: Digest,
    pub approval: Digest,
    pub grant: Digest,
    pub intent: Digest,
    pub full_archive: Digest,
    /// Digest::of the actual admitted current Instance, not raw file SHA.
    pub desired_instance: Digest,
    pub target: crate::security_epoch::restore_approval::TargetBinding,
    pub report: crate::security_epoch::kernel::restore::completion::TargetReport,
    pub terminal: Digest,
    pub terminal_version: crate::security_epoch::kernel::UpdateTime,
    pub records: Digest,
    pub parent_clock: Digest,
    pub parent_origin_ns: u64,
    pub parent_deadline_ns: u64,
}

impl RestoreAuthorizationData {
    pub(super) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-restore-controller-authorization-v1", self))
    }

    pub(super) fn validate_data(
        &self,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        now: std::time::Duration,
    ) -> Result<()> {
        certificate.verify(policy)?;
        let now = now.as_nanos();
        ensure!(
            self.issuer == certificate.digest()?
                && self.policy == policy.digest()?
                && self.target.scope == policy.bootstrap.scope
                && self.target.selection == Digest::of(&policy.store)?
                && self.target.authority == policy.store.authority_key()?
                && self.target.binding_generation > 0
                && self.target.security_epoch == 2
                && self.report.intent == self.intent
                && self.report.target_incarnation == self.target.incarnation
                && self.report.target_epoch == self.target.security_epoch
                && self.report.artifact == self.target.artifact
                && self.report.schema == self.target.schema
                && self.parent_origin_ns < self.parent_deadline_ns
                && self.parent_deadline_ns - self.parent_origin_ns <= 5_000_000_000
                && u128::from(self.parent_origin_ns) <= now
                && now < u128::from(self.parent_deadline_ns),
            "native_restore_authorization_data_changed"
        );
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreAuthorizationStatement {
    pub data: RestoreAuthorizationData,
    pub request: Digest,
    pub challenge: Digest,
    pub effective_deadline_ns: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedRestoreAuthorization {
    pub statement: RestoreAuthorizationStatement,
    pub signature: String,
}

impl SignedRestoreAuthorization {
    pub(super) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-signed-restore-authorization-v1", self))
    }

    pub(super) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        now: std::time::Duration,
    ) -> Result<()> {
        self.statement
            .data
            .validate_data(policy, certificate, now)?;
        ensure!(
            self.statement.effective_deadline_ns <= self.statement.data.parent_deadline_ns
                && u128::from(self.statement.data.parent_origin_ns) <= now.as_nanos()
                && now.as_nanos() < u128::from(self.statement.effective_deadline_ns),
            "native_restore_authorization_expired"
        );
        verify(
            &certificate.data.public_key,
            "restore-controller-authorized-v1",
            &self.statement,
            &self.signature,
        )
    }
}

/// The App supplies these bytes from its ACTUAL own five-second admission
/// original. Native client/server owners independently join/check its kernel
/// process and clock namespace; this DATA cannot reconstruct either clock.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreAppRequest {
    pub public_key: String,
    pub request: Digest,
    pub receiver_clock: Digest,
    pub receiver_origin_ns: u64,
    pub receiver_deadline_ns: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreAdmissionStatement {
    pub issuer: Digest,
    pub policy: Digest,
    pub authorization: Digest,
    pub process: ProcessData,
    pub runtime: RuntimeBinding,
    pub public_key: String,
    pub request: Digest,
    pub challenge: Digest,
    pub receiver_clock: Digest,
    pub receiver_origin_ns: u64,
    pub receiver_deadline_ns: u64,
    pub effective_deadline_ns: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedRestoreAdmission {
    pub statement: RestoreAdmissionStatement,
    pub signature: String,
}

impl SignedRestoreAdmission {
    /// Signature/binding comparison only. No normal role, holder, file, P3 or
    /// serving owner is constructed or returned by this DATA validator.
    pub(super) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        authorization: &SignedRestoreAuthorization,
        now: std::time::Duration,
    ) -> Result<()> {
        authorization.verify_data(policy, certificate, now)?;
        let statement = &self.statement;
        ensure!(
            statement.issuer == certificate.digest()?
                && statement.policy == policy.digest()?
                && statement.authorization == authorization.digest_data()?
                && statement.receiver_origin_ns < statement.receiver_deadline_ns
                && statement.receiver_deadline_ns - statement.receiver_origin_ns <= 5_000_000_000
                && statement.effective_deadline_ns <= statement.receiver_deadline_ns
                && statement.effective_deadline_ns <= authorization.statement.effective_deadline_ns
                && u128::from(statement.receiver_origin_ns) <= now.as_nanos()
                && now.as_nanos() < u128::from(statement.effective_deadline_ns)
                && statement.process.code == *policy.code(NativeRole::AppHost),
            "native_restore_app_admission_data_changed"
        );
        decode_key(&statement.public_key)?;
        verify(
            &certificate.data.public_key,
            "restore-app-admission-v1",
            statement,
            &self.signature,
        )
    }
}

/// Fixed final-exchange DATA. Only the actual native Controller peer may
/// assemble it from its retained authorization, accepted App, activation and
/// authenticated keeper acknowledgement. Decoding never supplies those owners.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreIssuerCompletionData {
    pub frozen: Digest,
    pub authorization: Digest,
    pub app: Digest,
    pub activation: Digest,
    pub cohort: super::storage_peer_wire::SqliteCohort,
}

impl RestoreIssuerCompletionData {
    pub(super) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-restore-issuer-completion-data-v1", self))
    }

    /// Signed-chain and exact-identity comparison only. Native callers must
    /// independently retain/check the actual process and file cohort.
    pub(super) fn validate_data(
        &self,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        app: &super::restore_peer_wire::RestoreAppStatement,
        now: std::time::Duration,
    ) -> Result<()> {
        app.validate(policy, certificate, &app.admission.statement.process, now)?;
        ensure!(
            self.frozen == app.authorization.statement.data.frozen
                && self.authorization == app.authorization.digest_data()?
                && self.app == app.digest()?,
            "native_restore_completion_binding_changed"
        );
        self.cohort.validate()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreIssuerCompletionStatement {
    pub data: RestoreIssuerCompletionData,
    pub request: Digest,
    pub challenge: Digest,
    pub effective_deadline_ns: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedRestoreIssuerCompletion {
    pub statement: RestoreIssuerCompletionStatement,
    pub signature: String,
}

impl SignedRestoreIssuerCompletion {
    pub(super) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        expected: &RestoreIssuerCompletionData,
        app: &super::restore_peer_wire::RestoreAppStatement,
        now: std::time::Duration,
    ) -> Result<()> {
        self.statement
            .data
            .validate_data(policy, certificate, app, now)?;
        ensure!(
            &self.statement.data == expected
                && self.statement.effective_deadline_ns <= app.original.deadline_ns
                && self.statement.effective_deadline_ns
                    <= app.admission.statement.effective_deadline_ns
                && now.as_nanos() < u128::from(self.statement.effective_deadline_ns),
            "native_restore_completion_expired_or_changed"
        );
        verify(
            &certificate.data.public_key,
            "restore-issuer-completed-v1",
            &self.statement,
            &self.signature,
        )
    }
}

/// Final role-activation DATA. Validation cannot install a role, reopen the
/// issuer, complete Controller posts, or adopt an App/SQLite owner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestoreRoleActivationStatement {
    pub completion: Digest,
    pub stage: SignedStage,
    pub request: Digest,
    pub challenge: Digest,
    pub effective_deadline_ns: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedRestoreRoleActivation {
    pub statement: RestoreRoleActivationStatement,
    pub signature: String,
}

impl SignedRestoreIssuerCompletion {
    pub(super) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-restore-issuer-completed-data-v1", self))
    }
}

impl SignedRestoreRoleActivation {
    /// Signature and exact comparison only. The actual producer and App must
    /// independently retain/check their original clocks, kernel peers, key,
    /// writer authority and first keeper; DATA cannot substitute for them.
    pub(super) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        completion: &SignedRestoreIssuerCompletion,
        app: &super::restore_peer_wire::RestoreAppStatement,
        exchange: (&Digest, &Digest),
        now: std::time::Duration,
    ) -> Result<()> {
        let (request, challenge) = exchange;
        completion.verify_data(policy, certificate, &completion.statement.data, app, now)?;
        let statement = &self.statement;
        let stage = &statement.stage.data;
        ensure!(
            statement.completion == completion.digest_data()?
                && &statement.request == request
                && &statement.challenge == challenge
                && stage.request == *request
                && stage.challenge == *challenge
                && stage.issuer == certificate.digest()?
                && stage.policy == policy.digest()?
                && stage.role == NativeRole::AppHost
                && stage.purpose == StagePurpose::CurrentRole
                && stage.public_key == app.admission.statement.public_key
                && stage.process == app.admission.statement.process
                && stage.runtime == app.admission.statement.runtime
                && stage.origin_ns == app.original.origin_ns
                && stage.deadline_ns == statement.effective_deadline_ns
                && stage.origin_ns < stage.deadline_ns
                && stage.deadline_ns - stage.origin_ns <= 5_000_000_000
                && statement.effective_deadline_ns <= completion.statement.effective_deadline_ns
                && statement.effective_deadline_ns <= app.original.deadline_ns
                && u128::from(stage.origin_ns) <= now.as_nanos()
                && now.as_nanos() < u128::from(statement.effective_deadline_ns),
            "native_restore_role_activation_binding_changed"
        );
        verify(
            &certificate.data.public_key,
            "role-stage",
            stage,
            &statement.stage.signature,
        )?;
        verify(
            &certificate.data.public_key,
            "restore-app-role-activated-v1",
            statement,
            &self.signature,
        )
    }
}

/// Prepared App confirmation comparison DATA only. A valid signature neither
/// completes Controller resource posts nor admits an ordinary role or keeper.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RestorePreparedConfirmationStatement {
    pub issuer: Digest,
    pub decision: Digest,
    pub completion: Digest,
    pub app: Digest,
    pub request: Digest,
    pub challenge: Digest,
    pub effective_deadline_ns: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedRestorePreparedConfirmation {
    pub statement: RestorePreparedConfirmationStatement,
    pub signature: String,
}

impl SignedRestoreRoleActivation {
    pub(super) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-restore-app-role-decision-data-v1", self))
    }
}

impl SignedRestorePreparedConfirmation {
    pub(super) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&("day2-restore-app-prepared-confirmation-data-v1", self))
    }

    pub(super) fn verify_data(
        &self,
        policy: &EnrollmentPolicy,
        certificate: &IssuerCertificate,
        chain: (&SignedRestoreRoleActivation, &SignedRestoreIssuerCompletion),
        app: &super::restore_peer_wire::RestoreAppStatement,
        exchange: (&Digest, &Digest),
        now: std::time::Duration,
    ) -> Result<()> {
        let (decision, completion) = chain;
        decision.verify_data(
            policy,
            certificate,
            completion,
            app,
            (&decision.statement.request, &decision.statement.challenge),
            now,
        )?;
        let statement = &self.statement;
        ensure!(
            statement.issuer == certificate.digest()?
                && statement.decision == decision.digest_data()?
                && statement.completion == completion.digest_data()?
                && statement.app == app.digest()?
                && &statement.request == exchange.0
                && &statement.challenge == exchange.1
                && statement.effective_deadline_ns <= decision.statement.effective_deadline_ns
                && now.as_nanos() < u128::from(statement.effective_deadline_ns),
            "native_restore_prepared_confirmation_expired_or_changed"
        );
        verify(
            &certificate.data.public_key,
            "restore-app-prepared-confirmed-v1",
            statement,
            &self.signature,
        )
    }
}

impl FreezeSelection {
    /// Request interval DATA only. The actual freeze handler separately binds
    /// the complete selection to its enrolled actors, fresh signed transcript,
    /// kernel sender and issuer. This never reconstructs a clock or renews a
    /// cold grant; the retained native acquisition supplies the other ceiling.
    pub(super) fn current_deadline_data(
        &self,
        now: std::time::Duration,
    ) -> Result<std::time::Duration> {
        self.controller
            .original
            .validate_request(now, StagePurpose::CurrentRole)?;
        self.app
            .original
            .validate_request(now, StagePurpose::CurrentRole)?;
        Ok(std::time::Duration::from_nanos(
            self.controller
                .original
                .deadline_ns
                .min(self.app.original.deadline_ns),
        ))
    }

    pub(super) fn history_digest(&self) -> Result<Digest> {
        let mut members = [&self.app, &self.controller];
        members.sort_by_key(|s| {
            (
                s.stage.data.process.process,
                s.stage.data.process.start_ticks,
                s.stage.data.role,
            )
        });
        Digest::of(&(
            "day2-native-issuer-cohort-v1",
            members.map(|s| {
                (
                    &s.stage.data.public_key,
                    &s.stage.data.process,
                    &s.stage.data.runtime,
                    s.stage.data.role,
                )
            }),
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Packet {
    BirthChallenge {
        policy: Digest,
        nonce: Digest,
    },
    BirthKey {
        nonce: Digest,
        public_key: String,
        signature: String,
    },
    BirthGrant {
        certificate: IssuerCertificate,
    },
    FreezeHello {
        selection: Box<FreezeSelection>,
        request: Digest,
    },
    FreezeNonce {
        request: Digest,
        challenge: Digest,
    },
    FreezeBind {
        selection: Box<FreezeSelection>,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    FreezeGrant {
        statement: Box<FrozenIssuance>,
        signature: String,
    },
    RestorePrepareHello {
        authorization: Box<RestoreAuthorizationData>,
        request: Digest,
    },
    RestorePrepareNonce {
        authorization: Digest,
        request: Digest,
        challenge: Digest,
    },
    RestorePrepareBind {
        authorization: Box<RestoreAuthorizationData>,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    RestorePrepareGrant {
        authorization: Box<SignedRestoreAuthorization>,
    },
    RestoreAppHello {
        request: Box<RestoreAppRequest>,
    },
    RestoreAppNonce {
        certificate: IssuerCertificate,
        authorization: Box<SignedRestoreAuthorization>,
        request: Digest,
        challenge: Digest,
    },
    RestoreAppBind {
        authorization: Digest,
        request: Box<RestoreAppRequest>,
        challenge: Digest,
        signature: String,
    },
    RestoreAppGrant {
        certificate: IssuerCertificate,
        admission: Box<SignedRestoreAdmission>,
    },
    RestoreFinishHello {
        completion: Box<RestoreIssuerCompletionData>,
        request: Digest,
    },
    RestoreFinishNonce {
        completion: Digest,
        request: Digest,
        challenge: Digest,
    },
    RestoreFinishBind {
        completion: Box<RestoreIssuerCompletionData>,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    RestoreFinishGrant {
        completion: Box<SignedRestoreIssuerCompletion>,
    },
    RestoreRoleHello {
        completion: Box<SignedRestoreIssuerCompletion>,
        request: Digest,
    },
    RestoreRoleNonce {
        completion: Digest,
        request: Digest,
        challenge: Digest,
    },
    RestoreRoleBind {
        completion: Box<SignedRestoreIssuerCompletion>,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    RestoreRoleGrant {
        activation: Box<SignedRestoreRoleActivation>,
    },
    RestoreAppConfirmHello {
        decision: Box<SignedRestoreRoleActivation>,
        request: Digest,
    },
    RestoreAppConfirmNonce {
        decision: Digest,
        request: Digest,
        challenge: Digest,
    },
    RestoreAppConfirmBind {
        decision: Box<SignedRestoreRoleActivation>,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    RestoreAppConfirmGrant {
        confirmation: Box<SignedRestorePreparedConfirmation>,
    },
    StageHello {
        policy: Digest,
        role: NativeRole,
        purpose: StagePurpose,
        public_key: String,
        request: Digest,
    },
    StageNonce {
        request: Digest,
        challenge: Digest,
    },
    StageBind {
        policy: Digest,
        role: NativeRole,
        purpose: StagePurpose,
        public_key: String,
        request: Digest,
        challenge: Digest,
        signature: String,
    },
    StageGrant {
        certificate: IssuerCertificate,
        stage: Box<SignedStage>,
    },
}

#[cfg(target_os = "linux")]
impl Packet {
    pub(super) fn frame(&self) -> Option<super::handshake::Frame> {
        use super::handshake::{Frame, Protocol, Step};
        let step = match self {
            Self::StageHello { .. }
            | Self::FreezeHello { .. }
            | Self::RestorePrepareHello { .. }
            | Self::RestoreAppHello { .. }
            | Self::RestoreFinishHello { .. }
            | Self::RestoreRoleHello { .. }
            | Self::RestoreAppConfirmHello { .. } => Step::Hello,
            Self::StageNonce { .. }
            | Self::FreezeNonce { .. }
            | Self::RestorePrepareNonce { .. }
            | Self::RestoreAppNonce { .. }
            | Self::RestoreFinishNonce { .. }
            | Self::RestoreRoleNonce { .. }
            | Self::RestoreAppConfirmNonce { .. } => Step::Challenge,
            Self::StageBind { .. }
            | Self::FreezeBind { .. }
            | Self::RestorePrepareBind { .. }
            | Self::RestoreAppBind { .. }
            | Self::RestoreFinishBind { .. }
            | Self::RestoreRoleBind { .. }
            | Self::RestoreAppConfirmBind { .. } => Step::Bind,
            Self::StageGrant { .. }
            | Self::FreezeGrant { .. }
            | Self::RestorePrepareGrant { .. }
            | Self::RestoreAppGrant { .. }
            | Self::RestoreFinishGrant { .. }
            | Self::RestoreRoleGrant { .. }
            | Self::RestoreAppConfirmGrant { .. } => Step::Grant,
            Self::BirthChallenge { .. } | Self::BirthKey { .. } | Self::BirthGrant { .. } => {
                return None;
            }
        };
        Some(Frame {
            protocol: Protocol::Enrollment,
            step,
            sequence: None,
        })
    }
}

/// Key possession belongs to one native executor. It is never a wire value.
pub(super) struct KeyOwner {
    key: Ed25519KeyPair,
    local: PhantomData<Rc<()>>,
}

impl KeyOwner {
    pub(super) fn generate() -> Result<Self> {
        let mut seed = zeroize::Zeroizing::new([0_u8; 32]);
        crate::host_inputs::Entropy::fill(&crate::host_inputs::SecureEntropy, seed.as_mut())?;
        let key = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| anyhow::anyhow!("native_enrollment_key_generation"))?;
        Ok(Self {
            key,
            local: PhantomData,
        })
    }

    pub(super) fn public(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.public_key().as_ref())
    }

    pub(super) fn sign<T: Serialize>(&self, purpose: &str, value: &T) -> Result<String> {
        let bytes = frame(purpose, value)?;
        Ok(URL_SAFE_NO_PAD.encode(self.key.sign(&bytes).as_ref()))
    }
}

fn frame<T: Serialize>(purpose: &str, value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&("day2-native-enrollment-v1", purpose, value))?;
    ensure!(bytes.len() <= MAX_PACKET, "native_enrollment_frame_bound");
    Ok(bytes)
}

pub(super) fn issuer_birth_frame(data: &IssuerData) -> Result<Vec<u8>> {
    frame("issuer-birth", data)
}

pub(super) fn verify<T: Serialize>(
    key: &str,
    purpose: &str,
    value: &T,
    encoded: &str,
) -> Result<()> {
    let key = decode_key(key)?;
    ensure!(encoded.len() == 86, "native_enrollment_signature_encoding");
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    ensure!(
        bytes.len() == 64 && URL_SAFE_NO_PAD.encode(&bytes) == encoded,
        "native_enrollment_signature_encoding"
    );
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(&frame(purpose, value)?, &bytes)
        .map_err(|_| anyhow::anyhow!("native_enrollment_signature_refused"))
}

impl IssuerCertificate {
    pub(super) fn verify(&self, policy: &EnrollmentPolicy) -> Result<()> {
        ensure!(
            self.data.policy == policy.digest()?
                && self.data.root_version == policy.root.version
                && self.data.process.code == policy.issuer_code
                && self.data.provisioner.code == policy.provisioner_code,
            "native_enrollment_issuer_selection"
        );
        decode_key(&self.data.public_key)?;
        verify(
            &policy.root.public_key,
            "issuer-birth",
            &self.data,
            &self.signature,
        )
    }

    pub(super) fn digest(&self) -> Result<Digest> {
        Digest::of(&("day2-native-issuer-certificate-v1", self))
    }
}

pub(super) fn nonce(purpose: &str) -> Result<Digest> {
    let mut bytes = [0_u8; 32];
    crate::host_inputs::Entropy::fill(&crate::host_inputs::SecureEntropy, &mut bytes)?;
    Digest::of(&("day2-native-enrollment-nonce-v1", purpose, bytes))
}

pub(super) fn decode(bytes: &[u8]) -> Result<Packet> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PACKET,
        "native_enrollment_packet_bound"
    );
    let value: serde_json::Value = crate::json::decode(bytes)?;
    ensure!(
        value.is_object(),
        "native_enrollment_packet_object_required"
    );
    // Keep the new restore wire closed to JSON sequences at every record
    // boundary, including nested target/scope, native identity and runtime.
    // The unique raw JSON decoder above still rejects duplicate keys before
    // any Value-to-typed conversion can discard them.
    let objects: &[&str] = match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("restore_app_confirm_hello" | "restore_app_confirm_bind") => &[
            "/decision",
            "/decision/statement",
            "/decision/statement/stage",
            "/decision/statement/stage/data",
            "/decision/statement/stage/data/process",
            "/decision/statement/stage/data/process/namespaces",
            "/decision/statement/stage/data/runtime",
            "/decision/statement/stage/data/runtime/container",
        ],
        Some("restore_app_confirm_grant") => &["/confirmation", "/confirmation/statement"],
        Some("restore_role_hello" | "restore_role_bind") => &[
            "/completion",
            "/completion/statement",
            "/completion/statement/data",
            "/completion/statement/data/cohort",
        ],
        Some("restore_role_grant") => &[
            "/activation",
            "/activation/statement",
            "/activation/statement/stage",
            "/activation/statement/stage/data",
            "/activation/statement/stage/data/process",
            "/activation/statement/stage/data/process/namespaces",
            "/activation/statement/stage/data/runtime",
            "/activation/statement/stage/data/runtime/container",
        ],
        Some("restore_finish_hello" | "restore_finish_bind") => {
            &["/completion", "/completion/cohort"]
        }
        Some("restore_finish_grant") => &[
            "/completion",
            "/completion/statement",
            "/completion/statement/data",
            "/completion/statement/data/cohort",
        ],
        Some("restore_prepare_hello" | "restore_prepare_bind") => &[
            "/authorization",
            "/authorization/target",
            "/authorization/target/scope",
            "/authorization/report",
        ],
        Some("restore_prepare_grant") => &[
            "/authorization",
            "/authorization/statement",
            "/authorization/statement/data",
            "/authorization/statement/data/target",
            "/authorization/statement/data/target/scope",
            "/authorization/statement/data/report",
        ],
        Some("restore_app_nonce") => &[
            "/authorization",
            "/authorization/statement",
            "/authorization/statement/data",
            "/authorization/statement/data/target",
            "/authorization/statement/data/target/scope",
            "/authorization/statement/data/report",
            "/certificate",
            "/certificate/data",
            "/certificate/data/process",
            "/certificate/data/process/namespaces",
            "/certificate/data/provisioner",
            "/certificate/data/provisioner/namespaces",
        ],
        Some("restore_app_hello" | "restore_app_bind") => &["/request"],
        Some("restore_app_grant") => &[
            "/admission",
            "/admission/statement",
            "/admission/statement/process",
            "/admission/statement/process/namespaces",
            "/admission/statement/runtime",
            "/admission/statement/runtime/container",
            "/certificate",
            "/certificate/data",
            "/certificate/data/process",
            "/certificate/data/process/namespaces",
            "/certificate/data/provisioner",
            "/certificate/data/provisioner/namespaces",
        ],
        _ => &[],
    };
    for path in objects {
        ensure!(
            value
                .pointer(path)
                .is_some_and(serde_json::Value::is_object),
            "native_restore_packet_object_required"
        );
    }
    let selection = match value.get("kind").and_then(serde_json::Value::as_str) {
        Some("freeze_hello" | "freeze_bind") => Some("/selection"),
        Some("freeze_grant") => {
            ensure!(
                value
                    .pointer("/statement")
                    .is_some_and(serde_json::Value::is_object),
                "native_enrollment_freeze_object_required"
            );
            Some("/statement/selection")
        }
        _ => None,
    };
    if let Some(path) = selection {
        ensure!(
            value
                .pointer(path)
                .is_some_and(serde_json::Value::is_object),
            "native_enrollment_freeze_object_required"
        );
        ensure!(
            value
                .pointer(&format!("{path}/stop"))
                .is_some_and(serde_json::Value::is_object),
            "native_enrollment_freeze_object_required"
        );
        for role in ["app", "controller"] {
            super::storage_peer_wire::require_stage_objects(&value, &format!("{path}/{role}"))?;
        }
    }
    Ok(serde_json::from_value(value)?)
}
