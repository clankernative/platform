//! Server-held protected restore ceremonies. A locator selects retained DATA;
//! it cannot reconstruct a ceremony or replace a genuine Controller reader.
//! Human waits retain no action, stage, exclusion or authenticated executor.
mod controller;
pub(in crate::security_epoch) use controller::{
    Attempt as ProtectedRestoreAttempt, ProtectedRestoreSession,
};

use super::{
    ActiveControllerStorageContinuity, PendingApproval, PendingRestoreExecution,
    RestoreAuthenticationAction,
};
use crate::security_epoch::{
    controller::serving_timing::ServingTiming,
    kernel::restore::Intent,
    native_enrollment::EnrolledRoleStage,
    restore_approval::{ApprovalIntent, signed::SignedApprovalRecord},
    restore_staging::PreparedNativeRestoreArchive,
    restore_webauthn::Assertion,
};
use crate::store::InitialStoreMetadata;
use anyhow::{Context, Result, ensure};
use day2_capabilities::{Digest, security_epoch::EpochStore};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Component, PathBuf},
};

const MAX_INPUT_BYTES: usize = 32_768;
const MAX_ATTEMPTS: usize = 64;
// Same closed credential-ID bound as the existing assertion decoder.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    format: Format,
    approval: ApprovalIntent,
    restore: Intent,
    archive_directory: PathBuf,
    approver: String,
    approver_credential: Vec<u8>,
    executor_credential: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
enum Format {
    #[serde(rename = "day2_protected_restore_v1")]
    V1,
}

impl Input {
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_INPUT_BYTES,
            "protected_restore_input_bound"
        );
        let value: serde_json::Value = crate::json::decode(bytes)
            .map_err(|_| anyhow::anyhow!("protected_restore_input_encoding"))?;
        // This single supported input representation is an object with an
        // actual string version. Derive-based sequence/enum-map aliases must
        // not normalize into the same selected command commitment.
        ensure!(
            value.is_object()
                && value
                    .get("format")
                    .is_some_and(serde_json::Value::is_string),
            "protected_restore_input_shape"
        );
        let input: Self = serde_json::from_value(value.clone())
            .map_err(|_| anyhow::anyhow!("protected_restore_input_encoding"))?;
        // Reused nested intent/identity DATA must have the exact object/string
        // representation too. A derive-supported sequence or enum-map alias
        // must not silently normalize into the same operator command.
        ensure!(
            serde_json::to_value(&input)? == value,
            "protected_restore_input_shape"
        );
        input.approval.validate()?;
        crate::authority::valid_actor(&input.approver)?;
        ensure!(
            (1..=MAX_CREDENTIAL_ID_BYTES).contains(&input.approver_credential.len())
                && (1..=MAX_CREDENTIAL_ID_BYTES).contains(&input.executor_credential.len())
                && input.archive_directory.is_absolute()
                && input.archive_directory.as_os_str().len() <= 4096
                && (2..=32).contains(&input.archive_directory.components().count())
                && input
                    .archive_directory
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "protected_restore_input_shape"
        );
        Ok(input)
    }

    // Complete DATA joins only. The native producer, full archive and kernel
    // still verify actual authority, clocks, keys, files and one-use admission.
    fn require_selected(&self, selected: &EpochStore) -> Result<()> {
        self.restore.commitment(selected)?;
        let target = &self.approval.target;
        ensure!(
            self.approval.full_archive_digest == self.restore.archive.full_archive_digest
                && target.scope == selected.scope
                && target.authority == selected.authority_key()?
                && target.selection == Digest::of(selected)?
                && target.incarnation == self.restore.target_incarnation
                && Some(target.security_epoch)
                    == self.restore.archive.security_epoch.checked_add(1)
                && target.artifact == self.restore.archive.artifact
                && target.schema == self.restore.archive.schema,
            "protected_restore_intent_join_changed"
        );
        Ok(())
    }

    fn id(&self) -> Result<Digest> {
        Digest::of(&("day2-protected-restore-command-v1", self))
    }
}

/// Bounded presentation/correlation DATA only. No pending ceremony, selected
/// key owner, authenticated administrator or archive/native handle is exposed.
/// The Controller independently repeats every real selection and registry check.
pub(crate) struct ProtectedRestoreCommandData {
    pub(crate) id: Digest,
    pub(crate) intent: ApprovalIntent,
    pub(crate) operation: Digest,
    pub(crate) approver_email: String,
    pub(crate) approver_credential: Vec<u8>,
    pub(crate) executor_credential: Vec<u8>,
}

pub(crate) fn protected_restore_command_data(
    bytes: &[u8],
    selected: &EpochStore,
) -> Result<ProtectedRestoreCommandData> {
    let input = Input::decode(bytes)?;
    input.require_selected(selected)?;
    Ok(ProtectedRestoreCommandData {
        id: input.id()?,
        // The executor ceremony binds the declared operation ID; the full
        // command ID above separately commits the complete restore input.
        operation: input.restore.operation,
        intent: input.approval,
        approver_email: input.approver,
        approver_credential: input.approver_credential,
        executor_credential: input.executor_credential,
    })
}

// Pure bounded correlation mechanics. The actual instantiation below is
// private and stores genuine opaque pending objects, never their wire copies.
struct Slot<T> {
    seen: BTreeSet<Digest>,
    current: Option<(Digest, T)>,
}

impl<T> Slot<T> {
    fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            current: None,
        }
    }

    fn claim(&mut self, grant: &Digest) -> Result<()> {
        ensure!(self.current.is_none(), "protected_restore_pending_busy");
        ensure!(
            self.seen.len() < MAX_ATTEMPTS,
            "protected_restore_attempt_bound"
        );
        ensure!(
            !self.seen.contains(grant),
            "protected_restore_attempt_spent"
        );
        self.seen.insert(grant.clone());
        Ok(())
    }

    fn insert(&mut self, id: Digest, value: T) -> Result<()> {
        ensure!(self.current.is_none(), "protected_restore_pending_busy");
        self.current = Some((id, value));
        Ok(())
    }

    fn selected(&self, id: &Digest) -> Result<&T> {
        let (actual, value) = self
            .current
            .as_ref()
            .context("protected_restore_pending_missing")?;
        ensure!(actual == id, "protected_restore_pending_changed");
        Ok(value)
    }

    fn take(&mut self, id: &Digest) -> Result<T> {
        self.selected(id)?;
        Ok(self
            .current
            .take()
            .context("protected_restore_pending_missing")?
            .1)
    }
}

enum Pending {
    Approval(Box<PendingApproval>),
    Approved(Box<SignedApprovalRecord>),
    Execution {
        pending: Box<PendingRestoreExecution>,
        record: Box<SignedApprovalRecord>,
    },
}

struct Command {
    input: Input,
    pending: Pending,
}

/// No codec, Clone, default owner, native getter or restart reconstruction.
/// Losing this process loses the actual pending ceremonies. The durable native
/// challenge/signing/consumption journals independently preserve spent work.
pub(in crate::security_epoch) struct ProtectedRestoreCommands {
    slot: Slot<Command>,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <ProtectedRestoreCommands as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
};

fn action<'metadata, 'storage, 'role>(
    input: &Input,
    active: &'storage mut ActiveControllerStorageContinuity,
    stage: EnrolledRoleStage<'role>,
    metadata: &'metadata InitialStoreMetadata,
    trace: &'storage ServingTiming,
) -> Result<RestoreAuthenticationAction<'metadata, 'storage, 'role>> {
    input.require_selected(&active.store)?;
    let reader = active
        .begin_accepting_admin_reader(
            metadata,
            stage,
            &input.approval.commitment()?,
            [&input.approver, &input.approval.executor.email],
            trace,
        )?
        .context("protected_restore_current_admin_required")?;
    reader.admit_restore_authentication(&input.approval)
}

impl ProtectedRestoreCommands {
    pub(in crate::security_epoch) fn new() -> Self {
        Self { slot: Slot::new() }
    }

    pub(in crate::security_epoch) fn issue_approval(
        &mut self,
        bytes: &[u8],
        active: &mut ActiveControllerStorageContinuity,
        stage: EnrolledRoleStage<'_>,
        metadata: &InitialStoreMetadata,
        trace: &ServingTiming,
    ) -> Result<(Digest, Vec<u8>)> {
        let input = Input::decode(bytes)?;
        input.require_selected(&active.store)?;
        let id = input.id()?;
        self.slot.claim(&input.approval.grant_id)?;
        let pending = action(&input, active, stage, metadata, trace)?
            .issue_approval(&input.approver_credential)?;
        let prompt = pending.request_options_data()?.encode()?;
        self.slot.insert(
            id.clone(),
            Command {
                input,
                pending: Pending::Approval(Box::new(pending)),
            },
        )?;
        Ok((id, prompt))
    }

    pub(in crate::security_epoch) fn approve(
        &mut self,
        id: &Digest,
        bytes: &[u8],
        active: &mut ActiveControllerStorageContinuity,
        stage: EnrolledRoleStage<'_>,
        metadata: &InitialStoreMetadata,
        trace: &ServingTiming,
    ) -> Result<Digest> {
        ensure!(
            matches!(&self.slot.selected(id)?.pending, Pending::Approval(_)),
            "protected_restore_step_changed"
        );
        let Command {
            input,
            pending: Pending::Approval(pending),
        } = self.slot.take(id)?
        else {
            unreachable!("checked actual pending variant")
        };
        let assertion = Assertion::decode(bytes)?;
        let signed = (*pending)
            .approve(action(&input, active, stage, metadata, trace)?, &assertion)?
            .context("protected_restore_passkey_refused")?;
        let commitment = Digest::of(&signed)?;
        self.slot.insert(
            id.clone(),
            Command {
                input,
                pending: Pending::Approved(Box::new(signed)),
            },
        )?;
        Ok(commitment)
    }

    pub(in crate::security_epoch) fn issue_execution(
        &mut self,
        id: &Digest,
        active: &mut ActiveControllerStorageContinuity,
        stage: EnrolledRoleStage<'_>,
        metadata: &InitialStoreMetadata,
        trace: &ServingTiming,
    ) -> Result<Vec<u8>> {
        ensure!(
            matches!(&self.slot.selected(id)?.pending, Pending::Approved(_)),
            "protected_restore_step_changed"
        );
        let Command {
            input,
            pending: Pending::Approved(record),
        } = self.slot.take(id)?
        else {
            unreachable!("checked actual pending variant")
        };
        let pending = action(&input, active, stage, metadata, trace)?.issue_execution(
            &record,
            &input.restore.operation,
            &input.executor_credential,
        )?;
        let prompt = pending.request_options_data()?.encode()?;
        self.slot.insert(
            id.clone(),
            Command {
                input,
                pending: Pending::Execution {
                    pending: Box::new(pending),
                    record,
                },
            },
        )?;
        Ok(prompt)
    }

    /// Consume the actual executor ceremony into the existing captured archive.
    /// Its genuine original is captured BEFORE the accepting reader, and the
    /// complete owner then stays held through the private writer composition.
    pub(in crate::security_epoch) fn authenticate_archive<'metadata, 'storage, 'role>(
        &mut self,
        id: &Digest,
        bytes: &[u8],
        active: &'storage mut ActiveControllerStorageContinuity,
        stage: EnrolledRoleStage<'role>,
        metadata: &'metadata InitialStoreMetadata,
        trace: &'storage ServingTiming,
    ) -> Result<PreparedNativeRestoreArchive<'metadata, 'storage, 'role>> {
        ensure!(
            matches!(&self.slot.selected(id)?.pending, Pending::Execution { .. }),
            "protected_restore_step_changed"
        );
        let Command {
            input,
            pending: Pending::Execution { pending, record },
        } = self.slot.take(id)?
        else {
            unreachable!("checked actual pending variant")
        };
        let assertion = Assertion::decode(bytes)?;
        input.require_selected(&active.store)?;
        let reader = active
            .begin_restore_execution_reader(
                metadata,
                stage,
                &record,
                &input.restore.operation,
                trace,
            )?
            .context("protected_restore_current_admin_required")?;
        let executor = (*pending)
            .authenticate(reader, &assertion)?
            .context("protected_restore_executor_refused")?;
        PreparedNativeRestoreArchive::capture(executor, &input.archive_directory, &input.restore)
    }

    /// A failed/unknown browser reply may discard only its matching DATA slot.
    /// It never removes the spent identifier or repairs any native disposition.
    pub(in crate::security_epoch) fn abandon(&mut self, id: &Digest) -> Result<()> {
        drop(self.slot.take(id)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
