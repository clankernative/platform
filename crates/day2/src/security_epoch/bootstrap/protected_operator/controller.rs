//! Fixed Controller-side consumer of the closed protected-restore interface.
//! The fixed startup integration uses the genuine native backend; command DATA
//! cannot construct a native peer or substitute for retained admission.
use super::super::ActiveControllerStorageContinuity;
use super::{Input, Pending, ProtectedRestoreCommands};
use crate::security_epoch::{
    controller::serving_timing::ServingTiming,
    native_enrollment::{
        EnrolledCurrentRequest, EnrolledProcessRoleOwner, EnrolledRoleStage, NativeConsumerOrigin,
        ProtectedRestoreListener, ProtectedRestorePeer, ProtectedRestoreRefusal,
        ProtectedRestoreReply, ProtectedRestoreRequest, ProtectedRestoreTurn,
    },
    restore_staging::PreparedNativeRestoreArchive,
};
use crate::store::InitialStoreMetadata;
use anyhow::{Context, Result};

/// The actual peer and its actual pending ceremonies have one owner. Dropping
/// this session loses its pending values; a new peer cannot adopt its cache.
pub(in crate::security_epoch) struct ProtectedRestoreSession {
    peer: ProtectedRestorePeer,
    request: Option<EnrolledCurrentRequest>,
    terminal: bool,
    commands: ProtectedRestoreCommands,
}

/// Negative roots only. This cannot create a peer, stage, clock or Current.
/// It is armed before capture/receive and remains with accepting work through
/// the eventual genuine terminal owner. Errors before a Turn exists and panic
/// unwind poison the SAME actual peer and, once captured, original.
pub(in crate::security_epoch) struct Attempt {
    peer: ProtectedRestoreRefusal,
    original: Option<NativeConsumerOrigin>,
    settled: bool,
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.settled {
            self.peer.refuse();
            if let Some(original) = &self.original {
                original.refuse();
            }
        }
    }
}

/// The accepting turn retains the actual peer borrow alongside the whole
/// authenticated archive. There is no parts getter or completed DATA reply.
/// Its eventual fixed consuming implementation must keep both through writer
/// installation and genuine finite output settlement. Dropping it refuses via
/// the retained turn and existing archive/executor terminal owners.
pub(in crate::security_epoch) struct PreparedProtectedRestore<'peer, 'metadata, 'storage, 'role> {
    archive: PreparedNativeRestoreArchive<'metadata, 'storage, 'role>,
    turn: ProtectedRestoreTurn<'peer>,
    attempt: Attempt,
}

impl Attempt {
    /// Only the genuine WHOLE retired installation can settle this terminal
    /// negative duty. No boolean, ACK, packet result or borrowed old stage is
    /// accepted here. The new serving loop retains that same carrier forever;
    /// errors/drop still refuse its genuine native/counter/target owners.
    pub(in crate::security_epoch) fn serve_installed(
        mut self,
        installation: crate::security_epoch::bootstrap::RetiredControllerCurrentInstallation<
            '_,
            '_,
            '_,
            '_,
            '_,
            '_,
            '_,
        >,
    ) -> Result<()> {
        self.settled = true;
        installation.serve_app_currents()
    }
}

impl PreparedProtectedRestore<'_, '_, '_, '_> {
    /// One fixed lexical driver keeps the archive, actual saved-original turn
    /// and armed Attempt through reset/writer/install/finite output. It returns
    /// no parts, permission or completed DATA. No generic callback is accepted.
    pub(in crate::security_epoch) fn run(self) -> Result<()> {
        let Self {
            archive,
            turn,
            attempt,
        } = self;
        archive.run_protected(turn, attempt)
    }
}

// A fixed DATA reply, under the exact borrowed request stage. The independent
// postcheck runs even after reply failure/unwind and cannot replace its primary.
fn reply(
    turn: ProtectedRestoreTurn<'_>,
    mut stage: EnrolledRoleStage<'_>,
    data: ProtectedRestoreReply,
) -> Result<()> {
    let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        turn.reply(&mut stage, data)
    }));
    let post = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
    observed(requested, post)
}

type Unwind<T> = std::result::Result<T, Box<dyn std::any::Any + Send>>;

// Pure merge of ALREADY observed outcomes. No callback or native authority.
fn observed(requested: Unwind<Result<()>>, post: Unwind<Result<()>>) -> Result<()> {
    match requested {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(Err(error)) => Err(error),
        Ok(Ok(())) => match post {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        },
    }
}

fn finish(
    request: &mut Option<EnrolledCurrentRequest>,
    role: &mut EnrolledProcessRoleOwner,
    attempt: &mut Attempt,
) -> Result<()> {
    request
        .take()
        .context("protected_restore_saved_request_missing")?
        .finish(role)?;
    attempt.settled = true;
    Ok(())
}

const _: () = {
    macro_rules! assert_not_impl {
        ($owner:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$owner as Ambiguous<_>>::check;
        }};
        ($owner:ty) => {
            assert_not_impl!($owner, Clone);
            assert_not_impl!($owner, Copy);
            assert_not_impl!($owner, Default);
            assert_not_impl!($owner, std::fmt::Debug);
            assert_not_impl!($owner, Send);
            assert_not_impl!($owner, Sync);
            assert_not_impl!($owner, serde::Serialize);
            assert_not_impl!($owner, serde::Deserialize<'static>);
        };
    }
    assert_not_impl!(ProtectedRestoreSession);
    assert_not_impl!(PreparedProtectedRestore<'static, 'static, 'static, 'static>);
    assert_not_impl!(Attempt);
};

// This is refusal-only routing DATA. Every selected core entry independently
// repeats its real phase/input checks and admits its genuine current supplier.
// A wrong locator/phase gets a closed refusal without consuming the rightful
// pending ceremony. No native action has begun at this preflight boundary.
fn matches_pending(commands: &ProtectedRestoreCommands, request: &ProtectedRestoreRequest) -> bool {
    match request {
        ProtectedRestoreRequest::BeginApproval { input } => {
            commands.slot.current.is_none()
                && commands.slot.seen.len() < super::MAX_ATTEMPTS
                && Input::decode(input)
                    .is_ok_and(|input| !commands.slot.seen.contains(&input.approval.grant_id))
        }
        ProtectedRestoreRequest::Approve { id, .. } => commands
            .slot
            .selected(id)
            .is_ok_and(|command| matches!(&command.pending, Pending::Approval(_))),
        ProtectedRestoreRequest::BeginExecution { id } => commands
            .slot
            .selected(id)
            .is_ok_and(|command| matches!(&command.pending, Pending::Approved(_))),
        ProtectedRestoreRequest::Authenticate { id, .. } => commands
            .slot
            .selected(id)
            .is_ok_and(|command| matches!(&command.pending, Pending::Execution { .. })),
        ProtectedRestoreRequest::Abandon { id } => commands.slot.selected(id).is_ok(),
    }
}

impl ProtectedRestoreSession {
    /// Only readiness DATA precedes the fresh bounded native acceptance. No
    /// role stage, original or action is kept while waiting for the human's
    /// first connection. The actual native accept still checks the real peer.
    /// The fixed native supplier checks the actual peer, with no startup fallback.
    pub(in crate::security_epoch) fn try_accept(
        listener: &mut ProtectedRestoreListener,
        role: &mut EnrolledProcessRoleOwner,
    ) -> Result<Option<Self>> {
        if !listener.pending()? {
            return Ok(None);
        }
        let peer = listener.accept(role)?;
        Ok(Some(Self {
            peer,
            request: None,
            terminal: false,
            commands: ProtectedRestoreCommands::new(),
        }))
    }

    /// Idle/prompt progress is DATA only. Some retains the actual exclusive
    /// native turn and authenticated archive together; it is not completion.
    /// A native/core error propagates unchanged and the unreplied turn poisons
    /// its actual peer. No alternate command or continuation runs after Err.
    pub(in crate::security_epoch) fn poll<'peer, 'metadata, 'storage, 'role>(
        &'peer mut self,
        active: &'storage mut ActiveControllerStorageContinuity,
        role: &'role mut EnrolledProcessRoleOwner,
        metadata: &'metadata InitialStoreMetadata,
        trace: &'storage ServingTiming,
    ) -> Result<Option<PreparedProtectedRestore<'peer, 'metadata, 'storage, 'role>>>
    where
        'peer: 'role,
    {
        // Stable, disjoint storage permits the archive to borrow the actual
        // saved request while its Turn borrows only the actual peer. Never
        // detach/reconstruct either owner, replace an in-flight request, or
        // retain a Current during human idle time.
        let mut attempt = Attempt {
            peer: self.peer.retained_refusal(),
            original: None,
            settled: false,
        };
        if self.terminal {
            anyhow::bail!("protected_restore_session_terminal");
        }
        if let Some(request) = &mut self.request {
            request.refuse();
            anyhow::bail!("protected_restore_request_already_active");
        }
        self.peer.require_owner(role)?;
        if !self.peer.pending()? {
            // No request/action was captured and no Turn or accepting work
            // exists. Readiness is DATA only, with no original across idle.
            attempt.settled = true;
            return Ok(None);
        }
        self.request = Some(role.begin_current_request()?);
        attempt.original = Some(
            self.request
                .as_ref()
                .expect("actual saved request")
                .consumer_origin(),
        );
        let mut turn = {
            let request = self.request.as_mut().expect("actual saved request");
            let mut stage = role.borrow_current_request(request)?;
            self.peer
                .try_receive(&mut stage)?
                .context("protected_restore_ready_request_missing")?
        };
        if !matches_pending(&self.commands, turn.request_data()) {
            let stage =
                role.borrow_current_request(self.request.as_mut().expect("same saved request"))?;
            reply(turn, stage, ProtectedRestoreReply::Refused)?;
            finish(&mut self.request, role, &mut attempt)?;
            return Ok(None);
        }
        // Separate the consuming return before any nonterminal core loan. A
        // reborrow is ALWAYS from this same saved request; it checks the same
        // original and cannot renew its clock. No unsafe/self-reference or
        // replacement acquisition is used to satisfy the Rust lifetime.
        if let ProtectedRestoreRequest::Authenticate { id, assertion } = turn.request_data() {
            // Copy bounded untrusted DATA only, ending the immutable Turn
            // borrow before its genuine consuming-owner method. No original,
            // stage, peer or clock is cloned or reconstructed.
            let (id, assertion) = (id.clone(), assertion.clone());
            self.terminal = true;
            let request = self.request.take().expect("same saved request");
            let stage = turn.take_accepting_stage(request, role)?;
            let archive = self
                .commands
                .authenticate_archive(&id, &assertion, active, stage, metadata, trace)?;
            return Ok(Some(PreparedProtectedRestore {
                archive,
                turn,
                attempt,
            }));
        }
        let stage =
            role.borrow_current_request(self.request.as_mut().expect("same saved request"))?;
        let data = match turn.request_data() {
            ProtectedRestoreRequest::BeginApproval { input } => {
                let (id, prompt) = self
                    .commands
                    .issue_approval(input, active, stage, metadata, trace)?;
                ProtectedRestoreReply::ApprovalPrompt { id, prompt }
            }
            ProtectedRestoreRequest::Approve { id, assertion } => {
                let commitment = self
                    .commands
                    .approve(id, assertion, active, stage, metadata, trace)?;
                ProtectedRestoreReply::ApprovalRecorded { commitment }
            }
            ProtectedRestoreRequest::BeginExecution { id } => {
                let prompt = self
                    .commands
                    .issue_execution(id, active, stage, metadata, trace)?;
                let id = id.clone();
                ProtectedRestoreReply::ExecutionPrompt { id, prompt }
            }
            ProtectedRestoreRequest::Authenticate { .. } => {
                unreachable!("terminal branch returned")
            }
            ProtectedRestoreRequest::Abandon { id } => {
                self.commands.abandon(id)?;
                drop(stage);
                ProtectedRestoreReply::Abandoned
            }
        };
        let stage =
            role.borrow_current_request(self.request.as_mut().expect("same saved request"))?;
        reply(turn, stage, data)?;
        finish(&mut self.request, role, &mut attempt)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
