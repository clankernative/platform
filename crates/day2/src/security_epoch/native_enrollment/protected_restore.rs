//! Closed interface for a separate protected-restore DATA transport.
//!
//! The authenticated protocol is not implemented. Every admission, receive,
//! request and reply refuses; no method constructs a listener, peer or turn.
//! These signatures permit the real Controller caller to be composed without
//! treating a serving peer, locator or passkey DATA as native admission.
mod admission;
mod wire;

use super::{
    EnrolledCurrentRequest, EnrolledProcessRoleOwner, EnrolledRoleStage, NativeConsumerOrigin,
    SameEnrolledOwner,
};
use anyhow::{Result, bail, ensure};
use day2_capabilities::Digest;
use std::{cell::Cell, marker::PhantomData, rc::Rc};

#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{channel::Channel, process::MessageProcess};
#[cfg(target_os = "linux")]
use std::fs::File;

const MAX_INPUT_BYTES: usize = 32_768;
const MAX_ASSERTION_BYTES: usize = 16_384;
const UNAVAILABLE: &str = "native_protected_restore_transport_unavailable";

// An immutable view of one closed message's DATA, never a signing key, peer,
// stage or permission. Only this private protocol can construct the view; the
// actual native signer separately checks its own role and SAME original.
pub(in crate::security_epoch::native_enrollment) struct ProtectedRestoreMessage<'message> {
    body: MessageData<'message>,
}

enum MessageData<'message> {
    Admission(&'message admission::Body),
    Command {
        data: &'message wire::Data,
        admitted: &'message super::serving_peer_wire::Statement,
    },
}

impl<'message> ProtectedRestoreMessage<'message> {
    fn admission(body: &'message admission::Body) -> Self {
        Self {
            body: MessageData::Admission(body),
        }
    }

    fn command(
        data: &'message wire::Data,
        admitted: &'message super::serving_peer_wire::Statement,
    ) -> Self {
        Self {
            body: MessageData::Command { data, admitted },
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn domain(&self) -> &'static str {
        match self.body {
            MessageData::Admission(_) => admission::DOMAIN,
            MessageData::Command { .. } => wire::SIGNING_DOMAIN,
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn commitment_for(
        &self,
        local: &super::serving_peer_wire::Statement,
    ) -> Result<Digest> {
        use super::{NativeRole, protocol::StagePurpose};
        ensure!(
            local.original.purpose == StagePurpose::CurrentRole
                && local.stage.data.purpose == StagePurpose::CurrentRole,
            "protected_restore_signer_current_role_required"
        );
        match self.body {
            MessageData::Admission(body) => body.commitment_for(local),
            MessageData::Command { data, admitted } => {
                ensure!(
                    local.same_enrollment(admitted)
                        && admitted.original.purpose == StagePurpose::CurrentRole
                        && admitted.stage.data.purpose == StagePurpose::CurrentRole,
                    "protected_restore_signer_enrollment_changed"
                );
                let direction = match local.stage.data.role {
                    NativeRole::SecurityShell => wire::Direction::Request,
                    NativeRole::EpochController => wire::Direction::Reply,
                    NativeRole::AppHost => bail!("protected_restore_signer_app_refused"),
                };
                data.require_sender(&admission::enrollment(admitted)?, direction)?;
                data.commitment()
            }
        }
    }
}

/// Untrusted bounded command DATA only. The real server-held ceremony and
/// accepting native action remain mandatory in the protected command caller.
pub(crate) enum ProtectedRestoreRequest {
    BeginApproval { input: Vec<u8> },
    Approve { id: Digest, assertion: Vec<u8> },
    BeginExecution { id: Digest },
    Authenticate { id: Digest, assertion: Vec<u8> },
    Abandon { id: Digest },
}

impl ProtectedRestoreRequest {
    fn validate_data(&self) -> Result<()> {
        let bytes = match self {
            Self::BeginApproval { input } => Some((input, MAX_INPUT_BYTES)),
            Self::Approve { assertion, .. } | Self::Authenticate { assertion, .. } => {
                Some((assertion, MAX_ASSERTION_BYTES))
            }
            Self::BeginExecution { .. } | Self::Abandon { .. } => None,
        };
        if let Some((bytes, limit)) = bytes {
            ensure!(
                !bytes.is_empty() && bytes.len() <= limit,
                "native_protected_restore_input_bound"
            );
        }
        Ok(())
    }
}

/// Prompt and correlation DATA, never an authenticated executor or restore
/// completion. No positive final-restore reply exists in this interface.
pub(crate) enum ProtectedRestoreReply {
    ApprovalPrompt { id: Digest, prompt: Vec<u8> },
    ApprovalRecorded { commitment: Digest },
    ExecutionPrompt { id: Digest, prompt: Vec<u8> },
    Abandoned,
    Refused,
}

/// Closed native output step DATA. Each step stays inside the whole installed
/// carrier's fresh pre/post checks. The actual Turn must enforce ordering and
/// one packet; selecting a step cannot authorize or complete a restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::security_epoch) enum ProtectedRestoreInstalledIo {
    Prepare,
    Sign,
    Send,
    Poll,
}

/// Allowlisted output DATA from the actual installed carrier. No decoded or
/// caller-composed copy supplies its source loan, original, peer or permission.
/// The target includes the exact security epoch. The installed digest commits
/// the actual TargetReport and held SQLite cohort under a distinct purpose.
/// Approval is ApprovalRequest::commitment(), not a signed-record commitment;
/// installed is native-reported DATA, not a client-verifiable grant or readiness.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct RestoreInstalledOutputData {
    pub(crate) approval: Digest,
    pub(crate) operation: Digest,
    pub(crate) full_archive: Digest,
    pub(crate) target: crate::security_epoch::restore_approval::TargetBinding,
    pub(crate) executor: crate::security_epoch::restore_approval::AdminIdentity,
    pub(crate) installed: Digest,
}

impl ProtectedRestoreReply {
    fn validate_data(&self) -> Result<()> {
        if let Self::ApprovalPrompt { prompt, .. } | Self::ExecutionPrompt { prompt, .. } = self {
            ensure!(
                !prompt.is_empty() && prompt.len() <= MAX_INPUT_BYTES,
                "native_protected_restore_prompt_bound"
            );
        }
        Ok(())
    }
}

/// Intended real admission resources, with no constructor accepting their
/// parts. Fixed native admission is currently closed on every platform.
pub(in crate::security_epoch) struct ProtectedRestoreListener {
    _same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    listener: Option<File>,
    refused: Cell<bool>,
    _local: PhantomData<Rc<()>>,
}

/// Intended retained admitted peer. Connection identity and kernel sender
/// anchors must be supplied by the future fixed protocol, never by DATA.
pub(in crate::security_epoch) struct ProtectedRestorePeer {
    _same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    channel: Option<Channel>,
    #[cfg(target_os = "linux")]
    _sender: MessageProcess,
    _connection: Digest,
    _sequence: u64,
    refused: Rc<Cell<bool>>,
    _local: PhantomData<Rc<()>>,
}

/// Negative access to the SAME peer root only. It can poison outstanding use
/// without borrowing the peer, but cannot close/adopt descriptors, observe a
/// clock, reset refusal or create a replacement peer. There is no Drop action:
/// the actual outer attempt guard chooses when to poison or disarm.
pub(in crate::security_epoch) struct ProtectedRestoreRefusal {
    root: Rc<Cell<bool>>,
}

/// Shell-side DATA courier. This does not hold a Current, SQL loan, stage,
/// executor or approval while the browser waits for its human.
pub(crate) struct ProtectedRestoreShell {
    _same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    channel: Option<Channel>,
    #[cfg(target_os = "linux")]
    _sender: MessageProcess,
    _connection: Digest,
    _sequence: u64,
    refused: Cell<bool>,
    _local: PhantomData<Rc<()>>,
}

/// One exclusive request/reply loan. The caller may read command DATA only;
/// it receives no channel, role, descriptor or stage. Abandonment poisons the
/// same actual peer. No factory currently constructs a turn.
pub(in crate::security_epoch) struct ProtectedRestoreTurn<'peer> {
    peer: &'peer mut ProtectedRestorePeer,
    request: ProtectedRestoreRequest,
    // Retained from the actual receive stage, never decoded from wire DATA.
    original: NativeConsumerOrigin,
    replied: bool,
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
    assert_not_impl!(ProtectedRestoreListener);
    assert_not_impl!(ProtectedRestorePeer);
    assert_not_impl!(ProtectedRestoreRefusal);
    assert_not_impl!(ProtectedRestoreShell);
    assert_not_impl!(ProtectedRestoreTurn<'static>);
};

impl ProtectedRestoreListener {
    pub(in crate::security_epoch) fn bind(_role: &mut EnrolledProcessRoleOwner) -> Result<Self> {
        bail!(UNAVAILABLE)
    }

    /// Readiness DATA only, before any bounded accept action begins. This
    /// cannot grant a role or hold an original across human idle time. Native
    /// readiness is not implemented yet, so this interface still refuses.
    pub(in crate::security_epoch) fn pending(&mut self) -> Result<bool> {
        self.refuse();
        bail!(UNAVAILABLE)
    }

    pub(in crate::security_epoch) fn accept(
        &mut self,
        _role: &mut EnrolledProcessRoleOwner,
    ) -> Result<ProtectedRestorePeer> {
        self.refuse();
        bail!(UNAVAILABLE)
    }

    fn refuse(&mut self) {
        self.refused.set(true);
        #[cfg(target_os = "linux")]
        {
            self.listener = None;
        }
    }
}

impl Drop for ProtectedRestoreListener {
    fn drop(&mut self) {
        self.refuse();
    }
}

impl ProtectedRestorePeer {
    /// Retain only the actual peer's negative root before a disjoint request /
    /// peer loan. A previous peer's handle cannot poison a replacement root.
    pub(in crate::security_epoch) fn retained_refusal(&self) -> ProtectedRestoreRefusal {
        ProtectedRestoreRefusal {
            root: Rc::clone(&self.refused),
        }
    }

    /// Bind an outer native action to this peer's exact enrolled owner, not
    /// merely equal scope/profile DATA. The eventual comparison must use the
    /// retained actual identity and refuse this peer on mismatch. This lends
    /// no identity, stage, action or renewed clock; admission is still closed.
    pub(in crate::security_epoch) fn require_owner(
        &mut self,
        _role: &EnrolledProcessRoleOwner,
    ) -> Result<()> {
        self.refuse();
        bail!(UNAVAILABLE)
    }

    /// Readiness DATA precedes the caller's capture of a fresh bounded request.
    /// It cannot create a stage or retain an original across human idle time.
    /// The native supplier is still unavailable, so no idle result is invented.
    pub(in crate::security_epoch) fn pending(&mut self) -> Result<bool> {
        self.refuse();
        bail!(UNAVAILABLE)
    }

    /// The caller retains the actual saved request in stable session storage.
    /// A turn borrows only this peer, not that request or the role stage. The
    /// core must consume this SAME stage, then reborrow the SAME saved request
    /// for a nonterminal reply. No new original may begin between these steps.
    /// Admission is still closed: both peer and actual stage refuse here.
    pub(in crate::security_epoch) fn try_receive<'peer>(
        &'peer mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<Option<ProtectedRestoreTurn<'peer>>> {
        self.refuse();
        stage.refuse_serving();
        bail!(UNAVAILABLE)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused.set(true);
        #[cfg(target_os = "linux")]
        {
            self.channel = None;
        }
    }
}

impl ProtectedRestoreRefusal {
    pub(in crate::security_epoch) fn refuse(&self) {
        self.root.set(true);
    }
}

impl Drop for ProtectedRestorePeer {
    fn drop(&mut self) {
        self.refuse();
    }
}

impl ProtectedRestoreShell {
    /// Connection setup borrows the same saved request stage as its first
    /// DATA exchange; it cannot acquire another original from a bare role.
    pub(crate) fn connect(_stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        bail!(UNAVAILABLE)
    }

    /// The fixed courier lends the stage from its SAME saved HTTP original.
    /// A future implementation must check this actual owner and its full
    /// SecurityShell selection around native I/O without acquiring a new
    /// stage or original. The borrow cannot escape this DATA exchange, and
    /// no accepting transport is implemented by this interface.
    pub(crate) fn request(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        request: ProtectedRestoreRequest,
    ) -> Result<ProtectedRestoreReply> {
        self.refuse();
        stage.refuse_serving();
        ensure!(
            !matches!(&request, ProtectedRestoreRequest::Authenticate { .. }),
            "native_protected_restore_authenticate_requires_fixed_exchange"
        );
        request.validate_data()?;
        bail!(UNAVAILABLE)
    }

    /// Fixed final exchange under the SAME saved Shell HTTP original. The
    /// genuine implementation must retain its admitted connection and sequence,
    /// bind this exact Authenticate command, verify the fixed signed terminal
    /// packet, and independently postcheck its peer/original/stage on errors
    /// and unwind without a capture, retry or renewed clock. The generic DATA
    /// reply entry cannot serve this purpose. No native transport is supplied
    /// here: both actual inputs refuse before returning any validation error.
    /// The terminal interface consumes the genuine whole Box. Its eventual
    /// positive path must retain that courier in the same saved HTTP frame;
    /// returned DATA alone can never disarm its negative Drop duty.
    /// Returned metadata will not prove completed human/HTTP delivery.
    pub(crate) fn authenticate(
        mut self: Box<Self>,
        stage: &mut EnrolledRoleStage<'_>,
        id: &Digest,
        assertion: &[u8],
    ) -> Result<RestoreInstalledOutputData> {
        self.refuse();
        stage.refuse_serving();
        let _ = id;
        ensure!(
            (1..=MAX_ASSERTION_BYTES).contains(&assertion.len()),
            "native_protected_restore_input_bound"
        );
        bail!(UNAVAILABLE)
    }

    pub(crate) fn refuse(&mut self) {
        self.refused.set(true);
        #[cfg(target_os = "linux")]
        {
            self.channel = None;
        }
    }
}

impl Drop for ProtectedRestoreShell {
    fn drop(&mut self) {
        self.refuse();
    }
}

impl ProtectedRestoreTurn<'_> {
    pub(in crate::security_epoch) fn request_data(&self) -> &ProtectedRestoreRequest {
        &self.request
    }

    /// Fixed consuming handoff for the actual Authenticate turn only. It
    /// compares this turn's actual negative original identity, then MOVES the
    /// saved request's actual acquisition into an owned stage without a new
    /// capture, narrowed copy or clock reset.
    /// Borrowed-original retirement must continue to refuse. The caller marks
    /// its session terminal before this attempt and retains both negative roots
    /// through the whole accepting owner; taking this request is not completion.
    /// Native peer admission remains closed, so no turn or successful stage
    /// can currently be supplied on any platform.
    pub(in crate::security_epoch) fn take_accepting_stage<'role>(
        &mut self,
        request: EnrolledCurrentRequest,
        role: &'role mut EnrolledProcessRoleOwner,
    ) -> Result<EnrolledRoleStage<'role>> {
        let result = role.take_protected_restore_request(request, self);
        if result.is_err() {
            self.refuse_transfer();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn require_accepting_original(
        &mut self,
        original: &NativeConsumerOrigin,
        role: &EnrolledProcessRoleOwner,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.peer.refused.get(), "protected_restore_peer_refused");
            ensure!(
                matches!(&self.request, ProtectedRestoreRequest::Authenticate { .. }),
                "protected_restore_authenticate_required"
            );
            self.original.require_same(original)?;
            self.peer.require_owner(role)
        })();
        if result.is_err() {
            original.refuse();
            self.refuse_transfer();
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse_transfer(&mut self) {
        self.original.refuse();
        self.peer.refuse();
    }

    /// Negative access for the WHOLE installed-carrier attempt, including a
    /// failure before its first native step. This cannot sample, renew, settle
    /// or disarm either root, and cannot make a failed Turn reusable.
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.original.refuse();
        self.peer.refuse();
    }

    /// Fixed native packet entry. Its source loan is created only by the whole
    /// Pending driver after actual App acceptance and its full post. No generic
    /// bytes, callback, stage getter, output receipt or scalar completion exists.
    /// That driver brackets EACH operation with full parent checks and retires
    /// the old counter/physical/original only after the final output post.
    /// Native output remains closed: all actual inputs refuse and no packet or
    /// positive transport disposition is produced. The accepting composition
    /// must supply the genuine loan type before this interface can compile.
    pub(in crate::security_epoch) fn installed_output(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreInstalledOutputLoan<'_, '_, '_>,
        _operation: ProtectedRestoreInstalledIo,
    ) -> Result<super::ReceiverProgress> {
        self.refuse();
        stage.refuse_serving();
        loan.refuse();
        bail!(UNAVAILABLE)
    }

    /// The terminal path consumes the WHOLE genuine installed carrier, never
    /// a completed DATA reply or caller assertion. Its future fixed driver must
    /// retain every original/target/cohort/peer owner through real App installed
    /// acceptance, its posts, ONE operator packet and independent native/full
    /// parent posts, then retire the old counter/peer/original LAST. Nothing may
    /// sample or revive that old original after retirement. Only a genuine
    /// consuming result may release the caller's negative Attempt duty. Only
    /// that result disarms this Turn's negative Drop. The fixed installed output
    /// supplier still refuses, so no positive terminal path is available yet.
    /// Generic reply stays DATA-only.
    pub(in crate::security_epoch) fn finish_installed<
        'frame,
        'confirm,
        'metadata,
        'storage,
        'role,
        'target,
        'selection,
    >(
        mut self,
        installation: crate::security_epoch::bootstrap::PendingControllerCurrentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    ) -> Result<
        crate::security_epoch::bootstrap::RetiredControllerCurrentInstallation<
            'frame,
            'confirm,
            'metadata,
            'storage,
            'role,
            'target,
            'selection,
        >,
    > {
        let retired = installation.finish_protected_restore(&mut self)?;
        // Only a genuine whole retired carrier can disarm this negative duty.
        // No old positive check, I/O, wait or callback follows retirement.
        self.replied = true;
        Ok(retired)
    }

    /// Result::Ok would mean this bounded DATA reply was sent, never that an
    /// accepting restore completed or a human received it. Actual native
    /// final-output settlement needs its own closed integration. No send or
    /// successful reply is currently implemented here. The native implementation
    /// must match this stage's actual negative original identity to the receive
    /// turn, independently postcheck it, and never accept equal clock DATA.
    pub(in crate::security_epoch) fn reply(
        self,
        stage: &mut EnrolledRoleStage<'_>,
        reply: ProtectedRestoreReply,
    ) -> Result<()> {
        self.peer.refuse();
        stage.refuse_serving();
        reply.validate_data()?;
        bail!(UNAVAILABLE)
    }
}

impl Drop for ProtectedRestoreTurn<'_> {
    fn drop(&mut self) {
        if !self.replied {
            self.original.refuse();
            self.peer.refuse();
        }
    }
}

#[cfg(test)]
mod terminal_source_tests {
    use quote::ToTokens;

    fn finish() -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("protected_restore.rs")).unwrap();
        let methods = file.items.into_iter().filter_map(|item| match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == "ProtectedRestoreTurn")) => Some(item),
            _ => None,
        }).flat_map(|item| item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "finish_installed" => Some(method),
            _ => None,
        }).collect::<Vec<_>>();
        assert_eq!(methods.len(), 1);
        methods.into_iter().next().unwrap()
    }

    fn genuine_finish(body: &syn::Block) -> bool {
        let expected: syn::Block = syn::parse_quote!({
            let retired = installation.finish_protected_restore(&mut self)?;
            self.replied = true;
            Ok(retired)
        });
        body.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    #[test]
    fn actual_shell_final_exchange_is_distinct_and_refuses_actual_inputs_before_data_errors() {
        fn method(name: &str) -> syn::ImplItemFn {
            let file = syn::parse_file(include_str!("protected_restore.rs")).unwrap();
            let mut methods = file.items.into_iter().filter_map(|item| match item {
                syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == "ProtectedRestoreShell")) => Some(item),
                _ => None,
            }).flat_map(|item| item.items).filter_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            }).collect::<Vec<_>>();
            assert_eq!(methods.len(), 1);
            methods.remove(0)
        }
        let auth = method("authenticate");
        let expected: syn::Signature = syn::parse_quote!(fn authenticate(mut self: Box<Self>, stage: &mut EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8]) -> Result<RestoreInstalledOutputData>);
        let signature = |signature: &syn::Signature| {
            let mut signature = signature.clone();
            signature.inputs.pop_punct();
            signature.to_token_stream().to_string()
        };
        let canonical = signature(&expected);
        let with_comma: syn::Signature = syn::parse_quote!(fn authenticate(mut self: Box<Self>, stage: &mut EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8],) -> Result<RestoreInstalledOutputData>);
        assert_eq!(signature(&with_comma), canonical);
        assert_eq!(signature(&auth.sig), canonical);
        for source in [
            "fn authenticate(&mut self, stage: &mut EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8]) -> Result<RestoreInstalledOutputData>",
            "fn authenticate(self, stage: &mut EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8]) -> Result<RestoreInstalledOutputData>",
            "fn authenticate(&mut self, stage: &EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8]) -> Result<RestoreInstalledOutputData>",
            "fn authenticate(&mut self, stage: &mut OtherStage, id: &Digest, assertion: &[u8]) -> Result<RestoreInstalledOutputData>",
            "fn authenticate(&mut self, stage: &mut EnrolledRoleStage<'_>, id: Digest, assertion: &[u8]) -> Result<RestoreInstalledOutputData>",
            "fn authenticate(&mut self, stage: &mut EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8], callback: Callback) -> Result<RestoreInstalledOutputData>",
            "fn authenticate(&mut self, stage: &mut EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8]) -> Result<ProtectedRestoreReply>",
            "unsafe fn authenticate(&mut self, stage: &mut EnrolledRoleStage<'_>, id: &Digest, assertion: &[u8]) -> Result<RestoreInstalledOutputData>",
        ] {
            let changed = syn::parse_str(source).unwrap();
            assert_ne!(signature(&changed), canonical);
        }
        assert!(
            matches!(&auth.vis, syn::Visibility::Restricted(vis) if vis.path.is_ident("crate"))
        );
        let expected: syn::Block = syn::parse_quote!({
            self.refuse();
            stage.refuse_serving();
            let _ = id;
            ensure!(
                (1..=MAX_ASSERTION_BYTES).contains(&assertion.len()),
                "native_protected_restore_input_bound"
            );
            bail!(UNAVAILABLE)
        });
        assert_eq!(
            auth.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        for index in 0..auth.block.stmts.len() {
            let mut removed = auth.block.clone();
            removed.stmts.remove(index);
            assert_ne!(
                removed.to_token_stream().to_string(),
                expected.to_token_stream().to_string()
            );
        }
        let mut late = auth.block.clone();
        late.stmts.swap(1, 3);
        assert_ne!(
            late.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let request = method("request");
        let expected: syn::Block = syn::parse_quote!({
            self.refuse();
            stage.refuse_serving();
            ensure!(
                !matches!(&request, ProtectedRestoreRequest::Authenticate { .. }),
                "native_protected_restore_authenticate_requires_fixed_exchange"
            );
            request.validate_data()?;
            bail!(UNAVAILABLE)
        });
        assert_eq!(
            request.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let mut generic = request.block;
        generic.stmts.remove(2);
        assert_ne!(
            generic.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    #[test]
    fn actual_terminal_finish_disarms_only_after_the_whole_installed_carrier_returns_retired() {
        let actual = finish();
        assert!(
            matches!(actual.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_none() && receiver.mutability.is_some())
        );
        assert!(genuine_finish(&actual.block));
        for index in 0..actual.block.stmts.len() {
            let mut missing = actual.block.clone();
            missing.stmts.remove(index);
            assert!(!genuine_finish(&missing));
        }
        let mut early = actual.block.clone();
        early.stmts.swap(0, 1);
        assert!(!genuine_finish(&early));
        for statement in [
            syn::parse_quote!(let retired = other.finish_protected_restore(&mut self)?;),
            syn::parse_quote!(let retired = installation.finish_protected_restore(&mut self);),
            syn::parse_quote!(let retired = caller_data;),
            syn::parse_quote!(let retired = (|| installation.finish_protected_restore(&mut self))();),
        ] {
            let mut changed = actual.block.clone();
            changed.stmts[0] = statement;
            assert!(!genuine_finish(&changed));
        }
        let mut sampled = actual.block.clone();
        sampled
            .stmts
            .insert(1, syn::parse_quote!(self.original.sample()?;));
        assert!(!genuine_finish(&sampled));
        let mut wrong_result = actual.block;
        wrong_result.stmts[2] = syn::Stmt::Expr(syn::parse_quote!(Ok(caller_data)), None);
        assert!(!genuine_finish(&wrong_result));
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    use quote::ToTokens;

    #[test]
    fn actual_accepting_handoff_matches_the_receive_original_and_authenticate_before_owner_transfer()
     {
        fn method(name: &str) -> syn::ImplItemFn {
            let file = syn::parse_file(include_str!("protected_restore.rs")).unwrap();
            let mut methods = file.items.into_iter().filter_map(|item| match item {
                syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == "ProtectedRestoreTurn")) => Some(item),
                _ => None,
            }).flat_map(|item| item.items).filter_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            }).collect::<Vec<_>>();
            assert_eq!(methods.len(), 1);
            methods.remove(0)
        }
        let taking = method("take_accepting_stage");
        let expected: syn::Block = syn::parse_quote!({
            let result = role.take_protected_restore_request(request, self);
            if result.is_err() {
                self.refuse_transfer();
            }
            result
        });
        assert_eq!(
            taking.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let checked = method("require_accepting_original");
        let expected: syn::Block = syn::parse_quote!({
            let result = (|| {
                ensure!(!self.peer.refused.get(), "protected_restore_peer_refused");
                ensure!(
                    matches!(&self.request, ProtectedRestoreRequest::Authenticate { .. }),
                    "protected_restore_authenticate_required"
                );
                self.original.require_same(original)?;
                self.peer.require_owner(role)
            })();
            if result.is_err() {
                original.refuse();
                self.refuse_transfer();
            }
            result
        });
        let checked = checked.block.to_token_stream().to_string();
        assert_eq!(checked, expected.to_token_stream().to_string());
        let statement = |source: &str| {
            syn::parse_str::<syn::Stmt>(source)
                .unwrap()
                .to_token_stream()
                .to_string()
        };
        let expression = |source: &str| {
            syn::parse_str::<syn::Expr>(source)
                .unwrap()
                .to_token_stream()
                .to_string()
        };
        for (needle, replacement) in [
            (
                statement("self.original.require_same(original)?;"),
                String::new(),
            ),
            (
                expression("ProtectedRestoreRequest::Authenticate"),
                expression("ProtectedRestoreRequest::BeginExecution"),
            ),
            (
                expression("self.peer.require_owner(role)"),
                expression("Ok(())"),
            ),
            (statement("original.refuse();"), String::new()),
            (statement("self.refuse_transfer();"), String::new()),
        ] {
            assert_eq!(checked.matches(&needle).count(), 1);
            let changed =
                syn::parse_str::<syn::Block>(&checked.replacen(&needle, &replacement, 1)).unwrap();
            assert_ne!(
                changed.to_token_stream().to_string(),
                expected.to_token_stream().to_string()
            );
        }
        let refused = method("refuse_transfer");
        let expected: syn::Block = syn::parse_quote!({
            self.original.refuse();
            self.peer.refuse();
        });
        assert_eq!(
            refused.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let dropped = method("drop");
        let expected: syn::Block = syn::parse_quote!({
            if !self.replied {
                self.original.refuse();
                self.peer.refuse();
            }
        });
        assert_eq!(
            dropped.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    #[test]
    fn negative_root_refusal_survives_other_loans_and_cannot_poison_a_replacement() {
        // Negative-root DATA fixture only: no native peer, sender, stage or
        // accepting owner is constructed. The source control below pins the
        // actual peer factory to precisely this retained Rc behavior.
        let first = Rc::new(Cell::new(false));
        let replacement = Rc::new(Cell::new(false));
        let retained = ProtectedRestoreRefusal {
            root: Rc::clone(&first),
        };
        let another = ProtectedRestoreRefusal {
            root: Rc::clone(&first),
        };
        let independent = ProtectedRestoreRefusal {
            root: Rc::clone(&replacement),
        };
        drop(first);
        retained.refuse();
        assert!(another.root.get());
        assert!(!replacement.get());
        drop(retained);
        assert!(another.root.get());
        independent.refuse();
        assert!(replacement.get());
    }

    #[test]
    fn actual_peer_factory_retains_its_own_root_and_the_handle_only_sets_refusal() {
        let file = syn::parse_file(include_str!("protected_restore.rs")).unwrap();
        let mut methods = Vec::new();
        for item in file.items {
            if let syn::Item::Impl(item) = item {
                let syn::Type::Path(owner) = item.self_ty.as_ref() else {
                    continue;
                };
                let Some(owner) = owner.path.segments.last() else {
                    continue;
                };
                if item.trait_.is_some() {
                    continue;
                }
                for method in item.items {
                    if let syn::ImplItem::Fn(method) = method {
                        methods.push((owner.ident.to_string(), method));
                    }
                }
            }
        }
        let peer = methods
            .iter()
            .filter(|(owner, method)| {
                owner == "ProtectedRestorePeer" && method.sig.ident == "retained_refusal"
            })
            .collect::<Vec<_>>();
        assert_eq!(peer.len(), 1);
        let expected: syn::Block = syn::parse_quote!({
            ProtectedRestoreRefusal {
                root: Rc::clone(&self.refused),
            }
        });
        let actual = peer[0].1.block.to_token_stream().to_string();
        assert_eq!(actual, expected.to_token_stream().to_string());
        for foreign in [
            syn::parse_quote!({
                ProtectedRestoreRefusal {
                    root: Rc::new(Cell::new(false)),
                }
            }),
            syn::parse_quote!({
                ProtectedRestoreRefusal {
                    root: Rc::clone(&other.refused),
                }
            }),
        ] {
            let foreign: syn::Block = foreign;
            assert_ne!(actual, foreign.to_token_stream().to_string());
        }
        let handle = methods
            .iter()
            .filter(|(owner, _)| owner == "ProtectedRestoreRefusal")
            .collect::<Vec<_>>();
        assert_eq!(handle.len(), 1, "no reset, live getter or adoption method");
        assert_eq!(handle[0].1.sig.ident, "refuse");
        let expected: syn::Block = syn::parse_quote!({
            self.root.set(true);
        });
        assert_eq!(
            handle[0].1.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }
}
