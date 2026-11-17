//! Closed interface for a separate protected-restore DATA transport.
//!
//! Listener setup retains actual pinned socket resources, with no Current
//! across idle time. Fixed initial admission validates the actual enrolled
//! peers and every kernel sender. Warm commands and final output retain their
//! actual peer in the saved frame; locator/passkey DATA is not native admission.
mod admission;
mod courier;
mod native;
#[cfg(test)]
mod native_source_tests;
mod terminal;
mod warm;
mod wire;

#[cfg(target_os = "linux")]
pub(in crate::security_epoch::native_enrollment) use terminal::{
    DOMAIN as INSTALLED_SIGNING_DOMAIN, InstalledSendStart,
    MAX_PACKET_BYTES as MAX_INSTALLED_PACKET_BYTES, Packet as UnverifiedInstalledPacket,
};
pub(in crate::security_epoch::native_enrollment) use terminal::{
    ProtectedRestoreInstalledData, ProtectedRestoreOutputFrame,
};

#[cfg(target_os = "linux")]
pub(super) use admission::{
    Body as AdmissionBody, MAX_PACKET_BYTES as MAX_ADMISSION_PACKET_BYTES,
    Packet as AdmissionPacket, enrollment as admission_enrollment,
};
#[cfg(target_os = "linux")]
pub(super) use wire::{
    Data as CommandData, MAX_PACKET_BYTES as MAX_COMMAND_PACKET_BYTES,
    UnverifiedPacket as UnverifiedCommandPacket,
};

use super::{
    EnrolledCurrentRequest, EnrolledProcessRoleOwner, EnrolledRoleStage, NativeConsumerOrigin,
    SameEnrolledOwner,
};
use anyhow::{Result, bail, ensure};
use day2_capabilities::Digest;
use std::{cell::Cell, marker::PhantomData, rc::Rc};

#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    channel::{
        Channel, ControllerReceipt, ProtectedRestoreSocketListener, ProtectedRestoreSocketObserver,
        ServingSender,
    },
    process::MessageProcess,
    serving_peer_wire::Statement,
};

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
    pub(in crate::security_epoch::native_enrollment) fn admission(
        body: &'message admission::Body,
    ) -> Self {
        Self {
            body: MessageData::Admission(body),
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn command(
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
                data.require_sender(
                    &admission::enrollment(admitted)?,
                    &local.original,
                    direction,
                )?;
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
    fn reply_purpose(&self) -> Result<ReplyPurpose> {
        match self {
            Self::BeginApproval { .. } => Ok(ReplyPurpose::BeginApproval),
            Self::Approve { .. } => Ok(ReplyPurpose::Approve),
            Self::BeginExecution { .. } => Ok(ReplyPurpose::BeginExecution),
            Self::Abandon { .. } => Ok(ReplyPurpose::Abandon),
            Self::Authenticate { .. } => {
                bail!("native_protected_restore_authenticate_requires_fixed_exchange")
            }
        }
    }

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

// Expected packet shape DATA only. This cannot select a native role, arm a
// request or authorize an operation; Authenticate has no ordinary reply kind.
enum ReplyPurpose {
    BeginApproval,
    Approve,
    BeginExecution,
    Abandon,
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreInstalledOutputData {
    pub(crate) approval: Digest,
    pub(crate) operation: Digest,
    pub(crate) full_archive: Digest,
    pub(crate) target: crate::security_epoch::restore_approval::TargetBinding,
    pub(crate) executor: crate::security_epoch::restore_approval::AdminIdentity,
    pub(crate) installed: Digest,
}

impl ProtectedRestoreReply {
    fn require_request(&self, request: &ProtectedRestoreRequest) -> Result<()> {
        self.require_purpose(request.reply_purpose()?)
    }

    fn require_purpose(&self, purpose: ReplyPurpose) -> Result<()> {
        ensure!(
            matches!(self, Self::Refused)
                || matches!(
                    (purpose, self),
                    (ReplyPurpose::BeginApproval, Self::ApprovalPrompt { .. })
                        | (ReplyPurpose::Approve, Self::ApprovalRecorded { .. })
                        | (ReplyPurpose::BeginExecution, Self::ExecutionPrompt { .. })
                        | (ReplyPurpose::Abandon, Self::Abandoned)
                ),
            "protected_restore_reply_kind_changed"
        );
        self.validate_data()
    }

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

/// Actual fixed listener resources, with no constructor accepting their parts.
/// Binding is distinct from the later bounded native admission attempt.
pub(in crate::security_epoch) struct ProtectedRestoreListener {
    _same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    listener: Option<ProtectedRestoreSocketListener>,
    refused: Cell<bool>,
    _local: PhantomData<Rc<()>>,
}

/// Retained admitted identity only, with its actual original kernel handles.
/// A new bounded command must independently validate fresh request authority.
pub(in crate::security_epoch) struct ProtectedRestorePeer {
    _same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    channel: Option<Channel>,
    #[cfg(target_os = "linux")]
    _sender: Vec<ServingSender>,
    #[cfg(target_os = "linux")]
    _local_statement: Statement,
    #[cfg(target_os = "linux")]
    _remote_statement: Statement,
    #[cfg(target_os = "linux")]
    last_remote: super::storage_peer_wire::OriginalInterval,
    _connection: Digest,
    _sequence: u64,
    refused: Rc<Cell<bool>>,
    _local: PhantomData<Rc<()>>,
}

/// A restriction attached only by the fixed authenticated receiver. It owns
/// actual check-only resources and the exact saved request identity; it is
/// never constructed from an observation DTO or returned as permission.
pub(in crate::security_epoch::native_enrollment) struct ProtectedRestoreActionGuard {
    peer: ProtectedRestoreGuardPeer,
}

struct ProtectedRestorePending {
    #[cfg(target_os = "linux")]
    sender: ServingSender,
    _local: PhantomData<Rc<()>>,
}

enum ProtectedRestoreGuardPeer {
    Controller(Box<ProtectedRestoreControllerGuard>),
    ShellReply(Box<ProtectedRestoreShellReplyGuard>),
    ShellTerminal(Box<ProtectedRestoreShellTerminalGuard>),
}

/// The whole actual courier stays inside the SAME HTTP request frame through
/// browser state publication and actual socket settlement. Remote interval
/// DATA is historical here: the Controller has retired it before returning.
struct ProtectedRestoreShellTerminalGuard {
    same: SameEnrolledOwner,
    original: NativeConsumerOrigin,
    shell: Box<ProtectedRestoreShell>,
    connection: Digest,
    sequence: u64,
    #[cfg(target_os = "linux")]
    remote: Statement,
    #[cfg(target_os = "linux")]
    socket: ProtectedRestoreSocketObserver,
    #[cfg(target_os = "linux")]
    receipt: ControllerReceipt,
}

struct ProtectedRestoreShellReplyGuard {
    same: SameEnrolledOwner,
    original: NativeConsumerOrigin,
    root: Rc<Cell<bool>>,
    connection: Digest,
    sequence: u64,
    #[cfg(target_os = "linux")]
    remote: Statement,
    #[cfg(target_os = "linux")]
    socket: ProtectedRestoreSocketObserver,
    #[cfg(target_os = "linux")]
    receipt: ControllerReceipt,
}

struct ProtectedRestoreControllerGuard {
    same: SameEnrolledOwner,
    original: NativeConsumerOrigin,
    root: Rc<Cell<bool>>,
    connection: Digest,
    sequence: u64,
    remote: super::storage_peer_wire::OriginalInterval,
    #[cfg(target_os = "linux")]
    socket: ProtectedRestoreSocketObserver,
    #[cfg(target_os = "linux")]
    sender: MessageProcess,
    retired: bool,
}

pub(in crate::security_epoch::native_enrollment) fn select_guard_check(
    first: std::thread::Result<Result<()>>,
    next: std::thread::Result<Result<()>>,
) -> std::thread::Result<Result<()>> {
    match first {
        Ok(Ok(())) => next,
        failed => failed,
    }
}

impl ProtectedRestoreActionGuard {
    pub(in crate::security_epoch::native_enrollment) fn require_stage(
        &self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        match &self.peer {
            ProtectedRestoreGuardPeer::Controller(_) => {
                stage.require_protected_restore_role(super::NativeRole::EpochController)
            }
            ProtectedRestoreGuardPeer::ShellReply(_) => {
                stage.require_protected_restore_role(super::NativeRole::SecurityShell)
            }
            ProtectedRestoreGuardPeer::ShellTerminal(_) => {
                stage.require_protected_restore_role(super::NativeRole::SecurityShell)
            }
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        owner: &EnrolledProcessRoleOwner,
        purpose: super::protocol::StagePurpose,
        acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        match &mut self.peer {
            ProtectedRestoreGuardPeer::Controller(guard) => {
                guard.check(owner, purpose, acquisition)
            }
            ProtectedRestoreGuardPeer::ShellReply(guard) => {
                guard.check(owner, purpose, acquisition)
            }
            ProtectedRestoreGuardPeer::ShellTerminal(guard) => {
                guard.check(owner, purpose, acquisition)
            }
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn require_binding(
        &mut self,
        root: &Rc<Cell<bool>>,
        original: &NativeConsumerOrigin,
        connection: &Digest,
        sequence: u64,
    ) -> Result<()> {
        match &mut self.peer {
            ProtectedRestoreGuardPeer::Controller(guard) => {
                guard.require_binding(root, original, connection, sequence)
            }
            ProtectedRestoreGuardPeer::ShellReply(guard) => {
                guard.require_binding(root, original, connection, sequence)
            }
            ProtectedRestoreGuardPeer::ShellTerminal(guard) => {
                guard.require_binding(root, original, connection, sequence)
            }
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        match &mut self.peer {
            ProtectedRestoreGuardPeer::Controller(guard) => guard.refuse(),
            ProtectedRestoreGuardPeer::ShellReply(guard) => guard.refuse(),
            ProtectedRestoreGuardPeer::ShellTerminal(guard) => guard.refuse(),
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn require_retirement(
        &mut self,
    ) -> Result<()> {
        if matches!(&self.peer,ProtectedRestoreGuardPeer::Controller(guard) if !guard.retired) {
            return Ok(());
        }
        self.refuse();
        bail!("protected_restore_shell_frame_cannot_retire")
    }

    pub(in crate::security_epoch::native_enrollment) fn retire(&mut self) {
        match &mut self.peer {
            ProtectedRestoreGuardPeer::Controller(guard) => guard.retire(),
            // The owning frame rejects this variant BEFORE its last sample.
            ProtectedRestoreGuardPeer::ShellReply(guard) => guard.refuse(),
            ProtectedRestoreGuardPeer::ShellTerminal(guard) => guard.refuse(),
        }
    }
}

impl ProtectedRestoreControllerGuard {
    pub(in crate::security_epoch::native_enrollment) fn check(
        &mut self,
        owner: &EnrolledProcessRoleOwner,
        purpose: super::protocol::StagePurpose,
        acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        // The old frame is retained after retirement but cannot sample or
        // positively check its old acquisition or peer again.
        ensure!(!self.retired, "protected_restore_request_guard_retired");
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            ensure!(
                !self.root.get() && self.sequence > 0,
                "protected_restore_request_guard_refused"
            );
            ensure!(
                purpose == super::protocol::StagePurpose::CurrentRole,
                "protected_restore_request_guard_purpose"
            );
            self.same.require_protected_restore_owner(owner)?;
            self.original.require_acquisition(acquisition)?;
            self.remote.validate_request(
                acquisition.sample()?.elapsed,
                super::protocol::StagePurpose::CurrentRole,
            )
        }));
        // All actual roots are observed independently, including after a
        // requested error/panic. There is no stage callback or recursive check.
        #[cfg(target_os = "linux")]
        let socket = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.socket.check(acquisition)
        }));
        #[cfg(target_os = "linux")]
        let sender = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.sender
                .check_identity(acquisition, &super::issuer_costs::HashCosts::disabled())
        }));
        #[cfg(not(target_os = "linux"))]
        let socket: std::thread::Result<Result<()>> = Ok(Err(anyhow::anyhow!(UNAVAILABLE)));
        #[cfg(not(target_os = "linux"))]
        let sender: std::thread::Result<Result<()>> = Ok(Err(anyhow::anyhow!(UNAVAILABLE)));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            acquisition.remaining().map(|_| ())
        }));
        let selected = select_guard_check(
            select_guard_check(select_guard_check(requested, socket), sender),
            checked,
        );
        if !matches!(&selected, Ok(Ok(()))) {
            self.refuse();
            acquisition.refuse();
        }
        match selected {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn require_binding(
        &mut self,
        root: &Rc<Cell<bool>>,
        original: &NativeConsumerOrigin,
        connection: &Digest,
        sequence: u64,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.retired
                    && !self.root.get()
                    && Rc::ptr_eq(&self.root, root)
                    && self.connection == *connection
                    && self.sequence == sequence
                    && sequence > 0,
                "protected_restore_request_guard_binding_changed"
            );
            self.original.require_same(original)
        })();
        if result.is_err() {
            self.refuse();
            original.refuse();
            root.set(true);
        }
        result
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        self.root.set(true);
        self.original.refuse();
        #[cfg(target_os = "linux")]
        self.socket.refuse();
    }

    /// Memory-only after the final retirement sample. Retaining these handles
    /// supplies no later positive old-frame validation or fresh-request right.
    pub(in crate::security_epoch::native_enrollment) fn retire(&mut self) {
        self.retired = true;
    }
}

impl ProtectedRestoreShellReplyGuard {
    fn check(
        &mut self,
        owner: &EnrolledProcessRoleOwner,
        purpose: super::protocol::StagePurpose,
        acquisition: &mut crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            ensure!(
                !self.root.get() && self.sequence > 0,
                "protected_restore_shell_reply_refused"
            );
            ensure!(
                purpose == super::protocol::StagePurpose::CurrentRole,
                "protected_restore_shell_reply_purpose"
            );
            self.original.require_acquisition(acquisition)?;
            #[cfg(target_os = "linux")]
            {
                self.same
                    .require_protected_restore_shell_owner(owner, &self.remote)?;
                self.remote.original.validate_request(
                    acquisition.sample()?.elapsed,
                    super::protocol::StagePurpose::CurrentRole,
                )
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = owner;
                bail!(UNAVAILABLE)
            }
        }));
        #[cfg(target_os = "linux")]
        let socket = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.socket.check(acquisition)
        }));
        #[cfg(target_os = "linux")]
        let receipt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.receipt
                .check_protected_restore_bound(&self.remote, acquisition)
        }));
        #[cfg(not(target_os = "linux"))]
        let socket: std::thread::Result<Result<()>> = Ok(Err(anyhow::anyhow!(UNAVAILABLE)));
        #[cfg(not(target_os = "linux"))]
        let receipt: std::thread::Result<Result<()>> = Ok(Err(anyhow::anyhow!(UNAVAILABLE)));
        let current = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            acquisition.remaining().map(|_| ())
        }));
        let selected = select_guard_check(
            select_guard_check(select_guard_check(requested, socket), receipt),
            current,
        );
        if !matches!(&selected, Ok(Ok(()))) {
            self.refuse();
            acquisition.refuse();
        }
        match selected {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        }
    }

    fn require_binding(
        &mut self,
        root: &Rc<Cell<bool>>,
        original: &NativeConsumerOrigin,
        connection: &Digest,
        sequence: u64,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                !self.root.get()
                    && Rc::ptr_eq(&self.root, root)
                    && self.connection == *connection
                    && sequence > 0
                    && self.sequence == sequence,
                "protected_restore_shell_reply_binding_changed"
            );
            self.original.require_same(original)
        })();
        if requested.is_err() {
            self.refuse();
            root.set(true);
            original.refuse();
        }
        requested
    }

    fn refuse(&mut self) {
        self.root.set(true);
        self.original.refuse();
        #[cfg(target_os = "linux")]
        self.socket.refuse();
    }
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
    _sender: Vec<ServingSender>,
    #[cfg(target_os = "linux")]
    _local_statement: Statement,
    #[cfg(target_os = "linux")]
    _remote_statement: Statement,
    #[cfg(target_os = "linux")]
    last_remote: super::storage_peer_wire::OriginalInterval,
    _connection: Digest,
    _sequence: u64,
    refused: Rc<Cell<bool>>,
    _local: PhantomData<Rc<()>>,
}

/// One exclusive request/reply loan. The caller may read command DATA only;
/// it receives no channel, role, descriptor or stage. Abandonment poisons the
/// same actual peer. No factory currently constructs a turn.
pub(in crate::security_epoch) struct ProtectedRestoreTurn<'peer> {
    peer: &'peer mut ProtectedRestorePeer,
    request: ProtectedRestoreRequest,
    request_commitment: Digest,
    // Retained from the actual receive stage, never decoded from wire DATA.
    original: NativeConsumerOrigin,
    output: Option<ProtectedRestoreOutputFrame>,
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
    assert_not_impl!(ProtectedRestoreActionGuard);
    assert_not_impl!(ProtectedRestoreControllerGuard);
    assert_not_impl!(ProtectedRestorePending);
    assert_not_impl!(ProtectedRestoreShellTerminalGuard);
    assert_not_impl!(ProtectedRestoreShellReplyGuard);
};

impl ProtectedRestoreListener {
    pub(in crate::security_epoch) fn bind(role: &mut EnrolledProcessRoleOwner) -> Result<Self> {
        let mut request = role.begin_current_request()?;
        let listener = {
            let mut stage = role.borrow_current_request(&mut request)?;
            let requested =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Self> {
                    // Descriptor setup is not a peer connection. Its request
                    // finishes here, before human idle. The one-shot fresh
                    // issuer admission belongs to the later bounded accept.
                    stage.require_protected_restore_role(super::NativeRole::EpochController)?;
                    #[cfg(not(target_os = "linux"))]
                    bail!(UNAVAILABLE);
                    #[cfg(target_os = "linux")]
                    {
                        let mut acquisition = stage.narrow_io_acquisition(5)?;
                        let listener =
                            ProtectedRestoreSocketListener::bind(&mut stage, &mut acquisition)?;
                        let same = stage.capture_same_owner()?;
                        stage.check_serving_acquisition(&mut acquisition)?;
                        Ok(Self {
                            _same: same,
                            listener: Some(listener),
                            refused: Cell::new(false),
                            _local: PhantomData,
                        })
                    }
                }));
            // Always observe the same saved original after requested failure
            // or panic. Neither a repaired clock nor a new role is a retry.
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
            if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
                stage.refuse_serving();
            }
            match requested {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(Err(error)) => return Err(error),
                Ok(Ok(listener)) => match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => {
                        result?;
                        listener
                    }
                },
            }
        };
        request.finish(role)?;
        Ok(listener)
    }

    /// Readiness DATA only, before any bounded accept action begins. This
    /// cannot grant a role or hold an original across human idle time. Any
    /// path/profile/readiness failure permanently refuses this actual listener.
    pub(in crate::security_epoch) fn pending(&mut self) -> Result<bool> {
        let requested =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<bool> {
                ensure!(!self.refused.get(), "protected_restore_listener_refused");
                #[cfg(not(target_os = "linux"))]
                bail!(UNAVAILABLE);
                #[cfg(target_os = "linux")]
                self.listener
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_listener_closed"))?
                    .pending()
            }));
        match requested {
            Err(payload) => {
                self.refuse();
                std::panic::resume_unwind(payload)
            }
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                }
                result
            }
        }
    }

    pub(in crate::security_epoch) fn accept(
        &mut self,
        role: &mut EnrolledProcessRoleOwner,
    ) -> Result<ProtectedRestorePeer> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(!self.refused.get(), "protected_restore_listener_refused");
            self._same.require_protected_restore_owner(role)?;
            let mut request = role.begin_current_request()?;
            let peer = {
                let mut stage = role.borrow_current_request(&mut request)?;
                let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    stage.begin_protected_restore_attempt(super::NativeRole::EpochController)?;
                    native::accept(self, &mut stage)
                }));
                let checked =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
                if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
                    stage.refuse_serving();
                }
                match requested {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(peer)) => match checked {
                        Err(payload) => std::panic::resume_unwind(payload),
                        Ok(result) => {
                            result?;
                            peer
                        }
                    },
                }
            };
            request.finish(role)?;
            Ok(peer)
        }));
        // This is a one-shot listener even on success. Closing its listening
        // descriptor does not close the accepted channel retained by the peer.
        self.refuse();
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        }
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
    /// merely equal scope/profile DATA. This local exclusion uses the retained
    /// actual identity without acquiring a Current before readiness. It lends
    /// no stage, action or clock; later native receive checks remain required.
    /// This cannot construct or revive a peer, or grant a fresh command.
    pub(in crate::security_epoch) fn require_owner(
        &mut self,
        role: &EnrolledProcessRoleOwner,
    ) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused.get(), "protected_restore_peer_refused");
            self._same.require_protected_restore_owner(role)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Readiness DATA precedes the caller's capture of a fresh bounded request.
    /// It cannot create a stage or retain an original across human idle time.
    /// Readiness alone cannot admit a turn or grant an action. The warm
    /// command supplier remains closed until its genuine backend is wired.
    pub(in crate::security_epoch) fn pending(&mut self) -> Result<bool> {
        let result = (|| {
            ensure!(!self.refused.get(), "protected_restore_peer_refused");
            #[cfg(not(target_os = "linux"))]
            bail!(UNAVAILABLE);
            #[cfg(target_os = "linux")]
            {
                let channel = self
                    .channel
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?;
                channel.idle_pending()
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// The caller retains the actual saved request in stable session storage.
    /// A turn borrows only this peer, not that request or the role stage. The
    /// core must consume this SAME stage, then reborrow the SAME saved request
    /// for a nonterminal reply. No new original may begin between these steps.
    /// The fixed receiver authenticates the next packet and attaches its
    /// actual peer restriction to the saved frame before lending command DATA.
    pub(in crate::security_epoch) fn try_receive<'peer>(
        &'peer mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<Option<ProtectedRestoreTurn<'peer>>> {
        let requested =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| warm::receive(self, stage)));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
        }
        let received = match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(value)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    value
                }
            },
        };
        Ok(received.map(
            |(request, original, request_commitment)| ProtectedRestoreTurn {
                peer: self,
                request,
                request_commitment,
                original,
                output: None,
                replied: false,
            },
        ))
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
    pub(crate) fn connect(stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stage.begin_protected_restore_attempt(super::NativeRole::SecurityShell)?;
            native::connect(stage)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(shell)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(shell)
                }
            },
        }
    }

    /// The fixed courier lends the stage from its SAME saved HTTP original.
    /// The fixed courier checks its actual owner and full SecurityShell
    /// selection around native I/O without acquiring a new stage or original.
    /// Its peer restriction remains in the saved HTTP frame after DATA returns.
    pub(crate) fn request(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        request: ProtectedRestoreRequest,
    ) -> Result<ProtectedRestoreReply> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !matches!(&request, ProtectedRestoreRequest::Authenticate { .. }),
                "native_protected_restore_authenticate_requires_fixed_exchange"
            );
            request.validate_data()?;
            courier::request(self, stage, request)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(reply)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(reply)
                }
            },
        }
    }

    /// Fixed final exchange under the SAME saved Shell HTTP original. The
    /// genuine implementation must retain its admitted connection and sequence,
    /// bind this exact Authenticate command, verify the fixed signed terminal
    /// packet, and independently postcheck its peer/original/stage on errors
    /// and unwind without a capture, retry or renewed clock. The generic DATA
    /// reply entry cannot serve this purpose. The terminal interface consumes
    /// the genuine whole Box and retains that courier in the saved HTTP frame;
    /// returned DATA alone can never disarm its negative Drop duty.
    /// Returned metadata will not prove completed human/HTTP delivery.
    pub(crate) fn authenticate(
        mut self: Box<Self>,
        stage: &mut EnrolledRoleStage<'_>,
        id: &Digest,
        assertion: &[u8],
    ) -> Result<RestoreInstalledOutputData> {
        if !(1..=MAX_ASSERTION_BYTES).contains(&assertion.len()) {
            self.refuse();
            stage.refuse_serving();
            bail!("native_protected_restore_input_bound");
        }
        courier::authenticate(self, stage, id, assertion)
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
    pub(in crate::security_epoch::native_enrollment) fn require_installed_binding(
        &self,
        data: &ProtectedRestoreInstalledData,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = data;
            self.original.refuse();
            self.peer.refused.set(true);
            bail!(UNAVAILABLE);
        }
        #[cfg(target_os = "linux")]
        {
            ensure!(
                !self.replied
                    && matches!(&self.request, ProtectedRestoreRequest::Authenticate { .. }),
                "protected_restore_authenticate_required"
            );
            data.require_binding(
                &self.peer._connection,
                &admission::enrollment(&self.peer._local_statement)?,
                self.peer._sequence,
                &self.request_commitment,
            )
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn admitted_statement(
        &self,
    ) -> Result<&super::serving_peer_wire::Statement> {
        #[cfg(not(target_os = "linux"))]
        {
            self.original.refuse();
            self.peer.refused.set(true);
            bail!(UNAVAILABLE);
        }
        #[cfg(target_os = "linux")]
        {
            Ok(&self.peer._local_statement)
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn require_received_guard(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        let result = super::owner::require_protected_restore_guard(
            stage,
            &self.peer.refused,
            &self.original,
            &self.peer._connection,
            self.peer._sequence,
        );
        if result.is_err() {
            self.refuse();
        }
        result
    }

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
    /// The fixed warm receiver has already attached the actual peer guard
    /// before this consuming handoff may move the same saved frame.
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
    /// Prepare and Sign use the genuine installed-output loan. Send and Poll
    /// perform one bounded transport step each; partial or uncertain output
    /// permanently refuses the frame. A delivered packet is not HTTP delivery.
    pub(in crate::security_epoch) fn installed_output(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        loan: &mut crate::security_epoch::bootstrap::RestoreInstalledOutputLoan<'_, '_, '_>,
        operation: ProtectedRestoreInstalledIo,
    ) -> Result<super::ReceiverProgress> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            terminal::step(self, stage, loan, operation)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let mut storage = stage.storage()?;
            loan.check(&mut storage).map(|_| ())
        }));
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        let checked = select_guard_check(checked, native);
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            if let Some(frame) = &mut self.output {
                frame.refuse();
            }
            self.refuse();
            stage.refuse_serving();
            loan.refuse();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(progress)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(progress)
                }
            },
        }
    }

    /// The terminal path consumes the WHOLE genuine installed carrier, never
    /// a completed DATA reply or caller assertion. Its future fixed driver must
    /// retain every original/target/cohort/peer owner through real App installed
    /// acceptance, its posts, ONE operator packet and independent native/full
    /// parent posts, then retire the old counter/peer/original LAST. Nothing may
    /// sample or revive that old original after retirement. Only a genuine
    /// consuming result may release the caller's negative Attempt duty. Only
    /// that result disarms this Turn's negative Drop. The fixed installed output
    /// supplier cannot disarm this Turn by itself. Generic reply stays DATA-only.
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
    /// sender matches this stage's actual negative original identity to the
    /// receive turn and retains all independent native posts. Equal clock DATA
    /// cannot substitute for that request, and Authenticate has no generic reply.
    pub(in crate::security_epoch) fn reply(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        reply: ProtectedRestoreReply,
    ) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reply.require_request(&self.request)?;
            self.require_received_guard(stage)?;
            self.original.check_current(stage)?;
            warm::reply(self.peer, &self.original, stage, reply)
        }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.original.check_current(stage)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
            stage.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(())) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => result?,
            },
        }
        self.replied = true;
        Ok(())
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
mod listener_source_tests {
    use quote::ToTokens;

    fn method(source: &str, owner: &str, name: &str) -> syn::ImplItemFn {
        let mut found = Vec::new();
        for item in syn::parse_file(source).unwrap().items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident(owner)) {
                continue;
            }
            for item in item.items {
                if let syn::ImplItem::Fn(item) = item
                    && item.sig.ident == name
                {
                    found.push(item);
                }
            }
        }
        assert_eq!(found.len(), 1);
        found.pop().unwrap()
    }

    fn tokens(value: &impl ToTokens) -> String {
        value.to_token_stream().to_string()
    }

    fn fragment(source: &str) -> String {
        // Compare parsed production AST to parsed probes. Syn prints a
        // closure's two separate Or tokens as `| |`, unlike lexical `||`.
        if let Ok(statement) = syn::parse_str::<syn::Stmt>(source) {
            return tokens(&statement);
        }
        if let Ok(expression) = syn::parse_str::<syn::Expr>(source) {
            return tokens(&expression);
        }
        let wrapper: syn::ExprMatch = syn::parse_str(&format!("match () {{ {source} }}")).unwrap();
        assert_eq!(wrapper.arms.len(), 1);
        tokens(&wrapper.arms[0])
    }

    fn contains(body: &syn::Block, source: &str) -> bool {
        tokens(body).matches(&fragment(source)).count() == 1
    }

    fn zero_timeout(body: &syn::Block) -> bool {
        #[derive(Default)]
        struct Times(Vec<syn::ExprStruct>);
        impl<'ast> syn::visit::Visit<'ast> for Times {
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                if value
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "Timespec")
                {
                    self.0.push(value.clone());
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let mut times = Times::default();
        syn::visit::Visit::visit_block(&mut times, body);
        let [time] = times.0.as_slice() else {
            return false;
        };
        let expected: syn::Path = syn::parse_quote!(rustix::event::Timespec);
        let zero: syn::Expr = syn::parse_quote!(0);
        time.attrs.is_empty()
            && time.qself.is_none()
            && time.rest.is_none()
            && tokens(&time.path) == tokens(&expected)
            && time.fields.len() == 2
            && time
                .fields
                .iter()
                .zip(["tv_sec", "tv_nsec"])
                .all(|(field, name)| {
                    field.attrs.is_empty()
                        && matches!(&field.member, syn::Member::Named(actual) if actual == name)
                        && tokens(&field.expr) == tokens(&zero)
                })
    }

    fn bound(body: &syn::Block) -> bool {
        let required = [
            "let mut request = role.begin_current_request()?;",
            "let mut stage = role.borrow_current_request(&mut request)?;",
            "stage.require_protected_restore_role(super::NativeRole::EpochController)?;",
            "let mut acquisition = stage.narrow_io_acquisition(5)?;",
            "let listener = ProtectedRestoreSocketListener::bind(&mut stage, &mut acquisition)?;",
            "let same = stage.capture_same_owner()?;",
            "stage.check_serving_acquisition(&mut acquisition)?;",
            "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));",
            "if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {stage.refuse_serving();}",
            "Ok(Err(error)) => return Err(error),",
        ];
        let finish: syn::Stmt = syn::parse_quote!(request.finish(role)?;);
        let result: syn::Expr = syn::parse_quote!(Ok(listener));
        body.stmts.len() == 4
            && required.iter().all(|fragment| contains(body, fragment))
            && tokens(&body.stmts[2]) == tokens(&finish)
            && matches!(&body.stmts[3], syn::Stmt::Expr(actual, None) if tokens(actual) == tokens(&result))
            && !tokens(body).contains("NativeAcquisition :: begin")
            && !tokens(body).contains("begin_protected_restore_attempt")
    }

    #[test]
    fn closure_post_probe_uses_the_same_ast_spacing_as_the_actual_method() {
        let actual = method(
            include_str!("protected_restore.rs"),
            "ProtectedRestoreListener",
            "bind",
        );
        let checked = "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));";
        let lexical: proc_macro2::TokenStream = checked.parse().unwrap();
        assert_ne!(tokens(&lexical), fragment(checked));
        assert_eq!(tokens(&actual.block).matches(&tokens(&lexical)).count(), 0);
        assert!(contains(&actual.block, checked));
    }

    #[test]
    fn actual_listener_bind_finishes_the_same_setup_request_after_independent_posts() {
        let actual = method(
            include_str!("protected_restore.rs"),
            "ProtectedRestoreListener",
            "bind",
        );
        assert!(bound(&actual.block));
        for (before, after) in [
            ("role.begin_current_request()?", "replacement_request()?"),
            (
                "role.borrow_current_request(&mut request)?",
                "role.borrow_current_request(&mut replacement)?",
            ),
            (
                "stage.require_protected_restore_role(super::NativeRole::EpochController)?;",
                "stage.require_protected_restore_role(super::NativeRole::SecurityShell)?;",
            ),
            (
                "stage.require_protected_restore_role(super::NativeRole::EpochController)?;",
                "{stage.require_protected_restore_role(super::NativeRole::EpochController)?;stage.begin_protected_restore_attempt(super::NativeRole::EpochController)?;}",
            ),
            (
                "ProtectedRestoreSocketListener::bind(&mut stage, &mut acquisition)?",
                "ProtectedRestoreSocketListener::bind(&mut stage, &mut replacement)?",
            ),
            ("stage.capture_same_owner()?", "replacement_same_owner()?"),
            (
                "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));",
                "let checked = Ok(Ok(()));",
            ),
            ("stage.refuse_serving();", "ignore_refusal();"),
            ("request.finish(role)?;", "replacement.finish(role)?;"),
            ("return Err(error)", "return Err(replacement)"),
        ] {
            let before = fragment(before);
            let after = fragment(after);
            let source = tokens(&actual.block);
            assert_eq!(source.matches(&before).count(), 1);
            let changed: syn::Block = syn::parse_str(&source.replacen(&before, &after, 1)).unwrap();
            assert!(!bound(&changed));
        }
    }

    #[test]
    fn actual_listener_idle_readiness_has_no_clock_and_keeps_its_negative_root() {
        let actual = method(
            include_str!("protected_restore.rs"),
            "ProtectedRestoreListener",
            "pending",
        );
        let source = tokens(&actual.block);
        for fragment in [
            "self.refused.get()",
            "self.listener.as_ref()",
            "self.refuse();",
            "std::panic::resume_unwind(payload)",
        ] {
            let fragment: proc_macro2::TokenStream = fragment.parse().unwrap();
            assert!(source.contains(&tokens(&fragment)));
        }
        assert_eq!(source.matches("self . refuse ()").count(), 2);
        for forbidden in [
            "NativeAcquisition",
            "begin_current",
            "borrow_current",
            "EnrolledRoleStage",
            "refused . set (false)",
        ] {
            assert!(!source.contains(forbidden));
        }
        let raw = include_str!("channel/protected_restore.rs");
        let pending = method(raw, "ProtectedRestoreSocketListener", "pending");
        let source = tokens(&pending.block);
        assert!(zero_timeout(&pending.block));
        let changed: syn::Block =
            syn::parse_str(&source.replacen("tv_nsec : 0", "tv_nsec : 1", 1)).unwrap();
        assert!(!zero_timeout(&changed));
        assert!(contains(
            &pending.block,
            "let checked = self.check_name().and_then(|()| require_listener_profile(&self.socket));"
        ));
        for forbidden in [
            "NativeAcquisition",
            "begin_current",
            "recv",
            "accept",
            "sign",
        ] {
            assert!(
                !source.contains(forbidden),
                "idle source contains {forbidden}"
            );
        }
        let bound = method(raw, "ProtectedRestoreSocketListener", "bind");
        assert!(contains(
            &bound.block,
            "StorageSocketDirectory::observe(&root)?"
        ));
        assert!(contains(
            &bound.block,
            "OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC"
        ));
        assert!(contains(
            &bound.block,
            "set_private_socket_mode(&name, acquisition)?"
        ));
        assert!(raw.contains("name.as_raw_fd().to_string()"));
        assert!(contains(
            &bound.block,
            "let checked = stage.check_serving_acquisition(acquisition);"
        ));
        let source = tokens(&bound.block);
        assert!(!source.contains("unlink") && !source.contains("from_raw_fd"));
    }

    fn transport_bound(body: &syn::Block, send: bool, admission: bool) -> bool {
        let source = tokens(body);
        let poison = if send {
            "if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {self.refuse(); stage.refuse_serving(); acquisition.refuse();}"
        } else {
            "if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {self.refuse(); stage.refuse_serving(); acquisition.refuse();}"
        };
        let operation = match (send, admission) {
            (true, true) => {
                "stage.sign_protected_restore_message(&ProtectedRestoreMessage::admission(&body))?"
            }
            (true, false) => {
                "stage.sign_protected_restore_message(&ProtectedRestoreMessage::command(&data, admitted),)?"
            }
            (false, _) => {
                "net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)])"
            }
        };
        body.stmts.len() == 4
            && contains(body, operation)
            && contains(
                body,
                "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {self.check_protected_open(stage, acquisition)}));",
            )
            && contains(body, poison)
            && contains(body, "Ok(Err(error)) => Err(error),")
            && source.matches("self . check_protected_open").count() == 4
            && source
                .matches("std :: panic :: resume_unwind (payload)")
                .count()
                == 2
            && if send {
                contains(
                    body,
                    "self.begin_packet(Direction::Send, Some(frame), acquisition)?;",
                ) && !source.contains("recv_pidfd_packet")
            } else {
                contains(
                    body,
                    "self.begin_packet(Direction::Receive, None, acquisition)?;",
                ) && contains(
                    body,
                    "self.receive_unprivileged_sender(received, &expected_code, acquisition)?",
                ) && contains(body, "ControllerReceipt::receive(received, acquisition)?")
                    && !source.contains("net :: send")
            }
            && !source.contains("NativeAcquisition :: begin")
            && !source.contains("begin_current")
            && !source.contains("narrow_io_acquisition")
    }

    #[test]
    fn actual_native_transport_keeps_fixed_signers_kernel_receipts_and_independent_posts() {
        // Production wiring controls only; no native role/peer/permission is
        // manufactured. Kernel conformance and the actual peer join are owed.
        let raw = include_str!("channel/protected_restore.rs");
        for (name, send, admission) in [
            ("send_protected_admission", true, true),
            ("receive_protected_admission", false, true),
            ("send_protected_command", true, false),
            ("receive_protected_command", false, false),
        ] {
            let actual = method(raw, "Channel", name);
            assert!(transport_bound(&actual.block, send, admission), "{name}");
            for (before, after) in [
                (
                    "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {self.check_protected_open(stage, acquisition)}));",
                    "let checked = Ok(Ok(()));",
                ),
                ("stage.refuse_serving();", "ignore_refusal();"),
                (
                    "Ok(Err(error)) => Err(error),",
                    "Ok(Err(error)) => Err(replacement),",
                ),
                (
                    if send {
                        if admission {
                            "ProtectedRestoreMessage::admission(&body)"
                        } else {
                            "ProtectedRestoreMessage::command(&data, admitted)"
                        }
                    } else {
                        "net::recv_pidfd_packet(&self.socket, &mut [IoSliceMut::new(&mut bytes)])"
                    },
                    "unrelated_boundary()",
                ),
            ] {
                let source = tokens(&actual.block);
                let before = fragment(before);
                let after = fragment(after);
                assert_eq!(source.matches(&before).count(), 1, "{name} target");
                let changed: syn::Block =
                    syn::parse_str(&source.replacen(&before, &after, 1)).unwrap();
                assert!(
                    !transport_bound(&changed, send, admission),
                    "{name} mutation"
                );
            }
        }
    }

    #[test]
    fn actual_socket_observer_shares_actual_resources_and_cannot_reenter_a_stage_or_transport() {
        let source = include_str!("channel/protected_restore.rs");
        let factory = method(source, "Channel", "protected_restore_observer");
        let check = method(source, "ProtectedRestoreSocketObserver", "check");
        fn guarded(factory: &syn::Block, check: &syn::Block) -> bool {
            let factory_required = [
                "self.check_protected_open(stage, acquisition)?;",
                "socket: Rc::clone(&self.socket)",
                "refused: Rc::clone(&self.refused)",
                "process: std::process::id()",
                "thread: std::thread::current().id()",
                "observer.check(acquisition)?;",
                "stage.check_serving_acquisition(acquisition)",
            ];
            // Fields are parsed in a struct, rather than pretending they are
            // standalone expressions or comparing lexical closure spacing.
            let field = |source: &str| {
                let value: syn::ExprStruct =
                    syn::parse_str(&format!("Observer {{ {source} }}")).unwrap();
                assert_eq!(value.fields.len(), 1);
                tokens(&value.fields[0])
            };
            let fields = &factory_required[1..5];
            if !fields
                .iter()
                .all(|item| tokens(factory).matches(&field(item)).count() == 1)
                || ![
                    factory_required[0],
                    factory_required[5],
                    factory_required[6],
                ]
                .iter()
                .all(|item| contains(factory, item))
            {
                return false;
            }
            let required = [
                "acquisition.remaining()?;",
                "require_idle_socket_profile(&self.socket)?;",
                "require_connected(&self.socket, acquisition)",
                "self.refuse();",
                "acquisition.refuse();",
            ];
            let post = [
                "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| acquisition.remaining().map(|_| ())));",
                "let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { acquisition.remaining().map(|_| ()) }));",
            ];
            required.iter().all(|item| contains(check, item))
                && post.iter().filter(|item| contains(check, item)).count() == 1
                && ![
                    "EnrolledRoleStage",
                    "stage .",
                    "recv",
                    "send",
                    "transport",
                    "begin_packet",
                    "packet_delivered",
                    "begin_current",
                    "NativeAcquisition :: begin",
                ]
                .iter()
                .any(|forbidden| tokens(check).contains(forbidden))
        }
        assert!(guarded(&factory.block, &check.block));
        for (target, replacement) in [
            (
                fragment("require_connected(&self.socket, acquisition)"),
                fragment("Ok(())"),
            ),
            (fragment("self.refuse();"), String::new()),
            (fragment("acquisition.refuse();"), String::new()),
            (
                fragment("require_idle_socket_profile(&self.socket)?;"),
                String::new(),
            ),
        ] {
            let actual = tokens(&check.block);
            assert_eq!(actual.matches(&target).count(), 1);
            let changed = syn::parse_str(&actual.replacen(&target, &replacement, 1)).unwrap();
            assert!(!guarded(&factory.block, &changed));
        }
        let actual = tokens(&factory.block);
        let target = fragment("Rc::clone(&self.socket)");
        assert_eq!(actual.matches(&target).count(), 1);
        let changed =
            syn::parse_str(&actual.replacen(&target, &fragment("Rc::clone(&foreign)"), 1)).unwrap();
        assert!(!guarded(&changed, &check.block));
        let mut missing_post = check.block.clone();
        let before = missing_post.stmts.len();
        missing_post.stmts.retain(|stmt| !matches!(stmt, syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "checked")));
        assert_eq!(missing_post.stmts.len() + 1, before);
        assert!(!guarded(&factory.block, &missing_post));
        let storage = syn::parse_file(include_str!("channel/storage.rs")).unwrap();
        let connected: Vec<_> = storage
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "require_connected" => Some(item),
                _ => None,
            })
            .collect();
        assert_eq!(connected.len(), 1);
        assert!(
            zero_timeout(&connected[0].block),
            "actual imported liveness must stay zero-time"
        );
    }

    #[test]
    fn actual_received_cap_meets_the_retained_saved_owner_before_the_data_cursor() {
        let raw = include_str!("channel/protected_restore.rs");
        let actual = method(raw, "Channel", "meet_protected_received");
        let native = fragment("same.meet_current_read_view(stage, acquisition)?;");
        let cursor = fragment(
            "self.transcript.as_mut().ok_or_else(|| anyhow::anyhow!(\"native_handshake_transcript_required\"))?.narrow_protected_received(Self::observation(acquisition))?;",
        );
        let guarded = |body: &syn::Block| {
            let source = tokens(body);
            let native_positions = source
                .match_indices(&native)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            let cursor_positions = source
                .match_indices(&cursor)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            native_positions.len() == 1
                && cursor_positions.len() == 1
                && native_positions[0] < cursor_positions[0]
                && source.matches("self . check_protected_open").count() == 3
                && contains(body, "Ok(Err(error)) => Err(error),")
                && contains(body, "stage.refuse_serving();")
                && contains(body, "acquisition.refuse();")
                && !source.contains("begin_current")
                && !source.contains("NativeAcquisition :: begin")
        };
        assert!(guarded(&actual.block));
        let source = tokens(&actual.block);
        for replacement in ["", "data_only_meet();"] {
            let changed: syn::Block =
                syn::parse_str(&source.replacen(&native, replacement, 1)).unwrap();
            assert!(!guarded(&changed));
        }
        let changed: syn::Block = syn::parse_str(&source.replacen(&native, "", 1).replacen(
            &cursor,
            &format!("{cursor} {native}"),
            1,
        ))
        .unwrap();
        assert!(!guarded(&changed));
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
            if !(1..=MAX_ASSERTION_BYTES).contains(&assertion.len()) {
                self.refuse();
                stage.refuse_serving();
                bail!("native_protected_restore_input_bound");
            }
            courier::authenticate(self, stage, id, assertion)
        });
        let canonical = expected.to_token_stream().to_string();
        assert_eq!(auth.block.to_token_stream().to_string(), canonical);
        for index in 0..auth.block.stmts.len() {
            let mut removed = auth.block.clone();
            removed.stmts.remove(index);
            assert_ne!(removed.to_token_stream().to_string(), canonical);
        }
        let mut late = auth.block.clone();
        late.stmts.swap(0, 1);
        assert_ne!(late.to_token_stream().to_string(), canonical);
        let request = method("request");
        let expected: syn::Block = syn::parse_quote!({
            let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ensure!(
                    !matches!(&request, ProtectedRestoreRequest::Authenticate { .. }),
                    "native_protected_restore_authenticate_requires_fixed_exchange"
                );
                request.validate_data()?;
                courier::request(self, stage, request)
            }));
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
            if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
                self.refuse();
                stage.refuse_serving();
            }
            match requested {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(Err(error)) => Err(error),
                Ok(Ok(reply)) => match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => {
                        result?;
                        Ok(reply)
                    }
                },
            }
        });
        assert_eq!(
            request.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let mut generic = request.block.clone();
        generic.stmts.remove(1);
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
    fn actual_peer_readiness_uses_only_retained_data_poll_and_keeps_refusal() {
        // Portable source control, not a native peer or kernel qualification.
        let file = syn::parse_file(include_str!("protected_restore.rs")).unwrap();
        let methods = file.items.into_iter().filter_map(|item| match item {
            syn::Item::Impl(item) if item.trait_.is_none()
                && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("ProtectedRestorePeer")) => Some(item),
            _ => None,
        }).flat_map(|item| item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "pending" => Some(method),
            _ => None,
        }).collect::<Vec<_>>();
        assert_eq!(methods.len(), 1);
        let actual = &methods[0].block;
        let expected: syn::Block = syn::parse_quote!({
            let result = (|| {
                ensure!(!self.refused.get(), "protected_restore_peer_refused");
                #[cfg(not(target_os = "linux"))]
                bail!(UNAVAILABLE);
                #[cfg(target_os = "linux")]
                {
                    let channel = self
                        .channel
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("protected_restore_channel_closed"))?;
                    channel.idle_pending()
                }
            })();
            if result.is_err() {
                self.refuse();
            }
            result
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(actual));
        let mut no_refusal = actual.clone();
        no_refusal.stmts.remove(1);
        assert!(!guarded(&no_refusal));
        let mut swallowed = actual.clone();
        swallowed.stmts[0] = syn::parse_quote!(let result = Ok(false););
        assert!(!guarded(&swallowed));
        let target: syn::Expr = syn::parse_quote!(channel.idle_pending());
        let target = target.to_token_stream().to_string();
        let text = actual.to_token_stream().to_string();
        assert_eq!(text.matches(&target).count(), 1);
        for replacement in [
            syn::parse_quote!(channel.pending_serving()),
            syn::parse_quote!(Ok(true)),
            syn::parse_quote!({
                let _ = crate::security_epoch::native_clock::NativeAcquisition::begin(5)?;
                channel.idle_pending()
            }),
        ] {
            let replacement: syn::Expr = replacement;
            let changed: syn::Block = syn::parse_str(&text.replacen(
                &target,
                &replacement.to_token_stream().to_string(),
                1,
            ))
            .unwrap();
            assert!(!guarded(&changed));
        }
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
