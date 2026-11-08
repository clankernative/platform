//! Narrow ownership boundary for genuine restored App admission and custody.
//! Every owning child is explicit. Unsupported platforms have no supplier;
//! no mode, clock fallback or ordinary-role adoption is implemented here.
#[cfg(target_os = "linux")]
use super::{birth, channel, issuer_peer, policy, protocol};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_clock::{NativeAcquisition, NativeOriginalRefusal};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::process::SelfSnapshot;
#[cfg(target_os = "linux")]
use day2_capabilities::Digest;
use std::{cell::Cell, marker::PhantomData, rc::Rc};
#[cfg(target_os = "linux")]
use std::{cell::RefCell, fs::File, thread::ThreadId};

mod activation;
mod artifact;
mod configuration;
mod file;
mod preparation;
mod read_identity;
mod receiver;
mod transport;

// Fields stay private to this closed module. Only the reviewed client and
// fixed restore transport children may borrow the same actual owners. This
// exposes no clock, stage, descriptor or generic-callback accessor.
pub(in crate::security_epoch) struct RestoredAppReceiver {
    #[cfg(target_os = "linux")]
    policy: policy::EnrollmentPolicy,
    #[cfg(target_os = "linux")]
    policy_file: Rc<RefCell<birth::PolicyFileOwner>>,
    #[cfg(target_os = "linux")]
    key: Rc<protocol::KeyOwner>,
    #[cfg(target_os = "linux")]
    current: Rc<RefCell<SelfSnapshot>>,
    #[cfg(target_os = "linux")]
    original: crate::security_epoch::native_clock::NativeAcquisition,
    #[cfg(target_os = "linux")]
    process: u32,
    #[cfg(target_os = "linux")]
    thread: std::thread::ThreadId,
    #[cfg(target_os = "linux")]
    refused: bool,
    local_only: PhantomData<Rc<()>>,
}

/// Actual restored process admission, not an ordinary role, P3 or writer.
pub(in crate::security_epoch) struct AdmittedRestoreProcess {
    #[cfg(target_os = "linux")]
    receiver: RestoredAppReceiver,
    #[cfg(target_os = "linux")]
    certificate: protocol::IssuerCertificate,
    #[cfg(target_os = "linux")]
    authorization: protocol::SignedRestoreAuthorization,
    #[cfg(target_os = "linux")]
    admission: protocol::SignedRestoreAdmission,
    #[cfg(target_os = "linux")]
    nonce_peer: Rc<RefCell<issuer_peer::IssuerReceipt>>,
    #[cfg(target_os = "linux")]
    grant_peer: Rc<RefCell<issuer_peer::IssuerReceipt>>,
    #[cfg(target_os = "linux")]
    channel: Rc<channel::Channel>,
    local_only: PhantomData<Rc<()>>,
}

/// The actual new App, fixed peer channel and every received Controller handle
/// after the selected offer. This still supplies no file/P3, keeper or Current.
pub(in crate::security_epoch) struct RestoredAppPeer {
    #[cfg(target_os = "linux")]
    process: AdmittedRestoreProcess,
    #[cfg(target_os = "linux")]
    channel: RestoreTransport,
    #[cfg(target_os = "linux")]
    controller: super::storage_peer_wire::StageStatement,
    #[cfg(target_os = "linux")]
    receipts: Vec<RestoredControllerReceipt>,
    #[cfg(target_os = "linux")]
    local: super::restore_peer_wire::RestoreAppStatement,
    #[cfg(target_os = "linux")]
    projection: super::restore_peer_wire::Projection,
    #[cfg(target_os = "linux")]
    exchange: super::restore_peer_wire::Exchange,
    #[cfg(target_os = "linux")]
    refused: bool,
    local_only: PhantomData<Rc<()>>,
}

/// Physical reset-file custody under the actual authenticated offer. This is
/// still neither P3 nor a writer/SQLite/Current authorization.
pub(in crate::security_epoch) struct CapturedRestoredFile {
    #[cfg(target_os = "linux")]
    peer: RestoredAppPeer,
    #[cfg(target_os = "linux")]
    root: std::fs::File,
    #[cfg(target_os = "linux")]
    private: std::fs::File,
    #[cfg(target_os = "linux")]
    directory: std::fs::File,
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    #[cfg(target_os = "linux")]
    root_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    private_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    directory_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    file_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    component: String,
    #[cfg(target_os = "linux")]
    image: zeroize::Zeroizing<Vec<u8>>,
    #[cfg(target_os = "linux")]
    refused: bool,
    local_only: PhantomData<Rc<()>>,
}

/// Same actual App and reset-file lifetime after the closed pre-writer
/// exchange. This owns neither a SQLite connection nor Current authority.
pub(in crate::security_epoch) struct PreparedRestoredFile {
    captured: CapturedRestoredFile,
}

/// The same prepared App after the actual Controller's activation message.
/// Its only next operation is its own strong read; this is NOT permission to
/// open SQLite or to treat the Controller's record as an App observation.
pub(in crate::security_epoch) struct RestoredWriterReadPending {
    captured: CapturedRestoredFile,
    #[cfg(target_os = "linux")]
    activation: super::restore_peer_wire::Activation,
}

// These owners consume the actual pending App. Failure/unwind drops that same
// App and its original; no separately acquired role or reconstructed clock can
// survive a failed authentication attempt. Neither exposes a bearer or route.
struct RestoreReadAuthentication {
    owner: RestoredWriterReadPending,
    #[cfg(target_os = "linux")]
    original: crate::security_epoch::native_clock::NativeAcquisition,
}

pub(in crate::security_epoch) struct RestoredReadIdentity {
    owner: RestoredWriterReadPending,
    #[cfg(target_os = "linux")]
    original: crate::security_epoch::native_clock::NativeAcquisition,
    #[cfg(target_os = "linux")]
    http: crate::security_epoch::transport::NativeHttp,
    #[cfg(target_os = "linux")]
    credential: crate::security_epoch::credential_material::CredentialMaterial,
}

/// Admitted installed material held by the actual non-serving restored App.
/// This is input to keeper birth, never a Runtime, Current or SQL permission.
pub(in crate::security_epoch) struct RestoredKeeperInput {
    owner: RestoredReadIdentity,
    artifact: crate::artifact::LoadedArtifact,
    installed: artifact::InstalledArtifact,
}

/// The actual restored App, installed artifact and current authenticated
/// Instance input. This still owns no SQLite connection or serving authority.
pub(in crate::security_epoch) struct RestoredConfiguredInput {
    input: RestoredKeeperInput,
    configuration: configuration::CurrentInstance,
}

/// Actual file resources after the App's own current writer observation. The
/// frozen image is consumed, never disabled by a flag. This is still not a
/// SQLite connection, keeper, acknowledged cohort or serving owner.
struct ActiveRestoredFile {
    #[cfg(target_os = "linux")]
    peer: RestoredAppPeer,
    #[cfg(target_os = "linux")]
    root: File,
    #[cfg(target_os = "linux")]
    private: File,
    #[cfg(target_os = "linux")]
    directory: File,
    file: std::fs::File,
    #[cfg(target_os = "linux")]
    root_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    private_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    directory_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    file_stamp: file::Stamp,
    #[cfg(target_os = "linux")]
    component: String,
    #[cfg(target_os = "linux")]
    refused: bool,
    local_only: PhantomData<Rc<()>>,
}

struct ActiveRestoredReadIdentity {
    captured: ActiveRestoredFile,
    #[cfg(target_os = "linux")]
    activation: super::restore_peer_wire::Activation,
    #[cfg(target_os = "linux")]
    original: crate::security_epoch::native_clock::NativeAcquisition,
    #[cfg(target_os = "linux")]
    http: crate::security_epoch::transport::NativeHttp,
    #[cfg(target_os = "linux")]
    credential: crate::security_epoch::credential_material::CredentialMaterial,
    local_only: PhantomData<Rc<()>>,
}

/// Short actual-owner borrow used by the ONE installed-artifact validator.
/// Neither variant carries DATA permission or reconstructs a clock/holder.
struct RestoredObservation<'borrow> {
    owner: RestoredObservationOwner<'borrow>,
}

enum RestoredObservationOwner<'borrow> {
    Frozen(&'borrow mut RestoredReadIdentity),
    Active(&'borrow mut ActiveRestoredReadIdentity),
}

/// The actual App borrow joined to its actual retained artifact resources.
/// Private factories borrow the fields together; no external DATA chooses an
/// owner, artifact, original or installed-file inventory.
struct RestoredMaterialBorrow<'borrow> {
    owner: RestoredObservation<'borrow>,
    artifact: &'borrow crate::artifact::LoadedArtifact,
    #[cfg(target_os = "linux")]
    installed: &'borrow artifact::InstalledArtifact,
}

/// Material held for the first SQLite connection, still with no connection or
/// ACK. Its future fixed factory must freshly validate configuration, artifact,
/// writer observation and these actual anchors before any SQLite activation.
pub(in crate::security_epoch) struct RestoredActiveKeeperInput {
    owner: ActiveRestoredReadIdentity,
    artifact: crate::artifact::LoadedArtifact,
    installed: artifact::InstalledArtifact,
    configuration: configuration::CurrentInstance,
}

/// Lexical birth loan. Only the fixed actual App factory borrows these fields;
/// no DATA, pathname, role getter or callback can manufacture this boundary.
pub(crate) struct RestoredKeeperBirth<'borrow> {
    owner: &'borrow mut ActiveRestoredReadIdentity,
    artifact: &'borrow crate::artifact::LoadedArtifact,
    installed: &'borrow artifact::InstalledArtifact,
    configuration: &'borrow configuration::CurrentInstance,
    path: std::path::PathBuf,
    scope: String,
    completed: bool,
    app: String,
}

impl Drop for RestoredKeeperBirth<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.refuse();
        }
    }
}

/// Teardown order is essential: the FIRST SQLite connection closes before any
/// raw same-inode descriptor in the App input. There is no custom Drop body
/// that could release those file resources ahead of the connection.
pub(in crate::security_epoch) struct RestoredAppKeeper {
    keeper: crate::store::NativeSqliteKeeper,
    input: RestoredActiveKeeperInput,
}

/// Fixed Runtime construction borrows the actual accepted App's first keeper.
/// Its private factory is never available from metadata or a database path.
/// Runtime remains inert native DATA until the genuine serving owner exists.
pub(crate) struct RestoredRuntimeBirth<'borrow> {
    keeper: &'borrow mut RestoredAppKeeper,
    completed: bool,
}

impl Drop for RestoredRuntimeBirth<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.keeper.keeper.refuse();
            self.keeper.input.owner.refuse();
        }
    }
}

/// The same genuine first connection and App resources after actual ACK,
/// authenticated Released and a fresh own writer read. This is still neither
/// an ordinary enrolled role nor a Runtime/Current or serving conversion.
pub(in crate::security_epoch) struct ReleasedRestoredApp {
    keeper: RestoredAppKeeper,
}

/// Authenticated final role-handoff receipt, retaining the SAME first keeper.
/// This still is not an ordinary enrolled role, Current, storage or Runtime.
/// The keeper closes SQLite before its raw file owners on every drop path.
pub(in crate::security_epoch::native_enrollment) struct ReceivedRoleRestoredApp {
    keeper: RestoredAppKeeper,
    #[cfg(target_os = "linux")]
    receipt: RestoredControllerReceipt,
    #[cfg(target_os = "linux")]
    completion: super::protocol::SignedRestoreIssuerCompletion,
    #[cfg(target_os = "linux")]
    role_transcript: super::handshake::Transcript,
}

/// Covers the actual keeper and BOTH originals before the first native bound
/// reduction. Failed authentication, a partial reduction, postcheck or unwind
/// cannot release any of those real owners for another attempt.
struct RoleReceiveAttempt<'borrow> {
    keeper: &'borrow mut RestoredAppKeeper,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
    #[cfg(target_os = "linux")]
    receipt: Option<RestoredControllerReceipt>,
    done: bool,
}

impl Drop for RoleReceiveAttempt<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.keeper.keeper.refuse();
            self.keeper.input.owner.refuse();
        }
    }
}

/// Actual Controller decision receipt on the same first keeper and completed
/// RoleReady history. It supplies no ordinary role, admission or Runtime.
pub(in crate::security_epoch::native_enrollment) struct ReceivedDecisionRestoredApp {
    received: ReceivedRoleRestoredApp,
    #[cfg(target_os = "linux")]
    receipt: RestoredControllerReceipt,
    #[cfg(target_os = "linux")]
    decision: super::protocol::SignedRestoreRoleActivation,
    #[cfg(target_os = "linux")]
    transcript: super::handshake::Transcript,
}

/// Negative ownership precedes every decision receive and original reduction.
struct DecisionReceiveAttempt<'borrow> {
    owner: &'borrow mut ReceivedRoleRestoredApp,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
    #[cfg(target_os = "linux")]
    receipt: Option<RestoredControllerReceipt>,
    done: bool,
}

impl Drop for DecisionReceiveAttempt<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.owner.refuse();
        }
    }
}

/// Direct issuer confirmation retains the actual App, first keeper, both
/// originals and every real issuer receipt. No fields/parts are exposed.
struct AppIssuerConfirmation {
    input: Option<ReceivedDecisionRestoredApp>,
    #[cfg(target_os = "linux")]
    channel: Option<channel::Channel>,
    #[cfg(target_os = "linux")]
    nonce_peer: Option<issuer_peer::IssuerReceipt>,
    #[cfg(target_os = "linux")]
    grant_peer: Option<issuer_peer::IssuerReceipt>,
    #[cfg(target_os = "linux")]
    request: Option<Digest>,
    #[cfg(target_os = "linux")]
    challenge: Option<Digest>,
    #[cfg(target_os = "linux")]
    confirmation: Option<protocol::SignedRestorePreparedConfirmation>,
    complete: bool,
    refused: bool,
}

/// PREPARED only. Direct issuer proof does not attest the Controller full
/// post, its acceptance, ordinary installation or final restore success.
pub(in crate::security_epoch::native_enrollment) struct PreparedConfirmedRestoredApp {
    pending: AppIssuerConfirmation,
}

/// One consumed prepared App through its actual acknowledgement and the
/// Controller's later acceptance. A send result alone never completes it.
struct AppPreparedHandoff {
    input: Option<PreparedConfirmedRestoredApp>,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
    #[cfg(target_os = "linux")]
    acknowledgement: Option<super::storage_peer_wire::Message>,
    #[cfg(target_os = "linux")]
    receipt: Option<RestoredControllerReceipt>,
    ack_delivered: bool,
    accepted: bool,
    installation_attempted: bool,
    refused: bool,
}

/// Actual Controller acceptance of this prepared App, retaining the first
/// keeper and every original. Still no installed acknowledgement or Runtime.
pub(in crate::security_epoch::native_enrollment) struct AcceptedRestoredApp {
    pending: AppPreparedHandoff,
    installed_attempted: bool,
    #[cfg(target_os = "linux")]
    installed: Option<InstalledAppHistory>,
}

/// Complete actual installed exchange, retained with the same first keeper.
/// Packet DATA is never a Current permission or evidence of Controller release.
struct InstalledAppHistory {
    local: PhantomData<std::rc::Rc<()>>,
    #[cfg(target_os = "linux")]
    acknowledgement: super::storage_peer_wire::Message,
    #[cfg(target_os = "linux")]
    acceptance: super::storage_peer_wire::Message,
    #[cfg(target_os = "linux")]
    receipt: Option<RestoredControllerReceipt>,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
}

/// Actual App owner and stage are borrowed before spending installation. No
/// unwind/refusal can leave either original healthy or release the first keeper.
struct AppInstalledHandoff<'borrow, 'stage, 'role> {
    owner: &'borrow mut AcceptedRestoredApp,
    stage: &'stage mut super::EnrolledRoleStage<'role>,
    #[cfg(target_os = "linux")]
    original: Option<NativeAcquisition>,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
    #[cfg(target_os = "linux")]
    acknowledgement: Option<super::storage_peer_wire::Message>,
    #[cfg(target_os = "linux")]
    receipt: Option<RestoredControllerReceipt>,
    ack_delivered: bool,
    accepted: bool,
    done: bool,
}

impl AppInstalledHandoff<'_, '_, '_> {
    // The factory stays in this material's owning module. Only the actual
    // completed driver can collect its retained packet, receipt and history;
    // no child import, caller DATA or boolean alone constructs this resource.
    fn retain_installed_history(
        &mut self,
        message: super::storage_peer_wire::Message,
    ) -> anyhow::Result<InstalledAppHistory> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = message;
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            use anyhow::Context;
            anyhow::ensure!(
                self.accepted
                    && self.ack_delivered
                    && self
                        .transcript
                        .as_ref()
                        .is_some_and(|history| history.complete())
                    && self.receipt.is_some(),
                "restore_installed_app_history_incomplete"
            );
            Ok(InstalledAppHistory {
                local: std::marker::PhantomData,
                acknowledgement: self
                    .acknowledgement
                    .take()
                    .context("restore_installed_app_ack_missing")?,
                acceptance: message,
                receipt: Some(
                    self.receipt
                        .take()
                        .context("restore_installed_app_receipt_missing")?,
                ),
                transcript: Some(
                    self.transcript
                        .take()
                        .context("restore_installed_app_transcript_missing")?,
                ),
            })
        }
    }
}

impl Drop for AppInstalledHandoff<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.owner.refuse();
            self.stage.refuse_serving();
            #[cfg(target_os = "linux")]
            if let Some(original) = &mut self.original {
                original.refuse();
            }
        }
    }
}

/// One shared owner of the WHOLE first-keeper history. Taking a fixed loan
/// empties this private slot before any checks or waits; no RefCell guard spans
/// provider I/O. The graph is acyclic: Accepted never refers back to this root.
pub(in crate::security_epoch::native_enrollment) struct RestoredAppHistory {
    retained: Cell<Option<AcceptedRestoredApp>>,
    refused: Cell<bool>,
    #[cfg(target_os = "linux")]
    receiver_refusal: NativeOriginalRefusal,
    #[cfg(target_os = "linux")]
    reader_refusal: NativeOriginalRefusal,
    #[cfg(target_os = "linux")]
    channel_refusal: Rc<Cell<bool>>,
}

/// Private fixed operation, never a generic callback, borrowed owner getter or
/// permission. It owns the SAME whole history across waits and returns it before
/// a positive result. Reentry sees an empty slot and poisons the shared roots.
struct RestoredHistoryLoan<'borrow> {
    root: &'borrow RestoredAppHistory,
    history: Option<AcceptedRestoredApp>,
    completed: bool,
}

impl Drop for RestoredHistoryLoan<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.root.refuse();
        }
        if let Some(history) = self.history.take()
            && let Some(unexpected) = self.root.retained.replace(Some(history))
        {
            self.root.refuse();
            drop(unexpected);
        }
    }
}

impl Drop for AppPreparedHandoff {
    fn drop(&mut self) {
        self.refuse();
    }
}

impl Drop for AppIssuerConfirmation {
    fn drop(&mut self) {
        self.refuse();
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <AppIssuerConfirmation as Ambiguous<_>>::check;
            let _ = <PreparedConfirmedRestoredApp as Ambiguous<_>>::check;
            let _ = <AppPreparedHandoff as Ambiguous<_>>::check;
            let _ = <AcceptedRestoredApp as Ambiguous<_>>::check;
            let _ = <InstalledAppHistory as Ambiguous<_>>::check;
            let _ = <AppInstalledHandoff<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoredAppHistory as Ambiguous<_>>::check;
            let _ = <RestoredHistoryLoan<'static> as Ambiguous<_>>::check;
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

/// Only the fixed installed-artifact factory creates this lexical borrow.
/// The shared artifact validator can start one bounded worker and issue its
/// closed contract queries, without obtaining a clock, path or owner getter.
pub(crate) struct RestoredArtifactAdmission<'borrow> {
    owner: &'borrow mut RestoredReadIdentity,
    installed: &'borrow artifact::InstalledArtifact,
    worker: Option<crate::worker::Worker>,
    completed: bool,
}

impl Drop for RestoredArtifactAdmission<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.refuse();
        }
    }
}

impl Drop for AdmittedRestoreProcess {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        self.receiver.refuse();
    }
}

impl Drop for RestoredAppPeer {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.refused = true;
            self.process.receiver.refuse();
        }
    }
}

/// Only receive_restore below constructs this from the ORIGINAL SCM_PIDFD.
/// It is deliberately distinct from the ordinary cold Controller receipt.
pub(in crate::security_epoch::native_enrollment) struct RestoredControllerReceipt {
    #[cfg(target_os = "linux")]
    pidfd: File,
    #[cfg(target_os = "linux")]
    sender: u32,
    #[cfg(target_os = "linux")]
    statement: Option<Digest>,
    #[cfg(target_os = "linux")]
    process: u32,
    #[cfg(target_os = "linux")]
    thread: ThreadId,
    #[cfg(target_os = "linux")]
    refused: bool,
    local_only: PhantomData<Rc<()>>,
}

struct RestoreTransport {
    #[cfg(target_os = "linux")]
    socket: Rc<std::fs::File>,
    #[cfg(target_os = "linux")]
    transcript: super::handshake::Transcript,
    #[cfg(target_os = "linux")]
    refused: Rc<Cell<bool>>,
    #[cfg(target_os = "linux")]
    operation: RestoreTransportOperation,
    local_only: PhantomData<Rc<()>>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RestoreTransportOperation {
    Restoring,
    Transferred,
}

struct ReceivedRestorePacket {
    #[cfg(target_os = "linux")]
    packet: rustix::net::ReceivedPidfdPacket,
    local_only: PhantomData<Rc<()>>,
}
