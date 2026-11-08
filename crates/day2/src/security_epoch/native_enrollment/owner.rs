//! Stable native executor ownership. Nothing here adopts a parsed certificate as
//! authority, moves a role between threads, or renews a failed original.

use crate::oauth::native_management::{
    NativeConsumerAffinity, NativeConsumerContext, NativeRequestFinalContext,
};
use crate::security_epoch::bootstrap::ServingDisposition;
use crate::security_epoch::native_clock::{
    NativeAcquisition, NativeOriginalRefusal, StageAcquisition, boottime,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::issuer_costs::HashCosts;
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::protocol;
use crate::security_epoch::native_enrollment::{
    NativeRole,
    policy::EnrollmentPolicy,
    protocol::{IssuerCertificate, KeyOwner, StagePurpose},
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    channel::Channel,
    issuer_peer::IssuerReceipt,
    process::{MessageProcess, SelfSnapshot},
    protocol::{Packet, SignedStage},
    runtime,
};
use crate::security_epoch::serving::{NativeProviderUse, NativeSqlUse, RuntimeServingUse};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::AuthorityScope};
#[cfg(target_os = "linux")]
use std::cell::RefCell;
use std::{
    marker::PhantomData,
    rc::{Rc, Weak},
    thread::ThreadId,
    time::Duration,
};

mod restore;
mod restore_receiver;
mod serving;
mod storage;
pub(in crate::security_epoch) use restore_receiver::ReceiverDurability;

struct OwnerIdentity;

pub(crate) struct EnrolledProcessRoleOwner {
    policy: EnrollmentPolicy,
    role: NativeRole,
    key: Rc<KeyOwner>,
    certificate: IssuerCertificate,
    incarnation: Digest,
    identity: Rc<OwnerIdentity>,
    process: u32,
    thread: ThreadId,
    refused: bool,
    // One-way refusal gate, never a holder permission or restored DATA flag.
    // Even a later fresh stage cannot restart an unknown initial exchange.
    initial_holder_attempted: bool,
    initial_handshake_attempted: bool,
    serving_attempted: bool,
    #[cfg(target_os = "linux")]
    issuer: Rc<RefCell<IssuerReceipt>>,
    #[cfg(target_os = "linux")]
    binding: super::runtime::RuntimeBinding,
    #[cfg(target_os = "linux")]
    self_data: super::protocol::ProcessData,
    #[cfg(target_os = "linux")]
    policy_file: Rc<RefCell<super::birth::PolicyFileOwner>>,
    #[cfg(target_os = "linux")]
    current: Rc<RefCell<SelfSnapshot>>,
    #[cfg(target_os = "linux")]
    clock: crate::security_epoch::native_clock::NativeConnectionClock,
    #[cfg(target_os = "linux")]
    admission: SignedStage,
    #[cfg(target_os = "linux")]
    admission_peers: Vec<Rc<RefCell<IssuerReceipt>>>,
    #[cfg(target_os = "linux")]
    _completed_admission: Rc<Channel>,
    local: PhantomData<Rc<()>>,
}

/// Not an ordinary enrolled-owner supplier yet. This private pending owner
/// retains the consumed accepted App, its FIRST keeper and both old originals.
/// Only fixed installation checks and counter work use that SAME original.
/// No request/stage/key/SQL getter or successful completion exists here.
pub(in crate::security_epoch) struct PendingRestoredEnrollment {
    owner: EnrolledProcessRoleOwner,
    history: Rc<super::restored::RestoredAppHistory>,
    file_continuity_attempted: bool,
    peer_continuity_attempted: bool,
    // Allocate once before any consumer can capture this Runtime's address.
    // Only fixed prepublication setup may get_mut before the first sharing.
    runtime: std::sync::Arc<crate::store::Runtime>,
    counter: crate::security_epoch::authenticated_reads::CounterConnectionSlot,
    #[cfg(target_os = "linux")]
    original: NativeAcquisition,
}

/// Native-only App handoff. The WHOLE pending installation, first keeper,
/// actual read connection and every negative guard remain retained. Its old
/// original stays live for the genuine installed-acknowledgement exchange.
/// This is no remote Current peer, ordinary Runtime or successful restore.
/// Only that actual same-original exchange and its independent posts may
/// precede retirement; a future Current must then read the lineage afresh.
pub(in crate::security_epoch) struct PreparedRestoredAppNative {
    pending: PendingRestoredEnrollment,
    file: RestoredAppFileContinuity,
    peer: RestoredAppPeerContinuity,
    lineage: crate::security_epoch::bootstrap::ActiveLineage,
}

impl Drop for PreparedRestoredAppNative {
    fn drop(&mut self) {
        // Preparation never disarms the actual Pending destructor or any
        // unknown/lost file, peer, read-connection or first-keeper obligation.
        self.pending.refuse();
    }
}

/// The actual App installed exchange completed and passed all independent
/// posts. It still retains the WHOLE prepared owner and all negative guards;
/// it is not an ordinary Current, remote grant or completed restore.
pub(in crate::security_epoch) struct InstalledRestoredAppNative {
    prepared: PreparedRestoredAppNative,
}

impl Drop for InstalledRestoredAppNative {
    fn drop(&mut self) {
        self.prepared.pending.refuse();
    }
}

impl PreparedRestoredAppNative {
    pub(in crate::security_epoch) fn confirm_installed(
        mut self,
    ) -> Result<InstalledRestoredAppNative> {
        let requested: Result<()> = (|| {
            self.pending.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let (_, deadline) = self.pending.original.interval_data()?;
                let mut stage = EnrolledRoleStage {
                    owner: &mut self.pending.owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::borrowed(&mut self.pending.original),
                    deadline,
                };
                self.file.check_current(&mut stage)?;
                let mut acquisition = stage.narrow_io_acquisition(5)?;
                self.peer.check_anchors(&mut stage, &mut acquisition)?;
                let requested = self.pending.history.confirm_installation(&mut stage);
                let peer_post = self.peer.check_anchors(&mut stage, &mut acquisition);
                let file_post = self.file.check_current(&mut stage);
                let native_post = stage.check();
                requested?;
                peer_post?;
                file_post?;
                native_post
            }
        })();
        let checked = self.pending.check();
        if requested.is_err() || checked.is_err() {
            self.pending.refuse();
        }
        requested?;
        checked?;
        Ok(InstalledRestoredAppNative { prepared: self })
    }
}

/// Whole installed App ownership after the actual old native original retires.
/// All first-keeper/runtime/file/peer/counter/history guards remain retained.
/// This is not an ordinary Runtime, Current, remote grant or restore result.
pub(in crate::security_epoch) struct RetiredRestoredAppNative {
    installed: InstalledRestoredAppNative,
    request_state: Rc<RestoredRequestGate>,
    current_peer: Option<super::RestoredPeerConnection<'static>>,
}

/// Only local one-shot disposition DATA. It grants no native or storage right.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RestoredRequestState {
    Vacant,
    Captured,
    Busy,
    Refused,
}

#[cfg(test)]
mod restored_request_state_tests {
    use super::RestoredRequestState;

    #[test]
    fn a_capture_is_one_shot_and_no_failed_or_lost_state_can_rearm_itself() {
        for (index, mut state) in [
            RestoredRequestState::Vacant,
            RestoredRequestState::Captured,
            RestoredRequestState::Busy,
            RestoredRequestState::Refused,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(state.capture().is_ok(), index == 0);
            assert!(
                state
                    == if index == 0 {
                        RestoredRequestState::Captured
                    } else {
                        RestoredRequestState::Refused
                    }
            );
            assert!(state.capture().is_err());
            assert!(state == RestoredRequestState::Refused);
            assert!(state.capture().is_err());
        }
    }
}

impl RestoredRequestState {
    fn capture(&mut self) -> Result<()> {
        let ready = *self == Self::Vacant;
        *self = Self::Refused;
        ensure!(ready, "restore_current_capture_busy_or_refused");
        *self = Self::Captured;
        Ok(())
    }
}

/// A unique incarnation/loss gate, never native or storage permission. It
/// travels by actual Rc identity while the whole owner moves into its lease.
struct RestoredRequestGate {
    state: std::cell::Cell<RestoredRequestState>,
    local: PhantomData<Rc<()>>,
}

impl RestoredRequestGate {
    fn new() -> Self {
        Self {
            state: std::cell::Cell::new(RestoredRequestState::Vacant),
            local: PhantomData,
        }
    }

    fn capture(&self) -> Result<()> {
        let mut state = self.state.get();
        let requested = state.capture();
        self.state.set(state);
        requested
    }

    fn begin(parent: &Rc<Self>, captured: &Rc<Self>) -> Result<()> {
        if !Rc::ptr_eq(parent, captured) || parent.state.get() != RestoredRequestState::Captured {
            parent.refuse();
            captured.refuse();
            anyhow::bail!("restore_current_capture_parent_changed_or_spent");
        }
        parent.state.set(RestoredRequestState::Busy);
        Ok(())
    }

    fn require_busy(&self) -> Result<()> {
        if self.state.get() != RestoredRequestState::Busy {
            self.refuse();
            anyhow::bail!("restore_current_scope_closed");
        }
        Ok(())
    }

    fn finish(&self) -> Result<()> {
        self.require_busy()?;
        self.state.set(RestoredRequestState::Vacant);
        Ok(())
    }

    fn finish_scope(&self) -> Result<()> {
        self.require_busy()?;
        self.state.set(RestoredRequestState::Captured);
        Ok(())
    }

    fn refuse(&self) {
        self.state.set(RestoredRequestState::Refused);
    }
}

/// Negative ownership of the actual shared gate before a borrowed scope
/// exists. It can only refuse; transfer merely hands that duty to the new
/// already-armed scope and never completes a native request.
struct RestoredCaptureRefusal {
    gate: Rc<RestoredRequestGate>,
    armed: bool,
}

impl RestoredCaptureRefusal {
    fn new(gate: &Rc<RestoredRequestGate>) -> Self {
        Self {
            gate: Rc::clone(gate),
            armed: true,
        }
    }
    fn refuse(&self) {
        self.gate.refuse();
    }
    fn transfer(&mut self) {
        self.armed = false;
    }
}

impl Drop for RestoredCaptureRefusal {
    fn drop(&mut self) {
        if self.armed {
            self.refuse();
        }
    }
}

/// The genuine native setup request starts before configuration file I/O.
/// This retains the WHOLE retired parent and its actual captured original;
/// neither Runtime configuration nor an Arc can recreate either root.
/// The later fixed installation must move both roots together, never expose
/// parts or capture a replacement original after configuration.
pub(in crate::security_epoch) struct RestoredAppHostSetupNative {
    parent: Option<RetiredRestoredAppNative>,
    captured: Option<CapturedRestoredAppRequest>,
}

impl RestoredAppHostSetupNative {
    pub(in crate::security_epoch) fn refuse(&mut self) {
        if let Some(parent) = &mut self.parent {
            parent.request_state.refuse();
            parent.installed.prepared.pending.refuse();
        }
        if let Some(captured) = &mut self.captured {
            captured.refuse();
        }
    }

    // Fixed setup composition only. The Runtime pointer is identity DATA;
    // actual native/file continuity and the later real Current remain required.
    fn install(
        mut self,
        inputs: crate::deployment::NativeRestoredHostInputs,
    ) -> Result<crate::deployment::RestoredHostInstallation> {
        self.check_native()?;
        let expected = std::sync::Arc::as_ptr(
            &self
                .parent
                .as_ref()
                .expect("actual native setup parent")
                .installed
                .prepared
                .pending
                .runtime,
        );
        let requested = inputs.configure(
            &mut self
                .parent
                .as_mut()
                .expect("actual native setup parent")
                .installed
                .prepared
                .pending
                .runtime,
        );
        let actual = std::sync::Arc::as_ptr(
            &self
                .parent
                .as_ref()
                .expect("actual native setup parent")
                .installed
                .prepared
                .pending
                .runtime,
        );
        let identity = if std::ptr::eq(expected, actual) {
            Ok(())
        } else {
            Err(anyhow::anyhow!("restore_host_setup_runtime_replaced"))
        };
        // Always collect the actual native/file postcheck, even if fixed
        // configuration or its allocation identity already failed.
        let checked = self.check_native();
        if requested.is_err() || identity.is_err() || checked.is_err() {
            self.refuse();
        }
        let configured = requested?;
        identity?;
        checked?;
        let runtime = std::sync::Arc::clone(
            &self
                .parent
                .as_ref()
                .expect("actual native setup parent")
                .installed
                .prepared
                .pending
                .runtime,
        );
        let parent = self.parent.take().expect("actual native setup parent");
        let captured = self
            .captured
            .take()
            .expect("actual pre-configuration request");
        let owner = crate::security_epoch::serving::RestoredAppServingOwner::from_native(parent);
        let captured =
            crate::security_epoch::serving::CapturedRestoredServingRequest::from_native(captured);
        configured.install(runtime, owner, captured)
    }

    // Passive native/file continuity only. This supplies no Current, SQL,
    // provider, human grant, stage, Runtime or positive publication witness.
    fn check_native(&mut self) -> Result<()> {
        let requested = (|| {
            let parent = self
                .parent
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_host_setup_parent_missing"))?;
            let captured = self
                .captured
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_host_setup_request_missing"))?;
            let mut attempt = RestoredHumanClockAttempt {
                captured,
                parent,
                completed: false,
            };
            attempt.check_posts()?;
            attempt.completed = true;
            Ok(())
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }
}

impl Drop for RestoredAppHostSetupNative {
    fn drop(&mut self) {
        self.refuse();
    }
}

/// Actual capture-time original, movable before the WHOLE native parent is
/// taken from its routing slot. Its opaque actual gate/history bind it to that
/// same parent; no timestamp, native stage, role or request getter exists.
/// A lost capture poisons its original and actual parent roots permanently.
pub(in crate::security_epoch) struct CapturedRestoredAppRequest {
    refusal: RestoredCaptureRefusal,
    history: Rc<super::restored::RestoredAppHistory>,
    request: Option<EnrolledCurrentRequest>,
    scope_settled: bool,
}

impl Drop for CapturedRestoredAppRequest {
    fn drop(&mut self) {
        if self.refusal.armed {
            self.refusal.refuse();
            self.history.refuse();
            if let Some(request) = &mut self.request {
                request.refuse();
            }
        }
    }
}

/// Both graphs are armed even while preparing the pure owned metadata for
/// the new borrowed frame. No partially constructed frame can lose a parent.
struct RestoredAppBeginAttempt<'scope, 'request, 'original> {
    parent: Option<&'scope mut RetiredRestoredAppNative>,
    captured: Option<&'scope mut CapturedRestoredAppRequest>,
    context: Option<NativeConsumerContext<'request, 'original>>,
}

impl Drop for RestoredAppBeginAttempt<'_, '_, '_> {
    fn drop(&mut self) {
        if let Some(parent) = &mut self.parent {
            parent.request_state.refuse();
            parent.installed.prepared.pending.refuse();
        }
        if let Some(captured) = &mut self.captured {
            captured.refuse();
        }
        // The context keeps its actual human/request negative roots armed.
    }
}

/// Both real roots stay armed across passive capture continuity and human-clock observations.
struct RestoredHumanClockAttempt<'capture, 'parent> {
    captured: &'capture mut CapturedRestoredAppRequest,
    parent: &'parent mut RetiredRestoredAppNative,
    completed: bool,
}

impl Drop for RestoredHumanClockAttempt<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.captured.refuse();
            self.parent.request_state.refuse();
            self.parent.installed.prepared.pending.refuse();
        }
    }
}

impl RestoredHumanClockAttempt<'_, '_> {
    fn require_parent(&mut self) -> Result<()> {
        let same = Rc::ptr_eq(&self.parent.request_state, &self.captured.refusal.gate)
            && Rc::ptr_eq(
                &self.parent.installed.prepared.pending.history,
                &self.captured.history,
            )
            && self.parent.request_state.state.get() == RestoredRequestState::Captured;
        if !same {
            self.captured.refuse();
            self.parent.request_state.refuse();
            self.parent.installed.prepared.pending.refuse();
            anyhow::bail!("restore_human_clock_parent_changed_or_busy");
        }
        Ok(())
    }

    fn check_posts(&mut self) -> Result<()> {
        self.require_parent()?;
        let prepared = &mut self.parent.installed.prepared;
        let request = self
            .captured
            .request
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
        let mut stage = prepared.pending.owner.borrow_current_request(request)?;
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let file = prepared.file.check_current(&mut stage);
        let anchors = prepared.peer.check_anchors(&mut stage, &mut acquisition);
        let native = stage.check();
        file?;
        anchors?;
        native
    }
}

struct RestoredRequestFinishAttempt<'parent, 'request, 'original> {
    parent: &'parent mut RetiredRestoredAppNative,
    captured: Option<CapturedRestoredAppRequest>,
    context: Option<NativeRequestFinalContext<'request, 'original>>,
    affinity: Option<NativeConsumerAffinity>,
    origin: Option<NativeConsumerOrigin>,
    completed: bool,
}

impl Drop for RestoredRequestFinishAttempt<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.parent.request_state.refuse();
            self.parent.installed.prepared.pending.refuse();
            if let Some(captured) = &mut self.captured {
                captured.refuse();
            }
            if let Some(context) = &mut self.context {
                context.refuse();
            }
            if let Some(origin) = &self.origin {
                origin.refuse();
            }
        }
    }
}

/// Exclusive field loans retain the entire parent graph while the genuine
/// captured request and one counter request perform this bounded exchange.
/// No stage, original, Runtime, descriptor or counter can escape this owner.
pub(in crate::security_epoch) struct RestoredAppCurrentPeer<'parent, 'request, 'original> {
    owner: &'parent mut EnrolledProcessRoleOwner,
    runtime: &'parent std::sync::Arc<crate::store::Runtime>,
    state: Rc<RestoredRequestGate>,
    #[cfg(target_os = "linux")]
    retired: &'parent mut NativeAcquisition,
    file: &'parent mut RestoredAppFileContinuity,
    anchors: &'parent mut RestoredAppPeerContinuity,
    history: Rc<super::restored::RestoredAppHistory>,
    lineage: &'parent crate::security_epoch::bootstrap::ActiveLineage,
    policy: day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
    store: day2_capabilities::security_epoch::EpochStore,
    counter_slot:
        Option<&'parent mut crate::security_epoch::authenticated_reads::CounterConnectionSlot>,
    counter: Option<crate::security_epoch::authenticated_reads::CounterRequest<'parent>>,
    returned: &'parent mut Option<super::RestoredPeerConnection<'static>>,
    captured: &'parent mut CapturedRestoredAppRequest,
    context: Option<NativeConsumerContext<'request, 'original>>,
    affinity: NativeConsumerAffinity,
    origin: NativeConsumerOrigin,
    disposition: ServingDisposition,
    phase: Option<super::CurrentStoragePeerPhase<'static>>,
    observed: Option<crate::security_epoch::bootstrap::ActiveObservation>,
    done: bool,
}

impl Drop for RestoredAppCurrentPeer<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.refuse();
        }
    }
}

impl CapturedRestoredAppRequest {
    /// Only the real final request/action driver owns this consuming call.
    /// Intermediate S3 scopes leave the same captured original reserved.
    pub(in crate::security_epoch) fn finish<'parent, 'request, 'original>(
        self,
        parent: &'parent mut RetiredRestoredAppNative,
        context: NativeRequestFinalContext<'request, 'original>,
    ) -> Result<()> {
        let mut attempt = RestoredRequestFinishAttempt {
            parent,
            captured: Some(self),
            context: Some(context),
            affinity: None,
            origin: None,
            completed: false,
        };
        let captured = attempt.captured.as_ref().expect("actual captured request");
        let context = attempt.context.as_ref().expect("actual final context");
        attempt.affinity = Some(context.affinity_data());
        attempt.origin = Some(captured.consumer_origin()?);
        ensure!(
            captured.scope_settled,
            "restore_request_has_no_settled_scope"
        );
        ensure!(
            Rc::ptr_eq(
                &captured.history,
                &attempt.parent.installed.prepared.pending.history
            ),
            "restore_request_final_history_changed"
        );
        RestoredRequestGate::begin(&attempt.parent.request_state, &captured.refusal.gate)?;
        {
            let context = attempt.context.as_mut().expect("actual final context");
            context.require_origin(attempt.origin.as_ref().expect("actual original"))?;
            context.require_affinity(attempt.affinity.as_ref().expect("actual final affinity"))?;
            let prepared = &mut attempt.parent.installed.prepared;
            context.require_runtime(prepared.pending.runtime.as_ref())?;
            let captured = attempt.captured.as_mut().expect("actual captured request");
            let request = captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = prepared.pending.owner.borrow_current_request(request)?;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let file = prepared.file.check_current(&mut stage);
            let anchors = prepared.peer.check_anchors(&mut stage, &mut acquisition);
            let native = stage.check();
            // LAST original sample, on this actual saved stage, after every
            // native/file post and before consuming the native HTTP original.
            let original = context.check_final(&mut stage, prepared.pending.runtime.as_ref());
            file?;
            anchors?;
            native?;
            original?;
        }
        attempt
            .captured
            .as_mut()
            .expect("actual captured request")
            .request
            .take()
            .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?
            .finish(&mut attempt.parent.installed.prepared.pending.owner)?;
        let context = attempt.context.take().expect("actual final context");
        context.complete_after_native(RestoredAppRequestSettlement {
            attempt,
            context_checked: false,
        })
    }

    /// A new HUMAN clock starts here; the native HTTP original is not begun,
    /// reset or replaced. BOOTTIME is the first fallible/native observation.
    pub(in crate::security_epoch) fn capture_human_clock(
        &mut self,
        parent: &mut RetiredRestoredAppNative,
    ) -> Result<EnrolledOriginalClock> {
        let mut attempt = RestoredHumanClockAttempt {
            captured: self,
            parent,
            completed: false,
        };
        let origin = boottime()?;
        let requested = (|| {
            attempt.require_parent()?;
            let request = attempt
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = attempt
                .parent
                .installed
                .prepared
                .pending
                .owner
                .borrow_current_request(request)?;
            EnrolledOriginalClock::capture_at(&mut stage, origin, NativeRole::AppHost)
        })();
        let checked = attempt.check_posts();
        let clock = requested?;
        checked?;
        attempt.completed = true;
        Ok(clock)
    }

    pub(in crate::security_epoch) fn sample_human_clock(
        &mut self,
        parent: &mut RetiredRestoredAppNative,
        clock: &mut EnrolledOriginalClock,
    ) -> Result<Duration> {
        let mut attempt = RestoredHumanClockAttempt {
            captured: self,
            parent,
            completed: false,
        };
        let requested = (|| {
            attempt.require_parent()?;
            let request = attempt
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = attempt
                .parent
                .installed
                .prepared
                .pending
                .owner
                .borrow_current_request(request)?;
            clock.sample(&mut stage)
        })();
        let checked = attempt.check_posts();
        let now = requested?;
        checked?;
        attempt.completed = true;
        Ok(now)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refusal.refuse();
        self.history.refuse();
        if let Some(request) = &mut self.request {
            request.refuse();
        }
    }

    /// The genuine request lease can carry this negative-only original join
    /// into its fixed context. No clock or positive native check is exposed.
    pub(crate) fn consumer_origin(&self) -> Result<NativeConsumerOrigin> {
        let Some(request) = &self.request else {
            self.refusal.refuse();
            self.history.refuse();
            anyhow::bail!("restore_current_capture_missing");
        };
        Ok(request.consumer_origin())
    }

    pub(in crate::security_epoch) fn begin_current<'scope, 'request, 'original>(
        &'scope mut self,
        parent: &'scope mut RetiredRestoredAppNative,
        context: NativeConsumerContext<'request, 'original>,
    ) -> Result<RestoredAppCurrentPeer<'scope, 'request, 'original>> {
        let mut attempt = RestoredAppBeginAttempt {
            parent: Some(parent),
            captured: Some(self),
            context: Some(context),
        };
        // Both actual roots and the real consumer stay negative during even
        // metadata allocation. The HTTP original is BORROWED, never taken.
        let (policy, store, state, history, affinity, origin) = {
            let parent = attempt.parent.as_ref().expect("actual supplied parent");
            let captured = attempt.captured.as_ref().expect("actual saved capture");
            let context = attempt.context.as_ref().expect("actual consumer context");
            let prepared = &parent.installed.prepared;
            (
                prepared.pending.owner.policy.bootstrap.clone(),
                prepared.pending.owner.policy.store.clone(),
                Rc::clone(&parent.request_state),
                Rc::clone(&prepared.pending.history),
                context.affinity_data(),
                captured.consumer_origin()?,
            )
        };
        let parent = attempt.parent.take().expect("actual supplied parent");
        let captured = attempt.captured.take().expect("actual saved capture");
        let prepared = &mut parent.installed.prepared;
        let mut current = RestoredAppCurrentPeer {
            policy,
            store,
            owner: &mut prepared.pending.owner,
            runtime: &prepared.pending.runtime,
            state,
            #[cfg(target_os = "linux")]
            retired: &mut prepared.pending.original,
            file: &mut prepared.file,
            anchors: &mut prepared.peer,
            history,
            lineage: &prepared.lineage,
            counter_slot: Some(&mut prepared.pending.counter),
            counter: None,
            returned: &mut parent.current_peer,
            captured,
            context: attempt.context.take(),
            affinity,
            origin,
            disposition: ServingDisposition::Unarmed,
            phase: None,
            observed: None,
            done: false,
        };
        ensure!(
            Rc::ptr_eq(&current.history, &current.captured.history),
            "restore_current_capture_history_changed"
        );
        RestoredRequestGate::begin(&current.state, &current.captured.refusal.gate)?;
        current.captured.scope_settled = false;
        let request = {
            let context = current
                .context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?;
            context.require_origin(&current.origin)?;
            context.require_affinity(&current.affinity)?;
            context.require_runtime(current.runtime.as_ref())?;
            let actual = current
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_capture_missing"))?;
            let mut stage = current.owner.borrow_current_request(actual)?;
            let (binding, _purpose) =
                context.checked_binding(&mut stage, current.runtime.as_ref())?;
            super::StoragePeerRequest::CurrentServing {
                binding: current.lineage.serving_binding(&binding)?,
            }
        };
        {
            let slot = current
                .counter_slot
                .take()
                .ok_or_else(|| anyhow::anyhow!("restore_current_counter_missing"))?;
            let actual = current
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = current.owner.borrow_current_request(actual)?;
            // One admitted counter loan narrows the actual stage BEFORE any
            // packet statement, signature, notification or peer constructor.
            current.counter = Some(slot.request(
                &mut stage,
                &current.policy,
                &current.store,
                NativeRole::AppHost,
            )?);
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let file = current.file.check_current(&mut stage);
            let anchors = current.anchors.check_anchors(&mut stage, &mut acquisition);
            let native = stage.check();
            finish_restored_app_posts(file, anchors, native)?;
            let connection = match current.returned.take() {
                Some(connection) => connection,
                None => {
                    super::RestoredPeerConnection::from_app_history(&current.history, &mut stage)?
                }
            };
            current.phase = Some(connection.begin_app(&mut stage, request)?);
            let reads = current
                .counter
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_counter_missing"))?;
            let phase = current
                .phase
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_peer_missing"))?;
            // Waiting is not consumer admission: receive the actual known
            // result on this SAME original before any lineage read or return.
            let waited = phase.await_known(&mut stage);
            // The first observation does not exist yet. Collect every other
            // actual post independently, even if waiting already refused.
            let file = current.file.check_current(&mut stage);
            let anchors = current.anchors.check_anchors(&mut stage, &mut acquisition);
            let peer = phase.check(&mut stage);
            let counter = reads.check(&mut stage);
            let native = stage.check();
            let context = current
                .context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .check(&mut stage, current.runtime.as_ref());
            waited?;
            file?;
            anchors?;
            peer?;
            counter?;
            native?;
            context?;
            current.observed = Some(current.lineage.read(&current.store, reads, &mut stage)?);
        }
        current.check_local()?;
        Ok(current)
    }
}

impl RestoredAppCurrentPeer<'_, '_, '_> {
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.disposition = ServingDisposition::Refused;
        self.state.refuse();
        self.owner.refused = true;
        self.history.refuse();
        #[cfg(target_os = "linux")]
        self.retired.refuse();
        self.captured.refuse();
        if let Some(context) = &mut self.context {
            context.refuse();
        }
        if let Some(counter) = &mut self.counter {
            counter.refuse();
        }
        if let Some(counter) = &mut self.counter_slot {
            counter.refuse();
        }
        if let Some(phase) = &mut self.phase {
            phase.refuse();
        }
    }

    pub(in crate::security_epoch) fn check_local(&mut self) -> Result<()> {
        let requested = (|| {
            ensure!(!self.done, "restore_current_scope_closed");
            self.state.require_busy()?;
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            let mut acquisition = stage.narrow_io_acquisition(5)?;
            let file = self.file.check_current(&mut stage);
            let anchors = self.anchors.check_anchors(&mut stage, &mut acquisition);
            let peer = self
                .phase
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_peer_missing"))?
                .check(&mut stage);
            let reads = self
                .counter
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_counter_missing"))?;
            let observed = self
                .observed
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_observation_missing"))?;
            let lineage = self.lineage.check(&self.store, reads, &mut stage, observed);
            let counter = reads.check(&mut stage);
            let native = stage.check();
            let context = self
                .context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .check(&mut stage, self.runtime.as_ref());
            file?;
            anchors?;
            peer?;
            lineage?;
            counter?;
            native?;
            context
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn reobserve(&mut self) -> Result<()> {
        // An expired/foreign/refused OLD observation is never repaired by a
        // new provider response, even if the new values happen to match.
        self.check_local()?;
        let requested: Result<()> = (|| {
            let actual = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(actual)?;
            let reads = self
                .counter
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_counter_missing"))?;
            self.observed = Some(self.lineage.read(&self.store, reads, &mut stage)?);
            Ok(())
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn check_file(&mut self) -> Result<()> {
        self.check_local()
    }

    /// A matching app/database/artifact is not this actual Runtime object.
    /// Refuse substitution before any native observation or operation.
    pub(in crate::security_epoch) fn require_runtime(
        &mut self,
        runtime: &crate::store::Runtime,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime.as_ref(), runtime) {
            self.refuse();
            anyhow::bail!("restore_current_runtime_changed");
        }
        let requested = (|| {
            ensure!(
                runtime.uses_native_storage(),
                "restore_current_native_runtime_required"
            );
            self.context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .require_runtime(runtime)?;
            self.check_local()
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    /// The closed Runtime consumer can borrow only its exact autonomous
    /// purpose. Human/creator/response relabeling fails before any native work.
    pub(in crate::security_epoch) fn require_runtime_purpose(
        &mut self,
        runtime: &crate::store::Runtime,
        purpose: RuntimeServingUse,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime.as_ref(), runtime) {
            self.refuse();
            anyhow::bail!("restore_current_runtime_changed");
        }
        let requested = (|| {
            self.context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .require_runtime_purpose(runtime, purpose)?;
            self.require_runtime(runtime)
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    /// Only the actual HTTP response context can enter the finite response
    /// engine. Selection is pure and precedes any saved native observation.
    pub(in crate::security_epoch) fn require_response(
        &mut self,
        runtime: &crate::store::Runtime,
    ) -> Result<()> {
        if !std::ptr::eq(self.runtime.as_ref(), runtime) {
            self.refuse();
            anyhow::bail!("restore_current_runtime_changed");
        }
        let requested = (|| {
            self.context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .require_response(runtime)?;
            self.require_runtime(runtime)
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    /// Fixed full selection on the SAME saved request. Scope equality alone
    /// cannot substitute a provider, key set, lease ceiling or runtime profile.
    /// The stage borrow already checks native facts, so its adjacent exact
    /// selection predicate stays DATA-only before independent local posts.
    pub(in crate::security_epoch) fn check_selection(
        &mut self,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        store: &day2_capabilities::security_epoch::EpochStore,
        role: NativeRole,
    ) -> Result<()> {
        if policy != &self.policy || store != &self.store || role != NativeRole::AppHost {
            self.refuse();
            anyhow::bail!("restore_current_selection_changed");
        }
        let requested: Result<()> = (|| {
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            stage.require_selection_data(policy, store, role)
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn prepare_sql(
        &mut self,
        runtime: &crate::store::Runtime,
        access: NativeSqlUse,
    ) -> Result<()> {
        self.require_runtime(runtime)?;
        let requested: Result<()> = (|| {
            ensure!(
                matches!(self.disposition, ServingDisposition::Armed),
                "restore_current_sql_unarmed_or_finished"
            );
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            self.context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .check_sql(&mut stage, runtime, access)
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn prepare_provider(
        &mut self,
        runtime: &crate::store::Runtime,
        use_: NativeProviderUse,
    ) -> Result<()> {
        self.require_runtime(runtime)?;
        let requested: Result<()> = (|| {
            ensure!(
                matches!(self.disposition, ServingDisposition::Armed),
                "restore_current_provider_unarmed_or_finished"
            );
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            self.context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .check_provider(&mut stage, runtime, use_)
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn require_human(
        &mut self,
        intent: &crate::oauth::fresh_auth::FreshIntent,
        phase: crate::oauth::native_management::Phase,
    ) -> Result<()> {
        self.check_local()?;
        let requested: Result<()> = (|| {
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            self.context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .require_human(&mut stage, self.runtime.as_ref(), intent, phase)
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn response_complete(&mut self) -> Result<()> {
        self.check_local()?;
        let requested: Result<()> = (|| {
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            self.context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .response_complete(&mut stage, self.runtime.as_ref())
        })();
        let checked = self.check_local();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn arm(&mut self) -> Result<()> {
        self.check_local()?;
        if !matches!(self.disposition, ServingDisposition::Unarmed) {
            self.refuse();
            anyhow::bail!("restore_current_already_armed");
        }
        self.disposition = ServingDisposition::Armed;
        self.check_local()
    }

    pub(in crate::security_epoch) fn finish_known(&mut self) -> Result<()> {
        self.check_local()?;
        if !matches!(
            self.disposition,
            ServingDisposition::Unarmed | ServingDisposition::Armed
        ) {
            self.refuse();
            anyhow::bail!("restore_current_result_already_recorded");
        }
        self.disposition = ServingDisposition::Known;
        self.check_local()
    }

    pub(in crate::security_epoch) fn finish_excluded(&mut self) -> Result<()> {
        if !matches!(self.disposition, ServingDisposition::Unarmed) {
            self.refuse();
            anyhow::bail!("restore_current_exclusion_after_attempt");
        }
        self.disposition = ServingDisposition::Excluded;
        Ok(())
    }

    /// The real result was received before admission. ACK/release and all
    /// independent S3 posts precede returning the SAME connection. Only the
    /// final actual request finish may rearm.
    pub(in crate::security_epoch) fn finish(mut self) -> Result<()> {
        self.check_local()?;
        ensure!(
            matches!(
                self.disposition,
                ServingDisposition::Known | ServingDisposition::Excluded
            ),
            "restore_current_unknown_result"
        );
        {
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            let phase = self
                .phase
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_peer_missing"))?;
            phase.acknowledge_known(&mut stage)?;
        }
        self.check_local()?;
        {
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            self.phase
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_peer_missing"))?
                .await_release(&mut stage)?;
        }
        self.check_local()?;
        {
            let request = self
                .captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_request_missing"))?;
            let mut stage = self.owner.borrow_current_request(request)?;
            self.counter
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_counter_missing"))?
                .finish(&mut stage)?;
            let phase = self
                .phase
                .take()
                .ok_or_else(|| anyhow::anyhow!("restore_current_peer_missing"))?;
            let connection = phase.finish_restored(&mut stage)?;
            let file = self.file.check_current(&mut stage);
            let native = stage.check();
            let context = self
                .context
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?
                .check_final(&mut stage, self.runtime.as_ref());
            file?;
            native?;
            context?;
            *self.returned = Some(connection);
        }
        let context = self
            .context
            .take()
            .ok_or_else(|| anyhow::anyhow!("restore_current_context_missing"))?;
        context.complete_scope(NativeConsumerCompletion {
            scope: self,
            context_checked: false,
        })
    }
}

impl RetiredRestoredAppNative {
    /// Fixed same-executor setup. A real native original precedes every
    /// configuration read; no caller can supply Runtime/native parts or reset
    /// the request between configuration and actual Host startup work.
    pub(in crate::security_epoch) fn install_host(
        self,
        inputs: crate::deployment::NativeRestoredHostInputs,
    ) -> Result<crate::deployment::RestoredHostInstallation> {
        self.prepare_host_native()?.install(inputs)
    }

    /// This is the setup action's original, before fixed configuration reads
    /// the Instance or constructs any retained service ports. It does not clone
    /// the Runtime Arc, so fixed configuration can still require Arc::get_mut.
    pub(in crate::security_epoch) fn prepare_host_native(
        self,
    ) -> Result<RestoredAppHostSetupNative> {
        let mut setup = RestoredAppHostSetupNative {
            parent: Some(self),
            captured: None,
        };
        let parent = setup.parent.as_mut().expect("actual native setup parent");
        setup.captured = Some(parent.capture_request()?);
        Ok(setup)
    }

    /// Capture before a response lease moves this WHOLE owner. The request
    /// retains its actual original while queued; begin cannot renew it later.
    pub(in crate::security_epoch) fn capture_request(
        &mut self,
    ) -> Result<CapturedRestoredAppRequest> {
        let mut captured = CapturedRestoredAppRequest {
            refusal: RestoredCaptureRefusal::new(&self.request_state),
            history: Rc::clone(&self.installed.prepared.pending.history),
            request: None,
            scope_settled: false,
        };
        captured.refusal.gate.capture()?;
        let pending = &mut self.installed.prepared.pending;
        captured.request = Some(pending.owner.begin_current_request()?);
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("native_restore_platform_unsupported");
        #[cfg(target_os = "linux")]
        {
            let fresh = captured
                .request
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("restore_current_capture_missing"))?;
            pending
                .original
                .require_retired_predecessor(&mut fresh.acquisition)?;
            pending.owner.borrow_current_request(fresh)?.check()?;
            Ok(captured)
        }
    }
}

impl Drop for RetiredRestoredAppNative {
    fn drop(&mut self) {
        self.request_state.refuse();
        self.installed.prepared.pending.refuse();
    }
}

impl InstalledRestoredAppNative {
    pub(in crate::security_epoch) fn retire_current_native(
        mut self,
    ) -> Result<RetiredRestoredAppNative> {
        // Consuming self owns the unchanged negative guards before the first
        // fallible native/keeper/ACK check; unwind cannot return an old owner.
        let requested = self.prepared.pending.history.check_installed();
        let checked = self.prepared.pending.check();
        if requested.is_err() || checked.is_err() {
            self.prepared.pending.refuse();
        }
        requested?;
        checked?;
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested: Result<()> = (|| {
                let (_, deadline) = self.prepared.pending.original.interval_data()?;
                let mut stage = EnrolledRoleStage {
                    owner: &mut self.prepared.pending.owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::borrowed(&mut self.prepared.pending.original),
                    deadline,
                };
                let mut acquisition = stage.narrow_io_acquisition(5)?;
                let file = self.prepared.file.check_current(&mut stage);
                let peer = self
                    .prepared
                    .peer
                    .check_anchors(&mut stage, &mut acquisition);
                let native = stage.check();
                finish_restored_app_posts(file, peer, native)
            })();
            let checked = self.prepared.pending.check();
            if requested.is_err() || checked.is_err() {
                self.prepared.pending.refuse();
            }
            requested?;
            checked?;
            // The actual SAME connection/original leaf is LAST. Only this
            // whole owning move follows: no wait, I/O or old positive check.
            self.prepared
                .pending
                .owner
                .clock
                .retire_checked(&mut self.prepared.pending.original)?;
            Ok(RetiredRestoredAppNative {
                installed: self,
                request_state: Rc::new(RestoredRequestGate::new()),
                current_peer: None,
            })
        }
    }
}

// Concrete Result selection only: all actual checks have already run. This
// helper cannot sample, invoke callbacks or supply a native/keeper permission.
pub(super) fn finish_restored_app_posts(
    file: Result<()>,
    peer: Result<()>,
    native: Result<()>,
) -> Result<()> {
    file?;
    peer?;
    native
}

/// SAME actual first keeper and raw anchors, with no old deadline or signing
/// verb. This physical input is not an installed ACK, writer or serving owner.
pub(crate) struct RestoredAppFileContinuity {
    history: Rc<super::restored::RestoredAppHistory>,
    same: SameEnrolledOwner,
}

impl Drop for RestoredAppFileContinuity {
    fn drop(&mut self) {
        self.history.refuse();
    }
}

/// Retains the SAME restore endpoint and original received sender anchors.
/// This supplies only native identity/liveness continuity. It cannot start a
/// request or cursor, authenticate a remote Current grant, or acknowledge that
/// the genuine installed/ordinary handoff has completed.
pub(crate) struct RestoredAppPeerContinuity {
    history: Rc<super::restored::RestoredAppHistory>,
    same: SameEnrolledOwner,
}

impl Drop for RestoredAppPeerContinuity {
    fn drop(&mut self) {
        self.history.refuse();
    }
}

struct RestoredPeerAnchorAttempt<'borrow> {
    history: &'borrow super::restored::RestoredAppHistory,
    acquisition: &'borrow mut NativeAcquisition,
    completed: bool,
}

impl Drop for RestoredPeerAnchorAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.history.refuse();
            self.acquisition.refuse();
        }
    }
}

impl RestoredAppPeerContinuity {
    /// The prospective ordinary owner must lend its ACTUAL current stage and
    /// narrowed acquisition. No historical original is sampled; a different
    /// local owner refuses before the retained socket/pidfds are consulted.
    pub(in crate::security_epoch) fn check_anchors(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        acquisition: &mut NativeAcquisition,
    ) -> Result<()> {
        let mut attempt = RestoredPeerAnchorAttempt {
            history: &self.history,
            acquisition,
            completed: false,
        };
        let requested = (|| {
            stage.require_current_role()?;
            self.same.check(stage)?;
            self.history
                .check_current_peer_anchors(stage, attempt.acquisition)
        })();
        let checked = self.same.check(stage);
        if requested.is_err() || checked.is_err() {
            self.history.refuse();
            attempt.acquisition.refuse();
        }
        requested?;
        checked?;
        attempt.completed = true;
        Ok(())
    }
}

/// A borrowing installation operation cannot survive caught unwind as a reusable
/// pending installation. Negative teardown never borrows RefCell resources.
struct PendingReaderAttempt<'borrow> {
    owner: &'borrow mut PendingRestoredEnrollment,
    completed: bool,
}

impl Drop for PendingReaderAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.refuse();
        }
    }
}

impl Drop for PendingRestoredEnrollment {
    fn drop(&mut self) {
        // Do not borrow RefCell resources during negative teardown: reentry or
        // unwind must still poison the actual prospective connection clock.
        #[cfg(target_os = "linux")]
        self.original.refuse();
        self.owner.refused = true;
        self.history.refuse();
        self.counter.refuse();
    }
}

impl PendingRestoredEnrollment {
    /// Consume the genuine pending App and keep all of its owning fields.
    /// Only its actual old request may admit the counter and construct file /
    /// peer continuity. Full old-owner posts precede this owning preparation;
    /// no old observation escapes as permission for a later request. The
    /// original remains live until actual installed acknowledgement completes.
    pub(in crate::security_epoch) fn prepare_current_native(
        mut self,
        lineage: crate::security_epoch::bootstrap::ActiveLineage,
    ) -> Result<PreparedRestoredAppNative> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&mut self, lineage);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            // This observation belongs to the OLD original. Its checks admit
            // the actual connection only; a later Current must read afresh.
            let _ = self.admit_current(&lineage)?;
            let file = self.prepare_file_continuity()?;
            let peer = self.prepare_peer_continuity()?;
            self.check()?;
            // No effect, wait or callback follows the final full old post
            // before this whole owning move. The same original is NOT retired:
            // the actual installed acknowledgement and its posts still owe it.
            Ok(PreparedRestoredAppNative {
                pending: self,
                file,
                peer,
                lineage,
            })
        }
    }

    /// Historical selector DATA only, from the same genuine pending App. No
    /// observation, request Budget, native stage or serving owner is returned.
    /// Bootstrap may select its closed lineage from this typed owner; it still
    /// needs the actual CounterRequest read and final physical/ACK handoff.
    pub(in crate::security_epoch) fn checked_restored_reader_data(
        &mut self,
        selection: &day2_capabilities::security_epoch::EpochStore,
    ) -> Result<crate::security_epoch::firestore::RestoreWriterPeerRead> {
        let mut attempt = PendingReaderAttempt {
            owner: self,
            completed: false,
        };
        let requested = (|| {
            attempt.owner.check()?;
            attempt.owner.history.restored_reader_data(selection)
        })();
        let checked = attempt.owner.check();
        if requested.is_err() || checked.is_err() {
            attempt.owner.refuse();
        }
        let reader = requested?;
        checked?;
        attempt.completed = true;
        Ok(reader)
    }

    /// Fixed cold counter admission and actual restored observation. The same
    /// native original spans authentication, read, close and both full posts.
    /// This never enables requests, finishes installation or returns a stage.
    fn admit_current(
        &mut self,
        lineage: &crate::security_epoch::bootstrap::ActiveLineage,
    ) -> Result<crate::security_epoch::bootstrap::ActiveObservation> {
        let mut attempt = PendingReaderAttempt {
            owner: self,
            completed: false,
        };
        let requested: Result<crate::security_epoch::bootstrap::ActiveObservation> = (|| {
            attempt.owner.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = lineage;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let selected = attempt.owner.owner.policy.store.clone();
                let policy = attempt.owner.owner.policy.bootstrap.clone();
                let expected = attempt.owner.history.restored_reader_data(&selected)?;
                // Another genuine pending App's selector is still the wrong
                // selector. Reject it before admitting a connection or reading.
                lineage.require_restored_reader_data(&expected)?;
                let (_, deadline) = attempt.owner.original.interval_data()?;
                let observed = {
                    let mut stage = EnrolledRoleStage {
                        owner: &mut attempt.owner.owner,
                        purpose: StagePurpose::CurrentRole,
                        acquisition: StageAcquisition::borrowed(&mut attempt.owner.original),
                        deadline,
                    };
                    attempt.owner.counter.admit(
                        &mut stage,
                        &policy,
                        &selected,
                        NativeRole::AppHost,
                    )?;
                    let mut reads = attempt.owner.counter.request(
                        &mut stage,
                        &policy,
                        &selected,
                        NativeRole::AppHost,
                    )?;
                    // This is the SOLE actual observation factory. It captures
                    // the request Budget before provider I/O, never from DATA.
                    let mut observed = lineage.read(&selected, &mut reads, &mut stage)?;
                    lineage.check(&selected, &mut reads, &mut stage, &mut observed)?;
                    reads.finish(&mut stage)?;
                    observed
                };
                Ok(observed)
            }
        })();
        let checked = attempt.owner.check();
        if requested.is_err() || checked.is_err() {
            attempt.owner.refuse();
        }
        let observed = requested?;
        checked?;
        attempt.completed = true;
        Ok(observed)
    }

    /// One actual file/first-keeper continuation; no Runtime, owner or ACK is
    /// released. A lost result spends installation and poisons the same roots.
    fn prepare_file_continuity(&mut self) -> Result<RestoredAppFileContinuity> {
        let mut attempt = PendingReaderAttempt {
            owner: self,
            completed: false,
        };
        let requested: Result<_> = (|| {
            anyhow::ensure!(
                !attempt.owner.file_continuity_attempted,
                "restore_file_continuity_attempt_spent"
            );
            attempt.owner.file_continuity_attempted = true;
            attempt.owner.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let (_, deadline) = attempt.owner.original.interval_data()?;
                let mut stage = EnrolledRoleStage {
                    owner: &mut attempt.owner.owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::borrowed(&mut attempt.owner.original),
                    deadline,
                };
                let same = stage.capture_same_owner()?;
                let mut file = RestoredAppFileContinuity {
                    history: Rc::clone(&attempt.owner.history),
                    same,
                };
                file.check_current(&mut stage)?;
                Ok(file)
            }
        })();
        let checked = attempt.owner.check();
        if requested.is_err() || checked.is_err() {
            attempt.owner.refuse();
        }
        let file = requested?;
        checked?;
        attempt.completed = true;
        Ok(file)
    }

    /// One genuine peer input, spent before any check or resource clone. It
    /// retains the SAME whole history; it never copies a transport or cursor.
    fn prepare_peer_continuity(&mut self) -> Result<RestoredAppPeerContinuity> {
        let mut attempt = PendingReaderAttempt {
            owner: self,
            completed: false,
        };
        let requested: Result<_> = (|| {
            anyhow::ensure!(
                !attempt.owner.peer_continuity_attempted,
                "restore_peer_continuity_attempt_spent"
            );
            attempt.owner.peer_continuity_attempted = true;
            attempt.owner.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let (_, deadline) = attempt.owner.original.interval_data()?;
                let mut stage = EnrolledRoleStage {
                    owner: &mut attempt.owner.owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::borrowed(&mut attempt.owner.original),
                    deadline,
                };
                let same = stage.capture_same_owner()?;
                let mut peer = RestoredAppPeerContinuity {
                    history: Rc::clone(&attempt.owner.history),
                    same,
                };
                let mut acquisition = stage.narrow_io_acquisition(5)?;
                peer.check_anchors(&mut stage, &mut acquisition)?;
                Ok(peer)
            }
        })();
        let checked = attempt.owner.check();
        if requested.is_err() || checked.is_err() {
            attempt.owner.refuse();
        }
        let peer = requested?;
        checked?;
        attempt.completed = true;
        Ok(peer)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        self.original.refuse();
        self.owner.refused = true;
        self.history.refuse();
        self.counter.refuse();
    }

    pub(super) fn from_restore(mut port: super::RestoredRoleInstallPort) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            port.history.refuse();
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            // The port has no DATA or public factory. Check its same actual
            // negative root before constructing the prospective ordinary owner.
            port.history.check()?;
            let stage = &port.admission.data;
            let incarnation = Digest::of(&(
                "day2-native-enrollment-owner-v1",
                port.certificate.digest()?,
                NativeRole::AppHost,
                port.key.public(),
                &stage.process,
                &stage.runtime,
            ))?;
            let mut pending = Self {
                owner: EnrolledProcessRoleOwner {
                    policy: port.policy,
                    role: NativeRole::AppHost,
                    key: port.key,
                    certificate: port.certificate,
                    incarnation,
                    identity: Rc::new(OwnerIdentity),
                    process: std::process::id(),
                    thread: std::thread::current().id(),
                    refused: false,
                    // The restored first-holder and peer lineage is already
                    // spent. It cannot restart any initial/cold exchange.
                    initial_holder_attempted: true,
                    initial_handshake_attempted: true,
                    serving_attempted: true,
                    issuer: port.issuer,
                    binding: stage.runtime.clone(),
                    self_data: stage.process.clone(),
                    policy_file: port.policy_file,
                    current: port.current,
                    clock: port.clock,
                    admission: port.admission,
                    admission_peers: vec![port.nonce_peer],
                    _completed_admission: port.channel,
                    local: PhantomData,
                },
                history: port.history.retain_history()?,
                file_continuity_attempted: false,
                peer_continuity_attempted: false,
                runtime: std::sync::Arc::new(port.runtime),
                counter: crate::security_epoch::authenticated_reads::CounterConnectionSlot::new(),
                original: port.original,
            };
            pending.check()?;
            Ok(pending)
        }
    }

    pub(super) fn check(&mut self) -> Result<()> {
        let requested: Result<()> = (|| {
            self.history.check()?;
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let (_, deadline) = self.original.interval_data()?;
                // This is a borrow of the original already retained by the
                // consumed attempt. No clock begin, capture, reset or renewal.
                let mut stage = EnrolledRoleStage {
                    owner: &mut self.owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: StageAcquisition::borrowed(&mut self.original),
                    deadline,
                };
                stage.check()
            }
        })();
        // Always evaluate the independent full old-owner post, even when the
        // prospective role check fails. Retain the requested primary error.
        let checked = self.history.check();
        if requested.is_err() || checked.is_err() {
            #[cfg(target_os = "linux")]
            self.original.refuse();
            self.owner.refused = true;
            self.history.refuse();
        }
        requested?;
        checked
    }
}

impl RestoredAppFileContinuity {
    pub(crate) fn check_current(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let requested = (|| {
            stage.require_current_role()?;
            self.same.check(stage)?;
            self.history.check_current_resources(stage)
        })();
        let checked = self.same.check(stage);
        if requested.is_err() || checked.is_err() {
            self.history.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.history.refuse();
    }
}

/// Native role continuity only: the SAME actually admitted Controller remains
/// borrowed. No target, storage, writer, installed ACK or restore result follows
/// from this type. The physical finalizer must close its genuine old owners
/// before consuming its actual stage into this fixed native transition.
pub(in crate::security_epoch) struct RetainedControllerNative<'role> {
    owner: &'role mut EnrolledProcessRoleOwner,
    refusal: NativeOriginalRefusal,
}

impl Drop for RetainedControllerNative<'_> {
    fn drop(&mut self) {
        self.owner.refused = true;
        self.refusal.refuse();
    }
}

struct ControllerNativeRetirement<'role> {
    stage: Option<EnrolledRoleStage<'role>>,
    completed: bool,
}

impl Drop for ControllerNativeRetirement<'_> {
    fn drop(&mut self) {
        if !self.completed
            && let Some(stage) = &mut self.stage
        {
            stage.owner.refused = true;
            stage.acquisition.as_mut().refuse();
        }
    }
}

impl RetainedControllerNative<'_> {
    /// Capture a distinct real request on this SAME admitted connection. The
    /// consumed old stage is never renewed or returned as current permission.
    /// Native role identity still supplies no storage/epoch/consumer authority.
    pub(in crate::security_epoch) fn begin_current_stage(
        &mut self,
    ) -> Result<EnrolledRoleStage<'_>> {
        self.owner.begin_current_stage()
    }
}

impl<'role> EnrolledRoleStage<'role> {
    pub(in crate::security_epoch) fn retire_controller_native(
        self,
    ) -> Result<RetainedControllerNative<'role>> {
        // Own the actual stage before the first native check or negative clone.
        let mut attempt = ControllerNativeRetirement {
            stage: Some(self),
            completed: false,
        };
        let requested: Result<NativeOriginalRefusal> = (|| {
            let stage = attempt
                .stage
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("native_controller_retirement_stage_missing"))?;
            stage.require_current_role()?;
            ensure!(
                stage.owner.role == NativeRole::EpochController,
                "native_controller_retirement_role_changed"
            );
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("native_controller_retirement_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                stage.acquisition.retire_owned(&mut stage.owner.clock)
            }
        })();
        let refusal = requested?;
        let stage = attempt
            .stage
            .take()
            .ok_or_else(|| anyhow::anyhow!("native_controller_retirement_stage_missing"))?;
        // No effect, wait, allocation or callback follows the final actual
        // original sample/retirement before this SAME owning borrow moves.
        let retained = RetainedControllerNative {
            owner: stage.owner,
            refusal,
        };
        attempt.completed = true;
        Ok(retained)
    }
}

pub(crate) struct EnrolledRoleStage<'a> {
    owner: &'a mut EnrolledProcessRoleOwner,
    purpose: StagePurpose,
    acquisition: StageAcquisition<'a>,
    deadline: Duration,
}

/// The actual closed issuer exchange and kernel message handles. This only
/// excludes new enrollments/cold-peer grants from THIS same issuer; it cannot
/// attest that business/remote rights drained or construct a new writer.
pub(crate) struct FrozenRoleIssuer {
    same: SameEnrolledOwner,
    original: NativeAcquisition,
    statement: super::protocol::FrozenIssuance,
    signature: String,
    certificate: IssuerCertificate,
    refused: bool,
    restore_attempted: bool,
    finish_attempted: bool,
    #[cfg(target_os = "linux")]
    nonce_peer: IssuerReceipt,
    #[cfg(target_os = "linux")]
    grant_peer: IssuerReceipt,
    #[cfg(target_os = "linux")]
    _channel: Channel,
}

/// Actual issuer-preparation lifetime. Every fixed message operation must be
/// bracketed by the full restore parent at its caller as well as these native
/// same-owner checks. It cannot be reconstructed from signed DATA.
pub(in crate::security_epoch) struct IssuerRestorePreparation {
    #[cfg(target_os = "linux")]
    same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    original: NativeAcquisition,
    #[cfg(target_os = "linux")]
    certificate: IssuerCertificate,
    #[cfg(target_os = "linux")]
    data: super::protocol::RestoreAuthorizationData,
    #[cfg(target_os = "linux")]
    request: Digest,
    #[cfg(target_os = "linux")]
    challenge: Option<Digest>,
    #[cfg(target_os = "linux")]
    bind_signature: Option<String>,
    #[cfg(target_os = "linux")]
    nonce_peer: Option<IssuerReceipt>,
    #[cfg(target_os = "linux")]
    grant_peer: Option<IssuerReceipt>,
    #[cfg(target_os = "linux")]
    signed: Option<super::protocol::SignedRestoreAuthorization>,
    #[cfg(target_os = "linux")]
    channel: Option<Channel>,
    phase: restore::PreparePhase,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

/// Genuine completed issuer exchange, still non-serving. The receiving
/// rendezvous consumes this same owner, not its signed authorization DATA.
pub(in crate::security_epoch) struct PreparedRestoreAdmission {
    preparation: IssuerRestorePreparation,
}

/// Fixed final issuer exchange, constructed only by joining the actual frozen
/// issuer, completed peer and final installation loan.
/// Short operation loans do not keep a storage stage borrowed across provider
/// work. This owner's original must be narrowed from the actual frozen owner.
pub(in crate::security_epoch) struct IssuerRestoreFinishing {
    original: NativeAcquisition,
    #[cfg(target_os = "linux")]
    same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    certificate: IssuerCertificate,
    #[cfg(target_os = "linux")]
    data: super::protocol::RestoreIssuerCompletionData,
    #[cfg(target_os = "linux")]
    app: super::restore_peer_wire::RestoreAppStatement,
    #[cfg(target_os = "linux")]
    request: Digest,
    #[cfg(target_os = "linux")]
    challenge: Option<Digest>,
    #[cfg(target_os = "linux")]
    bind_signature: Option<String>,
    #[cfg(target_os = "linux")]
    nonce_peer: Option<IssuerReceipt>,
    #[cfg(target_os = "linux")]
    grant_peer: Option<IssuerReceipt>,
    #[cfg(target_os = "linux")]
    signed: Option<super::protocol::SignedRestoreIssuerCompletion>,
    #[cfg(target_os = "linux")]
    channel: Option<Channel>,
    phase: restore::PreparePhase,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

/// Non-serving terminal resource, never a signed-DATA, role or Current factory.
/// It retains the finishing lifecycle, including its negative-only Drop.
pub(in crate::security_epoch) struct CompletedRestoreIssuer {
    finishing: IssuerRestoreFinishing,
    role_activation_attempted: bool,
}

/// Fixed final-activation client retaining its actual original and issuer
/// message handles. It creates no ordinary App role or delivery permission.
/// Failure/drop cannot yield a stage, key, clock or serialized permission.
pub(in crate::security_epoch) struct IssuerRestoreRoleActivating {
    #[cfg(target_os = "linux")]
    original: NativeAcquisition,
    #[cfg(target_os = "linux")]
    same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    certificate: IssuerCertificate,
    #[cfg(target_os = "linux")]
    completion: super::protocol::SignedRestoreIssuerCompletion,
    #[cfg(target_os = "linux")]
    app: super::restore_peer_wire::RestoreAppStatement,
    #[cfg(target_os = "linux")]
    request: Digest,
    #[cfg(target_os = "linux")]
    challenge: Option<Digest>,
    #[cfg(target_os = "linux")]
    nonce_peer: Option<IssuerReceipt>,
    #[cfg(target_os = "linux")]
    grant_peer: Option<IssuerReceipt>,
    #[cfg(target_os = "linux")]
    channel: Option<Channel>,
    #[cfg(target_os = "linux")]
    signed: Option<super::protocol::SignedRestoreRoleActivation>,
    phase: restore::PreparePhase,
    refused: bool,
    confirmation_attempted: bool,
    local: PhantomData<Rc<()>>,
}

/// Still non-serving: only the actual fixed client constructs this resource
/// from the issuer's decision. The Controller must finish its outer post
/// before retaining it. No ordinary role or Runtime factory is exposed.
pub(in crate::security_epoch) struct ActivatedRestoredAppRole {
    pending: IssuerRestoreRoleActivating,
}

impl Drop for IssuerRestoreRoleActivating {
    fn drop(&mut self) {
        self.refuse();
    }
}

impl Drop for ActivatedRestoredAppRole {
    fn drop(&mut self) {
        self.refuse();
    }
}

/// Prepared confirmation only: the future fixed native receiver must retain
/// the actual App kernel sender, exact issuer-confirmed decision and original.
/// No field/getter or DATA factory can certify installation or operator success.
/// Only the fixed native receiver constructs it from the actual App ACK.
pub(in crate::security_epoch) struct PreparedRestoredAppConfirmation {
    #[cfg(target_os = "linux")]
    sender: MessageProcess,
    #[cfg(target_os = "linux")]
    same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    original: NativeAcquisition,
    refused: bool,
    local: PhantomData<Rc<()>>,
    #[cfg(target_os = "linux")]
    confirmation: super::protocol::SignedRestorePreparedConfirmation,
    #[cfg(target_os = "linux")]
    transcript: super::handshake::Transcript,
    #[cfg(target_os = "linux")]
    acceptance: Option<super::storage_peer_wire::Message>,
    acceptance_phase: PreparedAcceptancePhase,
    installed_attempted: bool,
}

impl Drop for PreparedRestoredAppConfirmation {
    fn drop(&mut self) {
        self.refuse();
    }
}

/// Actual installed ACK retained from the same authenticated kernel sender,
/// original and first-keeper lineage. It is not an ordinary role or restore result.
pub(in crate::security_epoch) struct InstalledRestoredAppConfirmation {
    #[cfg(target_os = "linux")]
    sender: MessageProcess,
    #[cfg(target_os = "linux")]
    same: SameEnrolledOwner,
    #[cfg(target_os = "linux")]
    original: NativeAcquisition,
    #[cfg(target_os = "linux")]
    message: super::storage_peer_wire::Message,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
    #[cfg(target_os = "linux")]
    acceptance: Option<super::storage_peer_wire::Message>,
    acceptance_phase: PreparedAcceptancePhase,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

/// Negative root spans the actual installed packet receive and every full
/// native/keeper/parent post. No borrowed owner escapes an uncertain attempt.
struct InstalledConfirmationReceiveAttempt<'borrow, 'source, 'target, 'selection> {
    prepared: &'borrow mut PreparedRestoredAppConfirmation,
    peer: &'borrow mut RestoredWriterPeer,
    issuer: &'borrow mut CompletedRestoreIssuer,
    activation: &'borrow mut ActivatedRestoredAppRole,
    loan: &'borrow mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<
        'source,
        'target,
        'selection,
    >,
    #[cfg(target_os = "linux")]
    original: Option<NativeAcquisition>,
    #[cfg(target_os = "linux")]
    sender: Option<MessageProcess>,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
    done: bool,
}

impl Drop for InstalledConfirmationReceiveAttempt<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.prepared.refuse();
            self.peer.refuse();
            self.issuer.refuse();
            self.activation.refuse();
            self.loan.refuse();
        }
    }
}

impl Drop for InstalledRestoredAppConfirmation {
    fn drop(&mut self) {
        self.refuse();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparedAcceptancePhase {
    Fresh,
    Send,
    Poll,
    Delivered,
    Busy,
    Refused,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparedAcceptanceOperation {
    Send,
    Poll,
}

/// Negative root spans the actual prepared ACK receive and every post.
struct PreparedConfirmationReceiveAttempt<'borrow, 'source, 'target, 'selection> {
    peer: &'borrow mut RestoredWriterPeer,
    issuer: &'borrow mut CompletedRestoreIssuer,
    activation: &'borrow mut ActivatedRestoredAppRole,
    loan: &'borrow mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<
        'source,
        'target,
        'selection,
    >,
    #[cfg(target_os = "linux")]
    original: Option<NativeAcquisition>,
    #[cfg(target_os = "linux")]
    sender: Option<MessageProcess>,
    #[cfg(target_os = "linux")]
    transcript: Option<super::handshake::Transcript>,
    done: bool,
}

impl Drop for PreparedConfirmationReceiveAttempt<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.peer.refuse();
            self.issuer.refuse();
            self.activation.refuse();
            self.loan.refuse();
        }
    }
}

/// Every fixed send/poll keeps the same actual receipt and all parent owners.
struct PreparedAcceptanceAttempt<'borrow, 'source, 'target, 'selection> {
    confirmation: &'borrow mut PreparedRestoredAppConfirmation,
    peer: &'borrow mut RestoredWriterPeer,
    issuer: &'borrow mut CompletedRestoreIssuer,
    activation: &'borrow mut ActivatedRestoredAppRole,
    loan: &'borrow mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<
        'source,
        'target,
        'selection,
    >,
    done: bool,
}

impl Drop for PreparedAcceptanceAttempt<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.confirmation.refuse();
            self.peer.refuse();
            self.issuer.refuse();
            self.activation.refuse();
            self.loan.refuse();
        }
    }
}

/// Negative root for a fixed installed-acceptance send or bounded poll. It owns
/// every borrowed authority until both work and the independent post succeed.
struct InstalledAcceptanceAttempt<'borrow, 'source, 'target, 'selection> {
    confirmation: &'borrow mut InstalledRestoredAppConfirmation,
    prepared: &'borrow mut PreparedRestoredAppConfirmation,
    peer: &'borrow mut RestoredWriterPeer,
    issuer: &'borrow mut CompletedRestoreIssuer,
    activation: &'borrow mut ActivatedRestoredAppRole,
    loan: &'borrow mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<
        'source,
        'target,
        'selection,
    >,
    done: bool,
}

impl Drop for InstalledAcceptanceAttempt<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.confirmation.refuse();
            self.prepared.refuse();
            self.peer.refuse();
            self.issuer.refuse();
            self.activation.refuse();
            self.loan.refuse();
        }
    }
}

/// One actual nonescaping role-handoff operation. Only its fixed driver can
/// disarm negative teardown after both requested work and independent posts.
struct RoleHandoffAttempt<'borrow, 'source, 'target, 'selection> {
    peer: &'borrow mut RestoredWriterPeer,
    issuer: &'borrow mut CompletedRestoreIssuer,
    loan: &'borrow mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<
        'source,
        'target,
        'selection,
    >,
    done: bool,
}

/// One actual decision send operation, borrowing all four retained owners.
/// It cannot outlive its closed call or disarm refusal before the full post.
struct DecisionHandoffAttempt<'borrow, 'source, 'target, 'selection> {
    peer: &'borrow mut RestoredWriterPeer,
    issuer: &'borrow mut CompletedRestoreIssuer,
    activation: &'borrow mut ActivatedRestoredAppRole,
    loan: &'borrow mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<
        'source,
        'target,
        'selection,
    >,
    done: bool,
}

/// Binding DATA assembled only by the actual full restore parent. The native
/// factory supplies issuer/frozen/key identity from its retained owners, and
/// compares these clock fields with its actual original before any send.
pub(in crate::security_epoch) struct RestorePreparationData {
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

/// Fixed Controller exchange. The producer must supply the genuine owned
/// prepared issuer admission; signed wire DATA cannot populate that field.
/// No successful constructor exists until the actual transport is joined.
pub(in crate::security_epoch) struct ReceiverRendezvous {
    admission: PreparedRestoreAdmission,
    receiver: restore_receiver::ReceiverState,
    local: PhantomData<Rc<()>>,
}

/// The actual accepted pre-CAS App exchange. It retains every native sender,
/// the prepared original and the unfinished activation/ACK/release transcript.
/// The candidate's separate actual target/provider half remains mandatory.
pub(in crate::security_epoch) struct RestoredWriterPeer {
    receiver: ReceiverRendezvous,
}

/// The actual fresh role and both historical owners are poisoned on any
/// error, unwind or lost return. This loan predates every fallible native check.
struct RestoredControllerPortTransfer<'tail, 'stage, 'role> {
    peer: Option<&'tail mut RestoredWriterPeer>,
    installed: Option<&'tail mut InstalledRestoredAppConfirmation>,
    stage: &'stage mut EnrolledRoleStage<'role>,
    done: bool,
}

impl Drop for RestoredControllerPortTransfer<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            if let Some(peer) = &mut self.peer {
                peer.refuse();
            }
            if let Some(installed) = &mut self.installed {
                installed.refuse();
            }
            self.stage.refuse_serving();
        }
    }
}

impl FrozenRoleIssuer {
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        let stage = &mut *storage.stage;
        let requested: Result<()> = (|| {
            ensure!(!self.refused, "native_restore_issuer_refused");
            self.same
                .meet_current_read_view(stage, &mut self.original)?;
            stage.require_purpose(StagePurpose::CurrentRole)?;
            ensure!(
                self.certificate == stage.owner.certificate
                    && self.statement.issuer == self.certificate.digest()?
                    && self.statement.policy == stage.owner.policy.digest()?
                    && self.statement.cohort == self.statement.selection.history_digest()?,
                "native_restore_issuer_changed"
            );
            super::protocol::verify(
                &self.certificate.data.public_key,
                "restore-issuer-frozen",
                &self.statement,
                &self.signature,
            )?;
            #[cfg(target_os = "linux")]
            {
                self.nonce_peer.check_live(&mut self.original)?;
                self.grant_peer.check_live(&mut self.original)?;
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_issuer_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.original.remaining().map(|_| ())
        })();
        let checked = stage.check();
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked
    }

    pub(in crate::security_epoch::native_enrollment) fn stop_message(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        exchange: &super::storage_peer_wire::CurrentExchange,
    ) -> Result<super::storage_peer_wire::Body> {
        self.check(storage)?;
        ensure!(
            self.statement.selection.admin_binding == *exchange.request.binding()
                && self.statement.selection.app.digest()? == exchange.app_stage
                && self.statement.selection.controller.digest()? == exchange.controller_stage,
            "native_restore_issuer_peer_changed"
        );
        Ok(super::storage_peer_wire::Body::CurrentStop {
            exchange: exchange.digest()?,
            frozen: Box::new(self.statement.clone()),
            signature: self.signature.clone(),
        })
    }

    pub(in crate::security_epoch) fn digest_data(&self) -> Result<Digest> {
        Digest::of(&(
            "day2-native-frozen-issuer-v1",
            &self.statement,
            &self.signature,
        ))
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.original.refuse();
    }
}

impl Drop for IssuerRestorePreparation {
    fn drop(&mut self) {
        self.refuse();
    }
}

impl Drop for IssuerRestoreFinishing {
    fn drop(&mut self) {
        self.refused = true;
        self.phase = restore::PreparePhase::Refused;
        self.original.refuse();
    }
}

impl Drop for RoleHandoffAttempt<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.peer.refuse();
            self.issuer.refuse();
            self.loan.refuse();
        }
    }
}

impl Drop for DecisionHandoffAttempt<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.peer.refuse();
            self.issuer.refuse();
            self.activation.refuse();
            self.loan.refuse();
        }
    }
}

impl Drop for FrozenRoleIssuer {
    fn drop(&mut self) {
        self.refuse();
    }
}

/// Exclusive, short borrow of an actual enrolled stage for storage work.
/// Every operation retains that stage's exact purpose, clock and refusal.
/// There is no raw-stage getter, dereference, adoption or independent owner.
pub(crate) struct EnrolledStorageStage<'stage, 'role> {
    stage: &'stage mut EnrolledRoleStage<'role>,
}

/// One actual accepted-operation original, retained by its typed HTTP/driver
/// owner across lexical callbacks. It is not an enrolled role or Current
/// permission: every use must borrow the SAME live enrolled owner below.
pub(crate) struct EnrolledCurrentRequest {
    identity: Weak<OwnerIdentity>,
    incarnation: Digest,
    role: NativeRole,
    process: u32,
    thread: ThreadId,
    acquisition: NativeAcquisition,
    finished: bool,
    local: PhantomData<Rc<()>>,
}

/// Only the actual request's immutable identity and negative root. Matching
/// this cannot supply a role, sample, deadline, Current or provider permission.
pub(crate) struct NativeConsumerOrigin {
    refusal: NativeOriginalRefusal,
    domain: Digest,
}

/// Actual completed S3 scope, still owning its WHOLE negative native loan.
/// Only its fixed matching context may release that loan back to Captured.
pub(crate) struct NativeConsumerCompletion<'scope, 'request, 'original> {
    scope: RestoredAppCurrentPeer<'scope, 'request, 'original>,
    context_checked: bool,
}

impl<'scope, 'request, 'original> NativeConsumerCompletion<'scope, 'request, 'original> {
    pub(crate) fn check_context(
        &mut self,
        context: &mut NativeConsumerContext<'request, 'original>,
    ) -> Result<()> {
        let origin = context.require_origin(&self.scope.origin);
        let affinity = context.require_affinity(&self.scope.affinity);
        if self.context_checked || origin.is_err() || affinity.is_err() {
            self.scope.refuse();
            context.refuse();
        }
        ensure!(
            !self.context_checked,
            "restore_current_context_already_settled"
        );
        origin?;
        affinity?;
        self.context_checked = true;
        Ok(())
    }

    pub(crate) fn complete_native(mut self) -> Result<()> {
        ensure!(self.context_checked, "restore_current_context_not_settled");
        ensure!(
            !self.scope.owner.refused && self.scope.captured.refusal.armed,
            "restore_current_request_refused"
        );
        let actual = self.scope.captured.consumer_origin()?;
        self.scope.origin.require_same(&actual)?;
        self.scope.state.finish_scope()?;
        self.scope.captured.scope_settled = true;
        self.scope.done = true;
        Ok(())
    }
}

/// Whole final-request guard after actual native original completion. It is
/// never returned to a caller: the same final context consumes it immediately.
pub(crate) struct RestoredAppRequestSettlement<'scope, 'request, 'original> {
    attempt: RestoredRequestFinishAttempt<'scope, 'request, 'original>,
    context_checked: bool,
}

impl<'scope, 'request, 'original> RestoredAppRequestSettlement<'scope, 'request, 'original> {
    pub(crate) fn check_context(
        &mut self,
        context: &mut NativeRequestFinalContext<'request, 'original>,
    ) -> Result<()> {
        let origin = context.require_origin(self.attempt.origin.as_ref().expect("actual original"));
        let affinity = context.require_affinity(
            self.attempt
                .affinity
                .as_ref()
                .expect("actual final affinity"),
        );
        if self.context_checked || origin.is_err() || affinity.is_err() {
            context.refuse();
            self.attempt.parent.request_state.refuse();
            self.attempt.parent.installed.prepared.pending.refuse();
        }
        ensure!(
            !self.context_checked,
            "restore_request_context_already_settled"
        );
        origin?;
        affinity?;
        self.context_checked = true;
        Ok(())
    }

    pub(crate) fn complete_native(mut self) -> Result<()> {
        ensure!(self.context_checked, "restore_request_context_not_settled");
        ensure!(
            !self.attempt.parent.installed.prepared.pending.owner.refused,
            "restore_request_parent_refused"
        );
        let captured = self
            .attempt
            .captured
            .as_mut()
            .expect("actual captured request");
        ensure!(
            captured.refusal.armed && captured.request.is_none(),
            "restore_request_not_finished"
        );
        let original = self.attempt.origin.as_ref().expect("actual original");
        original.require_same(original)?;
        self.attempt.parent.request_state.finish()?;
        captured.refusal.transfer();
        self.attempt.completed = true;
        Ok(())
    }
}

impl NativeConsumerOrigin {
    pub(crate) fn require_same(&self, other: &Self) -> Result<()> {
        if self.domain != other.domain {
            self.refuse();
            other.refuse();
            anyhow::bail!("native_consumer_original_domain_changed");
        }
        self.refusal.require_same(&other.refusal)
    }

    /// Compare to the SAME actual stage original without observing a clock.
    /// The caller must still perform its real native/authority/time checks.
    pub(crate) fn check_current(&self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let actual = Self {
            refusal: stage.acquisition.as_mut().retained_refusal(),
            domain: stage
                .acquisition
                .as_mut()
                .historical_interval_observation()
                .0,
        };
        let selected = self.require_same(&actual);
        let current = stage.purpose == StagePurpose::CurrentRole;
        if selected.is_err() || !current {
            self.refuse();
            actual.refuse();
        }
        selected?;
        ensure!(current, "native_consumer_current_original_required");
        Ok(())
    }

    pub(crate) fn refuse(&self) {
        self.refusal.refuse();
    }
}

/// A Shell HTTP original captured before request-selected app data is read.
/// No app connection, role, issuer, epoch or signing permission is present.
/// Binding consumes it once and joins its retained actual native namespaces
/// to the selected already-enrolled Shell owner without starting another clock.
pub(crate) struct UnselectedShellRequest {
    acquisition: Option<NativeAcquisition>,
    namespaces: crate::security_epoch::NativeNamespaceObservation,
    process: u32,
    thread: ThreadId,
    local: PhantomData<Rc<()>>,
}

impl UnselectedShellRequest {
    pub(crate) fn capture() -> Result<Self> {
        let mut acquisition = NativeAcquisition::begin(5)?;
        let namespaces =
            crate::security_epoch::NativeNamespaceObservation::acquire(&mut acquisition)?;
        acquisition.remaining()?;
        Ok(Self {
            acquisition: Some(acquisition),
            namespaces,
            process: std::process::id(),
            thread: std::thread::current().id(),
            local: PhantomData,
        })
    }

    /// Clock and actual task/namespace continuity only. This never grants a
    /// selected role, SQL, counter, signing or application-result permission.
    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(
                self.process == std::process::id() && self.thread == std::thread::current().id(),
                "native_enrollment_request_owner_changed"
            );
            let original = self
                .acquisition
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("native_enrollment_request_already_bound"))?;
            original.remaining()?;
            self.namespaces.check(original)?;
            original.remaining()?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Plain unselected transport completed and passed its final postchecks.
    /// The driver calls this only after known finite response completion.
    pub(crate) fn finish(mut self) -> Result<()> {
        self.check()?;
        let _ = self.acquisition.take();
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        if let Some(original) = &mut self.acquisition {
            original.refuse();
        }
    }
}

impl Drop for UnselectedShellRequest {
    fn drop(&mut self) {
        // No selected connection was joined, so cancellation does not refuse
        // unused app connections. A bound acquisition is moved out exactly once.
        if let Some(original) = &mut self.acquisition {
            original.refuse();
        }
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
            let _ = <EnrolledCurrentRequest as Ambiguous<_>>::check;
            let _ = <NativeConsumerOrigin as Ambiguous<_>>::check;
            let _ = <NativeConsumerCompletion<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoredAppRequestSettlement<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <FrozenRoleIssuer as Ambiguous<_>>::check;
            let _ = <UnselectedShellRequest as Ambiguous<_>>::check;
            let _ = <IssuerRestorePreparation as Ambiguous<_>>::check;
            let _ = <PreparedRestoreAdmission as Ambiguous<_>>::check;
            let _ = <IssuerRestoreFinishing as Ambiguous<_>>::check;
            let _ = <CompletedRestoreIssuer as Ambiguous<_>>::check;
            let _ = <IssuerRestoreRoleActivating as Ambiguous<_>>::check;
            let _ = <ActivatedRestoredAppRole as Ambiguous<_>>::check;
            let _ = <PreparedRestoredAppConfirmation as Ambiguous<_>>::check;
            let _ = <InstalledRestoredAppConfirmation as Ambiguous<_>>::check;
            let _ = <RetainedControllerNative<'static> as Ambiguous<_>>::check;
            let _ = <ControllerNativeRetirement<'static> as Ambiguous<_>>::check;
            let _ = <RestoredAppPeerContinuity as Ambiguous<_>>::check;
            let _ = <PreparedRestoredAppNative as Ambiguous<_>>::check;
            let _ = <InstalledRestoredAppNative as Ambiguous<_>>::check;
            let _ = <RetiredRestoredAppNative as Ambiguous<_>>::check;
            let _ = <CapturedRestoredAppRequest as Ambiguous<_>>::check;
            let _ = <RestoredRequestGate as Ambiguous<_>>::check;
            let _ = <RestoredAppHostSetupNative as Ambiguous<_>>::check;
            let _ = <RestoredCaptureRefusal as Ambiguous<_>>::check;
            let _ = <RestoredAppBeginAttempt<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoredHumanClockAttempt<'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoredRequestFinishAttempt<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoredAppCurrentPeer<'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <RestoredControllerPortTransfer<'static,'static,'static> as Ambiguous<_>>::check;
            let _ = <RestoredPeerAnchorAttempt<'static> as Ambiguous<_>>::check;
            let _ = <PendingRestoredEnrollment as Ambiguous<_>>::check;
            let _ = <RestoredAppFileContinuity as Ambiguous<_>>::check;
            let _ = <PendingReaderAttempt<'static> as Ambiguous<_>>::check;
            let _ = <PreparedConfirmationReceiveAttempt<'static,'static,'static,'static> as Ambiguous<_>>::check;
            let _ = <PreparedAcceptanceAttempt<'static,'static,'static,'static> as Ambiguous<_>>::check;
            let _ = <InstalledConfirmationReceiveAttempt<'static,'static,'static,'static> as Ambiguous<_>>::check;
            let _ = <InstalledAcceptanceAttempt<'static,'static,'static,'static> as Ambiguous<_>>::check;
            let _ = <RoleHandoffAttempt<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ =
                <DecisionHandoffAttempt<'static, 'static, 'static, 'static> as Ambiguous<_>>::check;
            let _ = <ReceiverRendezvous as Ambiguous<_>>::check;
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

impl Drop for EnrolledCurrentRequest {
    fn drop(&mut self) {
        if !self.finished {
            self.acquisition.refuse();
        }
    }
}

impl EnrolledCurrentRequest {
    /// Retain negative identity of this actual request, never a clock getter.
    pub(crate) fn consumer_origin(&self) -> NativeConsumerOrigin {
        NativeConsumerOrigin {
            refusal: self.acquisition.retained_refusal(),
            domain: self.acquisition.historical_interval_observation().0,
        }
    }

    /// The enclosing driver calls this only after its actual known settlement,
    /// finite response and final postchecks. No child borrow can survive this
    /// consuming call. An error or cancellation keeps shared refusal terminal.
    pub(crate) fn finish(mut self, owner: &mut EnrolledProcessRoleOwner) -> Result<()> {
        {
            let mut stage = owner.borrow_current_request(&mut self)?;
            stage.check()?;
        }
        self.finished = true;
        Ok(())
    }

    pub(crate) fn refuse(&mut self) {
        self.acquisition.refuse();
    }
}

/// Captured at the actual creator entry, before any entropy or I/O. This owns
/// the original self-task and common-clock namespace anchors independently of
/// the short role-stage acquisition. It does not grant a human lifetime.
pub(crate) struct EnrolledOriginalClock {
    origin: Duration,
    latest: Duration,
    incarnation: Digest,
    role: NativeRole,
    process: u32,
    thread: ThreadId,
    refused: bool,
    #[cfg(target_os = "linux")]
    anchors: ClockAnchors,
    local: PhantomData<Rc<()>>,
}

/// Continuity of one actual enrollment owner across distinct bounded phases.
/// This is neither a current role nor preparation, P3 or human permission.
pub(crate) struct SameEnrolledOwner {
    identity: Weak<OwnerIdentity>,
    incarnation: Digest,
    refused: bool,
}

impl EnrolledProcessRoleOwner {
    /// Historical DATA from the successful enrollment, not a current check or
    /// grant. The private Controller evidence exporter cannot restore an owner.
    pub(in crate::security_epoch) fn historical_incarnation_data(&self) -> Digest {
        self.incarnation.clone()
    }

    /// Only operator-selected fixed configuration and the real native exchange
    /// can install a role. Call inside the executor's final owning OS thread.
    pub(crate) fn enroll_current_thread(scope: &AuthorityScope, role: NativeRole) -> Result<Self> {
        let mut acquisition = NativeAcquisition::begin(5)?;
        #[cfg(target_os = "linux")]
        {
            let (policy, mut policy_file) = super::birth::admit_policy(&mut acquisition)?;
            ensure!(
                policy.bootstrap.scope == *scope,
                "native_enrollment_scope_mismatch"
            );
            let key = KeyOwner::generate()?;
            let current = Rc::new(RefCell::new(SelfSnapshot::acquire(
                policy.code(role),
                &mut acquisition,
                &HashCosts::disabled(),
            )?));
            let (certificate, grant, issuer, nonce_peer, channel) = exchange(
                &policy,
                role,
                StagePurpose::CurrentRole,
                &key,
                &current,
                &mut acquisition,
            )?;
            let incarnation = Digest::of(&(
                "day2-native-enrollment-owner-v1",
                certificate.digest()?,
                role,
                key.public(),
                &grant.data.process,
                &grant.data.runtime,
            ))?;
            acquisition.remaining()?;
            policy_file.check(&mut acquisition)?;
            Ok(Self {
                policy,
                role,
                key: Rc::new(key),
                certificate,
                incarnation,
                identity: Rc::new(OwnerIdentity),
                process: std::process::id(),
                thread: std::thread::current().id(),
                refused: false,
                initial_holder_attempted: false,
                initial_handshake_attempted: false,
                serving_attempted: false,
                issuer: Rc::new(RefCell::new(issuer)),
                binding: grant.data.runtime.clone(),
                self_data: grant.data.process.clone(),
                policy_file: Rc::new(RefCell::new(policy_file)),
                current,
                clock: acquisition.into_connection_clock()?,
                admission: grant,
                // The original grant's actual receipt is retained in issuer.
                // A later complete admission retains both new packet handles.
                admission_peers: vec![Rc::new(RefCell::new(nonce_peer))],
                _completed_admission: Rc::new(channel),
                local: PhantomData,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (scope, role, &mut acquisition);
            anyhow::bail!("native_enrollment_platform_unsupported")
        }
    }

    pub(crate) fn begin_current_stage(&mut self) -> Result<EnrolledRoleStage<'_>> {
        self.begin_stage(StagePurpose::CurrentRole)
    }

    /// Capture ONCE at the real accepted operation entry, before entropy/I/O.
    /// Later callbacks retain this owner instead of constructing another stage
    /// original. The live enrolled process/role is never moved into this value.
    pub(crate) fn begin_current_request(&mut self) -> Result<EnrolledCurrentRequest> {
        let stage = self.begin_current_stage()?;
        Ok(EnrolledCurrentRequest {
            identity: Rc::downgrade(&stage.owner.identity),
            incarnation: stage.owner.incarnation.clone(),
            role: stage.owner.role,
            process: stage.owner.process,
            thread: stage.owner.thread,
            acquisition: stage.acquisition.into_owned()?,
            finished: false,
            local: PhantomData,
        })
    }

    pub(crate) fn bind_shell_request(
        &mut self,
        mut start: UnselectedShellRequest,
    ) -> Result<EnrolledCurrentRequest> {
        let result = (|| {
            self.check_local()?;
            ensure!(
                self.role == NativeRole::SecurityShell,
                "native_enrollment_request_shell_required"
            );
            ensure!(
                start.process == std::process::id() && start.thread == std::thread::current().id(),
                "native_enrollment_request_owner_changed"
            );
            let original = start
                .acquisition
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("native_enrollment_request_already_bound"))?;
            start.namespaces.check(original)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_enrollment_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    start.namespaces.data()
                        == self
                            .current
                            .try_borrow()
                            .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                            .namespace
                            .data(),
                    "native_enrollment_request_namespace_changed"
                );
                let original = start
                    .acquisition
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("native_enrollment_request_already_bound"))?;
                let acquisition = self.clock.bind_captured_current(original)?;
                let mut request = EnrolledCurrentRequest {
                    identity: Rc::downgrade(&self.identity),
                    incarnation: self.incarnation.clone(),
                    role: self.role,
                    process: self.process,
                    thread: self.thread,
                    acquisition,
                    finished: false,
                    local: PhantomData,
                };
                // This checks actual retained task/namespace/process and issuer
                // handles before any caller can map expiry or use the request.
                self.borrow_current_request(&mut request)?.check()?;
                Ok(request)
            }
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    /// Reborrow the SAME original with no clock factory, entropy or new grant.
    /// Both input borrows last through the returned stage; neither owner can
    /// be moved, finalized or concurrently reused while that stage is live.
    pub(crate) fn borrow_current_request<'request>(
        &'request mut self,
        request: &'request mut EnrolledCurrentRequest,
    ) -> Result<EnrolledRoleStage<'request>> {
        let result = (|| {
            self.check_local()?;
            ensure!(!request.finished, "native_enrollment_request_finished");
            let original = request
                .identity
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("native_enrollment_request_owner_dropped"))?;
            ensure!(
                Rc::ptr_eq(&original, &self.identity)
                    && request.incarnation == self.incarnation
                    && request.role == self.role
                    && request.process == std::process::id()
                    && request.thread == std::thread::current().id(),
                "native_enrollment_request_owner_changed"
            );
            let (_, deadline) = request.acquisition.interval_data()?;
            Ok(deadline)
        })();
        let deadline = match result {
            Ok(deadline) => deadline,
            Err(error) => {
                self.refused = true;
                request.acquisition.refuse();
                return Err(error);
            }
        };
        let mut stage = EnrolledRoleStage {
            owner: self,
            purpose: StagePurpose::CurrentRole,
            acquisition: StageAcquisition::borrowed(&mut request.acquisition),
            deadline,
        };
        stage.check()?;
        Ok(stage)
    }

    /// Only the original Ready/file/first-peer composition calls this entry.
    /// Authentication still spends at most five seconds of the SAME origin.
    pub(crate) fn begin_initial_first_holder_stage(&mut self) -> Result<EnrolledRoleStage<'_>> {
        self.begin_stage(StagePurpose::InitialFirstHolder)
    }

    /// Only the fixed Controller bootstrap lifecycle and its exact App
    /// responder use this purpose. Ordinary Current and serving stay separate.
    pub(crate) fn begin_storage_bootstrap_stage(&mut self) -> Result<EnrolledRoleStage<'_>> {
        self.begin_stage(StagePurpose::StorageBootstrap)
    }

    /// Controller-only read-only metadata qualification. This signed purpose
    /// is rejected by actual storage, peer, original and consumer factories.
    pub(in crate::security_epoch) fn begin_storage_metadata_observation_stage(
        &mut self,
    ) -> Result<EnrolledRoleStage<'_>> {
        self.begin_stage(StagePurpose::StorageMetadataObservation)
    }

    fn begin_stage(&mut self, purpose: StagePurpose) -> Result<EnrolledRoleStage<'_>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = purpose;
            self.refused = true;
            anyhow::bail!("native_enrollment_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            let result = (|| {
                let mut acquisition = match purpose {
                    StagePurpose::CurrentRole => self.clock.begin_current()?,
                    StagePurpose::InitialFirstHolder => self.clock.begin_initial_first_holder()?,
                    StagePurpose::StorageBootstrap => self.clock.begin_storage_bootstrap()?,
                    StagePurpose::StorageMetadataObservation => {
                        self.clock.begin_storage_metadata_observation()?
                    }
                };
                self.check_local()?;
                purpose.require_role(self.role)?;
                if purpose == StagePurpose::InitialFirstHolder {
                    ensure!(
                        !self.initial_handshake_attempted,
                        "storage_peer_initial_handshake_already_attempted"
                    );
                    self.initial_handshake_attempted = true;
                }
                #[cfg(target_os = "linux")]
                {
                    self.policy_file
                        .try_borrow_mut()
                        .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                        .check(&mut acquisition)?;
                    self.issuer
                        .try_borrow_mut()
                        .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                        .check_live(&mut acquisition)?;
                    self.certificate.verify(&self.policy)?;
                    self.current
                        .try_borrow_mut()
                        .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                        .check(&mut acquisition)?;
                    ensure!(
                        self.current
                            .try_borrow()
                            .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                            .data
                            == self.self_data,
                        "native_enrollment_self_changed"
                    );
                    let (_, deadline) = acquisition.interval_data()?;
                    Ok((acquisition, deadline))
                }
            })();
            if result.is_err() {
                self.refused = true;
            }
            #[cfg(target_os = "linux")]
            {
                let (acquisition, deadline) = result?;
                let mut stage = EnrolledRoleStage {
                    owner: self,
                    purpose,
                    acquisition: StageAcquisition::owned(acquisition),
                    deadline,
                };
                stage.check()?;
                Ok(stage)
            }
        }
    }

    pub(crate) fn capture_original_clock(
        &mut self,
        expected: NativeRole,
    ) -> Result<EnrolledOriginalClock> {
        // Must remain the first operation, including before role/owner checks.
        let origin = boottime().inspect_err(|_| self.refused = true)?;
        let result = (|| {
            self.check_local()?;
            ensure!(self.role == expected, "native_enrollment_clock_role");
            let mut stage = self.begin_current_stage()?;
            EnrolledOriginalClock::capture_at(&mut stage, origin, expected)
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    fn check_local(&mut self) -> Result<()> {
        ensure!(!self.refused, "native_enrollment_owner_refused");
        ensure!(
            self.process == std::process::id() && self.thread == std::thread::current().id(),
            "native_enrollment_owner_changed"
        );
        Ok(())
    }
}

impl EnrolledRoleStage<'_> {
    /// A newly created native peer connection requires a complete fresh issuer
    /// admission. Only cold peer factories call this; later requests borrow
    /// their retained peer. Authentication narrows this request's ORIGINAL
    /// interval to its first five seconds and never resets its clock.
    pub(in crate::security_epoch::native_enrollment) fn admit_peer_connection(
        &mut self,
    ) -> Result<()> {
        let result = (|| {
            self.check()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_enrollment_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let mut authentication = self.acquisition.as_mut().narrow_authentication()?;
                let (certificate, grant, grant_peer, nonce_peer, channel) = exchange(
                    &self.owner.policy,
                    self.owner.role,
                    self.purpose,
                    &self.owner.key,
                    &self.owner.current,
                    &mut authentication,
                )?;
                ensure!(
                    certificate == self.owner.certificate
                        && grant.data.runtime == self.owner.binding,
                    "native_enrollment_incarnation_or_runtime_changed"
                );
                self.owner
                    .issuer
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check_live(&mut authentication)?;
                let signed_deadline = Duration::from_nanos(grant.data.deadline_ns);
                self.acquisition
                    .as_mut()
                    .complete_authentication(authentication)?;
                // This cold exchange keeps any shorter authenticated ceiling
                // on its SAME request; no origin or observation is replaced.
                *self.acquisition.as_mut() =
                    self.acquisition.as_mut().narrow(60, signed_deadline)?;
                self.deadline = self.deadline.min(signed_deadline);
                self.owner.admission = grant;
                self.owner.admission_peers = vec![
                    Rc::new(RefCell::new(grant_peer)),
                    Rc::new(RefCell::new(nonce_peer)),
                ];
                self.owner._completed_admission = Rc::new(channel);
                self.check()
            }
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
        }
        result
    }

    /// Historical sample DATA only; no clock read or new check/permission.
    pub(in crate::security_epoch) fn diagnostic_progress(
        &self,
    ) -> crate::security_epoch::native_clock::AcquisitionProgress {
        self.acquisition
            .as_ref()
            .diagnostic_progress()
            .with_enrollment_data(self.owner.incarnation.clone())
    }

    /// Closed ordinary-consumer gate. No caller-selected purpose or timeout.
    pub(crate) fn require_current_role(&mut self) -> Result<()> {
        self.require_purpose(StagePurpose::CurrentRole)
    }

    pub(crate) fn capture_same_owner(&mut self) -> Result<SameEnrolledOwner> {
        self.check()?;
        Ok(SameEnrolledOwner {
            identity: Rc::downgrade(&self.owner.identity),
            incarnation: self.owner.incarnation.clone(),
            refused: false,
        })
    }

    /// The caller must retain this stage through native I/O and final admission.
    /// Returning a bounded clock does not return a role or storage permission.
    pub(crate) fn narrow_io_acquisition(
        &mut self,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        let result = (|| {
            self.require_purpose(StagePurpose::CurrentRole)?;
            self.check()?;
            let child = self
                .acquisition
                .as_mut()
                .narrow(max_lease_seconds, self.deadline)?;
            self.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
        }
        result
    }
}

impl<'role> EnrolledRoleStage<'role> {
    pub(in crate::security_epoch) fn storage(&mut self) -> Result<EnrolledStorageStage<'_, 'role>> {
        self.check()?;
        Ok(EnrolledStorageStage { stage: self })
    }
}

impl EnrolledStorageStage<'_, '_> {
    /// Join the real retained restore original to THIS enrolled Controller
    /// stage. This returns no stage, acquisition, descriptor or renewed clock.
    pub(in crate::security_epoch) fn check_restore_original(
        &mut self,
        original: &mut crate::security_epoch::restore_original::RestoreOriginalGuard,
        expected: &crate::security_epoch::restore_approval::ApprovalRequest,
        operation: &Digest,
    ) -> Result<()> {
        let requested = original
            .check_join(self.stage, expected, operation)
            .map(|_| ());
        let checked = self.stage.check();
        if requested.is_err() || checked.is_err() {
            original.refuse();
            self.stage.owner.refused = true;
            self.stage.acquisition.as_mut().refuse();
        }
        requested?;
        checked
    }

    /// Full provider authentication shares the stage's original plus five
    /// seconds, including time already spent authenticating its enrolled role.
    pub(in crate::security_epoch) fn narrow_storage_authentication(
        &mut self,
    ) -> Result<NativeAcquisition> {
        let result = (|| {
            self.require_storage_authentication_purpose()?;
            let child = self.stage.acquisition.as_mut().narrow_authentication()?;
            self.stage.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.stage.owner.refused = true;
            self.stage.acquisition.as_mut().refuse();
        }
        result
    }

    /// Consume the actual successful five-second child, then derive a new I/O
    /// view from the still-owned parent. The auth child is never widened.
    pub(in crate::security_epoch) fn complete_storage_authentication(
        &mut self,
        mut child: NativeAcquisition,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        if let Err(error) = self.require_storage_authentication_purpose() {
            child.refuse();
            self.stage.owner.refused = true;
            self.stage.acquisition.as_mut().refuse();
            return Err(error);
        }
        let result = (|| {
            self.stage
                .acquisition
                .as_mut()
                .complete_authentication(child)?;
            match self.stage.purpose {
                StagePurpose::StorageBootstrap => {
                    self.narrow_storage_bootstrap_io_acquisition(max_lease_seconds)
                }
                StagePurpose::StorageMetadataObservation => {
                    self.narrow_storage_metadata_observation_io_acquisition(max_lease_seconds)
                }
                _ => anyhow::bail!("native_enrollment_storage_authentication_purpose"),
            }
        })();
        if result.is_err() {
            self.stage.owner.refused = true;
            self.stage.acquisition.as_mut().refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn narrow_storage_bootstrap_io_acquisition(
        &mut self,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        let result = (|| {
            self.stage.require_purpose(StagePurpose::StorageBootstrap)?;
            self.stage
                .acquisition
                .as_mut()
                .require_storage_bootstrap()?;
            let child = self
                .stage
                .acquisition
                .as_mut()
                .narrow(max_lease_seconds, self.stage.deadline)?;
            self.stage.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.stage.owner.refused = true;
            self.stage.acquisition.as_mut().refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn narrow_storage_metadata_observation_io_acquisition(
        &mut self,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        let result = (|| {
            self.stage
                .require_purpose(StagePurpose::StorageMetadataObservation)?;
            self.stage
                .acquisition
                .as_mut()
                .require_storage_metadata_observation()?;
            let child = self
                .stage
                .acquisition
                .as_mut()
                .narrow(max_lease_seconds, self.stage.deadline)?;
            self.stage.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.stage.owner.refused = true;
            self.stage.acquisition.as_mut().refuse();
        }
        result
    }

    fn require_storage_authentication_purpose(&mut self) -> Result<()> {
        let result = (|| {
            self.stage.check()?;
            match self.stage.purpose {
                StagePurpose::StorageBootstrap => {
                    self.stage.acquisition.as_mut().require_storage_bootstrap()
                }
                StagePurpose::StorageMetadataObservation => self
                    .stage
                    .acquisition
                    .as_mut()
                    .require_storage_metadata_observation(),
                _ => anyhow::bail!("native_enrollment_storage_authentication_purpose"),
            }
        })();
        if result.is_err() {
            self.stage.owner.refused = true;
            self.stage.acquisition.as_mut().refuse();
        }
        result
    }
}

impl EnrolledRoleStage<'_> {
    pub(in crate::security_epoch) fn require_purpose(
        &mut self,
        purpose: StagePurpose,
    ) -> Result<()> {
        if let Err(error) = self.purpose.require_exact(purpose) {
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
            return Err(error);
        }
        self.check()
    }

    /// Every initial caller supplies its ceiling: peers use the fixed initial
    /// limit and files retain their configured shorter cap. The actual parent
    /// origin, signed ceiling, checks and permanent refusal stay unchanged.
    pub(in crate::security_epoch) fn initial_first_holder_acquisition(
        &mut self,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        let result = (|| {
            self.require_purpose(StagePurpose::InitialFirstHolder)?;
            let child = self
                .acquisition
                .as_mut()
                .narrow(max_lease_seconds, self.deadline)?;
            self.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
        }
        result
    }

    pub(crate) fn check_selection(
        &mut self,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        store: &day2_capabilities::security_epoch::EpochStore,
        role: NativeRole,
    ) -> Result<()> {
        self.require_selection_data(policy, store, role)?;
        self.check()
    }

    /// One full Current guard for the exact selection and purpose. These DATA
    /// predicates need no second adjacent native observation before I/O.
    pub(in crate::security_epoch) fn check_current_selection(
        &mut self,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        store: &day2_capabilities::security_epoch::EpochStore,
        role: NativeRole,
    ) -> Result<()> {
        self.require_selection_data(policy, store, role)?;
        self.require_purpose(StagePurpose::CurrentRole)
    }

    fn require_selection_data(
        &mut self,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        store: &day2_capabilities::security_epoch::EpochStore,
        role: NativeRole,
    ) -> Result<()> {
        if self.owner.policy.bootstrap != *policy || self.owner.policy.store != *store {
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
            anyhow::bail!("native_enrollment_full_selection_changed");
        }
        self.require_role_data(&policy.scope, role)
    }

    /// DATA from this actual checked executor, never a current grant factory.
    pub(in crate::security_epoch) fn incarnation_data(&mut self) -> Result<Digest> {
        self.check()?;
        Ok(self.owner.incarnation.clone())
    }

    pub(crate) fn check_for(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
        self.require_role_data(scope, role)?;
        self.check()
    }

    fn require_role_data(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
        let selected = self.owner.policy.bootstrap.scope == *scope && self.owner.role == role;
        if !selected {
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
            anyhow::bail!("native_enrollment_stage_selection_changed");
        }
        Ok(())
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.owner.check_local()?;
            self.purpose.require_role(self.owner.role)?;
            match self.purpose {
                StagePurpose::StorageBootstrap => {
                    self.acquisition.as_mut().require_storage_bootstrap()?
                }
                StagePurpose::StorageMetadataObservation => self
                    .acquisition
                    .as_mut()
                    .require_storage_metadata_observation()?,
                StagePurpose::CurrentRole | StagePurpose::InitialFirstHolder => {}
            }
            ensure!(
                self.acquisition.as_mut().sample()?.elapsed < self.deadline,
                "native_enrollment_stage_expired"
            );
            #[cfg(target_os = "linux")]
            {
                self.owner
                    .policy_file
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check(self.acquisition.as_mut())?;
                self.owner
                    .current
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check(self.acquisition.as_mut())?;
                self.owner
                    .issuer
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check_live(self.acquisition.as_mut())?;
                ensure!(
                    (1..=2).contains(&self.owner.admission_peers.len()),
                    "native_enrollment_admission_peer_bound"
                );
                for peer in &mut self.owner.admission_peers {
                    peer.try_borrow_mut()
                        .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                        .check_live(self.acquisition.as_mut())?;
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_enrollment_platform_unsupported")
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.as_mut().refuse();
        }
        result
    }
}

impl SameEnrolledOwner {
    /// Meet the actual read child's earlier bounds back into THIS same stage
    /// before a later physical/peer release can consume it. This accepts no
    /// scalar deadline or replacement clock, and returns no permission.
    pub(in crate::security_epoch) fn meet_current_read_view(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        actual: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            stage.require_current_role()?;
            stage.acquisition.as_mut().exchange_current_views(actual)?;
            stage.check()
        })();
        if result.is_err() {
            self.refused = true;
            stage.owner.refused = true;
            stage.acquisition.as_mut().refuse();
            actual.refuse();
        }
        result
    }

    pub(crate) fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_owner_continuity_refused");
            let original = self
                .identity
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("native_enrollment_original_owner_dropped"))?;
            ensure!(
                Rc::ptr_eq(&original, &stage.owner.identity)
                    && self.incarnation == stage.owner.incarnation,
                "native_enrollment_original_owner_replaced"
            );
            stage.check()
        })();
        if result.is_err() {
            self.refused = true;
            stage.owner.refused = true;
            stage.acquisition.as_mut().refuse();
        }
        result
    }
}

impl EnrolledOriginalClock {
    fn capture_at(
        stage: &mut EnrolledRoleStage<'_>,
        origin: Duration,
        expected: NativeRole,
    ) -> Result<Self> {
        let requested: Result<Self> = (|| {
            stage.require_purpose(StagePurpose::CurrentRole)?;
            ensure!(stage.owner.role == expected, "native_enrollment_clock_role");
            #[cfg(target_os = "linux")]
            {
                let anchors = ClockAnchors::capture(stage)?;
                let mut clock = Self {
                    origin,
                    latest: origin,
                    incarnation: stage.owner.incarnation.clone(),
                    role: expected,
                    process: std::process::id(),
                    thread: std::thread::current().id(),
                    refused: false,
                    anchors,
                    local: PhantomData,
                };
                clock.sample(stage)?;
                Ok(clock)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = origin;
                anyhow::bail!("native_enrollment_platform_unsupported")
            }
        })();
        let checked = stage.check();
        if requested.is_err() || checked.is_err() {
            stage.owner.refused = true;
            stage.acquisition.as_mut().refuse();
        }
        let clock = requested?;
        checked?;
        Ok(clock)
    }

    pub(crate) fn origin(&self) -> Duration {
        self.origin
    }

    pub(crate) fn sample(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<Duration> {
        let result = (|| {
            ensure!(!self.refused, "native_enrollment_original_clock_refused");
            ensure!(
                self.process == std::process::id()
                    && self.thread == std::thread::current().id()
                    && self.role == stage.owner.role
                    && self.incarnation == stage.owner.incarnation,
                "native_enrollment_original_clock_owner"
            );
            stage.require_purpose(StagePurpose::CurrentRole)?;
            #[cfg(target_os = "linux")]
            self.anchors.check(stage)?;
            let now = boottime()?;
            ensure!(
                now >= self.latest && now >= self.origin,
                "native_enrollment_original_clock_rewind"
            );
            stage.check()?;
            self.latest = now;
            Ok(now)
        })();
        if result.is_err() {
            self.refused = true;
            stage.owner.refused = true;
            stage.acquisition.as_mut().refuse();
        }
        result
    }
}

struct ClockAnchors {
    #[cfg(target_os = "linux")]
    proc: std::fs::File,
    #[cfg(target_os = "linux")]
    task: std::fs::File,
    #[cfg(target_os = "linux")]
    namespaces: std::collections::BTreeMap<String, std::fs::File>,
}

impl ClockAnchors {
    fn capture(stage: &mut EnrolledRoleStage<'_>) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stage;
            anyhow::bail!("native_enrollment_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            use crate::security_epoch::native_namespace as ns;
            stage.check()?;
            let proc = ns::open_root(stage.acquisition.as_mut())?;
            let task = ns::open_task(&proc, stage.acquisition.as_mut())?;
            let mut namespaces = std::collections::BTreeMap::new();
            for name in ["time", "time_for_children", "pid", "user"] {
                namespaces.insert(
                    name.to_owned(),
                    ns::open_namespace(&task, name, stage.acquisition.as_mut())?,
                );
            }
            let mut owner = Self {
                proc,
                task,
                namespaces,
            };
            owner.check(stage)?;
            Ok(owner)
        }
    }

    fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stage;
            anyhow::bail!("native_enrollment_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            use crate::security_epoch::native_namespace as ns;
            stage.check()?;
            let current = ns::open_root(stage.acquisition.as_mut())?;
            ensure!(
                ns::proc_identity(&current)? == ns::proc_identity(&self.proc)?,
                "native_enrollment_clock_proc_changed"
            );
            let current = ns::open_task(&current, stage.acquisition.as_mut())?;
            ensure!(
                ns::proc_identity(&current)? == ns::proc_identity(&self.task)?,
                "native_enrollment_clock_task_changed"
            );
            for (name, original) in &self.namespaces {
                let value = ns::namespace_identity(original)?;
                let current = ns::open_namespace(&current, name, stage.acquisition.as_mut())?;
                ensure!(
                    ns::namespace_identity(&current)? == value
                        && stage
                            .owner
                            .current
                            .try_borrow()
                            .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                            .data
                            .namespaces
                            .get(name)
                            == Some(&(value.device, value.inode)),
                    "native_enrollment_clock_namespace_changed"
                );
            }
            stage.check()
        }
    }
}

#[cfg(target_os = "linux")]
fn exchange(
    policy: &EnrollmentPolicy,
    role: NativeRole,
    purpose: StagePurpose,
    key: &KeyOwner,
    current: &Rc<RefCell<SelfSnapshot>>,
    acquisition: &mut NativeAcquisition,
) -> Result<(
    IssuerCertificate,
    SignedStage,
    IssuerReceipt,
    IssuerReceipt,
    Channel,
)> {
    let mut work = crate::security_epoch::admission_work::begin(
        crate::security_epoch::admission_work::Work::IssuerClientExchange,
    );
    let result = (|| {
        let request = protocol::nonce("role-request")?;
        let public_key = key.public();
        let policy_hash = policy.digest()?;
        let mut channel = Channel::connect(acquisition)?;
        {
            let _profile = crate::security_epoch::self_check_profile::enter(
                crate::security_epoch::self_check_profile::Category::IssuerTransport,
            );
            channel.send(
                &Packet::StageHello {
                    policy: policy_hash.clone(),
                    role,
                    purpose,
                    public_key: public_key.clone(),
                    request: request.clone(),
                },
                acquisition,
            )?;
        }
        let (packet, mut nonce_peer) = channel.receive_issuer(acquisition)?;
        let Packet::StageNonce {
            request: echoed,
            challenge,
        } = packet
        else {
            anyhow::bail!("native_enrollment_stage_order")
        };
        ensure!(echoed == request, "native_enrollment_request_nonce");
        let binding = (
            &policy_hash,
            role,
            purpose,
            &public_key,
            &request,
            &challenge,
        );
        let signature = key.sign("role-bind", &binding)?;
        {
            let _profile = crate::security_epoch::self_check_profile::enter(
                crate::security_epoch::self_check_profile::Category::IssuerTransport,
            );
            channel.send(
                &Packet::StageBind {
                    policy: policy_hash.clone(),
                    role,
                    purpose,
                    public_key: public_key.clone(),
                    request: request.clone(),
                    challenge: challenge.clone(),
                    signature,
                },
                acquisition,
            )?;
        }
        let (packet, mut issuer) = channel.receive_issuer(acquisition)?;
        let Packet::StageGrant { certificate, stage } = packet else {
            anyhow::bail!("native_enrollment_stage_order")
        };
        certificate.verify(policy)?;
        runtime::require_common(&certificate.data.process, &certificate.data.provisioner)?;
        runtime::require_common(
            &current
                .try_borrow()
                .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                .data,
            &certificate.data.process,
        )?;
        ensure!(
            stage.data.issuer == certificate.digest()?
                && stage.data.policy == policy_hash
                && stage.data.role == role
                && stage.data.purpose == purpose
                && stage.data.public_key == public_key
                && stage.data.request == request
                && stage.data.challenge == challenge
                && stage.data.process
                    == current
                        .try_borrow()
                        .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                        .data,
            "native_enrollment_stage_binding"
        );
        protocol::verify(
            &certificate.data.public_key,
            "role-stage",
            &stage.data,
            &stage.signature,
        )?;
        let now = acquisition.sample()?.elapsed;
        ensure!(
            stage.data.origin_ns < stage.data.deadline_ns
                && u128::from(stage.data.deadline_ns - stage.data.origin_ns)
                    <= purpose.limit().as_nanos()
                && Duration::from_nanos(stage.data.origin_ns) <= now
                && now < Duration::from_nanos(stage.data.deadline_ns),
            "native_enrollment_stage_interval"
        );
        current
            .try_borrow_mut()
            .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
            .check(acquisition)?;
        nonce_peer.bind(&certificate, policy, acquisition)?;
        issuer.bind(&certificate, policy, acquisition)?;
        nonce_peer.check_live(acquisition)?;
        issuer.check_live(acquisition)?;
        Ok((certificate, *stage, issuer, nonce_peer, channel))
    })();
    work.finish(result.is_ok());
    result
}

impl FrozenRoleIssuer {
    pub(in crate::security_epoch::native_enrollment) fn capture_restore(
        storage: &mut EnrolledStorageStage<'_, '_>,
        app: &super::storage_peer_wire::StageStatement,
        admin_binding: &Digest,
        stop: &crate::security_epoch::kernel::restore::StopSelection,
    ) -> Result<FrozenRoleIssuer> {
        let stage = &mut *storage.stage;
        let requested: Result<FrozenRoleIssuer> = (|| {
            stage.require_purpose(StagePurpose::CurrentRole)?;
            ensure!(
                stage.owner.role == NativeRole::EpochController,
                "native_restore_issuer_controller_required"
            );
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (app, admin_binding, stop);
                anyhow::bail!("native_restore_issuer_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let controller = stage.storage()?.storage_statement()?;
                let selection = protocol::FreezeSelection {
                    app: app.clone(),
                    controller,
                    admin_binding: admin_binding.clone(),
                    stop: stop.clone(),
                };
                let mut original = stage.narrow_io_acquisition(5)?;
                let request = protocol::nonce("restore-issuer-freeze-request")?;
                stage.check()?;
                let mut channel = Channel::connect(&mut original)?;
                channel.send(
                    &Packet::FreezeHello {
                        selection: Box::new(selection.clone()),
                        request: request.clone(),
                    },
                    &mut original,
                )?;
                stage.check()?;
                let (packet, mut nonce_peer) = channel.receive_issuer(&mut original)?;
                let Packet::FreezeNonce {
                    request: echoed,
                    challenge,
                } = packet
                else {
                    anyhow::bail!("native_restore_freeze_order");
                };
                ensure!(echoed == request, "native_restore_freeze_nonce_changed");
                nonce_peer.bind(&stage.owner.certificate, &stage.owner.policy, &mut original)?;
                stage.check()?;
                let signature = stage
                    .owner
                    .key
                    .sign("restore-issuer-freeze", &(&selection, &request, &challenge))?;
                channel.send(
                    &Packet::FreezeBind {
                        selection: Box::new(selection.clone()),
                        request: request.clone(),
                        challenge: challenge.clone(),
                        signature,
                    },
                    &mut original,
                )?;
                stage.check()?;
                let (packet, mut grant_peer) = channel.receive_issuer(&mut original)?;
                let Packet::FreezeGrant {
                    statement,
                    signature,
                } = packet
                else {
                    anyhow::bail!("native_restore_freeze_order");
                };
                let expected = protocol::FrozenIssuance {
                    selection: selection.clone(),
                    policy: stage.owner.policy.digest()?,
                    issuer: stage.owner.certificate.digest()?,
                    cohort: selection.history_digest()?,
                    request,
                    challenge,
                };
                ensure!(
                    *statement == expected,
                    "native_restore_freeze_statement_changed"
                );
                protocol::verify(
                    &stage.owner.certificate.data.public_key,
                    "restore-issuer-frozen",
                    &*statement,
                    &signature,
                )?;
                grant_peer.bind(&stage.owner.certificate, &stage.owner.policy, &mut original)?;
                stage.check()?;
                let same = stage.capture_same_owner()?;
                let frozen = FrozenRoleIssuer {
                    same,
                    original,
                    statement: *statement,
                    signature,
                    certificate: stage.owner.certificate.clone(),
                    refused: false,
                    restore_attempted: false,
                    finish_attempted: false,
                    nonce_peer,
                    grant_peer,
                    _channel: channel,
                };
                Ok(frozen)
            }
        })();
        let checked = stage.check();
        if requested.is_err() || checked.is_err() {
            stage.owner.refused = true;
            stage.acquisition.as_mut().refuse();
        }
        let mut frozen = requested?;
        checked?;
        frozen.check(storage)?;
        Ok(frozen)
    }
}

#[cfg(test)]
mod restored_app_current_source_tests {
    use quote::ToTokens;

    fn method(owner: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("owner.rs")).unwrap();
        let found=file.items.iter().filter_map(|item|match item {
            syn::Item::Impl(item) if matches!(item.self_ty.as_ref(),syn::Type::Path(path) if path.path.segments.last().is_some_and(|p|p.ident==owner))=>Some(item),_=>None,
        }).flat_map(|item|item.items.iter()).filter_map(|item|match item {
            syn::ImplItem::Fn(item) if item.sig.ident==name=>Some(item.clone()),_=>None,
        }).collect::<Vec<_>>();
        assert_eq!(found.len(), 1);
        found.into_iter().next().unwrap()
    }

    fn tokens(item: &syn::ImplItemFn) -> String {
        item.to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    fn ordered(text: &str, parts: &[&str]) -> bool {
        let mut tail = text;
        for part in parts {
            let Some((_, rest)) = tail.split_once(part) else {
                return false;
            };
            tail = rest;
        }
        true
    }

    fn begin_parts() -> [&'static str; 24] {
        [
            "letmutattempt=RestoredAppBeginAttempt{",
            "attempt.parent.as_ref().expect(",
            ".policy.bootstrap.clone()",
            "context.affinity_data()",
            "captured.consumer_origin()?",
            "attempt.parent.take().expect(",
            "attempt.captured.take().expect(",
            "letmutcurrent=RestoredAppCurrentPeer{",
            "Rc::ptr_eq(&current.history,&current.captured.history)",
            "RestoredRequestGate::begin(",
            "current.captured.scope_settled=false",
            "context.require_origin(&current.origin)?",
            "context.require_affinity(&current.affinity)?",
            "context.require_runtime(current.runtime.as_ref())?",
            "let(binding,_purpose)=context.checked_binding(&mutstage,current.runtime.as_ref())?",
            "current.lineage.serving_binding(&binding)?",
            "current.counter=Some(slot.request(",
            "super::RestoredPeerConnection::from_app_history(",
            "connection.begin_app(&mutstage,request)?",
            "letphase=current.phase.as_mut()",
            "letwaited=phase.await_known(&mutstage);",
            "context?;",
            "current.lineage.read(&current.store,reads,&mutstage)?",
            "current.check_local()?",
        ]
    }

    fn actual_gate_binding(item: &syn::ImplItemFn) -> Vec<syn::ExprCall> {
        use syn::visit::Visit;
        struct Calls(Vec<syn::ExprCall>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(call.func.as_ref(),syn::Expr::Path(path) if path.path.to_token_stream().to_string()=="RestoredRequestGate :: begin")
                {
                    self.0.push(call.clone());
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(&item.block);
        calls.0
    }

    fn exact_gate_binding(call: &syn::ExprCall) -> bool {
        let args = call
            .args
            .iter()
            .map(|arg| {
                arg.to_token_stream()
                    .to_string()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        args == ["&current.state", "&current.captured.refusal.gate"]
    }

    fn actual_peer_factory(item: &syn::ImplItemFn) -> Vec<syn::ExprCall> {
        use syn::visit::Visit;
        struct Calls(Vec<syn::ExprCall>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(call.func.as_ref(),syn::Expr::Path(path) if path.path.to_token_stream().to_string()=="super :: RestoredPeerConnection :: from_app_history")
                {
                    self.0.push(call.clone());
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(&item.block);
        calls.0
    }

    fn exact_peer_factory(call: &syn::ExprCall) -> bool {
        let args = call
            .args
            .iter()
            .map(|arg| {
                arg.to_token_stream()
                    .to_string()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        args == ["&current.history", "&mutstage"]
    }

    fn method_calls(item: &syn::ImplItemFn, name: &str) -> Vec<syn::ExprMethodCall> {
        use syn::visit::Visit;
        struct Calls(Vec<syn::ExprMethodCall>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.0.push(call.clone());
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(&item.block);
        calls
            .0
            .into_iter()
            .filter(|call| call.method == name)
            .collect()
    }

    fn exact_counter(call: &syn::ExprMethodCall) -> bool {
        let compact = |value: &syn::Expr| {
            value
                .to_token_stream()
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        };
        call.method == "request"
            && call.turbofish.is_none()
            && compact(&call.receiver) == "slot"
            && call.args.iter().map(compact).collect::<Vec<_>>()
                == [
                    "&mutstage",
                    "&current.policy",
                    "&current.store",
                    "NativeRole::AppHost",
                ]
    }

    fn bounded_begin(text: &str) -> bool {
        ordered(text, &begin_parts())
            && ![
                "begin_current_request(",
                "NativeAcquisition::begin(",
                "clock.retire(",
                "finish_known(",
                "captured.request.take()",
                "captured.refusal.transfer()",
                "self.state.finish()",
            ]
            .iter()
            .any(|part| text.contains(part))
    }

    fn admission_posts() -> [&'static str; 15] {
        [
            "letfile=current.file.check_current(&mutstage);",
            "letanchors=current.anchors.check_anchors(&mutstage,&mutacquisition);",
            "letpeer=phase.check(&mutstage);",
            "letcounter=reads.check(&mutstage);",
            "letnative=stage.check();",
            ".check(&mutstage,current.runtime.as_ref());",
            "waited?;",
            "file?;",
            "anchors?;",
            "peer?;",
            "counter?;",
            "native?;",
            "context?;",
            "current.observed=Some(",
            "current.lineage.read(&current.store,reads,&mutstage)?",
        ]
    }

    fn known_before_observation(text: &str) -> bool {
        let Some((_, posts)) = text.split_once("letwaited=phase.await_known(&mutstage);") else {
            return false;
        };
        text.matches("await_known(").count() == 1 && ordered(posts, &admission_posts())
    }

    fn runtime_binding_first(item: &syn::ImplItemFn) -> bool {
        let Some(syn::Stmt::Expr(syn::Expr::If(first), _)) = item.block.stmts.first() else {
            return false;
        };
        let condition = first
            .cond
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        condition == "!std::ptr::eq(self.runtime.as_ref(),runtime)"
            && ordered(
                &tokens(item),
                &[
                    "self.refuse()",
                    "restore_current_runtime_changed",
                    "runtime.uses_native_storage()",
                    "self.check_local()",
                ],
            )
    }

    #[test]
    fn consumer_origin_is_only_the_actual_saved_original_negative_identity() {
        let native = method("EnrolledCurrentRequest", "consumer_origin")
            .block
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let required = [
            "NativeConsumerOrigin{",
            "refusal:self.acquisition.retained_refusal()",
            "domain:self.acquisition.historical_interval_observation().0",
        ];
        assert!(ordered(&native, &required));
        for part in required {
            assert!(!ordered(
                &native.replacen(part, "unrelated()", 1),
                &required
            ));
        }
        let captured = tokens(&method("CapturedRestoredAppRequest", "consumer_origin"));
        let required = [
            "letSome(request)=&self.requestelse",
            "self.refusal.refuse()",
            "self.history.refuse()",
            "restore_current_capture_missing",
            "Ok(request.consumer_origin())",
        ];
        assert!(ordered(&captured, &required));
        for part in required {
            assert!(!ordered(
                &captured.replacen(part, "unrelated()", 1),
                &required
            ));
        }
        let checked = tokens(&method("NativeConsumerOrigin", "check_current"));
        let required = [
            "stage.acquisition.as_mut().retained_refusal()",
            "stage.acquisition.as_mut().historical_interval_observation().0",
            "self.require_same(&actual)",
            "stage.purpose==StagePurpose::CurrentRole",
            "selected.is_err()||!current",
            "self.refuse()",
            "actual.refuse()",
            "selected?",
        ];
        assert!(ordered(&checked, &required));
        for part in required {
            assert!(!ordered(
                &checked.replacen(part, "unrelated()", 1),
                &required
            ));
        }
        let same = tokens(&method("NativeConsumerOrigin", "require_same"));
        assert!(ordered(
            &same,
            &[
                "self.domain!=other.domain",
                "self.refuse()",
                "other.refuse()",
                "self.refusal.require_same(&other.refusal)",
            ]
        ));
        for body in [native, captured, checked, same] {
            assert!(
                ![
                    ".sample(",
                    ".remaining(",
                    ".budget(",
                    "begin_current_request(",
                    "NativeAcquisition::begin("
                ]
                .iter()
                .any(|term| body.contains(term))
            );
        }
    }

    #[test]
    fn actual_runtime_identity_and_native_scope_cannot_be_replaced_by_matching_metadata() {
        let begin = tokens(&method("CapturedRestoredAppRequest", "begin_current"));
        let source = "runtime:&prepared.pending.runtime";
        assert_eq!(begin.matches(source).count(), 1);
        assert!(
            !begin
                .replacen(source, "runtime:&other.runtime", 1)
                .contains(source)
        );
        let actual = method("RestoredAppCurrentPeer", "require_runtime");
        assert!(runtime_binding_first(&actual));
        let mut late = actual.clone();
        late.block
            .stmts
            .insert(0, syn::parse_quote! {self.check_local()?;});
        assert!(!runtime_binding_first(&late));
        let mut metadata = actual.clone();
        let syn::Stmt::Expr(syn::Expr::If(first), _) = &mut metadata.block.stmts[0] else {
            panic!("pointer first");
        };
        *first.cond = syn::parse_quote!(self.runtime.app() != runtime.app());
        assert!(!runtime_binding_first(&metadata));
        let mut no_refusal = actual.clone();
        let syn::Stmt::Expr(syn::Expr::If(first), _) = &mut no_refusal.block.stmts[0] else {
            panic!("pointer first");
        };
        first.then_branch.stmts.remove(0);
        assert!(!runtime_binding_first(&no_refusal));
        let selected = tokens(&method("RestoredAppCurrentPeer", "check_selection"));
        let required = [
            "policy!=&self.policy||store!=&self.store||role!=NativeRole::AppHost",
            "self.refuse()",
            "restore_current_selection_changed",
            "self.captured.request.as_mut()",
            "self.owner.borrow_current_request(request)?",
            "stage.require_selection_data(policy,store,role)",
            "letchecked=self.check_local()",
            "requested.is_err()||checked.is_err()",
            "self.refuse()",
            "requested?",
            "checked}",
        ];
        assert!(ordered(&selected, &required));
        for part in required
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
        {
            assert_eq!(
                selected.matches(part).count(),
                required.iter().filter(|value| **value == part).count(),
                "{part}"
            );
            for (index, _) in selected.match_indices(part) {
                let changed = format!(
                    "{}unrelated(){}",
                    &selected[..index],
                    &selected[index + part.len()..]
                );
                assert!(!ordered(&changed, &required), "{part}");
            }
        }
        for wider in [
            "policy.scope!=self.policy.scope||role!=NativeRole::AppHost",
            "policy!=&self.policy||role!=NativeRole::AppHost",
            "store!=&self.store||role!=NativeRole::AppHost",
        ] {
            assert!(!ordered(
                &selected.replacen(required[0], wider, 1),
                &required
            ));
        }
        for extra in [
            "stage.check_selection(policy,store,role)",
            "stage.check_for(&policy.scope,role)",
            "stage.check()",
        ] {
            assert!(
                !selected.contains(extra),
                "no redundant adjacent stage guard: {extra}"
            );
        }
        for body in [tokens(&actual), selected] {
            assert!(
                ![
                    ".reobserve(",
                    ".lineage.read(",
                    "begin_current_request(",
                    "NativeAcquisition::begin("
                ]
                .iter()
                .any(|term| body.contains(term))
            );
        }
    }

    #[test]
    fn actual_app_scope_joins_one_real_counter_before_wire_and_reads_lineage_after_peer() {
        let actual_method = method("CapturedRestoredAppRequest", "begin_current");
        let binds = actual_gate_binding(&actual_method);
        assert_eq!(binds.len(), 1);
        assert!(exact_gate_binding(&binds[0]));
        for omitted in 0..binds[0].args.len() {
            let mut changed = binds[0].clone();
            changed.args = changed
                .args
                .into_iter()
                .enumerate()
                .filter_map(|(i, arg)| (i != omitted).then_some(arg))
                .collect();
            assert!(!exact_gate_binding(&changed));
        }
        let mut foreign = binds[0].clone();
        foreign.args[0] = syn::parse_quote!(&other.state);
        assert!(!exact_gate_binding(&foreign));
        let peers = actual_peer_factory(&actual_method);
        assert_eq!(peers.len(), 1);
        assert!(exact_peer_factory(&peers[0]));
        for omitted in 0..peers[0].args.len() {
            let mut changed = peers[0].clone();
            changed.args = changed
                .args
                .into_iter()
                .enumerate()
                .filter_map(|(index, arg)| (index != omitted).then_some(arg))
                .collect();
            assert!(!exact_peer_factory(&changed));
        }
        let mut foreign_history = peers[0].clone();
        foreign_history.args[0] = syn::parse_quote!(&foreign_history);
        assert!(!exact_peer_factory(&foreign_history));
        let mut foreign_stage = peers[0].clone();
        foreign_stage.args[1] = syn::parse_quote!(&mut foreign_stage);
        assert!(!exact_peer_factory(&foreign_stage));
        let calls = method_calls(&actual_method, "request");
        assert_eq!(calls.len(), 1);
        assert!(exact_counter(&calls[0]));
        for omitted in 0..calls[0].args.len() {
            let mut changed = calls[0].clone();
            changed.args = changed
                .args
                .into_iter()
                .enumerate()
                .filter_map(|(index, arg)| (index != omitted).then_some(arg))
                .collect();
            assert!(!exact_counter(&changed));
        }
        let mut wrong = calls[0].clone();
        wrong.args[2] = syn::parse_quote!(&other.store);
        assert!(!exact_counter(&wrong));
        let mut foreign = calls[0].clone();
        *foreign.receiver = syn::parse_quote!(other_slot);
        assert!(!exact_counter(&foreign));
        let actual = tokens(&actual_method);
        assert!(bounded_begin(&actual));
        assert!(known_before_observation(&actual));
        for part in begin_parts() {
            assert_eq!(actual.matches(part).count(), 1, "{part}");
            assert!(
                !bounded_begin(&actual.replacen(part, "unrelated()", 1)),
                "{part}"
            );
        }
        let counter = "current.counter=Some(slot.request(";
        let reordered = actual.replacen(counter, "", 1).replacen(
            "connection.begin_app(&mutstage,request)?",
            &format!("connection.begin_app(&mutstage,request)?;{counter}"),
            1,
        );
        assert!(!bounded_begin(&reordered));
        let waits = method_calls(&actual_method, "await_known");
        assert_eq!(waits.len(), 1);
        let exact_wait = |call: &syn::ExprMethodCall| {
            call.method == "await_known"
                && call.turbofish.is_none()
                && call.receiver.to_token_stream().to_string() == "phase"
                && call.args.len() == 1
                && call.args[0].to_token_stream().to_string() == "& mut stage"
        };
        assert!(exact_wait(&waits[0]));
        let mut foreign = waits[0].clone();
        *foreign.receiver = syn::parse_quote!(foreign_phase);
        assert!(!exact_wait(&foreign));
        let mut foreign = waits[0].clone();
        foreign.args[0] = syn::parse_quote!(&mut foreign_stage);
        assert!(!exact_wait(&foreign));
        let mut omitted = waits[0].clone();
        omitted.args.clear();
        assert!(!exact_wait(&omitted));
        let wait = "letwaited=phase.await_known(&mutstage);";
        assert!(!known_before_observation(&actual.replacen(wait, "", 1)));
        let late = actual.replacen(wait, "", 1).replacen(
            "current.check_local()?",
            &format!("{wait}current.check_local()?"),
            1,
        );
        assert!(!known_before_observation(&late));
        let (before, posts) = actual.split_once(wait).unwrap();
        for part in admission_posts() {
            let omitted = format!("{before}{wait}{}", posts.replacen(part, "unrelated()", 1));
            assert!(!known_before_observation(&omitted), "{part}");
        }
        let premature = format!(
            "{before}{wait}waited?;{}",
            posts.replacen("waited?;", "", 1)
        );
        assert!(!known_before_observation(&premature));
        let local = tokens(&method("RestoredAppCurrentPeer", "check_local"));
        let checks = [
            "self.owner.borrow_current_request(request)?",
            "letfile=self.file.check_current(&mutstage)",
            "letanchors=self.anchors.check_anchors(&mutstage,&mutacquisition)",
            ".check(&mutstage)",
            "self.lineage.check(&self.store,reads,&mutstage,observed)",
            "letcounter=reads.check(&mutstage)",
            "letnative=stage.check()",
            ".check(&mutstage,self.runtime.as_ref())",
            "file?",
            "anchors?",
            "peer?",
            "lineage?",
            "counter?",
            "native?",
            "context",
        ];
        assert!(ordered(&local, &checks));
        for part in [&checks[1], &checks[2], &checks[4], &checks[5], &checks[6]] {
            assert!(!ordered(&local.replacen(part, "unrelated()", 1), &checks));
        }
    }

    #[test]
    fn owned_capture_and_both_constructor_roots_remain_negative_until_the_real_scope_exists() {
        let capture = tokens(&method("RetiredRestoredAppNative", "capture_request"));
        let required = [
            "RestoredCaptureRefusal::new(&self.request_state)",
            "captured.refusal.gate.capture()?",
            "pending.owner.begin_current_request()?",
            "require_retired_predecessor(",
            "pending.owner.borrow_current_request(fresh)?.check()?",
            "Ok(captured)",
        ];
        assert!(ordered(&capture, &required));
        for part in required {
            assert!(!ordered(
                &capture.replacen(part, "unrelated()", 1),
                &required
            ));
        }
        let first = tokens(&method("RestoredAppBeginAttempt", "drop"));
        assert!(ordered(
            &first,
            &[
                "ifletSome(parent)=&mutself.parent",
                "parent.request_state.refuse()",
                "parent.installed.prepared.pending.refuse()"
            ]
        ));
        let drop = tokens(&method("CapturedRestoredAppRequest", "drop"));
        assert!(ordered(
            &drop,
            &[
                "ifself.refusal.armed",
                "self.refusal.refuse()",
                "self.history.refuse()",
                "request.refuse()"
            ]
        ));
        let transfer = tokens(&method("RestoredCaptureRefusal", "transfer"));
        assert!(transfer.contains("self.armed=false"));
        let file = syn::parse_file(include_str!("owner.rs")).unwrap();
        let captured = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(value) if value.ident == "CapturedRestoredAppRequest" => {
                    Some(value)
                }
                _ => None,
            })
            .unwrap();
        assert!(captured.generics.params.is_empty());
        let expected: [(&str, syn::Type); 4] = [
            ("refusal", syn::parse_quote!(RestoredCaptureRefusal)),
            (
                "history",
                syn::parse_quote!(Rc<super::restored::RestoredAppHistory>),
            ),
            ("request", syn::parse_quote!(Option<EnrolledCurrentRequest>)),
            ("scope_settled", syn::parse_quote!(bool)),
        ];
        assert_eq!(captured.fields.len(), expected.len());
        for (field, (name, ty)) in captured.fields.iter().zip(expected) {
            assert!(matches!(field.vis, syn::Visibility::Inherited));
            assert_eq!(field.ident.as_ref().unwrap(), name);
            assert_eq!(
                field.ty.to_token_stream().to_string(),
                ty.to_token_stream().to_string()
            );
        }
    }

    #[test]
    fn actual_reobserve_cannot_repair_an_old_observation_or_rearm_before_known_final_posts() {
        let actual = tokens(&method("RestoredAppCurrentPeer", "reobserve"));
        let required = [
            "self.check_local()?",
            "self.owner.borrow_current_request(actual)?",
            "self.lineage.read(&self.store,reads,&mutstage)?",
            "letchecked=self.check_local()",
            "requested?",
            "checked",
        ];
        assert!(ordered(&actual, &required));
        for part in required {
            assert!(!ordered(
                &actual.replacen(part, "unrelated()", 1),
                &required
            ));
        }
        let finish = tokens(&method("RestoredAppCurrentPeer", "finish"));
        let required = [
            "self.check_local()?",
            "phase.acknowledge_known(&mutstage)?",
            "self.check_local()?",
            ".await_release(&mutstage)?",
            "self.check_local()?",
            ".finish(&mutstage)?",
            "phase.finish_restored(&mutstage)?",
            "letfile=self.file.check_current(&mutstage)",
            "letnative=stage.check()",
            ".check_final(&mutstage,self.runtime.as_ref())",
            "file?",
            "native?",
            "context?",
            "*self.returned=Some(connection)",
            "letcontext=self.context.take()",
            "context.complete_scope(NativeConsumerCompletion{",
            "scope:self",
            "context_checked:false",
        ];
        let after_admission = |body: &str| {
            ![
                "await_known(",
                "request.take()",
                "self.state.finish()",
                "self.done=true",
            ]
            .iter()
            .any(|term| body.contains(term))
                && ordered(body, &required)
        };
        assert!(after_admission(&finish));
        for part in [
            "phase.acknowledge_known(&mutstage)?",
            ".await_release(&mutstage)?",
            ".finish(&mutstage)?",
            "phase.finish_restored(&mutstage)?",
            "letfile=self.file.check_current(&mutstage)",
            "letnative=stage.check()",
            ".check_final(&mutstage,self.runtime.as_ref())",
            "context.complete_scope(NativeConsumerCompletion{",
            "scope:self",
            "context_checked:false",
        ] {
            assert!(
                !after_admission(&finish.replacen(part, "unrelated()", 1)),
                "{part}"
            );
        }
        let repeated_wait = finish.replacen(
            "phase.acknowledge_known(&mutstage)?",
            "phase.await_known(&mutstage)?;phase.acknowledge_known(&mutstage)?",
            1,
        );
        assert!(!after_admission(&repeated_wait));
        let refusal = tokens(&method("RestoredAppCurrentPeer", "refuse"));
        for part in [
            "self.state.refuse()",
            "self.owner.refused=true",
            "self.history.refuse()",
            "self.retired.refuse()",
            "self.captured.refuse()",
            "context.refuse()",
            "counter.refuse()",
            "phase.refuse()",
        ] {
            assert!(refusal.contains(part), "{part}");
        }
        let drop = tokens(&method("RestoredAppCurrentPeer", "drop"));
        assert!(drop.contains("if!self.done{self.refuse();}"));
    }
    fn body_tokens(owner: &str, name: &str) -> String {
        method(owner, name)
            .block
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    fn required_with_deletion_controls(text: &str, required: &[&str]) {
        assert!(
            ordered(text, required),
            "actual source does not satisfy ordered boundary"
        );
        for part in required {
            assert_eq!(text.matches(part).count(), 1, "ambiguous mutation: {part}");
            assert!(
                !ordered(&text.replacen(part, "unrelated()", 1), required),
                "missing {part}"
            );
        }
    }

    #[test]
    fn runtime_view_rejects_human_or_other_purpose_before_any_native_observation() {
        let actual = method("RestoredAppCurrentPeer", "require_runtime_purpose");
        let Some(syn::Stmt::Expr(syn::Expr::If(first), _)) = actual.block.stmts.first() else {
            panic!("actual pointer first");
        };
        let condition = first
            .cond
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        assert_eq!(condition, "!std::ptr::eq(self.runtime.as_ref(),runtime)");
        let body = body_tokens("RestoredAppCurrentPeer", "require_runtime_purpose");
        required_with_deletion_controls(
            &body,
            &[
                "!std::ptr::eq(self.runtime.as_ref(),runtime)",
                "restore_current_runtime_changed",
                ".require_runtime_purpose(runtime,purpose)?",
                "self.require_runtime(runtime)",
                "ifrequested.is_err()",
                "requested}",
            ],
        );
        let selected = ".require_runtime_purpose(runtime,purpose)?";
        let native = "self.require_runtime(runtime)";
        let late =
            body.replacen(selected, "", 1)
                .replacen(native, &format!("{native};{selected}"), 1);
        assert!(!ordered(&late, &[selected, native]));
        for forbidden in [
            "borrow_current_request(",
            "begin_current_request(",
            ".sample(",
            ".check_local(",
        ] {
            assert!(!body.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn response_view_requires_the_actual_http_context_before_any_native_observation() {
        let actual = method("RestoredAppCurrentPeer", "require_response");
        let Some(syn::Stmt::Expr(syn::Expr::If(first), _)) = actual.block.stmts.first() else {
            panic!("actual pointer first");
        };
        let condition = first
            .cond
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        assert_eq!(condition, "!std::ptr::eq(self.runtime.as_ref(),runtime)");
        let body = body_tokens("RestoredAppCurrentPeer", "require_response");
        required_with_deletion_controls(
            &body,
            &[
                "!std::ptr::eq(self.runtime.as_ref(),runtime)",
                "restore_current_runtime_changed",
                ".require_response(runtime)?",
                "self.require_runtime(runtime)",
                "ifrequested.is_err()",
                "requested}",
            ],
        );
        let selected = ".require_response(runtime)?";
        let native = "self.require_runtime(runtime)";
        let late =
            body.replacen(selected, "", 1)
                .replacen(native, &format!("{native};{selected}"), 1);
        assert!(!ordered(&late, &[selected, native]));
        for forbidden in [
            "borrow_current_request(",
            "begin_current_request(",
            ".sample(",
            ".check_local(",
        ] {
            assert!(!body.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn host_setup_retains_the_genuine_capture_before_configuration_and_has_no_parts_escape() {
        let capture = body_tokens("RetiredRestoredAppNative", "prepare_host_native");
        required_with_deletion_controls(
            &capture,
            &[
                "letmutsetup=RestoredAppHostSetupNative{",
                "parent:Some(self)",
                "captured:None",
                "setup.parent.as_mut()",
                "setup.captured=Some(parent.capture_request()?)",
                "Ok(setup)",
            ],
        );
        for forbidden in [
            "Arc::clone(",
            ".runtime.clone(",
            "Arc::make_mut(",
            "begin_current_stage(",
            "NativeAcquisition::begin(",
            "inputs.configure(",
        ] {
            assert!(!capture.contains(forbidden), "{forbidden}");
        }
        let checked = body_tokens("RestoredAppHostSetupNative", "check_native");
        required_with_deletion_controls(
            &checked,
            &[
                "self.parent.as_mut()",
                "self.captured.as_mut()",
                "letmutattempt=RestoredHumanClockAttempt{",
                "attempt.check_posts()?",
                "attempt.completed=true",
                "ifrequested.is_err()",
                "self.refuse()",
                "requested}",
            ],
        );
        let refusal = body_tokens("RestoredAppHostSetupNative", "refuse");
        required_with_deletion_controls(
            &refusal,
            &[
                "ifletSome(parent)=&mutself.parent",
                "parent.request_state.refuse()",
                "parent.installed.prepared.pending.refuse()",
                "ifletSome(captured)=&mutself.captured",
                "captured.refuse()",
            ],
        );
        let drop = body_tokens("RestoredAppHostSetupNative", "drop");
        assert_eq!(drop, "{self.refuse();}");
        let file = syn::parse_file(include_str!("owner.rs")).unwrap();
        let value = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == "RestoredAppHostSetupNative" => Some(item),
                _ => None,
            })
            .unwrap();
        assert_eq!(value.fields.len(), 2);
        assert!(
            value
                .fields
                .iter()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        );
        let methods=file.items.iter().filter_map(|item|match item {syn::Item::Impl(item) if matches!(item.self_ty.as_ref(),syn::Type::Path(path) if path.path.is_ident("RestoredAppHostSetupNative"))=>Some(item),_=>None}).flat_map(|item|item.items.iter()).filter_map(|item|match item {syn::ImplItem::Fn(item)=>Some(item.sig.ident.to_string()),_=>None}).collect::<Vec<_>>();
        assert_eq!(methods, ["refuse", "install", "check_native", "drop"]);
    }

    #[test]
    fn fixed_host_configuration_preserves_original_runtime_and_independent_posts_before_transfer() {
        let entry = body_tokens("RetiredRestoredAppNative", "install_host");
        assert_eq!(entry, "{self.prepare_host_native()?.install(inputs)}");
        let body = body_tokens("RestoredAppHostSetupNative", "install");
        required_with_deletion_controls(
            &body,
            &[
                "self.check_native()?;",
                "letexpected=std::sync::Arc::as_ptr(",
                "letrequested=inputs.configure(",
                "letactual=std::sync::Arc::as_ptr(",
                "letidentity=ifstd::ptr::eq(expected,actual)",
                "restore_host_setup_runtime_replaced",
                "letchecked=self.check_native();",
                "requested.is_err()||identity.is_err()||checked.is_err()",
                "self.refuse()",
                "letconfigured=requested?;",
                "identity?;",
                "checked?;",
                "letruntime=std::sync::Arc::clone(",
                "letparent=self.parent.take()",
                "letcaptured=self.captured.take()",
                "RestoredAppServingOwner::from_native(parent)",
                "CapturedRestoredServingRequest::from_native(captured)",
                "configured.install(runtime,owner,captured)",
            ],
        );
        let configured = "letrequested=inputs.configure(";
        let posts = "letchecked=self.check_native();";
        let premature =
            body.replacen(posts, "", 1)
                .replacen(configured, &format!("{posts}{configured}"), 1);
        assert!(!ordered(&premature, &[configured, posts]));
        for forbidden in [
            "capture_request(",
            "begin_current_stage(",
            "begin_current_request(",
            "NativeAcquisition::begin(",
            "Arc::make_mut(",
            "Arc::downgrade(",
            ".run(",
        ] {
            assert!(!body.contains(forbidden), "{forbidden}");
        }
        let item = method("RestoredAppHostSetupNative", "install");
        let calls = method_calls(&item, "configure");
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.receiver.to_token_stream().to_string(), "inputs");
        let exact = |call: &syn::ExprMethodCall| {
            call.args.len() == 1
                && call.args[0]
                    .to_token_stream()
                    .to_string()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
                    == "&mutself.parent.as_mut().expect(\"actualnativesetupparent\").installed.prepared.pending.runtime"
        };
        assert!(exact(call));
        let mut replaced = call.clone();
        replaced.args[0] = syn::parse_quote!(&mut other.runtime);
        assert!(!exact(&replaced));
        let mut absent = call.clone();
        absent.args.clear();
        assert!(!exact(&absent));
    }

    #[test]
    fn borrowed_scope_completion_retains_the_native_request_and_its_actual_context() {
        let begin = body_tokens("CapturedRestoredAppRequest", "begin_current");
        for forbidden in [
            "request.take()",
            "refusal.transfer()",
            ".finish(self.owner)",
            "begin_current_request(",
        ] {
            assert!(!begin.contains(forbidden), "{forbidden}");
        }
        let finish = body_tokens("RestoredAppCurrentPeer", "finish");
        for forbidden in [
            "request.take()",
            "refusal.transfer()",
            "self.state.finish()",
            "self.done=true",
        ] {
            assert!(!finish.contains(forbidden), "{forbidden}");
        }
        let joined = body_tokens("NativeConsumerCompletion", "check_context");
        required_with_deletion_controls(
            &joined,
            &[
                "letorigin=context.require_origin(&self.scope.origin);",
                "letaffinity=context.require_affinity(&self.scope.affinity);",
                "self.context_checked||origin.is_err()||affinity.is_err()",
                "self.scope.refuse()",
                "context.refuse()",
                "ensure!(!self.context_checked,",
                "origin?;",
                "affinity?;",
                "self.context_checked=true",
            ],
        );
        let settled = body_tokens("NativeConsumerCompletion", "complete_native");
        required_with_deletion_controls(
            &settled,
            &[
                "ensure!(self.context_checked,",
                "!self.scope.owner.refused&&self.scope.captured.refusal.armed",
                "self.scope.captured.consumer_origin()?",
                "self.scope.origin.require_same(&actual)?",
                "self.scope.state.finish_scope()?",
                "self.scope.captured.scope_settled=true",
                "self.scope.done=true",
            ],
        );
        assert!(!settled.contains("request.take()"));
        let gate = body_tokens("RestoredRequestGate", "finish_scope");
        required_with_deletion_controls(
            &gate,
            &[
                "self.require_busy()?",
                "self.state.set(RestoredRequestState::Captured)",
            ],
        );
        assert!(!gate.contains("Vacant"));
    }

    #[test]
    fn only_the_distinct_final_context_consumes_the_saved_request_after_final_posts() {
        let finish = body_tokens("CapturedRestoredAppRequest", "finish");
        required_with_deletion_controls(
            &finish,
            &[
                "letmutattempt=RestoredRequestFinishAttempt{",
                "context.affinity_data()",
                "captured.consumer_origin()?",
                "ensure!(captured.scope_settled,",
                "Rc::ptr_eq(&captured.history,&attempt.parent.installed.prepared.pending.history)",
                "RestoredRequestGate::begin(&attempt.parent.request_state,&captured.refusal.gate)?",
                "context.require_origin(",
                "context.require_affinity(",
                "context.require_runtime(prepared.pending.runtime.as_ref())?",
                "prepared.pending.owner.borrow_current_request(request)?",
                "letfile=prepared.file.check_current(&mutstage);",
                "letanchors=prepared.peer.check_anchors(&mutstage,&mutacquisition);",
                "letnative=stage.check();",
                "letoriginal=context.check_final(&mutstage,prepared.pending.runtime.as_ref());",
                "file?;",
                "anchors?;",
                "native?;",
                "original?;",
                ".request.take()",
                ".finish(&mutattempt.parent.installed.prepared.pending.owner)?",
                "letcontext=attempt.context.take()",
                "context.complete_after_native(RestoredAppRequestSettlement{",
                "attempt,",
                "context_checked:false",
            ],
        );
        let (_, after) = finish
            .split_once(".finish(&mutattempt.parent.installed.prepared.pending.owner)?")
            .unwrap();
        for forbidden in [
            ".check_final(",
            ".sample(",
            "borrow_current_request(",
            "begin_current_request(",
        ] {
            assert!(
                !after.contains(forbidden),
                "post-native original work: {forbidden}"
            );
        }
        let joined = body_tokens("RestoredAppRequestSettlement", "check_context");
        required_with_deletion_controls(
            &joined,
            &[
                "letorigin=context.require_origin(",
                "letaffinity=context.require_affinity(",
                "self.context_checked||origin.is_err()||affinity.is_err()",
                "context.refuse()",
                "self.attempt.parent.request_state.refuse()",
                "self.attempt.parent.installed.prepared.pending.refuse()",
                "ensure!(!self.context_checked,",
                "origin?;",
                "affinity?;",
                "self.context_checked=true",
            ],
        );
        let settled = body_tokens("RestoredAppRequestSettlement", "complete_native");
        required_with_deletion_controls(
            &settled,
            &[
                "ensure!(self.context_checked,",
                "!self.attempt.parent.installed.prepared.pending.owner.refused",
                "captured.refusal.armed&&captured.request.is_none()",
                "original.require_same(original)?",
                "self.attempt.parent.request_state.finish()?",
                "captured.refusal.transfer()",
                "self.attempt.completed=true",
            ],
        );
        for forbidden in [
            ".check_final(",
            ".sample(",
            "borrow_current_request(",
            "begin_current_request(",
        ] {
            assert!(
                !joined.contains(forbidden) && !settled.contains(forbidden),
                "{forbidden}"
            );
        }
        for (owner, captured, context) in [
            ("RestoredAppBeginAttempt", "captured.refuse()", ""),
            (
                "RestoredRequestFinishAttempt",
                "captured.refuse()",
                "context.refuse()",
            ),
        ] {
            let drop = body_tokens(owner, "drop");
            assert!(drop.contains("pending.refuse()"));
            assert!(drop.contains(captured));
            if !context.is_empty() {
                assert!(drop.contains(context));
            }
        }
    }

    #[test]
    fn restored_human_clock_uses_the_saved_request_and_keeps_both_roots_armed() {
        let capture = body_tokens("CapturedRestoredAppRequest", "capture_human_clock");
        required_with_deletion_controls(
            &capture,
            &[
                "letmutattempt=RestoredHumanClockAttempt{",
                "letorigin=boottime()?;",
                "attempt.require_parent()?",
                "attempt.captured.request.as_mut()",
                "attempt.parent.installed.prepared.pending.owner.borrow_current_request(request)?",
                "EnrolledOriginalClock::capture_at(&mutstage,origin,NativeRole::AppHost)",
                "letchecked=attempt.check_posts();",
                "letclock=requested?;",
                "checked?;",
                "attempt.completed=true",
            ],
        );
        let sampled = body_tokens("CapturedRestoredAppRequest", "sample_human_clock");
        required_with_deletion_controls(
            &sampled,
            &[
                "letmutattempt=RestoredHumanClockAttempt{",
                "attempt.require_parent()?",
                "attempt.captured.request.as_mut()",
                "attempt.parent.installed.prepared.pending.owner.borrow_current_request(request)?",
                "clock.sample(&mutstage)",
                "letchecked=attempt.check_posts();",
                "letnow=requested?;",
                "checked?;",
                "attempt.completed=true",
            ],
        );
        for body in [&capture, &sampled] {
            for forbidden in [
                "begin_current_stage(",
                "begin_current_request(",
                "NativeAcquisition::begin(",
                ".retire(",
            ] {
                assert!(!body.contains(forbidden), "{forbidden}");
            }
        }
        let posts = body_tokens("RestoredHumanClockAttempt", "check_posts");
        required_with_deletion_controls(
            &posts,
            &[
                "self.require_parent()?",
                "self.captured.request.as_mut()",
                "prepared.pending.owner.borrow_current_request(request)?",
                "letfile=prepared.file.check_current(&mutstage);",
                "letanchors=prepared.peer.check_anchors(&mutstage,&mutacquisition);",
                "letnative=stage.check();",
                "file?;",
                "anchors?;",
                "native}",
            ],
        );
        let cold = body_tokens("EnrolledProcessRoleOwner", "capture_original_clock");
        assert!(cold.starts_with("{letorigin=boottime()"));
        let canonical = body_tokens("EnrolledOriginalClock", "capture_at");
        required_with_deletion_controls(
            &canonical,
            &[
                "stage.require_purpose(StagePurpose::CurrentRole)?",
                "stage.owner.role==expected",
                "ClockAnchors::capture(stage)?",
                "clock.sample(stage)?",
                "letchecked=stage.check();",
                "requested.is_err()||checked.is_err()",
                "stage.owner.refused=true",
                "stage.acquisition.as_mut().refuse()",
                "letclock=requested?;",
                "checked?;",
            ],
        );
        assert_eq!(
            cold.matches("EnrolledOriginalClock::capture_at(").count(),
            1
        );
        let actual = method("RestoredHumanClockAttempt", "require_parent");
        use syn::visit::Visit;
        struct Joins(Vec<syn::ExprCall>);
        impl<'ast> Visit<'ast> for Joins {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(call.func.as_ref(),syn::Expr::Path(path) if path.path.to_token_stream().to_string()=="Rc :: ptr_eq")
                {
                    self.0.push(call.clone());
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut joins = Joins(Vec::new());
        joins.visit_block(&actual.block);
        let compact = |arg: &syn::Expr| {
            arg.to_token_stream()
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        };
        let expected = [
            ["&self.parent.request_state", "&self.captured.refusal.gate"],
            [
                "&self.parent.installed.prepared.pending.history",
                "&self.captured.history",
            ],
        ];
        assert_eq!(joins.0.len(), expected.len());
        for (join, expected) in joins.0.iter().zip(expected) {
            let exact = |call: &syn::ExprCall| {
                call.args.iter().map(compact).collect::<Vec<_>>() == expected
            };
            assert!(exact(join));
            for omitted in 0..join.args.len() {
                let mut missing = join.clone();
                missing.args = missing
                    .args
                    .into_iter()
                    .enumerate()
                    .filter_map(|(i, arg)| (i != omitted).then_some(arg))
                    .collect();
                assert!(!exact(&missing));
                let mut foreign = join.clone();
                foreign.args[omitted] = syn::parse_quote!(&other.history);
                assert!(!exact(&foreign));
            }
        }
        let parent = body_tokens("RestoredHumanClockAttempt", "require_parent");
        required_with_deletion_controls(
            &parent,
            &[
                "self.parent.request_state.state.get()==RestoredRequestState::Captured",
                "if!same",
                "self.captured.refuse()",
                "self.parent.request_state.refuse()",
                "self.parent.installed.prepared.pending.refuse()",
            ],
        );
        let drop = body_tokens("RestoredHumanClockAttempt", "drop");
        required_with_deletion_controls(
            &drop,
            &[
                "if!self.completed",
                "self.captured.refuse()",
                "self.parent.request_state.refuse()",
                "self.parent.installed.prepared.pending.refuse()",
            ],
        );
    }
}

#[cfg(test)]
mod restored_owned_capture_gate_tests {
    use super::{RestoredCaptureRefusal, RestoredRequestGate, RestoredRequestState};
    use std::rc::Rc;

    // Only the production incarnation/loss latch is instantiated below. These
    // are NOT enrolled owners, requests, histories, peers or native completion.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Expected {
        Free,
        Waiting,
        Running,
        Dead,
    }

    fn actual(gate: &RestoredRequestGate) -> Expected {
        match gate.state.get() {
            RestoredRequestState::Vacant => Expected::Free,
            RestoredRequestState::Captured => Expected::Waiting,
            RestoredRequestState::Busy => Expected::Running,
            RestoredRequestState::Refused => Expected::Dead,
        }
    }

    #[test]
    fn actual_capture_identity_survives_owner_move_and_rejects_an_equal_but_foreign_gate() {
        let parent = Rc::new(RestoredRequestGate::new());
        let mut capture = RestoredCaptureRefusal::new(&parent);
        parent.capture().unwrap();
        // Moving an owned parent/container does not copy its incarnation.
        let moved = Box::new(parent);
        RestoredRequestGate::begin(&moved, &capture.gate).unwrap();
        let mut active = RestoredCaptureRefusal::new(&moved);
        capture.transfer();
        drop(capture);
        assert_eq!(actual(&moved), Expected::Running);
        moved.finish().unwrap();
        active.transfer();
        drop(active);
        assert_eq!(actual(&moved), Expected::Free);

        let parent = Rc::new(RestoredRequestGate::new());
        let foreign = Rc::new(RestoredRequestGate::new());
        let capture = RestoredCaptureRefusal::new(&parent);
        parent.capture().unwrap();
        foreign.capture().unwrap();
        assert!(RestoredRequestGate::begin(&foreign, &capture.gate).is_err());
        assert_eq!(actual(&parent), Expected::Dead);
        assert_eq!(actual(&foreign), Expected::Dead);
        assert!(parent.capture().is_err());
        assert!(foreign.finish().is_err());
    }

    #[test]
    fn actual_capture_loss_and_constructor_unwind_never_rearm_a_moved_parent() {
        for after_begin in [false, true] {
            for unwind in [false, true] {
                let parent = Rc::new(RestoredRequestGate::new());
                let capture = RestoredCaptureRefusal::new(&parent);
                parent.capture().unwrap();
                let moved = Box::new(parent);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _actual = capture;
                    if after_begin {
                        RestoredRequestGate::begin(&moved, &_actual.gate).unwrap();
                    }
                    if unwind {
                        panic!("controlled capture construction loss");
                    }
                    Err::<(), _>("controlled refusal")
                }));
                assert_eq!(result.is_err(), unwind);
                assert_eq!(actual(&moved), Expected::Dead);
                assert!(moved.capture().is_err());
                assert!(moved.finish().is_err());
            }
        }
        let parent = Rc::new(RestoredRequestGate::new());
        let capture = RestoredCaptureRefusal::new(&parent);
        parent.capture().unwrap();
        RestoredRequestGate::begin(&parent, &capture.gate).unwrap();
        assert!(RestoredRequestGate::begin(&parent, &capture.gate).is_err());
        assert_eq!(actual(&parent), Expected::Dead);
        assert!(parent.finish().is_err());
    }

    #[test]
    fn intermediate_scopes_keep_one_capture_reserved_until_the_final_request_settles() {
        let parent = Rc::new(RestoredRequestGate::new());
        let mut captured = RestoredCaptureRefusal::new(&parent);
        parent.capture().unwrap();
        for _ in 0..4 {
            RestoredRequestGate::begin(&parent, &captured.gate).unwrap();
            assert_eq!(actual(&parent), Expected::Running);
            parent.finish_scope().unwrap();
            assert_eq!(actual(&parent), Expected::Waiting);
            assert!(captured.armed);
        }
        RestoredRequestGate::begin(&parent, &captured.gate).unwrap();
        parent.finish().unwrap();
        captured.transfer();
        drop(captured);
        assert_eq!(actual(&parent), Expected::Free);
        parent.capture().unwrap();

        let parent = Rc::new(RestoredRequestGate::new());
        let captured = RestoredCaptureRefusal::new(&parent);
        parent.capture().unwrap();
        RestoredRequestGate::begin(&parent, &captured.gate).unwrap();
        parent.finish_scope().unwrap();
        // A second capture is never a renewal between storage units.
        assert!(parent.capture().is_err());
        assert_eq!(actual(&parent), Expected::Dead);
        assert!(RestoredRequestGate::begin(&parent, &captured.gate).is_err());
        assert!(parent.finish().is_err());

        let parent = Rc::new(RestoredRequestGate::new());
        let captured = RestoredCaptureRefusal::new(&parent);
        parent.capture().unwrap();
        RestoredRequestGate::begin(&parent, &captured.gate).unwrap();
        parent.finish_scope().unwrap();
        drop(captured);
        assert_eq!(actual(&parent), Expected::Dead);
        assert!(parent.capture().is_err());
        assert!(parent.finish_scope().is_err());
        assert!(parent.finish().is_err());
    }

    #[test]
    fn generated_gate_histories_match_an_independent_move_capture_and_refusal_model() {
        for seed in 1u64..=64 {
            let mut random = seed;
            let mut gates = [
                Rc::new(RestoredRequestGate::new()),
                Rc::new(RestoredRequestGate::new()),
            ];
            let mut expected = [Expected::Free; 2];
            for step in 0..64 {
                random = random
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let selected = (random as usize >> 4) & 1;
                let other = selected ^ 1;
                match (random >> 32) % 7 {
                    0 => {
                        let ok = expected[selected] == Expected::Free;
                        assert_eq!(gates[selected].capture().is_ok(), ok);
                        expected[selected] = if ok {
                            Expected::Waiting
                        } else {
                            Expected::Dead
                        };
                    }
                    1 => {
                        let ok = expected[selected] == Expected::Waiting;
                        assert_eq!(
                            RestoredRequestGate::begin(&gates[selected], &gates[selected]).is_ok(),
                            ok
                        );
                        expected[selected] = if ok {
                            Expected::Running
                        } else {
                            Expected::Dead
                        };
                    }
                    2 => {
                        assert!(
                            RestoredRequestGate::begin(&gates[selected], &gates[other]).is_err()
                        );
                        expected = [Expected::Dead; 2];
                    }
                    3 => {
                        let ok = expected[selected] == Expected::Running;
                        assert_eq!(gates[selected].finish().is_ok(), ok);
                        expected[selected] = if ok { Expected::Free } else { Expected::Dead };
                    }
                    4 => {
                        let ok = expected[selected] == Expected::Running;
                        assert_eq!(gates[selected].finish_scope().is_ok(), ok);
                        expected[selected] = if ok {
                            Expected::Waiting
                        } else {
                            Expected::Dead
                        };
                    }
                    5 => {
                        let moved = Box::new(gates[selected].clone());
                        gates[selected] = *moved;
                    }
                    _ => {
                        let loss = RestoredCaptureRefusal::new(&gates[selected]);
                        drop(loss);
                        expected[selected] = Expected::Dead;
                    }
                }
                assert_eq!(
                    [actual(&gates[0]), actual(&gates[1])],
                    expected,
                    "seed {seed} step {step}"
                );
            }
        }
    }
}
