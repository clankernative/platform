//! Stable native executor ownership. Nothing here adopts a parsed certificate as
//! authority, moves a role between threads, or renews a failed original.

use crate::security_epoch::native_clock::{NativeAcquisition, StageAcquisition, boottime};
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
    process::SelfSnapshot,
    protocol::{Packet, SignedStage},
    runtime,
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::AuthorityScope};
use std::{
    marker::PhantomData,
    rc::{Rc, Weak},
    thread::ThreadId,
    time::Duration,
};

mod request_exclusion;
mod serving;
mod storage;
pub(crate) use request_exclusion::{IdleCredentialAdmission, IdleCredentialPublication};
use request_exclusion::{LiveRequest, RequestRegistry};

struct OwnerIdentity;

pub(crate) struct EnrolledProcessRoleOwner {
    policy: EnrollmentPolicy,
    role: NativeRole,
    key: KeyOwner,
    certificate: IssuerCertificate,
    incarnation: Digest,
    diagnostic_producer: Option<Digest>,
    diagnostic_owner_ordinal: Option<u64>,
    diagnostic_request_counter: Option<u64>,
    identity: Rc<OwnerIdentity>,
    requests: Rc<RequestRegistry>,
    process: u32,
    thread: ThreadId,
    refused: bool,
    // One-way refusal gate, never a holder permission or restored DATA flag.
    // Even a later fresh stage cannot restart an unknown initial exchange.
    initial_holder_attempted: bool,
    initial_handshake_attempted: bool,
    serving_attempted: bool,
    #[cfg(target_os = "linux")]
    issuer: IssuerReceipt,
    #[cfg(target_os = "linux")]
    binding: super::runtime::RuntimeBinding,
    #[cfg(target_os = "linux")]
    self_data: super::protocol::ProcessData,
    #[cfg(target_os = "linux")]
    policy_file: super::birth::PolicyFileOwner,
    #[cfg(target_os = "linux")]
    current: SelfSnapshot,
    #[cfg(target_os = "linux")]
    clock: crate::security_epoch::native_clock::NativeConnectionClock,
    #[cfg(target_os = "linux")]
    admission: SignedStage,
    #[cfg(target_os = "linux")]
    admission_peers: Vec<IssuerReceipt>,
    #[cfg(target_os = "linux")]
    _completed_admission: Channel,
    local: PhantomData<Rc<()>>,
}

pub(crate) struct EnrolledRoleStage<'a> {
    owner: &'a mut EnrolledProcessRoleOwner,
    purpose: StagePurpose,
    acquisition: StageAcquisition<'a>,
    deadline: Duration,
    diagnostic_request_ordinal: Option<u64>,
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
    live_request: LiveRequest,
    incarnation: Digest,
    role: NativeRole,
    process: u32,
    thread: ThreadId,
    acquisition: NativeAcquisition,
    diagnostic_request_ordinal: Option<u64>,
    finished: bool,
    diagnostic_data: super::EnrolledRequestDiagnosticData,
    local: PhantomData<Rc<()>>,
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
            let _ = <UnselectedShellRequest as Ambiguous<_>>::check;
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
            self.live_request.refuse();
            self.acquisition.refuse();
        }
    }
}

impl EnrolledCurrentRequest {
    /// Historical labels from this actual constructor, never a current check.
    pub(crate) fn historical_diagnostic_data(&self) -> super::EnrolledRequestDiagnosticData {
        self.diagnostic_data.clone()
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
        self.live_request.refuse();
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
            let mut current =
                SelfSnapshot::acquire(policy.code(role), &mut acquisition, &HashCosts::disabled())?;
            let (certificate, grant, issuer, nonce_peer, channel) = exchange(
                &policy,
                role,
                StagePurpose::CurrentRole,
                &key,
                &mut current,
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
            let (diagnostic_producer, diagnostic_owner_ordinal) =
                crate::security_epoch::admission_work::register_owner();
            Ok(Self {
                policy,
                role,
                key,
                certificate,
                incarnation,
                diagnostic_producer,
                diagnostic_owner_ordinal,
                diagnostic_request_counter: Some(0),
                identity: Rc::new(OwnerIdentity),
                requests: RequestRegistry::new(),
                process: std::process::id(),
                thread: std::thread::current().id(),
                refused: false,
                initial_holder_attempted: false,
                initial_handshake_attempted: false,
                serving_attempted: false,
                issuer,
                binding: grant.data.runtime.clone(),
                self_data: grant.data.process.clone(),
                policy_file,
                current,
                clock: acquisition.into_connection_clock()?,
                admission: grant,
                // The original grant's actual receipt is retained in issuer.
                // A later complete admission retains both new packet handles.
                admission_peers: vec![nonce_peer],
                _completed_admission: channel,
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
        let live_request = stage.owner.requests.start()?;
        let diagnostic_data = stage
            .diagnostic_progress()
            .historical_request_binding_data()
            .unwrap_or_else(|_| super::EnrolledRequestDiagnosticData::unknown());
        Ok(EnrolledCurrentRequest {
            identity: Rc::downgrade(&stage.owner.identity),
            live_request,
            incarnation: stage.owner.incarnation.clone(),
            role: stage.owner.role,
            process: stage.owner.process,
            thread: stage.owner.thread,
            acquisition: stage.acquisition.into_owned()?,
            diagnostic_request_ordinal: stage.diagnostic_request_ordinal,
            finished: false,
            diagnostic_data,
            local: PhantomData,
        })
    }

    pub(crate) fn bind_shell_request(
        &mut self,
        mut start: UnselectedShellRequest,
    ) -> Result<EnrolledCurrentRequest> {
        self.requests.allow_request()?;
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
                    start.namespaces.data() == self.current.namespace.data(),
                    "native_enrollment_request_namespace_changed"
                );
                let original = start
                    .acquisition
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("native_enrollment_request_already_bound"))?;
                let acquisition = self.clock.bind_captured_current(original)?;
                let diagnostic_request_ordinal = self
                    .diagnostic_request_counter
                    .and_then(|n| n.checked_add(1));
                self.diagnostic_request_counter = diagnostic_request_ordinal;
                let mut request = EnrolledCurrentRequest {
                    identity: Rc::downgrade(&self.identity),
                    live_request: self.requests.start()?,
                    incarnation: self.incarnation.clone(),
                    role: self.role,
                    process: self.process,
                    thread: self.thread,
                    acquisition,
                    diagnostic_request_ordinal,
                    finished: false,
                    diagnostic_data: super::EnrolledRequestDiagnosticData::unknown(),
                    local: PhantomData,
                };
                // This checks actual retained task/namespace/process and issuer
                // handles before any caller can map expiry or use the request.
                request.diagnostic_data = {
                    let mut stage = self.borrow_current_request(&mut request)?;
                    stage.check()?;
                    stage
                        .diagnostic_progress()
                        .historical_request_binding_data()
                        .unwrap_or_else(|_| super::EnrolledRequestDiagnosticData::unknown())
                };
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
        self.requests.allow_request()?;
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
            diagnostic_request_ordinal: request.diagnostic_request_ordinal,
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
        self.requests.allow_request()?;
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
                    self.policy_file.check(&mut acquisition)?;
                    self.issuer.check_live(&mut acquisition)?;
                    self.certificate.verify(&self.policy)?;
                    self.current.check(&mut acquisition)?;
                    ensure!(
                        self.current.data == self.self_data,
                        "native_enrollment_self_changed"
                    );
                    let (_, deadline) = acquisition.interval_data()?;
                    let diagnostic_request_ordinal = self
                        .diagnostic_request_counter
                        .and_then(|n| n.checked_add(1));
                    self.diagnostic_request_counter = diagnostic_request_ordinal;
                    Ok((acquisition, deadline, diagnostic_request_ordinal))
                }
            })();
            if result.is_err() {
                self.refused = true;
            }
            #[cfg(target_os = "linux")]
            {
                let (acquisition, deadline, diagnostic_request_ordinal) = result?;
                let mut stage = EnrolledRoleStage {
                    owner: self,
                    purpose,
                    acquisition: StageAcquisition::owned(acquisition),
                    deadline,
                    diagnostic_request_ordinal,
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
        // A busy idle admission rejects before observing its actual winner.
        // For an accepted original, capture still precedes role/owner checks.
        self.requests.allow_request()?;
        let origin = boottime().inspect_err(|_| self.refused = true)?;
        let result = (|| {
            self.check_local()?;
            ensure!(self.role == expected, "native_enrollment_clock_role");
            #[cfg(target_os = "linux")]
            {
                let mut stage = self.begin_current_stage()?;
                let anchors = ClockAnchors::capture(&mut stage)?;
                let incarnation = stage.owner.incarnation.clone();
                let mut clock = EnrolledOriginalClock {
                    origin,
                    latest: origin,
                    incarnation,
                    role: expected,
                    process: std::process::id(),
                    thread: std::thread::current().id(),
                    refused: false,
                    anchors,
                    local: PhantomData,
                };
                clock.sample(&mut stage)?;
                Ok(clock)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = origin;
                anyhow::bail!("native_enrollment_platform_unsupported")
            }
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    fn require_role_data(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
        let selected = self.policy.bootstrap.scope == *scope && self.role == role;
        if !selected {
            self.refused = true;
            anyhow::bail!("native_enrollment_stage_selection_changed");
        }
        Ok(())
    }

    fn check_local(&mut self) -> Result<()> {
        self.requests.require_not_refused()?;
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
                    &mut self.owner.current,
                    &mut authentication,
                )?;
                ensure!(
                    certificate == self.owner.certificate
                        && grant.data.runtime == self.owner.binding,
                    "native_enrollment_incarnation_or_runtime_changed"
                );
                self.owner.issuer.check_live(&mut authentication)?;
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
                self.owner.admission_peers = vec![grant_peer, nonce_peer];
                self.owner._completed_admission = channel;
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
    pub(crate) fn diagnostic_progress(&self) -> super::AcquisitionProgress {
        let progress = self
            .acquisition
            .as_ref()
            .diagnostic_progress()
            .with_enrollment_data(
                self.owner.incarnation.clone(),
                self.owner.diagnostic_producer.clone(),
                self.owner.diagnostic_owner_ordinal,
                self.diagnostic_request_ordinal,
                self.owner.role,
                self.purpose,
            );
        #[cfg(target_os = "linux")]
        let progress = progress.with_issuer_admission_data(Digest::of(&self.owner.admission).ok());
        progress
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
        self.owner
            .require_role_data(&policy.scope, role)
            .inspect_err(|_| self.acquisition.as_mut().refuse())
    }

    /// DATA from this actual checked executor, never a current grant factory.
    pub(in crate::security_epoch) fn incarnation_data(&mut self) -> Result<Digest> {
        self.check()?;
        Ok(self.owner.incarnation.clone())
    }

    pub(crate) fn check_for(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
        self.owner
            .require_role_data(scope, role)
            .inspect_err(|_| self.acquisition.as_mut().refuse())?;
        self.check()
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
                self.owner.policy_file.check(self.acquisition.as_mut())?;
                self.owner.current.check(self.acquisition.as_mut())?;
                self.owner.issuer.check_live(self.acquisition.as_mut())?;
                ensure!(
                    (1..=2).contains(&self.owner.admission_peers.len()),
                    "native_enrollment_admission_peer_bound"
                );
                for peer in &mut self.owner.admission_peers {
                    peer.check_live(self.acquisition.as_mut())?;
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
                        && stage.owner.current.data.namespaces.get(name)
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
    current: &mut SelfSnapshot,
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
        runtime::require_common(&current.data, &certificate.data.process)?;
        ensure!(
            stage.data.issuer == certificate.digest()?
                && stage.data.policy == policy_hash
                && stage.data.role == role
                && stage.data.purpose == purpose
                && stage.data.public_key == public_key
                && stage.data.request == request
                && stage.data.challenge == challenge
                && stage.data.process == current.data,
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
        current.check(acquisition)?;
        nonce_peer.bind(&certificate, policy, acquisition)?;
        issuer.bind(&certificate, policy, acquisition)?;
        nonce_peer.check_live(acquisition)?;
        issuer.check_live(acquisition)?;
        Ok((certificate, *stage, issuer, nonce_peer, channel))
    })();
    work.finish(result.is_ok());
    result
}
