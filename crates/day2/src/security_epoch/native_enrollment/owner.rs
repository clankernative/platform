//! Stable native executor ownership. Nothing here adopts a parsed certificate as
//! authority, moves a role between threads, or renews a failed original.

use crate::security_epoch::native_clock::{NativeAcquisition, boottime};
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

mod serving;
mod storage;

struct OwnerIdentity;

pub(crate) struct EnrolledProcessRoleOwner {
    policy: EnrollmentPolicy,
    role: NativeRole,
    key: KeyOwner,
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
    issuer: IssuerReceipt,
    #[cfg(target_os = "linux")]
    binding: super::runtime::RuntimeBinding,
    #[cfg(target_os = "linux")]
    self_data: super::protocol::ProcessData,
    local: PhantomData<Rc<()>>,
}

pub(crate) struct EnrolledRoleStage<'a> {
    owner: &'a mut EnrolledProcessRoleOwner,
    purpose: StagePurpose,
    acquisition: NativeAcquisition,
    deadline: Duration,
    #[cfg(target_os = "linux")]
    current: SelfSnapshot,
    #[cfg(target_os = "linux")]
    nonce_peer: IssuerReceipt,
    #[cfg(target_os = "linux")]
    grant_peer: IssuerReceipt,
    #[cfg(target_os = "linux")]
    channel: Channel,
    #[cfg(target_os = "linux")]
    current_grant: SignedStage,
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
            let policy = super::birth::load_policy(&mut acquisition)?;
            ensure!(
                policy.bootstrap.scope == *scope,
                "native_enrollment_scope_mismatch"
            );
            let key = KeyOwner::generate()?;
            let mut current =
                SelfSnapshot::acquire(policy.code(role), &mut acquisition, &HashCosts::disabled())?;
            let (certificate, grant, issuer, _nonce_peer, _channel) = exchange(
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
            Ok(Self {
                policy,
                role,
                key,
                certificate,
                incarnation,
                identity: Rc::new(OwnerIdentity),
                process: std::process::id(),
                thread: std::thread::current().id(),
                refused: false,
                initial_holder_attempted: false,
                initial_handshake_attempted: false,
                serving_attempted: false,
                issuer,
                binding: grant.data.runtime,
                self_data: grant.data.process,
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

    /// Only the original Ready/file/first-peer composition calls this entry.
    /// Authentication still spends at most five seconds of the SAME origin.
    pub(crate) fn begin_initial_first_holder_stage(&mut self) -> Result<EnrolledRoleStage<'_>> {
        self.begin_stage(StagePurpose::InitialFirstHolder)
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
                    StagePurpose::CurrentRole => NativeAcquisition::begin(5)?,
                    StagePurpose::InitialFirstHolder => {
                        NativeAcquisition::begin_initial_first_holder()?
                    }
                };
                let (_, ceiling) = acquisition.interval_data()?;
                let mut authentication = acquisition.narrow(5, ceiling)?;
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
                    ensure!(
                        super::birth::load_policy(&mut authentication)? == self.policy,
                        "native_enrollment_operator_selection_changed"
                    );
                    self.issuer.check_live(&mut authentication)?;
                    self.certificate.verify(&self.policy)?;
                    let mut current = SelfSnapshot::acquire(
                        self.policy.code(self.role),
                        &mut authentication,
                        &HashCosts::disabled(),
                    )?;
                    ensure!(
                        current.data == self.self_data,
                        "native_enrollment_self_changed"
                    );
                    let (certificate, grant, grant_peer, nonce_peer, channel) = exchange(
                        &self.policy,
                        self.role,
                        purpose,
                        &self.key,
                        &mut current,
                        &mut authentication,
                    )?;
                    ensure!(
                        certificate == self.certificate && grant.data.runtime == self.binding,
                        "native_enrollment_incarnation_or_runtime_changed"
                    );
                    self.issuer.check_live(&mut authentication)?;
                    Ok((
                        acquisition,
                        authentication,
                        current,
                        grant,
                        grant_peer,
                        nonce_peer,
                        channel,
                    ))
                }
            })();
            if result.is_err() {
                self.refused = true;
            }
            #[cfg(target_os = "linux")]
            {
                let (acquisition, authentication, current, grant, grant_peer, nonce_peer, channel) =
                    result?;
                let deadline = Duration::from_nanos(grant.data.deadline_ns);
                let mut stage = EnrolledRoleStage {
                    owner: self,
                    purpose,
                    acquisition,
                    deadline,
                    current,
                    nonce_peer,
                    grant_peer,
                    channel,
                    current_grant: grant,
                };
                stage.check()?;
                // A ten-second peer interval never gives role authentication
                // more than its original five-second acquisition. No reset.
                if let Err(error) = stage.acquisition.complete_authentication(authentication) {
                    stage.owner.refused = true;
                    stage.acquisition.refuse();
                    return Err(error);
                }
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
            let child = self.acquisition.narrow(max_lease_seconds, self.deadline)?;
            self.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn require_purpose(
        &mut self,
        purpose: StagePurpose,
    ) -> Result<()> {
        if self.purpose != purpose {
            self.owner.refused = true;
            self.acquisition.refuse();
            anyhow::bail!("native_enrollment_stage_purpose_changed");
        }
        self.check()
    }

    pub(in crate::security_epoch) fn initial_first_holder_acquisition(
        &mut self,
    ) -> Result<NativeAcquisition> {
        let result = (|| {
            self.require_purpose(StagePurpose::InitialFirstHolder)?;
            let seconds = super::super::native_clock::INITIAL_FIRST_HOLDER_HANDSHAKE_LIMIT
                .as_secs()
                .try_into()?;
            let child = self.acquisition.narrow(seconds, self.deadline)?;
            self.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
        }
        result
    }

    /// The initial file still honors a shorter configured ceiling. Same
    /// origin, signed ceiling, checks and permanent refusal as peer I/O.
    pub(in crate::security_epoch) fn initial_first_holder_file_acquisition(
        &mut self,
        max_lease_seconds: u32,
    ) -> Result<NativeAcquisition> {
        let result = (|| {
            self.require_purpose(StagePurpose::InitialFirstHolder)?;
            let child = self.acquisition.narrow(max_lease_seconds, self.deadline)?;
            self.check()?;
            Ok(child)
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
        }
        result
    }

    pub(crate) fn check_selection(
        &mut self,
        policy: &day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        store: &day2_capabilities::security_epoch::EpochStore,
        role: NativeRole,
    ) -> Result<()> {
        if self.owner.policy.bootstrap != *policy || self.owner.policy.store != *store {
            self.owner.refused = true;
            self.acquisition.refuse();
            anyhow::bail!("native_enrollment_full_selection_changed");
        }
        self.check_for(&policy.scope, role)
    }

    /// DATA from this actual checked executor, never a current grant factory.
    pub(in crate::security_epoch) fn incarnation_data(&mut self) -> Result<Digest> {
        self.check()?;
        Ok(self.owner.incarnation.clone())
    }

    pub(crate) fn check_for(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
        let selected = self.owner.policy.bootstrap.scope == *scope && self.owner.role == role;
        if !selected {
            self.owner.refused = true;
            self.acquisition.refuse();
            anyhow::bail!("native_enrollment_stage_selection_changed");
        }
        self.check()
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.owner.check_local()?;
            ensure!(
                self.acquisition.sample()?.elapsed < self.deadline,
                "native_enrollment_stage_expired"
            );
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    super::birth::load_policy(&mut self.acquisition)? == self.owner.policy,
                    "native_enrollment_operator_selection_changed"
                );
                self.current.check(&mut self.acquisition)?;
                self.owner.issuer.check_live(&mut self.acquisition)?;
                self.nonce_peer.check_live(&mut self.acquisition)?;
                self.grant_peer.check_live(&mut self.acquisition)?;
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_enrollment_platform_unsupported")
        })();
        if result.is_err() {
            self.owner.refused = true;
            self.acquisition.refuse();
        }
        result
    }
}

impl SameEnrolledOwner {
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
            stage.acquisition.refuse();
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
            stage.acquisition.refuse();
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
            let proc = ns::open_root(&mut stage.acquisition)?;
            let task = ns::open_task(&proc, &mut stage.acquisition)?;
            let mut namespaces = std::collections::BTreeMap::new();
            for name in ["time", "time_for_children", "pid", "user"] {
                namespaces.insert(
                    name.to_owned(),
                    ns::open_namespace(&task, name, &mut stage.acquisition)?,
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
            let current = ns::open_root(&mut stage.acquisition)?;
            ensure!(
                ns::proc_identity(&current)? == ns::proc_identity(&self.proc)?,
                "native_enrollment_clock_proc_changed"
            );
            let current = ns::open_task(&current, &mut stage.acquisition)?;
            ensure!(
                ns::proc_identity(&current)? == ns::proc_identity(&self.task)?,
                "native_enrollment_clock_task_changed"
            );
            for (name, original) in &self.namespaces {
                let value = ns::namespace_identity(original)?;
                let current = ns::open_namespace(&current, name, &mut stage.acquisition)?;
                ensure!(
                    ns::namespace_identity(&current)? == value
                        && stage.current.data.namespaces.get(name)
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
    let request = protocol::nonce("role-request")?;
    let public_key = key.public();
    let policy_hash = policy.digest()?;
    let mut channel = Channel::connect(acquisition)?;
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
}
