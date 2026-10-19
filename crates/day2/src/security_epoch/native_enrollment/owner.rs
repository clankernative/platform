//! Stable native executor ownership. Nothing here adopts a parsed certificate as
//! authority, moves a role between threads, or renews a failed original.

use crate::security_epoch::native_clock::{NativeAcquisition, boottime};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::protocol;
use crate::security_epoch::native_enrollment::{
    NativeRole,
    policy::EnrollmentPolicy,
    protocol::{IssuerCertificate, KeyOwner},
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    channel::Channel,
    process::{MessageProcess, SelfSnapshot},
    protocol::{Packet, SignedStage},
    runtime,
};
use anyhow::{Result, ensure};
use day2_capabilities::{Digest, security_epoch::AuthorityScope};
use std::{marker::PhantomData, rc::Rc, thread::ThreadId, time::Duration};

pub(crate) struct EnrolledProcessRoleOwner {
    policy: EnrollmentPolicy,
    role: NativeRole,
    key: KeyOwner,
    certificate: IssuerCertificate,
    incarnation: Digest,
    process: u32,
    thread: ThreadId,
    refused: bool,
    #[cfg(target_os = "linux")]
    issuer: MessageProcess,
    #[cfg(target_os = "linux")]
    binding: super::runtime::RuntimeBinding,
    #[cfg(target_os = "linux")]
    self_data: super::protocol::ProcessData,
    local: PhantomData<Rc<()>>,
}

pub(crate) struct EnrolledRoleStage<'a> {
    owner: &'a mut EnrolledProcessRoleOwner,
    acquisition: NativeAcquisition,
    deadline: Duration,
    #[cfg(target_os = "linux")]
    current: SelfSnapshot,
    #[cfg(target_os = "linux")]
    nonce_peer: MessageProcess,
    #[cfg(target_os = "linux")]
    grant_peer: MessageProcess,
    #[cfg(target_os = "linux")]
    channel: Channel,
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

impl EnrolledProcessRoleOwner {
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
            let mut current = SelfSnapshot::acquire(policy.code(role), &mut acquisition)?;
            let (certificate, grant, issuer, _nonce_peer, _channel) =
                exchange(&policy, role, &key, &mut current, &mut acquisition)?;
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
                process: std::process::id(),
                thread: std::thread::current().id(),
                refused: false,
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
        #[cfg(not(target_os = "linux"))]
        {
            self.refused = true;
            anyhow::bail!("native_enrollment_platform_unsupported")
        }
        #[cfg(target_os = "linux")]
        {
            let result = (|| {
                let mut acquisition = NativeAcquisition::begin(5)?;
                self.check_local()?;
                #[cfg(target_os = "linux")]
                {
                    ensure!(
                        super::birth::load_policy(&mut acquisition)? == self.policy,
                        "native_enrollment_operator_selection_changed"
                    );
                    self.issuer.check_identity(&mut acquisition)?;
                    self.certificate.verify(&self.policy)?;
                    let mut current =
                        SelfSnapshot::acquire(self.policy.code(self.role), &mut acquisition)?;
                    ensure!(
                        current.data == self.self_data,
                        "native_enrollment_self_changed"
                    );
                    let (certificate, grant, grant_peer, nonce_peer, channel) = exchange(
                        &self.policy,
                        self.role,
                        &self.key,
                        &mut current,
                        &mut acquisition,
                    )?;
                    ensure!(
                        certificate == self.certificate && grant.data.runtime == self.binding,
                        "native_enrollment_incarnation_or_runtime_changed"
                    );
                    self.issuer.check_identity(&mut acquisition)?;
                    Ok((acquisition, current, grant, grant_peer, nonce_peer, channel))
                }
            })();
            if result.is_err() {
                self.refused = true;
            }
            #[cfg(target_os = "linux")]
            {
                let (acquisition, current, grant, grant_peer, nonce_peer, channel) = result?;
                let deadline = Duration::from_nanos(grant.data.deadline_ns);
                let mut stage = EnrolledRoleStage {
                    owner: self,
                    acquisition,
                    deadline,
                    current,
                    nonce_peer,
                    grant_peer,
                    channel,
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
                self.owner.issuer.check_identity(&mut self.acquisition)?;
                self.nonce_peer.check_identity(&mut self.acquisition)?;
                self.grant_peer.check_identity(&mut self.acquisition)?;
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
            stage.check()?;
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
    key: &KeyOwner,
    current: &mut SelfSnapshot,
    acquisition: &mut NativeAcquisition,
) -> Result<(
    IssuerCertificate,
    SignedStage,
    MessageProcess,
    MessageProcess,
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
            public_key: public_key.clone(),
            request: request.clone(),
        },
        acquisition,
    )?;
    let (packet, mut nonce_peer) = channel.receive(&policy.issuer_code, acquisition)?;
    let Packet::StageNonce {
        request: echoed,
        challenge,
    } = packet
    else {
        anyhow::bail!("native_enrollment_stage_order")
    };
    ensure!(echoed == request, "native_enrollment_request_nonce");
    let binding = (&policy_hash, role, &public_key, &request, &challenge);
    let signature = key.sign("role-bind", &binding)?;
    channel.send(
        &Packet::StageBind {
            policy: policy_hash.clone(),
            role,
            public_key: public_key.clone(),
            request: request.clone(),
            challenge: challenge.clone(),
            signature,
        },
        acquisition,
    )?;
    let (packet, mut issuer) = channel.receive(&policy.issuer_code, acquisition)?;
    let Packet::StageGrant { certificate, stage } = packet else {
        anyhow::bail!("native_enrollment_stage_order")
    };
    certificate.verify(policy)?;
    ensure!(
        issuer.data() == &certificate.data.process && nonce_peer.data() == issuer.data(),
        "native_enrollment_issuer_sender_changed"
    );
    runtime::require_common(&certificate.data.process, &certificate.data.provisioner)?;
    runtime::require_common(&current.data, &certificate.data.process)?;
    ensure!(
        stage.data.issuer == certificate.digest()?
            && stage.data.policy == policy_hash
            && stage.data.role == role
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
            && stage.data.deadline_ns - stage.data.origin_ns <= 5_000_000_000
            && Duration::from_nanos(stage.data.origin_ns) <= now
            && now < Duration::from_nanos(stage.data.deadline_ns),
        "native_enrollment_stage_interval"
    );
    current.check(acquisition)?;
    nonce_peer.check_identity(acquisition)?;
    issuer.check_identity(acquisition)?;
    Ok((certificate, *stage, issuer, nonce_peer, channel))
}
