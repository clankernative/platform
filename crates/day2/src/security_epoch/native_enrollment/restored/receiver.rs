//! Actual new-App admission, distinct from ordinary enrollment and Current.
//! The fixed issuer connection discovers its one prepared restore cohort. Wire
//! records alone cannot construct this process/key/policy/clock owner.
use super::{
    AdmittedRestoreProcess, CapturedRestoredFile, PreparedRestoredFile, ReceivedRestorePacket,
    ReceivedRoleRestoredApp, RestoreReadAuthentication, RestoreTransport, RestoredAppPeer,
    RestoredAppReceiver, RestoredControllerReceipt, RestoredReadIdentity,
    RestoredWriterReadPending, RoleReceiveAttempt,
};
#[cfg(target_os = "linux")]
use crate::security_epoch::native_clock::NativeAcquisition;
#[cfg(target_os = "linux")]
use crate::security_epoch::native_enrollment::{
    NativeRole, birth,
    channel::Channel,
    issuer_costs::HashCosts,
    process::SelfSnapshot,
    protocol::{self, KeyOwner, Packet, RestoreAppRequest},
    runtime,
};
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::ensure;
#[cfg(target_os = "linux")]
use std::{cell::RefCell, rc::Rc, time::Duration};

impl RestoredAppReceiver {
    /// Capture the real App's own five-second original before policy, entropy
    /// or process work. No Controller interval DATA creates this acquisition.
    pub(in crate::security_epoch) fn begin() -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut original = NativeAcquisition::begin(5)?;
            let requested: Result<_> = (|| {
                let (policy, mut policy_file) = birth::admit_policy(&mut original)?;
                let key = KeyOwner::generate()?;
                let current = SelfSnapshot::acquire(
                    policy.code(NativeRole::AppHost),
                    &mut original,
                    &HashCosts::disabled(),
                )?;
                policy_file.check(&mut original)?;
                original.remaining()?;
                Ok((policy, policy_file, key, current))
            })();
            let checked = original.remaining();
            if requested.is_err() || checked.is_err() {
                original.refuse();
            }
            let (policy, policy_file, key, current) = requested?;
            checked?;
            Ok(Self {
                policy,
                policy_file: Rc::new(RefCell::new(policy_file)),
                key: Rc::new(key),
                current: Rc::new(RefCell::new(current)),
                original,
                process: std::process::id(),
                thread: std::thread::current().id(),
                refused: false,
                local_only: std::marker::PhantomData,
            })
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested: Result<_> = (|| {
                ensure!(
                    !self.refused
                        && self.process == std::process::id()
                        && self.thread == std::thread::current().id(),
                    "restore_app_receiver_changed"
                );
                self.original.remaining()?;
                self.policy_file
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check(&mut self.original)?;
                self.current
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check(&mut self.original)?;
                Ok(())
            })();
            let checked = self.original.remaining();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            requested?;
            checked.map(|_| ())
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn refuse(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.refused = true;
            self.original.refuse();
        }
    }

    // This is a REAL narrowed child of this App's actual original, with the
    // same Rc/domain/origin/spent time. Only an authenticated ceiling is met;
    // no Controller acquisition is reconstructed or joined from wire DATA.
    pub(in crate::security_epoch::native_enrollment) fn narrow_authenticated_ceiling(
        &mut self,
        ceiling: u64,
    ) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, ceiling);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let mut narrowed = self.original.narrow(5, Duration::from_nanos(ceiling))?;
            self.original.exchange_current_views(&mut narrowed)
        }
    }

    /// The sole successful construction requires actual kernel receipts,
    /// native self checks, key possession and the complete issuer exchange.
    pub(in crate::security_epoch) fn receive(mut self) -> Result<AdmittedRestoreProcess> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (&mut self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<_> = (|| {
                let (origin, deadline) = self.original.interval_data()?;
                let request = RestoreAppRequest {
                    public_key: self.key.public(),
                    request: protocol::nonce("restore-app-request")?,
                    receiver_clock: self.original.sample()?.domain,
                    receiver_origin_ns: origin.as_nanos().try_into()?,
                    receiver_deadline_ns: deadline.as_nanos().try_into()?,
                };
                let mut channel = Channel::connect(&mut self.original)?;
                self.check()?;
                let sent = channel.send(
                    &Packet::RestoreAppHello {
                        request: Box::new(request.clone()),
                    },
                    &mut self.original,
                );
                let checked = self.check();
                sent?;
                checked?;
                let received = channel.receive_issuer(&mut self.original);
                let checked = self.check();
                let (packet, mut nonce_peer) = received?;
                checked?;
                let Packet::RestoreAppNonce {
                    certificate,
                    authorization,
                    request: echoed,
                    challenge,
                } = packet
                else {
                    anyhow::bail!("restore_app_admission_order");
                };
                ensure!(
                    echoed == request.request,
                    "restore_app_request_nonce_changed"
                );
                certificate.verify(&self.policy)?;
                nonce_peer.bind(&certificate, &self.policy, &mut self.original)?;
                runtime::require_common(&certificate.data.process, &certificate.data.provisioner)?;
                runtime::require_common(
                    &self
                        .current
                        .try_borrow()
                        .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                        .data,
                    &certificate.data.process,
                )?;
                authorization.verify_data(
                    &self.policy,
                    &certificate,
                    self.original.sample()?.elapsed,
                )?;
                // Absolute BOOTTIME is interpreted only AFTER genuine common
                // node/boot/time-namespace admission of both actual processes.
                self.narrow_authenticated_ceiling(authorization.statement.effective_deadline_ns)?;
                self.check()?;
                let authorization_digest = authorization.digest_data()?;
                let signature = self.key.sign(
                    "restore-app-bind",
                    &(&request, &authorization_digest, &challenge),
                )?;
                let sent = channel.send(
                    &Packet::RestoreAppBind {
                        authorization: authorization_digest.clone(),
                        request: Box::new(request.clone()),
                        challenge: challenge.clone(),
                        signature,
                    },
                    &mut self.original,
                );
                let checked = self.check();
                sent?;
                checked?;
                let received = channel.receive_issuer(&mut self.original);
                let checked = self.check();
                let (packet, mut grant_peer) = received?;
                checked?;
                let Packet::RestoreAppGrant {
                    certificate: granted_certificate,
                    admission,
                } = packet
                else {
                    anyhow::bail!("restore_app_admission_order");
                };
                ensure!(
                    granted_certificate == certificate,
                    "restore_app_issuer_changed"
                );
                grant_peer.bind(&certificate, &self.policy, &mut self.original)?;
                admission.verify_data(
                    &self.policy,
                    &certificate,
                    &authorization,
                    self.original.sample()?.elapsed,
                )?;
                let statement = &admission.statement;
                ensure!(
                    statement.authorization == authorization_digest
                        && statement.process
                            == self
                                .current
                                .try_borrow()
                                .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                                .data
                        && statement.public_key == request.public_key
                        && statement.request == request.request
                        && statement.challenge == challenge
                        && statement.receiver_clock == request.receiver_clock
                        && statement.receiver_origin_ns == request.receiver_origin_ns
                        && statement.receiver_deadline_ns == request.receiver_deadline_ns,
                    "restore_app_admission_binding_changed"
                );
                self.narrow_authenticated_ceiling(statement.effective_deadline_ns)?;
                nonce_peer.check_live(&mut self.original)?;
                grant_peer.check_live(&mut self.original)?;
                self.check()?;
                Ok((
                    certificate,
                    *authorization,
                    *admission,
                    nonce_peer,
                    grant_peer,
                    channel,
                ))
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.refuse();
            }
            let (certificate, authorization, admission, nonce_peer, grant_peer, channel) =
                requested?;
            checked?;
            Ok(AdmittedRestoreProcess {
                receiver: self,
                certificate,
                authorization,
                admission,
                nonce_peer: Rc::new(RefCell::new(nonce_peer)),
                grant_peer: Rc::new(RefCell::new(grant_peer)),
                channel: Rc::new(channel),
                local_only: std::marker::PhantomData,
            })
        }
    }
}

impl AdmittedRestoreProcess {
    /// Closed transcript DATA from this actual live owner. It returns neither
    /// an ordinary stage nor access to a key, original, process or channel.
    pub(in crate::security_epoch::native_enrollment) fn statement_data(
        &mut self,
    ) -> Result<super::super::restore_peer_wire::RestoreAppStatement> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            self.check()?;
            let requested: Result<_> = (|| {
                let (origin, deadline) = self.receiver.original.interval_data()?;
                let domain = self.receiver.original.sample()?.domain;
                Ok(super::super::restore_peer_wire::RestoreAppStatement {
                    certificate: self.certificate.clone(),
                    authorization: self.authorization.clone(),
                    admission: self.admission.clone(),
                    original: super::super::restore_peer_wire::RestoreOriginal {
                        domain,
                        origin_ns: origin.as_nanos().try_into()?,
                        deadline_ns: deadline.as_nanos().try_into()?,
                    },
                })
            })();
            let checked = self.check();
            if requested.is_err() || checked.is_err() {
                self.receiver.refuse();
            }
            let statement = requested?;
            checked?;
            Ok(statement)
        }
    }

    pub(in crate::security_epoch::native_enrollment) fn check(&mut self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self,);
            anyhow::bail!("native_restore_platform_unsupported");
        }
        #[cfg(target_os = "linux")]
        {
            let requested: Result<_> = (|| {
                self.receiver.check()?;
                self.nonce_peer
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check_live(&mut self.receiver.original)?;
                self.grant_peer
                    .try_borrow_mut()
                    .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                    .check_live(&mut self.receiver.original)?;
                self.admission.verify_data(
                    &self.receiver.policy,
                    &self.certificate,
                    &self.authorization,
                    self.receiver.original.sample()?.elapsed,
                )?;
                ensure!(
                    self.admission.statement.process
                        == self
                            .receiver
                            .current
                            .try_borrow()
                            .map_err(|_| anyhow::anyhow!("native_enrollment_resource_busy"))?
                            .data
                        && self.admission.statement.public_key == self.receiver.key.public(),
                    "restore_app_owner_binding_changed"
                );
                Ok(())
            })();
            let checked = self.receiver.check();
            if requested.is_err() || checked.is_err() {
                self.receiver.refuse();
            }
            requested?;
            checked
        }
    }
}

// The genuine keeper transition must consume/retain this owner. A lost
// admission cannot leave another actual narrowed view reusable after panic.
// These are actual process/key/clock/received-handle owners. Neither can be
// copied, serialized, moved to another executor or supplied by an empty value.
const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <RestoredAppReceiver as Ambiguous<_>>::check;
            let _ = <AdmittedRestoreProcess as Ambiguous<_>>::check;
            let _ = <RestoredAppPeer as Ambiguous<_>>::check;
            let _ = <CapturedRestoredFile as Ambiguous<_>>::check;
            let _ = <RestoredControllerReceipt as Ambiguous<_>>::check;
            let _ = <RestoreTransport as Ambiguous<_>>::check;
            let _ = <ReceivedRestorePacket as Ambiguous<_>>::check;
            let _ = <PreparedRestoredFile as Ambiguous<_>>::check;
            let _ = <RestoredWriterReadPending as Ambiguous<_>>::check;
            let _ = <RestoreReadAuthentication as Ambiguous<_>>::check;
            let _ = <RestoredReadIdentity as Ambiguous<_>>::check;
            let _ = <ReceivedRoleRestoredApp as Ambiguous<_>>::check;
            let _ = <RoleReceiveAttempt<'static> as Ambiguous<_>>::check;
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
