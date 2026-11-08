//! Fixed Controller issuer exchange under the already frozen same owner.
//! Every public step additionally requires the enclosing full Fenced parent
//! pre/post guards. No ordinary role or App file/P3/keeper is created here.
use super::{
    ActivatedRestoredAppRole, CompletedRestoreIssuer, EnrolledStorageStage, FrozenRoleIssuer,
    InstalledAcceptanceAttempt, InstalledConfirmationReceiveAttempt,
    InstalledRestoredAppConfirmation, IssuerRestoreFinishing, IssuerRestorePreparation,
    IssuerRestoreRoleActivating, PreparedAcceptanceAttempt, PreparedConfirmationReceiveAttempt,
    PreparedRestoreAdmission, PreparedRestoredAppConfirmation, RestorePreparationData,
    RestoredWriterPeer, RoleHandoffAttempt,
};
#[cfg(target_os = "linux")]
use super::{Channel, NativeRole, Packet, StagePurpose, protocol};
#[cfg(target_os = "linux")]
use anyhow::Context as _;
use anyhow::{Result, ensure};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PreparePhase {
    Connecting,
    Hello,
    Nonce,
    Sign,
    Bind,
    Grant,
    Complete,
    InFlight,
    Refused,
}

impl PreparePhase {
    fn enter(&mut self, expected: Self) -> Result<()> {
        if *self != expected {
            *self = Self::Refused;
            anyhow::bail!("native_restore_preparation_order");
        }
        // A caught unwind can never replay this step or finish the exchange.
        *self = Self::InFlight;
        Ok(())
    }

    fn complete(&mut self, next: Self) -> Result<()> {
        ensure!(
            *self == Self::InFlight,
            "native_restore_preparation_step_lost"
        );
        *self = next;
        Ok(())
    }
}

impl FrozenRoleIssuer {
    /// Join the actual frozen issuer and completed native peer under the
    /// consuming Controller installation's distinct, short-lived loan.
    pub(in crate::security_epoch) fn begin_finish_restore(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<IssuerRestoreFinishing> {
        let requested: Result<IssuerRestoreFinishing> = (|| {
            self.check(storage)?;
            ensure!(
                !self.finish_attempted,
                "native_restore_issuer_finish_attempt_spent"
            );
            self.finish_attempted = true;
            let (data, app) = peer.finish_binding_data(storage, loan)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (data, app);
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    data.frozen == self.digest_data()?
                        && app.certificate == self.certificate
                        && app.authorization.statement.data.controller
                            == self.statement.selection.controller.digest()?,
                    "native_restore_issuer_finish_generation_changed"
                );
                let original = self
                    .original
                    .narrow(5, std::time::Duration::from_nanos(app.original.deadline_ns))?;
                let mut pending = IssuerRestoreFinishing {
                    original,
                    same: storage.stage.capture_same_owner()?,
                    certificate: self.certificate.clone(),
                    data,
                    app,
                    request: protocol::nonce("restore-issuer-finish-request")?,
                    challenge: None,
                    bind_signature: None,
                    nonce_peer: None,
                    grant_peer: None,
                    signed: None,
                    channel: None,
                    phase: PreparePhase::Connecting,
                    refused: false,
                    local: std::marker::PhantomData,
                };
                pending.phase.enter(PreparePhase::Connecting)?;
                pending.check(storage, peer, loan)?;
                let connected = Channel::connect(&mut pending.original);
                let checked = pending.check(storage, peer, loan);
                if connected.is_err() || checked.is_err() {
                    pending.refuse();
                    peer.refuse();
                    loan.refuse();
                }
                pending.channel = Some(connected?);
                checked?;
                pending.phase.complete(PreparePhase::Hello)?;
                Ok(pending)
            }
        })();
        let issuer_post = self.check(storage);
        let peer_post = peer.check_final_installation(storage, loan);
        if requested.is_err() || issuer_post.is_err() || peer_post.is_err() {
            self.refuse();
            peer.refuse();
            loan.refuse();
        }
        let pending = requested?;
        issuer_post?;
        peer_post?;
        Ok(pending)
    }

    /// The whole restore parent supplies this exact metadata only after known
    /// target settlement, retained keys, approval/UV and actual target checks.
    /// The native layer checks its actual original, frozen generation and key.
    pub(in crate::security_epoch) fn begin_restore_preparation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        supplied: &RestorePreparationData,
    ) -> Result<IssuerRestorePreparation> {
        let requested: Result<IssuerRestorePreparation> = (|| {
            self.check(storage)?;
            ensure!(
                !self.restore_attempted,
                "native_restore_preparation_attempt_spent"
            );
            self.restore_attempted = true;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = supplied;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let stage = &mut *storage.stage;
                stage.require_purpose(StagePurpose::CurrentRole)?;
                // Authority identities come from the retained native owners,
                // not caller metadata, a path, a role label or a certificate.
                let data = protocol::RestoreAuthorizationData {
                    issuer: self.certificate.digest()?,
                    policy: stage.owner.policy.digest()?,
                    frozen: self.digest_data()?,
                    controller: self.statement.selection.controller.digest()?,
                    operation: supplied.operation.clone(),
                    approval: supplied.approval.clone(),
                    grant: supplied.grant.clone(),
                    intent: supplied.intent.clone(),
                    full_archive: supplied.full_archive.clone(),
                    desired_instance: supplied.desired_instance.clone(),
                    target: supplied.target.clone(),
                    report: supplied.report.clone(),
                    terminal: supplied.terminal.clone(),
                    terminal_version: supplied.terminal_version.clone(),
                    records: supplied.records.clone(),
                    parent_clock: supplied.parent_clock.clone(),
                    parent_origin_ns: supplied.parent_origin_ns,
                    parent_deadline_ns: supplied.parent_deadline_ns,
                };
                ensure!(
                    stage.owner.role == NativeRole::EpochController
                        && data.frozen == self.digest_data()?
                        && data.controller == self.statement.selection.controller.digest()?,
                    "native_restore_preparation_frozen_binding_changed"
                );
                let (origin, ceiling) = self.original.interval_data()?;
                let sample = self.original.sample()?;
                ensure!(
                    data.parent_clock == sample.domain
                        && u128::from(data.parent_origin_ns) == origin.as_nanos()
                        && std::time::Duration::from_nanos(data.parent_deadline_ns) <= ceiling,
                    "native_restore_preparation_original_changed"
                );
                data.validate_data(&stage.owner.policy, &self.certificate, sample.elapsed)?;
                let original = self
                    .original
                    .narrow(5, std::time::Duration::from_nanos(data.parent_deadline_ns))?;
                let mut pending = IssuerRestorePreparation {
                    same: stage.capture_same_owner()?,
                    original,
                    certificate: self.certificate.clone(),
                    data: data.clone(),
                    request: protocol::nonce("restore-controller-prepare-request")?,
                    challenge: None,
                    bind_signature: None,
                    nonce_peer: None,
                    grant_peer: None,
                    signed: None,
                    channel: None,
                    phase: PreparePhase::Connecting,
                    refused: false,
                    local: std::marker::PhantomData,
                };
                // The pending lifecycle exists BEFORE connect, so a failure
                // or unwind drops/refuses the actual same original.
                pending.phase.enter(PreparePhase::Connecting)?;
                pending.check(storage)?;
                let connected = Channel::connect(&mut pending.original);
                let checked = pending.check(storage);
                if connected.is_err() || checked.is_err() {
                    pending.refuse();
                }
                pending.channel = Some(connected?);
                checked?;
                pending.phase.complete(PreparePhase::Hello)?;
                Ok(pending)
            }
        })();
        let checked = self.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let pending = requested?;
        checked?;
        Ok(pending)
    }
}

impl IssuerRestoreFinishing {
    fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(
                !self.refused && self.phase != PreparePhase::Refused,
                "native_restore_issuer_finish_refused"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let stage = &mut *storage.stage;
                self.same
                    .meet_current_read_view(stage, &mut self.original)?;
                stage.require_purpose(StagePurpose::CurrentRole)?;
                ensure!(
                    stage.owner.role == NativeRole::EpochController
                        && stage.owner.certificate == self.certificate,
                    "native_restore_issuer_finish_owner_changed"
                );
                self.data.validate_data(
                    &stage.owner.policy,
                    &self.certificate,
                    &self.app,
                    self.original.sample()?.elapsed,
                )?;
                if let Some(signed) = &self.signed {
                    signed.verify_data(
                        &stage.owner.policy,
                        &self.certificate,
                        &self.data,
                        &self.app,
                        self.original.sample()?.elapsed,
                    )?;
                    ensure!(
                        signed.statement.request == self.request
                            && Some(&signed.statement.challenge) == self.challenge.as_ref(),
                        "native_restore_issuer_finish_grant_changed"
                    );
                }
                if let Some(issuer) = &mut self.nonce_peer {
                    issuer.check_live(&mut self.original)?;
                }
                if let Some(issuer) = &mut self.grant_peer {
                    issuer.check_live(&mut self.original)?;
                }
                stage.check()?;
                self.original.remaining().map(|_| ())
            }
        })();
        // The actual peer and physical/known/UV half are independent of an
        // earlier owner, clock or issuer-receipt failure.
        let peer_post: Result<()> = (|| {
            let (data, app) = peer.finish_binding_data(storage, loan)?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (data, app);
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    data == self.data && app == self.app,
                    "native_restore_issuer_finish_peer_changed"
                );
                Ok(())
            }
        })();
        let original_post = self.original.remaining();
        if requested.is_err() || peer_post.is_err() || original_post.is_err() {
            self.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        peer_post?;
        original_post.map(|_| ())
    }

    // Accept a produced Result only; never an effect callback or permission
    // argument. Each fixed public operation selects its own next position.
    fn complete_step(
        &mut self,
        requested: Result<()>,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
        next: PreparePhase,
    ) -> Result<()> {
        let checked = self.check(storage, peer, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        checked?;
        let advanced = self.phase.complete(next);
        if advanced.is_err() {
            self.refuse();
            peer.refuse();
            loan.refuse();
        }
        advanced
    }

    pub(in crate::security_epoch) fn send_hello(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Hello)?;
            self.check(storage, peer, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.channel
                .as_mut()
                .context("native_restore_issuer_finish_channel_missing")?
                .send(
                    &Packet::RestoreFinishHello {
                        completion: Box::new(self.data.clone()),
                        request: self.request.clone(),
                    },
                    &mut self.original,
                )
        })();
        self.complete_step(requested, storage, peer, loan, PreparePhase::Nonce)
    }

    pub(in crate::security_epoch) fn receive_nonce(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Nonce)?;
            self.check(storage, peer, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let received = self
                    .channel
                    .as_mut()
                    .context("native_restore_issuer_finish_channel_missing")?
                    .receive_issuer(&mut self.original);
                let checked = self.check(storage, peer, loan);
                let (packet, mut issuer) = received?;
                checked?;
                let Packet::RestoreFinishNonce {
                    completion,
                    request,
                    challenge,
                } = packet
                else {
                    anyhow::bail!("native_restore_issuer_finish_nonce_expected");
                };
                ensure!(
                    completion == self.data.digest_data()? && request == self.request,
                    "native_restore_issuer_finish_nonce_changed"
                );
                issuer.bind(
                    &self.certificate,
                    &storage.stage.owner.policy,
                    &mut self.original,
                )?;
                issuer.check_live(&mut self.original)?;
                self.nonce_peer = Some(issuer);
                self.challenge = Some(challenge);
                Ok(())
            }
        })();
        self.complete_step(requested, storage, peer, loan, PreparePhase::Sign)
    }

    pub(in crate::security_epoch) fn sign_bind(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Sign)?;
            self.check(storage, peer, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let challenge = self
                    .challenge
                    .as_ref()
                    .context("native_restore_issuer_finish_challenge_missing")?;
                let signed = storage.stage.owner.key.sign(
                    "restore-issuer-finish-bind-v1",
                    &(&self.data, &self.request, challenge),
                );
                let checked = self.check(storage, peer, loan);
                let signature = signed?;
                checked?;
                self.bind_signature = Some(signature);
                Ok(())
            }
        })();
        self.complete_step(requested, storage, peer, loan, PreparePhase::Bind)
    }

    pub(in crate::security_epoch) fn send_bind(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Bind)?;
            self.check(storage, peer, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let challenge = self
                    .challenge
                    .as_ref()
                    .context("native_restore_issuer_finish_challenge_missing")?
                    .clone();
                let signature = self
                    .bind_signature
                    .take()
                    .context("native_restore_issuer_finish_signature_missing")?;
                self.channel
                    .as_mut()
                    .context("native_restore_issuer_finish_channel_missing")?
                    .send(
                        &Packet::RestoreFinishBind {
                            completion: Box::new(self.data.clone()),
                            request: self.request.clone(),
                            challenge,
                            signature,
                        },
                        &mut self.original,
                    )
            }
        })();
        self.complete_step(requested, storage, peer, loan, PreparePhase::Grant)
    }

    pub(in crate::security_epoch) fn receive_grant(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Grant)?;
            self.check(storage, peer, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let received = self
                    .channel
                    .as_mut()
                    .context("native_restore_issuer_finish_channel_missing")?
                    .receive_issuer(&mut self.original);
                let checked = self.check(storage, peer, loan);
                let (packet, mut issuer) = received?;
                checked?;
                let Packet::RestoreFinishGrant { completion } = packet else {
                    anyhow::bail!("native_restore_issuer_finish_grant_expected");
                };
                completion.verify_data(
                    &storage.stage.owner.policy,
                    &self.certificate,
                    &self.data,
                    &self.app,
                    self.original.sample()?.elapsed,
                )?;
                ensure!(
                    completion.statement.request == self.request
                        && Some(&completion.statement.challenge) == self.challenge.as_ref(),
                    "native_restore_issuer_finish_grant_changed"
                );
                issuer.bind(
                    &self.certificate,
                    &storage.stage.owner.policy,
                    &mut self.original,
                )?;
                issuer.check_live(&mut self.original)?;
                self.original = self.original.narrow(
                    5,
                    std::time::Duration::from_nanos(completion.statement.effective_deadline_ns),
                )?;
                self.signed = Some(*completion);
                self.grant_peer = Some(issuer);
                Ok(())
            }
        })();
        self.complete_step(requested, storage, peer, loan, PreparePhase::Complete)
    }

    pub(in crate::security_epoch) fn finish(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<CompletedRestoreIssuer> {
        let requested = (|| {
            ensure!(
                self.phase == PreparePhase::Complete,
                "native_restore_issuer_finish_incomplete"
            );
            #[cfg(target_os = "linux")]
            ensure!(
                self.signed.is_some() && self.nonce_peer.is_some() && self.grant_peer.is_some(),
                "native_restore_issuer_finish_handles_missing"
            );
            self.check(storage, peer, loan)
        })();
        let checked = self.check(storage, peer, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        checked?;
        Ok(CompletedRestoreIssuer {
            finishing: self,
            role_activation_attempted: false,
        })
    }

    fn refuse(&mut self) {
        self.refused = true;
        self.phase = PreparePhase::Refused;
        self.original.refuse();
    }
}

impl CompletedRestoreIssuer {
    pub(super) fn refuse(&mut self) {
        self.finishing.refuse();
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                self.finishing.phase == PreparePhase::Complete,
                "native_restore_completed_issuer_changed"
            );
            self.finishing.check(storage, peer, loan)
        })();
        let checked = self.finishing.check(storage, peer, loan);
        if requested.is_err() || checked.is_err() {
            self.finishing.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        checked
    }
}

impl IssuerRestorePreparation {
    fn check(&mut self, storage: &mut EnrolledStorageStage<'_, '_>) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(
                !self.refused && self.phase != PreparePhase::Refused,
                "native_restore_preparation_refused"
            );
            #[cfg(not(target_os = "linux"))]
            {
                let _ = storage;
                anyhow::bail!("native_restore_platform_unsupported");
            }
            #[cfg(target_os = "linux")]
            {
                let stage = &mut *storage.stage;
                self.same
                    .meet_current_read_view(stage, &mut self.original)?;
                stage.require_purpose(StagePurpose::CurrentRole)?;
                ensure!(
                    stage.owner.role == NativeRole::EpochController
                        && self.certificate == stage.owner.certificate,
                    "native_restore_preparation_owner_changed"
                );
                let (origin, deadline) = self.original.interval_data()?;
                let now = self.original.sample()?;
                ensure!(
                    self.data.parent_clock == now.domain
                        && u128::from(self.data.parent_origin_ns) == origin.as_nanos()
                        && deadline
                            <= std::time::Duration::from_nanos(self.data.parent_deadline_ns),
                    "native_restore_preparation_interval_changed"
                );
                self.data
                    .validate_data(&stage.owner.policy, &self.certificate, now.elapsed)?;
                if let Some(signed) = &self.signed {
                    signed.verify_data(&stage.owner.policy, &self.certificate, now.elapsed)?;
                    ensure!(
                        signed.statement.data == self.data
                            && signed.statement.request == self.request
                            && Some(&signed.statement.challenge) == self.challenge.as_ref(),
                        "native_restore_preparation_grant_changed"
                    );
                }
                if let Some(peer) = &mut self.nonce_peer {
                    peer.check_live(&mut self.original)?;
                }
                if let Some(peer) = &mut self.grant_peer {
                    peer.check_live(&mut self.original)?;
                }
                stage.check()?;
                self.original.remaining().map(|_| ())
            }
        })();
        if requested.is_err() {
            self.refuse();
        }
        requested
    }

    pub(in crate::security_epoch) fn send_hello(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.phase.enter(PreparePhase::Hello)?;
            self.check(storage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.channel
                .as_mut()
                .context("native_restore_preparation_channel_missing")?
                .send(
                    &Packet::RestorePrepareHello {
                        authorization: Box::new(self.data.clone()),
                        request: self.request.clone(),
                    },
                    &mut self.original,
                )
        })();
        let checked = self.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        self.phase.complete(PreparePhase::Nonce)
    }

    pub(in crate::security_epoch) fn receive_nonce(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.phase.enter(PreparePhase::Nonce)?;
            self.check(storage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let received = self
                    .channel
                    .as_mut()
                    .context("native_restore_preparation_channel_missing")?
                    .receive_issuer(&mut self.original);
                let checked = self.check(storage);
                let (packet, mut peer) = received?;
                checked?;
                let Packet::RestorePrepareNonce {
                    authorization,
                    request,
                    challenge,
                } = packet
                else {
                    anyhow::bail!("native_restore_preparation_nonce_expected");
                };
                ensure!(
                    authorization == self.data.digest_data()? && request == self.request,
                    "native_restore_preparation_nonce_changed"
                );
                peer.bind(
                    &self.certificate,
                    &storage.stage.owner.policy,
                    &mut self.original,
                )?;
                peer.check_live(&mut self.original)?;
                self.nonce_peer = Some(peer);
                self.challenge = Some(challenge);
                Ok(())
            }
        })();
        let checked = self.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        self.phase.complete(PreparePhase::Sign)
    }

    pub(in crate::security_epoch) fn sign_bind(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.phase.enter(PreparePhase::Sign)?;
            self.check(storage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let challenge = self
                    .challenge
                    .as_ref()
                    .context("native_restore_preparation_challenge_missing")?
                    .clone();
                // Only this fixed request/challenge tuple and domain. There
                // is no general signing callback or escaping key/role borrow.
                let signed = storage.stage.owner.key.sign(
                    "restore-controller-authorize",
                    &(&self.data, &self.request, &challenge),
                );
                let checked = self.check(storage);
                let signature = signed?;
                checked?;
                self.bind_signature = Some(signature);
                Ok(())
            }
        })();
        let checked = self.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        self.phase.complete(PreparePhase::Bind)
    }

    pub(in crate::security_epoch) fn send_bind(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.phase.enter(PreparePhase::Bind)?;
            self.check(storage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let challenge = self
                    .challenge
                    .as_ref()
                    .context("native_restore_preparation_challenge_missing")?
                    .clone();
                let signature = self
                    .bind_signature
                    .take()
                    .context("native_restore_preparation_signature_missing")?;
                self.channel
                    .as_mut()
                    .context("native_restore_preparation_channel_missing")?
                    .send(
                        &Packet::RestorePrepareBind {
                            authorization: Box::new(self.data.clone()),
                            request: self.request.clone(),
                            challenge,
                            signature,
                        },
                        &mut self.original,
                    )
            }
        })();
        let checked = self.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        self.phase.complete(PreparePhase::Grant)
    }

    pub(in crate::security_epoch) fn receive_grant(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            self.phase.enter(PreparePhase::Grant)?;
            self.check(storage)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let received = self
                    .channel
                    .as_mut()
                    .context("native_restore_preparation_channel_missing")?
                    .receive_issuer(&mut self.original);
                let checked = self.check(storage);
                let (packet, mut peer) = received?;
                checked?;
                let Packet::RestorePrepareGrant { authorization } = packet else {
                    anyhow::bail!("native_restore_preparation_grant_expected");
                };
                authorization.verify_data(
                    &storage.stage.owner.policy,
                    &self.certificate,
                    self.original.sample()?.elapsed,
                )?;
                ensure!(
                    authorization.statement.data == self.data
                        && authorization.statement.request == self.request
                        && Some(&authorization.statement.challenge) == self.challenge.as_ref(),
                    "native_restore_preparation_grant_changed"
                );
                peer.bind(
                    &self.certificate,
                    &storage.stage.owner.policy,
                    &mut self.original,
                )?;
                peer.check_live(&mut self.original)?;
                // First final issuer ceiling can only tighten THIS retained
                // shared original. It never constructs a replacement clock.
                self.original = self.original.narrow(
                    5,
                    std::time::Duration::from_nanos(authorization.statement.effective_deadline_ns),
                )?;
                self.signed = Some(*authorization);
                self.grant_peer = Some(peer);
                Ok(())
            }
        })();
        let checked = self.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        self.phase.complete(PreparePhase::Complete)
    }

    pub(in crate::security_epoch) fn finish(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<PreparedRestoreAdmission> {
        let requested: Result<()> = (|| {
            ensure!(
                self.phase == PreparePhase::Complete,
                "native_restore_preparation_incomplete"
            );
            #[cfg(target_os = "linux")]
            ensure!(
                self.signed.is_some() && self.nonce_peer.is_some() && self.grant_peer.is_some(),
                "native_restore_preparation_handles_missing"
            );
            self.check(storage)
        })();
        let checked = self.check(storage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        requested?;
        checked?;
        Ok(PreparedRestoreAdmission { preparation: self })
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.phase = PreparePhase::Refused;
        #[cfg(target_os = "linux")]
        self.original.refuse();
    }
}

impl PreparedRestoreAdmission {
    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
    ) -> Result<()> {
        if self.preparation.phase != PreparePhase::Complete {
            self.refuse();
            anyhow::bail!("native_restore_prepared_admission_incomplete");
        }
        self.preparation.check(storage)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.preparation.refuse();
    }
}

#[cfg(test)]
mod finish_source_tests {
    use quote::ToTokens;

    fn tokens(source: &str) -> String {
        fn normalized(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            stream
                .into_iter()
                .filter_map(|token| match token {
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',' => None,
                    proc_macro2::TokenTree::Punct(punct) if punct.as_char() == '?' => {
                        Some(proc_macro2::TokenTree::Punct(proc_macro2::Punct::new(
                            '?',
                            proc_macro2::Spacing::Alone,
                        )))
                    }
                    proc_macro2::TokenTree::Group(group) => Some(proc_macro2::TokenTree::Group(
                        proc_macro2::Group::new(group.delimiter(), normalized(group.stream())),
                    )),
                    other => Some(other),
                })
                .collect()
        }
        normalized(source.parse::<proc_macro2::TokenStream>().unwrap()).to_string()
    }

    fn method(owner_name: &str, name: &str) -> String {
        let file = syn::parse_file(include_str!("restore.rs")).unwrap();
        let mut found = file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(owner) = item else {
                return None;
            };
            if !matches!(&*owner.self_ty,syn::Type::Path(path) if path.path.is_ident(owner_name)) {
                return None;
            }
            owner.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => {
                    Some(tokens(&method.into_token_stream().to_string()))
                }
                _ => None,
            })
        });
        let method = found.next().unwrap();
        assert!(found.next().is_none());
        method
    }

    fn ordered(body: &str, parts: &[&str]) -> bool {
        let mut rest = body;
        for part in parts {
            let part = tokens(part);
            let Some(at) = rest.find(&part) else {
                return false;
            };
            rest = &rest[at + part.len()..];
        }
        true
    }

    #[test]
    fn role_activation_factory_arms_actual_refusal_before_spending_or_connecting() {
        let actual = method("CompletedRestoreIssuer", "begin_app_role_activation");
        let closed = |body: &str| {
            ordered(
                body,
                &[
                    "let mut attempt=RoleHandoffAttempt",
                    "!attempt.issuer.role_activation_attempted",
                    "attempt.issuer.role_activation_attempted=true;",
                    "attempt.issuer.check(storage,attempt.peer,attempt.loan)?;",
                    "attempt.peer.require_role_handoff_delivered()?;",
                    "attempt.issuer.finishing.signed.as_ref()",
                    "attempt.issuer.finishing.original.narrow",
                    "storage.stage.capture_same_owner()?",
                    "pending.phase.enter(PreparePhase::Connecting)?;",
                    "let connected=Channel::connect(&mut pending.original);",
                    "let checked=pending.check(storage,attempt.peer,attempt.issuer,attempt.loan);",
                    "pending.channel=Some(connected?);checked?;",
                    "let checked=attempt.issuer.check(storage,attempt.peer,attempt.loan);",
                    "let pending=requested?;checked?;attempt.done=true;Ok(pending)",
                ],
            )
        };
        assert!(closed(&actual));
        for (before, after) in [
            (
                "attempt.issuer.role_activation_attempted=true;",
                "let _not_spent=();",
            ),
            (
                "attempt.peer.require_role_handoff_delivered()?;",
                "let _not_delivered=();",
            ),
            (
                "let checked=attempt.issuer.check(storage,attempt.peer,attempt.loan);",
                "let checked=Ok::<(),anyhow::Error>(());",
            ),
            ("attempt.done=true;", "let _not_finished=();"),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1);
            assert!(!closed(&actual.replacen(&before, &tokens(after), 1)));
        }
        assert!(!actual.contains(&tokens("NativeAcquisition::begin")));
    }

    #[test]
    fn role_activation_fixed_steps_keep_native_and_completed_posts_on_every_result() {
        for (name, prior, next, packet) in [
            ("send_hello", "Hello", "Nonce", "Packet::RestoreRoleHello"),
            ("receive_nonce", "Nonce", "Bind", "Packet::RestoreRoleNonce"),
            ("send_bind", "Bind", "Grant", "Packet::RestoreRoleBind"),
            (
                "receive_grant",
                "Grant",
                "Complete",
                "Packet::RestoreRoleGrant",
            ),
        ] {
            let actual = method("IssuerRestoreRoleActivating", name);
            let closed = |body: &str| {
                ordered(
                    body,
                    &[
                        &format!("self.phase.enter(PreparePhase::{prior})?;"),
                        "self.check(storage,peer,completed,loan)?;",
                        packet,
                        &format!(
                            "self.complete_role_step(requested,storage,peer,completed,loan,PreparePhase::{next})"
                        ),
                    ],
                )
            };
            assert!(closed(&actual), "{name}");
            let post = tokens(&format!(
                "self.complete_role_step(requested,storage,peer,completed,loan,PreparePhase::{next})"
            ));
            assert_eq!(actual.matches(&post).count(), 1);
            assert!(!closed(&actual.replacen(&post, &tokens("requested"), 1)));
            assert!(!actual.contains(&tokens("NativeAcquisition::begin")));
        }
        let post = method("IssuerRestoreRoleActivating", "complete_role_step");
        assert!(ordered(
            &post,
            &[
                "let checked=self.check(storage,peer,completed,loan);",
                "requested.is_err() || checked.is_err()",
                "self.refuse();completed.refuse();peer.refuse();loan.refuse();",
                "requested?;checked?;",
                "self.phase.complete(next)"
            ]
        ));
        let native = method("IssuerRestoreRoleActivating", "check");
        assert!(ordered(
            &native,
            &[
                "self.same.meet_current_read_view",
                "completed.finishing.signed.as_ref()==Some(&self.completion)",
                "completed.finishing.app==self.app",
                "self.completion.verify_data",
                "let checked=completed.check(storage,peer,loan);",
                "let original_post=self.original.remaining()",
                "requested?;checked?;original_post"
            ]
        ));
    }

    #[test]
    fn role_activation_actual_grant_authenticates_and_tightens_both_native_originals() {
        let actual = method("IssuerRestoreRoleActivating", "receive_grant");
        assert!(ordered(
            &actual,
            &[
                ".receive_issuer(&mut self.original)",
                "let checked=self.check(storage,peer,completed,loan);",
                "let (packet,mut issuer)=received?;checked?;",
                "issuer.bind",
                "issuer.check_live(&mut self.original)?;",
                "Packet::RestoreRoleGrant",
                "activation.verify_data",
                "self.original=self.original.narrow(5,ceiling)?;",
                "completed.finishing.original=completed.finishing.original.narrow(5,ceiling)?;",
                "self.grant_peer=Some(issuer);self.signed=Some(*activation)"
            ]
        ));
        let finish = method("IssuerRestoreRoleActivating", "finish");
        assert!(ordered(
            &finish,
            &[
                "self.phase==PreparePhase::Complete",
                "self.signed.is_some() && self.nonce_peer.is_some() && self.grant_peer.is_some()",
                "let checked=self.check(storage,peer,completed,loan);",
                "requested?;checked?;",
                "Ok(ActivatedRestoredAppRole {pending:self})"
            ]
        ));
        let refusal = method("IssuerRestoreRoleActivating", "refuse");
        assert!(ordered(
            &refusal,
            &[
                "self.refused=true;",
                "self.phase=PreparePhase::Refused;",
                "self.original.refuse();"
            ]
        ));
        // Source and signature DATA only: no portable fixture constructs an
        // actual native role, SCM receipt, first keeper or accepting Current.
    }

    fn begin_is_actual(body: &str) -> bool {
        ordered(
            body,
            &[
                "self.check(storage)?;",
                "!self.finish_attempted",
                "self.finish_attempted=true;",
                "peer.finish_binding_data(storage,loan)?",
                "data.frozen==self.digest_data()?",
                "app.certificate==self.certificate",
                "app.authorization.statement.data.controller==self.statement.selection.controller.digest()?",
                "self.original.narrow(5,std::time::Duration::from_nanos(app.original.deadline_ns))?",
                "let mut pending=IssuerRestoreFinishing",
                "storage.stage.capture_same_owner()?",
                "pending.phase.enter(PreparePhase::Connecting)?;",
                "pending.check(storage,peer,loan)?;",
                "let connected=Channel::connect(&mut pending.original);",
                "let checked=pending.check(storage,peer,loan);",
                "pending.refuse();peer.refuse();loan.refuse();",
                "pending.channel=Some(connected?);checked?;",
                "pending.phase.complete(PreparePhase::Hello)?;",
                "let issuer_post=self.check(storage);",
                "let peer_post=peer.check_final_installation(storage,loan);",
                "self.refuse();peer.refuse();loan.refuse();",
                "let pending=requested?;issuer_post?;peer_post?;Ok(pending)",
            ],
        ) && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    fn check_is_joined(body: &str) -> bool {
        ordered(
            body,
            &[
                "!self.refused && self.phase!=PreparePhase::Refused",
                "self.same.meet_current_read_view(stage,&mut self.original)?;",
                "stage.require_purpose(StagePurpose::CurrentRole)?;",
                "stage.owner.role==NativeRole::EpochController",
                "stage.owner.certificate==self.certificate",
                "self.data.validate_data",
                "signed.verify_data",
                "signed.statement.request==self.request",
                "Some(&signed.statement.challenge)==self.challenge.as_ref()",
                "self.nonce_peer",
                "issuer.check_live(&mut self.original)?;",
                "self.grant_peer",
                "issuer.check_live(&mut self.original)?;",
                "let peer_post:Result<()>",
                "peer.finish_binding_data(storage,loan)?;",
                "data==self.data && app==self.app",
                "let original_post=self.original.remaining();",
                "if requested.is_err() || peer_post.is_err() || original_post.is_err() {self.refuse();peer.refuse();loan.refuse();}",
                "requested?;peer_post?;original_post.map",
            ],
        ) && body.matches(&tokens("requested?")).count() == 1
            && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    fn completed_check_is_actual(body: &str) -> bool {
        ordered(
            body,
            &[
                "let requested",
                "self.finishing.phase==PreparePhase::Complete",
                "self.finishing.check(storage,peer,loan)",
                "let checked=self.finishing.check(storage,peer,loan);",
                "if requested.is_err() || checked.is_err() {self.finishing.refuse();peer.refuse();loan.refuse();}",
                "requested?;checked",
            ],
        ) && body
            .matches(&tokens("self.finishing.check(storage,peer,loan)"))
            .count()
            == 2
            && body.matches(&tokens("requested?")).count() == 1
            && !body.contains(&tokens("NativeAcquisition::begin"))
    }

    #[test]
    fn actual_completed_issuer_rechecks_its_own_live_pending_and_loan_at_later_boundaries() {
        let actual = method("CompletedRestoreIssuer", "check");
        assert!(completed_check_is_actual(&actual));
        assert!(!completed_check_is_actual(&tokens(
            "fn check()->Result<()> {Ok(())}"
        )));
        for (before, after, count) in [
            ("self.finishing.phase==PreparePhase::Complete", "true", 1),
            ("self.finishing.check(storage,peer,loan)", "Ok(())", 2),
            (
                "let checked=self.finishing.check(storage,peer,loan);",
                "let checked:Result<()>=Ok(());",
                1,
            ),
            (
                "let checked=self.finishing.check(storage,peer,loan);",
                "requested?;let checked=self.finishing.check(storage,peer,loan);",
                1,
            ),
            (
                "requested.is_err() || checked.is_err()",
                "checked.is_err()",
                1,
            ),
            (
                "self.finishing.refuse();peer.refuse();loan.refuse();",
                "self.finishing.refuse();",
                1,
            ),
            ("requested?;checked", "checked?;requested", 1),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), count, "{before}");
            assert!(
                !completed_check_is_actual(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }

    #[test]
    fn actual_finish_factory_uses_same_original_owners_and_spends_before_connect() {
        let actual = method("FrozenRoleIssuer", "begin_finish_restore");
        assert!(begin_is_actual(&actual));
        for (before, after) in [
            ("self.finish_attempted=true;", "let _reusable=();"),
            (
                "peer.finish_binding_data(storage,loan)?",
                "caller_binding()",
            ),
            ("data.frozen==self.digest_data()?", "true"),
            (
                "self.original.narrow(5,std::time::Duration::from_nanos(app.original.deadline_ns))?",
                "NativeAcquisition::begin(5)?",
            ),
            (
                "let checked=pending.check(storage,peer,loan);",
                "let checked:Result<()>=Ok(());",
            ),
            (
                "let pending=requested?;issuer_post?;peer_post?;Ok(pending)",
                "peer_post?;issuer_post?;let pending=requested?;Ok(pending)",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !begin_is_actual(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }

    #[test]
    fn actual_pending_check_joins_same_role_live_issuer_and_exact_peer_even_on_failure() {
        let actual = method("IssuerRestoreFinishing", "check");
        assert!(check_is_joined(&actual));
        assert!(!check_is_joined(&tokens("fn check()->Result<()> {Ok(())}")));
        for (before, after) in [
            (
                "self.same.meet_current_read_view(stage,&mut self.original)?;",
                "let _unchecked=();",
            ),
            ("stage.owner.certificate==self.certificate", "true"),
            ("signed.statement.request==self.request", "true"),
            (
                "Some(&signed.statement.challenge)==self.challenge.as_ref()",
                "true",
            ),
            ("data==self.data && app==self.app", "true"),
            (
                "let peer_post:Result<()>",
                "requested?;let peer_post:Result<()>",
            ),
            (
                "let original_post=self.original.remaining();",
                "let original_post=Ok(std::time::Duration::ZERO);",
            ),
            (
                "self.refuse();peer.refuse();loan.refuse();",
                "self.refuse();",
            ),
            (
                "requested?;peer_post?;original_post.map",
                "peer_post?;requested?;original_post.map",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(actual.matches(&before).count(), 1, "{before}");
            assert!(
                !check_is_joined(&actual.replacen(&before, &tokens(after), 1)),
                "{before}"
            );
        }
    }

    #[test]
    fn every_fixed_finish_operation_has_actual_guard_and_independent_result_post() {
        for (name, current, next, effect) in [
            ("send_hello", "Hello", "Nonce", "Packet::RestoreFinishHello"),
            (
                "receive_nonce",
                "Nonce",
                "Sign",
                "Packet::RestoreFinishNonce",
            ),
            (
                "sign_bind",
                "Sign",
                "Bind",
                "\"restore-issuer-finish-bind-v1\"",
            ),
            ("send_bind", "Bind", "Grant", "Packet::RestoreFinishBind"),
            (
                "receive_grant",
                "Grant",
                "Complete",
                "Packet::RestoreFinishGrant",
            ),
        ] {
            let actual = method("IssuerRestoreFinishing", name);
            let valid = |body: &str| {
                ordered(
                    body,
                    &[
                        "RestoreFinalInstallationLoan",
                        &format!("self.phase.enter(PreparePhase::{current})?;"),
                        "self.check(storage,peer,loan)?;",
                        effect,
                        &format!(
                            "self.complete_step(requested,storage,peer,loan,PreparePhase::{next})"
                        ),
                    ],
                ) && !body.contains(&tokens("NativeAcquisition::begin"))
            };
            assert!(valid(&actual), "{name}");
            let before = tokens("self.check(storage,peer,loan)?;");
            assert_eq!(actual.matches(&before).count(), 1);
            assert!(!valid(&actual.replacen(
                &before,
                &tokens("let _unchecked=();"),
                1
            )));
        }
        let post = method("IssuerRestoreFinishing", "complete_step");
        let valid = |body: &str| {
            ordered(
                body,
                &[
                    "let checked=self.check(storage,peer,loan);",
                    "if requested.is_err() || checked.is_err() {self.refuse();peer.refuse();loan.refuse();}",
                    "requested?;checked?;",
                    "let advanced=self.phase.complete(next);",
                    "if advanced.is_err() {self.refuse();peer.refuse();loan.refuse();}",
                    "advanced",
                ],
            ) && body.matches(&tokens("requested?")).count() == 1
        };
        assert!(valid(&post));
        for (before, after) in [
            (
                "let checked=self.check(storage,peer,loan);",
                "requested?;let checked=self.check(storage,peer,loan);",
            ),
            ("requested?;checked?;", "checked?;requested?;"),
            (
                "if requested.is_err() || checked.is_err() {self.refuse();peer.refuse();loan.refuse();}",
                "if requested.is_err() || checked.is_err() {self.refuse();}",
            ),
            (
                "if advanced.is_err() {self.refuse();peer.refuse();loan.refuse();}",
                "if advanced.is_err() {self.refuse();}",
            ),
        ] {
            let before = tokens(before);
            assert_eq!(post.matches(&before).count(), 1);
            assert!(!valid(&post.replacen(&before, &tokens(after), 1)));
        }
        let finish = method("IssuerRestoreFinishing", "finish");
        assert!(ordered(
            &finish,
            &[
                "self.phase==PreparePhase::Complete",
                "self.signed.is_some() && self.nonce_peer.is_some() && self.grant_peer.is_some()",
                "self.check(storage,peer,loan)",
                "let checked=self.check(storage,peer,loan);",
                "requested?;checked?;Ok(CompletedRestoreIssuer {finishing:self,role_activation_attempted:false})"
            ]
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::PreparePhase as Phase;
    use syn::visit::Visit;

    fn method<'a>(file: &'a syn::File, owner: &str, name: &str) -> &'a syn::ImplItemFn {
        file.items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(implementation) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*implementation.self_ty else {
                    return None;
                };
                if !path.path.is_ident(owner) {
                    return None;
                }
                implementation.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                    _ => None,
                })
            })
            .unwrap()
    }

    #[derive(Default)]
    struct Calls {
        operations: Vec<String>,
        signature_domains: Vec<String>,
        renewed: bool,
    }

    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            let name = call.method.to_string();
            if ["send", "receive_issuer", "sign"].contains(&name.as_str())
                || (name == "check"
                    && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("self")))
            {
                self.operations.push(name.clone());
            }
            if name == "sign"
                && let Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(value),
                    ..
                })) = call.args.first()
            {
                self.signature_domains.push(value.value());
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.renewed |= path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "begin");
            }
            syn::visit::visit_expr_call(self, call);
        }
    }

    fn fixed_operation(method: &syn::ImplItemFn, expected: &[&str], sign: bool) -> bool {
        let mut calls = Calls::default();
        calls.visit_impl_item_fn(method);
        fn propagated(statement: &syn::Stmt, name: &str) -> bool {
            matches!(statement,syn::Stmt::Expr(syn::Expr::Try(tried),Some(_))
                if matches!(&*tried.expr,syn::Expr::Path(path) if path.path.is_ident(name)))
        }
        method.block.stmts.len() == 6
            && propagated(&method.block.stmts[3], "requested")
            && propagated(&method.block.stmts[4], "checked")
            && !calls.renewed
            && calls.operations == expected
            && calls.signature_domains
                == if sign {
                    vec!["restore-controller-authorize"]
                } else {
                    vec![]
                }
            && matches!(method.block.stmts.get(1),Some(syn::Stmt::Local(local))
                if matches!(&local.pat,syn::Pat::Ident(name) if name.ident=="checked")
                && matches!(local.init.as_ref().map(|init|&*init.expr),Some(syn::Expr::MethodCall(call))
                    if call.method=="check" && call.args.len()==1
                    && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("self"))
                    && matches!(&call.args[0],syn::Expr::Path(path) if path.path.is_ident("storage"))))
    }

    #[test]
    fn actual_prepare_steps_keep_independent_native_posts_and_fixed_key_domain() {
        let file = syn::parse_file(include_str!("restore.rs")).unwrap();
        for (name, expected, sign) in [
            ("send_hello", vec!["check", "send", "check"], false),
            (
                "receive_nonce",
                vec!["check", "receive_issuer", "check", "check"],
                false,
            ),
            ("sign_bind", vec!["check", "sign", "check", "check"], true),
            ("send_bind", vec!["check", "send", "check"], false),
            (
                "receive_grant",
                vec!["check", "receive_issuer", "check", "check"],
                false,
            ),
        ] {
            let actual = method(&file, "IssuerRestorePreparation", name);
            assert!(fixed_operation(actual, &expected, sign), "{name}");
            let mut missing = actual.clone();
            missing.block.stmts[1] = syn::parse_quote!(let checked: Result<()> = Ok(()););
            assert!(
                !fixed_operation(&missing, &expected, sign),
                "missing unconditional post {name}"
            );
            let mut discarded = actual.clone();
            discarded.block.stmts[4] = syn::parse_quote!(let _ = checked;);
            assert!(
                !fixed_operation(&discarded, &expected, sign),
                "discarded failed post {name}"
            );
            let mut renewed = actual.clone();
            renewed.block.stmts.insert(
                0,
                syn::parse_quote!(let _replacement=NativeAcquisition::begin(5)?;),
            );
            assert!(
                !fixed_operation(&renewed, &expected, sign),
                "renewed original {name}"
            );
        }
    }

    #[test]
    fn fixed_prepare_order_never_replays_or_finishes_an_uncertain_step() {
        for (index, next) in [
            Phase::Hello,
            Phase::Nonce,
            Phase::Sign,
            Phase::Bind,
            Phase::Grant,
            Phase::Complete,
        ]
        .into_iter()
        .enumerate()
        {
            let expected = [
                Phase::Connecting,
                Phase::Hello,
                Phase::Nonce,
                Phase::Sign,
                Phase::Bind,
                Phase::Grant,
            ][index];
            let mut phase = expected;
            phase.enter(expected).unwrap();
            assert!(phase == Phase::InFlight);
            let mut uncertain = phase;
            assert!(uncertain.enter(expected).is_err());
            assert!(uncertain == Phase::Refused);
            assert!(uncertain.complete(next).is_err());
            phase.complete(next).unwrap();
            assert!(phase == next);
            assert!(phase.enter(expected).is_err());
            assert!(phase == Phase::Refused);
        }
    }
}

impl CompletedRestoreIssuer {
    pub(in crate::security_epoch) fn begin_app_role_activation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<IssuerRestoreRoleActivating> {
        let mut attempt = RoleHandoffAttempt {
            peer,
            issuer: self,
            loan,
            done: false,
        };
        let requested: Result<IssuerRestoreRoleActivating> = (|| {
            ensure!(
                !attempt.issuer.role_activation_attempted,
                "native_restore_role_activation_attempt_spent"
            );
            attempt.issuer.role_activation_attempted = true;
            attempt.issuer.check(storage, attempt.peer, attempt.loan)?;
            attempt.peer.require_role_handoff_delivered()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let completion = attempt
                    .issuer
                    .finishing
                    .signed
                    .as_ref()
                    .context("native_restore_role_completion_missing")?
                    .clone();
                let original = attempt.issuer.finishing.original.narrow(
                    5,
                    std::time::Duration::from_nanos(completion.statement.effective_deadline_ns),
                )?;
                let mut pending = IssuerRestoreRoleActivating {
                    original,
                    same: storage.stage.capture_same_owner()?,
                    certificate: attempt.issuer.finishing.certificate.clone(),
                    completion,
                    app: attempt.issuer.finishing.app.clone(),
                    request: protocol::nonce("restore-app-role-request")?,
                    challenge: None,
                    nonce_peer: None,
                    grant_peer: None,
                    channel: None,
                    signed: None,
                    phase: PreparePhase::Connecting,
                    refused: false,
                    confirmation_attempted: false,
                    local: std::marker::PhantomData,
                };
                pending.phase.enter(PreparePhase::Connecting)?;
                pending.check(storage, attempt.peer, attempt.issuer, attempt.loan)?;
                let connected = Channel::connect(&mut pending.original);
                let checked = pending.check(storage, attempt.peer, attempt.issuer, attempt.loan);
                if connected.is_err() || checked.is_err() {
                    pending.refuse();
                }
                pending.channel = Some(connected?);
                checked?;
                pending.phase.complete(PreparePhase::Hello)?;
                Ok(pending)
            }
        })();
        let checked = attempt.issuer.check(storage, attempt.peer, attempt.loan);
        if requested.is_err() || checked.is_err() {
            attempt.peer.refuse();
            attempt.issuer.refuse();
            attempt.loan.refuse();
        }
        let pending = requested?;
        checked?;
        attempt.done = true;
        Ok(pending)
    }
}

impl IssuerRestoreRoleActivating {
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.phase = PreparePhase::Refused;
        #[cfg(target_os = "linux")]
        self.original.refuse();
    }

    fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(
                !self.refused && self.phase != PreparePhase::Refused,
                "native_restore_role_activation_refused"
            );
            peer.require_role_handoff_delivered()?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let stage = &mut *storage.stage;
                self.same
                    .meet_current_read_view(stage, &mut self.original)?;
                stage.require_purpose(StagePurpose::CurrentRole)?;
                ensure!(
                    stage.owner.role == NativeRole::EpochController
                        && stage.owner.certificate == self.certificate
                        && completed.role_activation_attempted
                        && completed.finishing.signed.as_ref() == Some(&self.completion)
                        && completed.finishing.app == self.app,
                    "native_restore_role_activation_owner_changed"
                );
                self.completion.verify_data(
                    &stage.owner.policy,
                    &self.certificate,
                    &self.completion.statement.data,
                    &self.app,
                    self.original.sample()?.elapsed,
                )?;
                if let Some(signed) = &self.signed {
                    signed.verify_data(
                        &stage.owner.policy,
                        &self.certificate,
                        &self.completion,
                        &self.app,
                        (
                            &self.request,
                            self.challenge
                                .as_ref()
                                .context("native_restore_role_challenge_missing")?,
                        ),
                        self.original.sample()?.elapsed,
                    )?;
                }
                if let Some(issuer) = &mut self.nonce_peer {
                    issuer.check_live(&mut self.original)?;
                }
                if let Some(issuer) = &mut self.grant_peer {
                    issuer.check_live(&mut self.original)?;
                }
                stage.check()?;
                self.original.remaining().map(|_| ())
            }
        })();
        let checked = completed.check(storage, peer, loan);
        #[cfg(target_os = "linux")]
        let original_post = self.original.remaining().map(|_| ());
        #[cfg(not(target_os = "linux"))]
        let original_post: Result<()> = Err(anyhow::anyhow!("native_restore_platform_unsupported"));
        if requested.is_err() || checked.is_err() || original_post.is_err() {
            self.refuse();
            completed.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        checked?;
        original_post
    }

    // Result-only post helper: no callback or caller-supplied operation escapes.
    fn complete_role_step(
        &mut self,
        requested: Result<()>,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
        next: PreparePhase,
    ) -> Result<()> {
        let checked = self.check(storage, peer, completed, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            completed.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        checked?;
        let advanced = self.phase.complete(next);
        if advanced.is_err() {
            self.refuse();
            completed.refuse();
            peer.refuse();
            loan.refuse();
        }
        advanced
    }

    pub(in crate::security_epoch) fn send_hello(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Hello)?;
            self.check(storage, peer, completed, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            self.channel
                .as_mut()
                .context("native_restore_role_channel_missing")?
                .send(
                    &Packet::RestoreRoleHello {
                        completion: Box::new(self.completion.clone()),
                        request: self.request.clone(),
                    },
                    &mut self.original,
                )
        })();
        self.complete_role_step(
            requested,
            storage,
            peer,
            completed,
            loan,
            PreparePhase::Nonce,
        )
    }

    pub(in crate::security_epoch) fn receive_nonce(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Nonce)?;
            self.check(storage, peer, completed, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let received = self
                    .channel
                    .as_mut()
                    .context("native_restore_role_channel_missing")?
                    .receive_issuer(&mut self.original);
                let checked = self.check(storage, peer, completed, loan);
                let (packet, mut issuer) = received?;
                checked?;
                let Packet::RestoreRoleNonce {
                    completion,
                    request,
                    challenge,
                } = packet
                else {
                    anyhow::bail!("native_restore_role_nonce_expected")
                };
                ensure!(
                    completion == self.completion.digest_data()? && request == self.request,
                    "native_restore_role_nonce_changed"
                );
                issuer.bind(
                    &self.certificate,
                    &storage.stage.owner.policy,
                    &mut self.original,
                )?;
                issuer.check_live(&mut self.original)?;
                self.nonce_peer = Some(issuer);
                self.challenge = Some(challenge);
                Ok(())
            }
        })();
        self.complete_role_step(
            requested,
            storage,
            peer,
            completed,
            loan,
            PreparePhase::Bind,
        )
    }

    pub(in crate::security_epoch) fn send_bind(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Bind)?;
            self.check(storage, peer, completed, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let challenge = self
                    .challenge
                    .as_ref()
                    .context("native_restore_role_challenge_missing")?
                    .clone();
                let signed = storage.stage.owner.key.sign(
                    "restore-app-role-bind-v1",
                    &(&self.completion, &self.request, &challenge),
                );
                let checked = self.check(storage, peer, completed, loan);
                let signature = signed?;
                checked?;
                self.channel
                    .as_mut()
                    .context("native_restore_role_channel_missing")?
                    .send(
                        &Packet::RestoreRoleBind {
                            completion: Box::new(self.completion.clone()),
                            request: self.request.clone(),
                            challenge,
                            signature,
                        },
                        &mut self.original,
                    )
            }
        })();
        self.complete_role_step(
            requested,
            storage,
            peer,
            completed,
            loan,
            PreparePhase::Grant,
        )
    }

    pub(in crate::security_epoch) fn receive_grant(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested = (|| {
            self.phase.enter(PreparePhase::Grant)?;
            self.check(storage, peer, completed, loan)?;
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                let received = self
                    .channel
                    .as_mut()
                    .context("native_restore_role_channel_missing")?
                    .receive_issuer(&mut self.original);
                let checked = self.check(storage, peer, completed, loan);
                let (packet, mut issuer) = received?;
                checked?;
                issuer.bind(
                    &self.certificate,
                    &storage.stage.owner.policy,
                    &mut self.original,
                )?;
                issuer.check_live(&mut self.original)?;
                let Packet::RestoreRoleGrant { activation } = packet else {
                    anyhow::bail!("native_restore_role_grant_expected")
                };
                activation.verify_data(
                    &storage.stage.owner.policy,
                    &self.certificate,
                    &self.completion,
                    &self.app,
                    (
                        &self.request,
                        self.challenge
                            .as_ref()
                            .context("native_restore_role_challenge_missing")?,
                    ),
                    self.original.sample()?.elapsed,
                )?;
                let ceiling =
                    std::time::Duration::from_nanos(activation.statement.effective_deadline_ns);
                self.original = self.original.narrow(5, ceiling)?;
                completed.finishing.original = completed.finishing.original.narrow(5, ceiling)?;
                self.grant_peer = Some(issuer);
                self.signed = Some(*activation);
                Ok(())
            }
        })();
        self.complete_role_step(
            requested,
            storage,
            peer,
            completed,
            loan,
            PreparePhase::Complete,
        )
    }

    pub(in crate::security_epoch) fn finish(
        mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<ActivatedRestoredAppRole> {
        let requested: Result<()> = (|| {
            ensure!(
                self.phase == PreparePhase::Complete,
                "native_restore_role_activation_incomplete"
            );
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_restore_platform_unsupported");
            #[cfg(target_os = "linux")]
            {
                ensure!(
                    self.signed.is_some() && self.nonce_peer.is_some() && self.grant_peer.is_some(),
                    "native_restore_role_native_receipts_missing"
                );
                self.check(storage, peer, completed, loan)
            }
        })();
        let checked = self.check(storage, peer, completed, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            completed.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        checked?;
        Ok(ActivatedRestoredAppRole { pending: self })
    }
}

impl ActivatedRestoredAppRole {
    /// Prepared acknowledgement only. Its caller independently checks the full
    /// restore parent before retaining this receipt or sending any acceptance.
    pub(in crate::security_epoch) fn receive_app_confirmation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<PreparedRestoredAppConfirmation> {
        PreparedConfirmationReceiveAttempt {
            peer,
            issuer: completed,
            activation: self,
            loan,
            #[cfg(target_os = "linux")]
            original: None,
            #[cfg(target_os = "linux")]
            sender: None,
            #[cfg(target_os = "linux")]
            transcript: None,
            done: false,
        }
        .receive(storage)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.pending.refuse();
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            ensure!(
                self.pending.phase == PreparePhase::Complete,
                "native_restore_role_activation_incomplete"
            );
            self.pending.check(storage, peer, completed, loan)
        })();
        let checked = self.pending.check(storage, peer, completed, loan);
        if requested.is_err() || checked.is_err() {
            self.refuse();
            completed.refuse();
            peer.refuse();
            loan.refuse();
        }
        requested?;
        checked
    }
}

impl PreparedRestoredAppConfirmation {
    /// Distinct installed acknowledgement, never a send-only prepared result.
    /// The fixed receiver checks the real sender and complete installed DATA.
    pub(in crate::security_epoch) fn receive_installed_confirmation(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<InstalledRestoredAppConfirmation> {
        InstalledConfirmationReceiveAttempt {
            prepared: self,
            peer,
            issuer: completed,
            activation,
            loan,
            #[cfg(target_os = "linux")]
            original: None,
            #[cfg(target_os = "linux")]
            sender: None,
            #[cfg(target_os = "linux")]
            transcript: None,
            done: false,
        }
        .receive(storage)
    }

    /// Only the retained prepared carrier's fixed driver may call this after
    /// its full parent post. The same packet remains bound on every retry.
    pub(in crate::security_epoch) fn try_send_acceptance(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        PreparedAcceptanceAttempt {
            confirmation: self,
            peer,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, super::PreparedAcceptanceOperation::Send)
    }

    pub(in crate::security_epoch) fn poll_acceptance(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        PreparedAcceptanceAttempt {
            confirmation: self,
            peer,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, super::PreparedAcceptanceOperation::Poll)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.acceptance_phase = super::PreparedAcceptancePhase::Refused;
        #[cfg(target_os = "linux")]
        {
            self.same.refused = true;
            self.original.refuse();
        }
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        self.check_received_confirmation(storage, peer, completed, activation, loan)
    }
}

impl InstalledRestoredAppConfirmation {
    /// The same actual installed carrier's fixed send step. This remains
    /// retains one signed packet through retries. The caller brackets each
    /// step with full parent posts.
    pub(in crate::security_epoch) fn try_send_acceptance(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        prepared: &mut PreparedRestoredAppConfirmation,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        InstalledAcceptanceAttempt {
            confirmation: self,
            prepared,
            peer,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, super::PreparedAcceptanceOperation::Send)
    }

    /// Bounded wait on that same retained packet, never a retry/reconstruction.
    /// The same original and immutable packet survive every interrupted wait.
    pub(in crate::security_epoch) fn poll_acceptance(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        prepared: &mut PreparedRestoredAppConfirmation,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<crate::security_epoch::native_enrollment::ReceiverProgress> {
        InstalledAcceptanceAttempt {
            confirmation: self,
            prepared,
            peer,
            issuer: completed,
            activation,
            loan,
            done: false,
        }
        .perform(storage, super::PreparedAcceptanceOperation::Poll)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.acceptance_phase = super::PreparedAcceptancePhase::Refused;
        #[cfg(target_os = "linux")]
        {
            self.same.refused = true;
            self.original.refuse();
        }
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        storage: &mut EnrolledStorageStage<'_, '_>,
        peer: &mut RestoredWriterPeer,
        completed: &mut CompletedRestoreIssuer,
        activation: &mut ActivatedRestoredAppRole,
        prepared: &mut PreparedRestoredAppConfirmation,
        loan: &mut crate::security_epoch::bootstrap::RestoreFinalInstallationLoan<'_, '_, '_>,
    ) -> Result<()> {
        self.check_received_installation(storage, peer, completed, activation, prepared, loan)
    }
}
