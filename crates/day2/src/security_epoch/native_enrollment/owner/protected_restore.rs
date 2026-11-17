//! Fixed protected-message signing on the actual enrolled thread/key/stage.
//! No parsed certificate, caller key, scalar clock or generic signing purpose
//! can replace this owner. These hooks do not admit a native peer or Current.

use super::request_frame::EnrolledStageFrame;
use super::{
    EnrolledCurrentRequest, EnrolledProcessRoleOwner, EnrolledRoleStage, NativeConsumerOrigin,
    SameEnrolledOwner,
};
use crate::security_epoch::native_enrollment::{
    NativeRole,
    protected_restore::{
        ProtectedRestoreActionGuard, ProtectedRestoreMessage, ProtectedRestoreTurn,
    },
    protocol::StagePurpose,
    serving_peer_wire::Statement,
};
use anyhow::{Result, ensure};

/// Fixed installed-output signer. The installed carrier is checked AFTER all
/// native statement work, immediately before key use. Nothing can replace the
/// retained turn, loan or original with decoded output DATA.
pub(in crate::security_epoch::native_enrollment) fn sign_protected_restore_installed(
    turn: &mut ProtectedRestoreTurn<'_>,
    stage: &mut EnrolledRoleStage<'_>,
    loan: &mut crate::security_epoch::bootstrap::RestoreInstalledOutputLoan<'_, '_, '_>,
    original: &NativeConsumerOrigin,
    data:&crate::security_epoch::native_enrollment::protected_restore::ProtectedRestoreInstalledData,
) -> Result<String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = data;
        turn.refuse();
        stage.refuse_serving();
        loan.refuse();
        original.refuse();
        anyhow::bail!("native_protected_restore_transport_unavailable");
    }
    #[cfg(target_os = "linux")]
    {
        let requested =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<String> {
                turn.require_received_guard(stage)?;
                turn.require_installed_binding(data)?;
                let local = stage.protected_restore_statement()?;
                data.require_signer(&local, turn.admitted_statement()?)?;
                let commitment = data.commitment()?;
                let output = {
                    let mut storage = stage.storage()?;
                    loan.check(&mut storage)?
                };
                data.require_output(&output)?;
                check_protected_restore_installed_original(stage, original, data)?;
                stage.owner.key.sign(
            crate::security_epoch::native_enrollment::protected_restore::INSTALLED_SIGNING_DOMAIN,
            &commitment,
        )
            }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let output = {
                let mut storage = stage.storage()?;
                loan.check(&mut storage)?
            };
            data.require_output(&output)?;
            check_protected_restore_installed_original(stage, original, data)
        }));
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        let checked =
            crate::security_epoch::native_enrollment::protected_restore::select_guard_check(
                checked, native,
            );
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            loan.refuse();
            turn.refuse();
            original.refuse();
            stage.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(signature)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(signature)
                }
            },
        }
    }
}

/// Only the same actual retained original and its already-narrowed interval.
/// No native I/O or issuer work occurs between the last loan check and signing
/// or sending. Equality/rewind/expiry still refuse on the actual original.
pub(in crate::security_epoch::native_enrollment) fn check_protected_restore_installed_original(
    stage: &mut EnrolledRoleStage<'_>,
    original: &NativeConsumerOrigin,
    data:&crate::security_epoch::native_enrollment::protected_restore::ProtectedRestoreInstalledData,
) -> Result<()> {
    let requested = (|| {
        // require_purpose itself performs native I/O; the full native/role
        // check already ran before the loan. This last join is deliberately
        // identity/interval plus a fresh sample of the actual original only.
        ensure!(
            stage.purpose == StagePurpose::CurrentRole
                && stage.owner.role == NativeRole::EpochController
                && !stage.owner.refused,
            "protected_restore_installed_native_role_changed"
        );
        original.require_acquisition(stage.acquisition.as_mut())?;
        let (domain, origin, deadline, _) =
            stage.acquisition.as_mut().historical_interval_observation();
        let actual =
            crate::security_epoch::native_enrollment::storage_peer_wire::OriginalInterval {
                purpose: StagePurpose::CurrentRole,
                domain,
                origin_ns: u64::try_from(origin.as_nanos())?,
                deadline_ns: u64::try_from(deadline.min(stage.deadline).as_nanos())?,
            };
        data.require_original(&actual)?;
        stage.acquisition.as_mut().remaining().map(|_| ())
    })();
    if requested.is_err() {
        original.refuse();
        stage.refuse_serving();
    }
    requested
}

/// Only a genuine opaque receiver-produced guard can enter this hook. It is
/// stored in the actual saved frame, not in a temporary stage or caller DTO.
pub(in crate::security_epoch::native_enrollment) fn attach_protected_restore_guard(
    stage: &mut EnrolledRoleStage<'_>,
    guard: ProtectedRestoreActionGuard,
) -> Result<()> {
    let mut pending = Some(guard);
    let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        pending
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_request_guard_missing"))?
            .require_stage(stage)?;
        pending
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_request_guard_missing"))?
            .check(stage.owner, stage.purpose, stage.acquisition.as_mut())?;
        let guard = pending
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_request_guard_missing"))?;
        if let Err(rejected) = stage.acquisition.attach(guard) {
            // Retain THIS packet's resources through the independent post,
            // including duplicate attachment. Refusal follows observation.
            pending = Some(rejected);
            anyhow::bail!("protected_restore_request_guard_already_attached");
        }
        Ok(())
    }));
    let pending_checked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match &mut pending {
            Some(guard) => guard.check(stage.owner, stage.purpose, stage.acquisition.as_mut()),
            None => Ok(()),
        }));
    let stage_checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
    let checked = match pending_checked {
        Ok(Ok(())) => stage_checked,
        failed => failed,
    };
    if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
        if let Some(guard) = &mut pending {
            guard.refuse();
        }
        stage.refuse_serving();
    }
    match requested {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(Err(error)) => Err(error),
        Ok(Ok(())) => match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result,
        },
    }
}

pub(in crate::security_epoch::native_enrollment) fn require_protected_restore_guard(
    stage: &mut EnrolledRoleStage<'_>,
    root: &std::rc::Rc<std::cell::Cell<bool>>,
    original: &NativeConsumerOrigin,
    connection: &day2_capabilities::Digest,
    sequence: u64,
) -> Result<()> {
    let result = stage
        .acquisition
        .require_guard(root, original, connection, sequence);
    if result.is_err() {
        stage.refuse_serving();
    }
    result
}

/// A consuming transfer is still an outstanding use of the original. Failure
/// or unwinding poisons both actual roots; taking the request is not settlement.
struct ProtectedRequestTransfer<'role> {
    owner: Option<&'role mut EnrolledProcessRoleOwner>,
    original: NativeConsumerOrigin,
    completed: bool,
}

impl Drop for ProtectedRequestTransfer<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.original.refuse();
            if let Some(owner) = self.owner.as_deref_mut() {
                owner.refused = true;
            }
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
            let _ = <ProtectedRequestTransfer<'static> as Ambiguous<_>>::check;
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

impl EnrolledProcessRoleOwner {
    /// The fixed native Authenticate turn consumes the SAME saved request.
    /// Its genuine acquisition moves only after requested and independent post
    /// checks. No borrowed stage is detached, and no clock is captured or copied.
    pub(in crate::security_epoch::native_enrollment) fn take_protected_restore_request<'role>(
        &'role mut self,
        mut request: EnrolledCurrentRequest,
        turn: &mut ProtectedRestoreTurn<'_>,
    ) -> Result<EnrolledRoleStage<'role>> {
        let mut attempt = ProtectedRequestTransfer {
            original: request.consumer_origin(),
            owner: Some(self),
            completed: false,
        };
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owner = attempt
                .owner
                .as_deref_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
            turn.require_accepting_original(&attempt.original, owner)?;
            let mut stage = owner.borrow_current_request(&mut request)?;
            stage.require_protected_restore_role(NativeRole::EpochController)?;
            turn.require_received_guard(&mut stage)?;
            attempt.original.check_current(&mut stage)
        }));
        // This observes the actual saved request even after a requested error
        // or panic. A repaired clock cannot rescue either failed check.
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
            let owner = attempt
                .owner
                .as_deref_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
            let mut stage = owner.borrow_current_request(&mut request)?;
            stage.require_protected_restore_role(NativeRole::EpochController)?;
            turn.require_received_guard(&mut stage)?;
            attempt.original.check_current(&mut stage)?;
            Ok(stage.deadline)
        }));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(_))) {
            turn.refuse_transfer();
        }
        // Preserve the requested primary result or panic. Only the actual
        // independent post can supply the final already-checked deadline DATA.
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(())) => {}
        }
        let deadline = match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => result?,
        };
        let frame = request
            .acquisition
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_original_missing"))?;
        let owner = attempt
            .owner
            .take()
            .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
        // After these successful takes, only construction of the SAME owned
        // stage and disarming this guard remain. Request Drop has no acquisition
        // left to finish/refuse; the returned stage and outer attempt own it.
        let stage = EnrolledRoleStage {
            owner,
            purpose: StagePurpose::CurrentRole,
            acquisition: EnrolledStageFrame::owned(frame),
            deadline,
        };
        attempt.completed = true;
        Ok(stage)
    }
}

impl SameEnrolledOwner {
    /// Fixed Shell side of the admitted restore channel. This is an identity
    /// and policy join, not a stage callback or native permission factory.
    pub(in crate::security_epoch::native_enrollment) fn require_protected_restore_shell_owner(
        &mut self,
        role: &EnrolledProcessRoleOwner,
        controller: &Statement,
    ) -> Result<()> {
        let requested = (|| {
            ensure!(
                !self.refused && !role.refused,
                "protected_restore_native_owner_refused"
            );
            ensure!(
                role.role == NativeRole::SecurityShell
                    && role.process == std::process::id()
                    && role.thread == std::thread::current().id(),
                "protected_restore_native_owner_changed"
            );
            let original = self
                .identity
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("native_enrollment_original_owner_dropped"))?;
            ensure!(
                std::rc::Rc::ptr_eq(&original, &role.identity)
                    && self.incarnation == role.incarnation,
                "native_enrollment_original_owner_replaced"
            );
            ensure!(
                controller.certificate == role.certificate
                    && controller.stage.data.policy == role.policy.digest()?
                    && controller.stage.data.role == NativeRole::EpochController,
                "protected_restore_shell_controller_identity_changed"
            );
            Ok(())
        })();
        if requested.is_err() {
            self.refused = true;
        }
        requested
    }

    /// Idle peer exclusion only: the actual owner identity, role, process and
    /// thread must still match before the caller captures a request. This
    /// observes no clock, kernel handle or provider and returns no Current.
    /// The later receive stage must independently check actual native facts.
    pub(in crate::security_epoch::native_enrollment) fn require_protected_restore_owner(
        &mut self,
        role: &EnrolledProcessRoleOwner,
    ) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.refused && !role.refused,
                "protected_restore_native_owner_refused"
            );
            ensure!(
                role.role == NativeRole::EpochController
                    && role.process == std::process::id()
                    && role.thread == std::thread::current().id(),
                "protected_restore_native_owner_changed"
            );
            let original = self
                .identity
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("native_enrollment_original_owner_dropped"))?;
            ensure!(
                std::rc::Rc::ptr_eq(&original, &role.identity)
                    && self.incarnation == role.incarnation,
                "native_enrollment_original_owner_replaced"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }
}

impl NativeConsumerOrigin {
    /// Negative identity of the actual saved Shell HTTP request. No clock,
    /// role or future response permission is exported by this fixed supplier.
    pub(in crate::security_epoch::native_enrollment) fn protected_restore_shell_reply(
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<Self> {
        let requested =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Self> {
                stage.require_protected_restore_role(NativeRole::SecurityShell)?;
                stage.acquisition.require_guard_slot()?;
                Ok(Self {
                    refusal: stage.acquisition.as_mut().retained_refusal(),
                    domain: stage
                        .acquisition
                        .as_mut()
                        .historical_interval_observation()
                        .0,
                })
            }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(origin)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(origin)
                }
            },
        }
    }

    /// Negative identity comparison only, for the fixed peer guard's actual
    /// acquisition. No clock observation or reusable checked token escapes.
    pub(in crate::security_epoch::native_enrollment) fn require_acquisition(
        &self,
        acquisition: &crate::security_epoch::native_clock::NativeAcquisition,
    ) -> Result<()> {
        let actual = Self {
            refusal: acquisition.retained_refusal(),
            domain: acquisition.historical_interval_observation().0,
        };
        self.require_same(&actual)
    }
    /// Negative identity of the ACTUAL Controller request being received.
    /// The result exposes no clock sample or acquisition, grants no native
    /// admission and cannot move the saved request. The fixed receiver must
    /// authenticate its actual peer, signed packet and cursor separately.
    pub(in crate::security_epoch::native_enrollment) fn received_protected_restore(
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<Self> {
        let requested =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Self> {
                stage.require_protected_restore_role(NativeRole::EpochController)?;
                Ok(Self {
                    refusal: stage.acquisition.as_mut().retained_refusal(),
                    domain: stage
                        .acquisition
                        .as_mut()
                        .historical_interval_observation()
                        .0,
                })
            }));
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            stage.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(origin)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(origin)
                }
            },
        }
    }
}

impl EnrolledRoleStage<'_> {
    pub(in crate::security_epoch::native_enrollment) fn require_protected_restore_role(
        &mut self,
        expected: NativeRole,
    ) -> Result<()> {
        let result = (|| {
            self.require_purpose(StagePurpose::CurrentRole)?;
            ensure!(
                matches!(
                    expected,
                    NativeRole::SecurityShell | NativeRole::EpochController
                ) && self.owner.role == expected,
                "protected_restore_native_role_changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse_serving();
        }
        result
    }

    /// The one-way attempt is recorded BEFORE issuer/connection I/O. Cold
    /// admission narrows the SAME captured original, never starts another one.
    pub(in crate::security_epoch::native_enrollment) fn begin_protected_restore_attempt(
        &mut self,
        expected: NativeRole,
    ) -> Result<()> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.require_protected_restore_role(expected)?;
            ensure!(
                !self.owner.protected_restore_attempted,
                "protected_restore_native_attempt_already_started"
            );
            self.owner.protected_restore_attempted = true;
            self.admit_peer_connection()?;
            self.require_protected_restore_role(expected)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse_serving();
                }
                result
            }
            Err(payload) => {
                self.refuse_serving();
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Enrollment/original DATA only. The shared native identity statement is
    /// not a serving connection, native peer or permission in this protocol.
    pub(in crate::security_epoch::native_enrollment) fn protected_restore_statement(
        &mut self,
    ) -> Result<Statement> {
        let result = (|| {
            ensure!(
                self.owner.protected_restore_attempted,
                "protected_restore_native_admission_not_attempted"
            );
            // Reuse the actual closed-role/current-purpose native statement
            // validator; do not repeat its full check immediately before it.
            self.serving_statement()
        })();
        if result.is_err() {
            self.refuse_serving();
        }
        result
    }

    /// Only the protocol's immutable closed DATA view selects one of its two
    /// fixed signature purposes. No arbitrary domain, bytes or key is accepted.
    pub(in crate::security_epoch::native_enrollment) fn sign_protected_restore_message(
        &mut self,
        message: &ProtectedRestoreMessage<'_>,
    ) -> Result<String> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let local = self.protected_restore_statement()?;
            let commitment = message.commitment_for(&local)?;
            self.owner.key.sign(message.domain(), &commitment)
        }));
        // Observe the SAME original even if DATA/signing failed. Neither an
        // uncertainty nor a repaired clock can make this owner reusable.
        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse_serving();
        }
        match requested {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(Err(error)) => Err(error),
            Ok(Ok(signature)) => match checked {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(result) => {
                    result?;
                    Ok(signature)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::request_frame::EnrolledRequestFrame;
    use super::*;
    use quote::ToTokens;
    use std::{marker::PhantomData, rc::Weak, time::Duration};

    fn fixture_request() -> EnrolledCurrentRequest {
        // Clock/refusal fixture only. No enrolled owner, peer or native stage
        // is fabricated, and no accepting transfer can run on this value.
        EnrolledCurrentRequest {
            identity: Weak::new(),
            incarnation: day2_capabilities::Digest::new(b"transfer-clock-fixture"),
            role: NativeRole::EpochController,
            process: std::process::id(),
            thread: std::thread::current().id(),
            acquisition: Some(EnrolledRequestFrame::new(
                crate::security_epoch::NativeAcquisition::fixture(
                    day2_capabilities::Digest::new(b"transfer-clock-domain"),
                    std::process::id(),
                    Duration::from_secs(100),
                    Duration::from_secs(5),
                ),
            )),
            finished: false,
            local: PhantomData,
        }
    }

    #[test]
    fn saved_request_drop_still_refuses_its_actual_clock_before_any_transfer() {
        let request = fixture_request();
        let original = request.consumer_origin();
        original.require_same(&original).unwrap();
        drop(request);
        assert!(original.require_same(&original).is_err());
    }

    #[test]
    fn actual_transfer_guard_refuses_the_moved_clock_on_error_and_unwind() {
        for unwind in [false, true] {
            for cut in 0..3 {
                let mut request = fixture_request();
                let mut moved = None;
                let mut stage = None;
                let original = request.consumer_origin();
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                        let _attempt = ProtectedRequestTransfer {
                            owner: None,
                            original: request.consumer_origin(),
                            completed: false,
                        };
                        if cut >= 1 {
                            moved = Some(request.acquisition.take().unwrap());
                        }
                        if cut >= 2 {
                            stage = Some(EnrolledStageFrame::owned(moved.take().unwrap()));
                        }
                        if unwind {
                            panic!("transfer fixture unwind");
                        }
                        anyhow::bail!("transfer fixture error")
                    }));
                if unwind {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_err());
                }
                assert!(original.require_same(&original).is_err());
                if let Some(original) = &mut request.acquisition {
                    assert!(original.original_mut().sample().is_err());
                }
                if let Some(original) = &mut moved {
                    assert!(original.original_mut().sample().is_err());
                }
                if let Some(stage) = &mut stage {
                    assert!(stage.as_mut().sample().is_err());
                }
                if cut >= 1 {
                    assert!(request.original_mut().is_err());
                }
            }
        }
    }

    #[test]
    fn moving_the_actual_acquisition_preserves_identity_and_an_equal_clock_cannot_replace_it() {
        let mut request = fixture_request();
        let original = request.consumer_origin();
        let mut stage = EnrolledStageFrame::owned(request.acquisition.take().unwrap());
        drop(request);
        let moved = NativeConsumerOrigin {
            refusal: stage.as_mut().retained_refusal(),
            domain: stage.as_mut().historical_interval_observation().0,
        };
        original.require_same(&moved).unwrap();
        stage.as_mut().sample().unwrap();
        let other = fixture_request();
        assert!(original.require_same(&other.consumer_origin()).is_err());
        assert!(stage.as_mut().sample().is_err());
        assert!(
            other
                .consumer_origin()
                .require_same(&other.consumer_origin())
                .is_err()
        );
    }

    #[test]
    fn received_negative_identity_from_a_real_saved_borrow_cannot_be_replaced_by_equal_clock_data()
    {
        let mut request = fixture_request();
        let saved = request.consumer_origin();
        let other = fixture_request();
        {
            // Actual saved acquisition borrow only. No enrolled owner, stage,
            // peer or Current permission is manufactured by this fixture.
            let mut borrowed = EnrolledStageFrame::borrowed(request.acquisition.as_mut().unwrap());
            let received = NativeConsumerOrigin {
                refusal: borrowed.as_mut().retained_refusal(),
                domain: borrowed.as_mut().historical_interval_observation().0,
            };
            saved.require_same(&received).unwrap();
            assert!(received.require_same(&other.consumer_origin()).is_err());
            assert!(borrowed.as_mut().sample().is_err());
        }
        assert!(saved.require_same(&saved).is_err());
        assert!(
            request
                .acquisition
                .as_mut()
                .unwrap()
                .original_mut()
                .sample()
                .is_err()
        );
        assert!(
            other
                .consumer_origin()
                .require_same(&other.consumer_origin())
                .is_err()
        );
    }

    #[test]
    fn actual_received_origin_captures_only_the_saved_negative_root_after_the_closed_role_guard() {
        let actual = method("received_protected_restore");
        assert_eq!(actual.sig.inputs.len(), 1);
        assert_eq!(actual.block.stmts.len(), 4);
        let capture = captured(&actual.block, "requested");
        let expected: syn::Block = syn::parse_quote!({
            stage.require_protected_restore_role(NativeRole::EpochController)?;
            Ok(Self {
                refusal: stage.acquisition.as_mut().retained_refusal(),
                domain: stage
                    .acquisition
                    .as_mut()
                    .historical_interval_observation()
                    .0,
            })
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&capture));
        for replacement in [
            syn::parse_quote!({
                Ok(Self {
                    refusal: stage.acquisition.as_mut().retained_refusal(),
                    domain: stage
                        .acquisition
                        .as_mut()
                        .historical_interval_observation()
                        .0,
                })
            }),
            syn::parse_quote!({
                stage.require_protected_restore_role(NativeRole::SecurityShell)?;
                Ok(Self {
                    refusal: stage.acquisition.as_mut().retained_refusal(),
                    domain: stage
                        .acquisition
                        .as_mut()
                        .historical_interval_observation()
                        .0,
                })
            }),
            syn::parse_quote!({
                stage.require_protected_restore_role(NativeRole::EpochController)?;
                Ok(Self {
                    refusal: other.acquisition.as_mut().retained_refusal(),
                    domain: stage
                        .acquisition
                        .as_mut()
                        .historical_interval_observation()
                        .0,
                })
            }),
        ] {
            assert!(!guarded(&replacement));
        }
        let post: syn::Stmt = syn::parse_quote!(let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check())););
        assert!(same(&actual.block.stmts[1], &post));
        let refused: syn::Stmt = syn::parse_quote! {
            if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) { stage.refuse_serving(); }
        };
        assert!(same(&actual.block.stmts[2], &refused));
        let text = actual.block.to_token_stream().to_string();
        for forbidden in [
            "NativeAcquisition",
            "begin_current",
            "sample",
            "interval_data",
            "narrow",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }

    fn method(name: &str) -> syn::ImplItemFn {
        method_in(include_str!("protected_restore.rs"), name)
    }

    fn method_in(source: &str, name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(source).unwrap();
        let methods = file
            .items
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item) => Some(item),
                _ => None,
            })
            .flat_map(|item| item.items)
            .filter_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 1, "one actual {name}");
        methods.into_iter().next().unwrap()
    }

    #[test]
    fn actual_idle_peer_exclusion_uses_the_retained_owner_without_a_current_or_clock() {
        // Actual production wiring controls only. No enrolled owner, native
        // peer or successful admission is invented by this portable test.
        let actual = method("require_protected_restore_owner");
        let expected: syn::Block = syn::parse_quote!({
            let result = (|| {
                ensure!(
                    !self.refused && !role.refused,
                    "protected_restore_native_owner_refused"
                );
                ensure!(
                    role.role == NativeRole::EpochController
                        && role.process == std::process::id()
                        && role.thread == std::thread::current().id(),
                    "protected_restore_native_owner_changed"
                );
                let original = self
                    .identity
                    .upgrade()
                    .ok_or_else(|| anyhow::anyhow!("native_enrollment_original_owner_dropped"))?;
                ensure!(
                    std::rc::Rc::ptr_eq(&original, &role.identity)
                        && self.incarnation == role.incarnation,
                    "native_enrollment_original_owner_replaced"
                );
                Ok(())
            })();
            if result.is_err() {
                self.refused = true;
            }
            result
        });
        fn exact(actual: &syn::Block, expected: &syn::Block) -> bool {
            actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
        }
        assert!(exact(&actual.block, &expected));
        fn signature(value: &syn::Signature) -> String {
            let mut value = value.clone();
            value.inputs.pop_punct();
            value.to_token_stream().to_string()
        }
        let expected_signature: syn::Signature = syn::parse_quote!(fn require_protected_restore_owner(&mut self, role: &EnrolledProcessRoleOwner) -> Result<()>);
        assert_eq!(signature(&actual.sig), signature(&expected_signature));
        fn work(block: &mut syn::Block) -> &mut syn::Block {
            let syn::Stmt::Local(local) = &mut block.stmts[0] else {
                panic!("actual result");
            };
            let syn::Expr::Call(call) = &mut *local.init.as_mut().unwrap().expr else {
                panic!("actual work");
            };
            let syn::Expr::Paren(paren) = &mut *call.func else {
                panic!("direct closure");
            };
            let syn::Expr::Closure(closure) = &mut *paren.expr else {
                panic!("closed work");
            };
            let syn::Expr::Block(body) = &mut *closure.body else {
                panic!("actual work body");
            };
            &mut body.block
        }
        let mut selected = actual.block.clone();
        assert_eq!(work(&mut selected).stmts.len(), 5);
        for index in 0..5 {
            let mut missing = actual.block.clone();
            work(&mut missing).stmts.remove(index);
            assert!(!exact(&missing, &expected));
        }
        for (index, changed) in [
            (
                0,
                syn::parse_quote!(ensure!(true, "protected_restore_native_owner_refused");),
            ),
            (
                1,
                syn::parse_quote!(ensure!(role.role == NativeRole::EpochController, "protected_restore_native_owner_changed");),
            ),
            (
                1,
                syn::parse_quote!(ensure!(role.process == std::process::id() && role.thread == std::thread::current().id(), "protected_restore_native_owner_changed");),
            ),
            (
                2,
                syn::parse_quote!(let original = std::rc::Rc::new(super::super::OwnerIdentity);),
            ),
            (
                3,
                syn::parse_quote!(ensure!(self.incarnation == role.incarnation, "native_enrollment_original_owner_replaced");),
            ),
            (
                3,
                syn::parse_quote!(ensure!(std::rc::Rc::ptr_eq(&original, &other.identity), "native_enrollment_original_owner_replaced");),
            ),
        ] {
            let mut wrong = actual.block.clone();
            work(&mut wrong).stmts[index] = changed;
            assert!(!exact(&wrong, &expected));
        }
        for index in 0..actual.block.stmts.len() {
            let mut missing = actual.block.clone();
            missing.stmts.remove(index);
            assert!(!exact(&missing, &expected));
        }
        let mut reset = actual.block.clone();
        reset.stmts[1] = syn::parse_quote!(if result.is_err() {
            self.refused = false;
        });
        assert!(!exact(&reset, &expected));
        let mut capture = actual.block.clone();
        capture
            .stmts
            .insert(0, syn::parse_quote!(let _ = role.begin_current_request()?;));
        assert!(!exact(&capture, &expected));

        let peer = method_in(include_str!("../protected_restore.rs"), "require_owner");
        let expected_signature: syn::Signature = syn::parse_quote!(fn require_owner(&mut self, role: &EnrolledProcessRoleOwner) -> Result<()>);
        assert_eq!(signature(&peer.sig), signature(&expected_signature));
        let expected: syn::Block = syn::parse_quote!({
            let result = (|| {
                ensure!(!self.refused.get(), "protected_restore_peer_refused");
                self._same.require_protected_restore_owner(role)
            })();
            if result.is_err() {
                self.refuse();
            }
            result
        });
        assert!(exact(&peer.block, &expected));
        for index in 0..peer.block.stmts.len() {
            let mut missing = peer.block.clone();
            missing.stmts.remove(index);
            assert!(!exact(&missing, &expected));
        }
        let mut other = peer.block.clone();
        work(&mut other).stmts[1] = syn::Stmt::Expr(
            syn::parse_quote!(other._same.require_protected_restore_owner(role)),
            None,
        );
        assert!(!exact(&other, &expected));
        let mut skipped = peer.block.clone();
        work(&mut skipped).stmts[1] = syn::Stmt::Expr(syn::parse_quote!(Ok(())), None);
        assert!(!exact(&skipped, &expected));
    }

    fn captured(block: &syn::Block, name: &str) -> syn::Block {
        let syn::Stmt::Local(local) = &block.stmts[0] else {
            panic!("first actual operation");
        };
        assert!(matches!(&local.pat, syn::Pat::Ident(id) if id.ident == name));
        let syn::Expr::Call(catch) = &*local.init.as_ref().unwrap().expr else {
            panic!("catch");
        };
        assert_eq!(
            catch.func.to_token_stream().to_string(),
            "std :: panic :: catch_unwind"
        );
        assert_eq!(catch.args.len(), 1);
        let syn::Expr::Call(safe) = &catch.args[0] else {
            panic!("unwind-safe wrapper");
        };
        assert_eq!(
            safe.func.to_token_stream().to_string(),
            "std :: panic :: AssertUnwindSafe"
        );
        assert_eq!(safe.args.len(), 1);
        let syn::Expr::Closure(closed) = &safe.args[0] else {
            panic!("actual closed work");
        };
        assert!(closed.inputs.is_empty() && closed.asyncness.is_none() && closed.capture.is_none());
        let syn::Expr::Block(body) = &*closed.body else {
            panic!("actual work block");
        };
        body.block.clone()
    }

    fn same(actual: &syn::Stmt, expected: &syn::Stmt) -> bool {
        actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
    }

    #[test]
    fn actual_guard_attachment_keeps_pending_sender_observable_after_role_failure_panic_or_duplicate()
     {
        let methods = syn::parse_file(include_str!("protected_restore.rs"))
            .unwrap()
            .items
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "attach_protected_restore_guard" => {
                    Some(item)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 1);
        let actual = &methods[0].block;
        let expected: syn::Block = syn::parse_quote!({
            let pending_checked =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match &mut pending {
                    Some(guard) => {
                        guard.check(stage.owner, stage.purpose, stage.acquisition.as_mut())
                    }
                    None => Ok(()),
                }));
            let stage_checked =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.check()));
            let checked = match pending_checked {
                Ok(Ok(())) => stage_checked,
                failed => failed,
            };
            if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
                if let Some(guard) = &mut pending {
                    guard.refuse();
                }
                stage.refuse_serving();
            }
            match requested {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(Err(error)) => Err(error),
                Ok(Ok(())) => match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => result,
                },
            }
        });
        fn same_guard_post(actual: &syn::Stmt, expected: &syn::Stmt) -> bool {
            fn guard_call(value: &syn::Expr) -> bool {
                let expected: syn::Expr = syn::parse_str(
                    "guard.check(stage.owner, stage.purpose, stage.acquisition.as_mut())",
                )
                .unwrap();
                value.to_token_stream().to_string() == expected.to_token_stream().to_string()
            }
            fn statement_value(statement: &mut syn::Stmt) {
                match statement {
                    syn::Stmt::Local(local) => {
                        if let Some(init) = &mut local.init {
                            expression(&mut init.expr);
                        }
                    }
                    syn::Stmt::Expr(value, _) => expression(value),
                    _ => {}
                }
            }
            fn expression(value: &mut syn::Expr) {
                match value {
                    syn::Expr::Call(call) => {
                        expression(&mut call.func);
                        for arg in &mut call.args {
                            expression(arg);
                        }
                    }
                    syn::Expr::Closure(closure) => expression(&mut closure.body),
                    syn::Expr::Match(value) => {
                        for arm in &mut value.arms {
                            expression(&mut arm.body);
                            if guard_call(&arm.body) {
                                arm.comma = Some(Default::default());
                            }
                        }
                    }
                    syn::Expr::Block(block) => {
                        if block.attrs.is_empty()
                            && block.label.is_none()
                            && let [syn::Stmt::Expr(call, None)] = block.block.stmts.as_slice()
                            && guard_call(call)
                        {
                            *value = call.clone();
                            return;
                        }
                        for stmt in &mut block.block.stmts {
                            statement_value(stmt);
                        }
                    }
                    _ => {}
                }
            }
            let (mut actual, mut expected) = (actual.clone(), expected.clone());
            statement_value(&mut actual);
            statement_value(&mut expected);
            same(&actual, &expected)
        }

        let posts = |body: &syn::Block| {
            body.stmts.len() == 7
                && body.stmts[2..]
                    .iter()
                    .zip(&expected.stmts)
                    .all(|(a, b)| same_guard_post(a, b))
        };
        assert!(posts(actual));
        for index in 2..7 {
            let mut removed = (**actual).clone();
            removed.stmts.remove(index);
            assert!(!posts(&removed));
        }
        let mut reordered = (**actual).clone();
        reordered.stmts.swap(2, 3);
        assert!(!posts(&reordered));
        let requested = syn::Block {
            brace_token: actual.brace_token,
            stmts: vec![actual.stmts[1].clone()],
        };
        let body = captured(&requested, "requested");
        let duplicate: syn::Stmt =
            syn::parse_quote!(if let Err(rejected) = stage.acquisition.attach(guard) {
                pending = Some(rejected);
                anyhow::bail!("protected_restore_request_guard_already_attached");
            });
        let retained = |body: &syn::Block| {
            body.stmts
                .iter()
                .filter(|value| same(value, &duplicate))
                .count()
                == 1
        };
        assert!(retained(&body));
        let index = body
            .stmts
            .iter()
            .position(|value| same(value, &duplicate))
            .unwrap();
        let mut dropped = body.clone();
        dropped.stmts[index] =
            syn::parse_quote!(if let Err(mut rejected) = stage.acquisition.attach(guard) {
                rejected.refuse();
                anyhow::bail!("protected_restore_request_guard_already_attached");
            });
        assert!(!retained(&dropped));
        let mut deferred = body.clone();
        deferred.stmts[index] = syn::parse_quote!(if false { #duplicate });
        assert!(!retained(&deferred));
    }

    fn transfer_statement_tokens(statement: &syn::Stmt) -> String {
        fn statement_value(statement: &mut syn::Stmt) {
            match statement {
                syn::Stmt::Local(local) => {
                    if let Some(initializer) = &mut local.init {
                        expression(&mut initializer.expr);
                    }
                }
                syn::Stmt::Expr(value, _) => expression(value),
                _ => {}
            }
        }

        fn expression(value: &mut syn::Expr) {
            match value {
                syn::Expr::Closure(closure) => {
                    // Only a bare block containing this exact error macro may
                    // differ because of formatting. Keep all closure inputs,
                    // captures and attributes, and every other AST node intact.
                    let replacement = match closure.body.as_ref() {
                        syn::Expr::Block(block)
                            if block.attrs.is_empty() && block.label.is_none() =>
                        {
                            match block.block.stmts.as_slice() {
                                [syn::Stmt::Expr(syn::Expr::Macro(value), None)]
                                    if value.attrs.is_empty()
                                        && value.mac.path.leading_colon.is_none()
                                        && value.mac.path.segments.len() == 2
                                        && value.mac.path.segments[0].ident == "anyhow"
                                        && value.mac.path.segments[1].ident == "anyhow" =>
                                {
                                    Some(syn::Expr::Macro(value.clone()))
                                }
                                _ => None,
                            }
                        }
                        _ => None,
                    };
                    if let Some(replacement) = replacement {
                        *closure.body = replacement;
                    }
                    expression(&mut closure.body);
                }
                syn::Expr::Block(block) => {
                    for statement in &mut block.block.stmts {
                        statement_value(statement);
                    }
                }
                syn::Expr::Try(attempt) => expression(&mut attempt.expr),
                syn::Expr::Call(call) => {
                    expression(&mut call.func);
                    for argument in &mut call.args {
                        expression(argument);
                    }
                }
                syn::Expr::MethodCall(call) => {
                    expression(&mut call.receiver);
                    for argument in &mut call.args {
                        expression(argument);
                    }
                }
                _ => {}
            }
        }

        let mut statement = statement.clone();
        statement_value(&mut statement);
        statement.to_token_stream().to_string()
    }

    #[test]
    fn transfer_oracle_accepts_only_a_bare_error_expression_block() {
        let direct: syn::Stmt =
            syn::parse_quote!(let value = input.ok_or_else(|| anyhow::anyhow!("fixed"))?;);
        let formatted: syn::Stmt =
            syn::parse_quote!(let value = input.ok_or_else(|| { anyhow::anyhow!("fixed") })?;);
        let expected = transfer_statement_tokens(&direct);
        assert_eq!(transfer_statement_tokens(&formatted), expected);
        for source in [
            "let value = input.ok_or_else(|| { foreign(); anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| 'scope: { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| { #[allow(unused)] anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| #[allow(unused)] { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| { anyhow::anyhow!(\"fixed\"); })?;",
            "let value = input.ok_or_else(move || { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|other| { anyhow::anyhow!(\"fixed\") })?;",
            "let value = input.ok_or_else(|| { anyhow::anyhow!(\"different\") })?;",
            "let value = input.ok_or_else(|| { foreign::anyhow!(\"fixed\") })?;",
        ] {
            let changed = syn::parse_str(source).unwrap();
            assert_ne!(transfer_statement_tokens(&changed), expected);
        }
    }

    fn fixed_transfer(body: &syn::Block) -> bool {
        if body.stmts.len() != 11 {
            return false;
        }
        let expected: syn::Block =
            syn::parse_quote!({
                let mut attempt = ProtectedRequestTransfer {
                    original: request.consumer_origin(),
                    owner: Some(self),
                    completed: false,
                };
                let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let owner = attempt.owner.as_deref_mut().ok_or_else(|| {
                        anyhow::anyhow!("protected_restore_transfer_owner_missing")
                    })?;
                    turn.require_accepting_original(&attempt.original, owner)?;
                    let mut stage = owner.borrow_current_request(&mut request)?;
                    stage.require_protected_restore_role(NativeRole::EpochController)?;
                    turn.require_received_guard(&mut stage)?;
                    attempt.original.check_current(&mut stage)
                }));
                let checked =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<_> {
                        let owner = attempt.owner.as_deref_mut().ok_or_else(|| {
                            anyhow::anyhow!("protected_restore_transfer_owner_missing")
                        })?;
                        let mut stage = owner.borrow_current_request(&mut request)?;
                        stage.require_protected_restore_role(NativeRole::EpochController)?;
                        turn.require_received_guard(&mut stage)?;
                        attempt.original.check_current(&mut stage)?;
                        Ok(stage.deadline)
                    }));
                if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(_))) {
                    turn.refuse_transfer();
                }
                match requested {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(())) => {}
                }
                let deadline = match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => result?,
                };
                let frame = request.acquisition.take().ok_or_else(|| {
                    anyhow::anyhow!("protected_restore_transfer_original_missing")
                })?;
                let owner = attempt
                    .owner
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("protected_restore_transfer_owner_missing"))?;
                let stage = EnrolledRoleStage {
                    owner,
                    purpose: StagePurpose::CurrentRole,
                    acquisition: EnrolledStageFrame::owned(frame),
                    deadline,
                };
                attempt.completed = true;
                Ok(stage)
            });
        body.stmts
            .iter()
            .zip(&expected.stmts)
            .all(|(actual, expected)| {
                transfer_statement_tokens(actual) == transfer_statement_tokens(expected)
            })
    }

    #[test]
    fn actual_consuming_transfer_checks_the_same_request_then_moves_its_whole_acquisition() {
        let actual = method("take_protected_restore_request");
        assert!(fixed_transfer(&actual.block));
        for index in 0..actual.block.stmts.len() {
            let mut missing = actual.block.clone();
            missing.stmts.remove(index);
            assert!(!fixed_transfer(&missing));
        }
        for (first, second) in [(0, 1), (2, 4), (5, 6), (6, 9)] {
            let mut moved = actual.block.clone();
            moved.stmts.swap(first, second);
            assert!(!fixed_transfer(&moved));
        }
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
        let field = |source: &str| {
            let parsed = syn::parse_str::<syn::Expr>(&format!("Transfer {{ {source} }}")).unwrap();
            let syn::Expr::Struct(parsed) = parsed else {
                panic!("field wrapper");
            };
            assert_eq!(parsed.fields.len(), 1);
            parsed.fields[0].to_token_stream().to_string()
        };
        for (needle, replacement) in [
            (
                statement("turn.require_accepting_original(&attempt.original,owner)?;"),
                String::new(),
            ),
            (
                expression("owner.borrow_current_request(&mut request)?"),
                expression("owner.begin_current_stage()?"),
            ),
            (
                statement("stage.require_protected_restore_role(NativeRole::EpochController)?;"),
                String::new(),
            ),
            (
                statement("turn.require_received_guard(&mut stage)?;"),
                String::new(),
            ),
            (
                expression("attempt.original.check_current(&mut stage)"),
                expression("Ok(())"),
            ),
            (
                expression("EnrolledStageFrame::owned(frame)"),
                expression("EnrolledStageFrame::fresh(frame.original_mut().narrow(5,deadline)?)"),
            ),
            (
                field("original:request.consumer_origin()"),
                field("original:other.consumer_origin()"),
            ),
        ] {
            let text = actual.block.to_token_stream().to_string();
            assert!(
                text.contains(&needle),
                "missing actual mutation target: {needle}"
            );
            let changed = syn::parse_str(&text.replacen(&needle, &replacement, 1)).unwrap();
            assert!(!fixed_transfer(&changed));
        }
        let negative = method("drop");
        let expected: syn::Block = syn::parse_quote!({
            if !self.completed {
                self.original.refuse();
                if let Some(owner) = self.owner.as_deref_mut() {
                    owner.refused = true;
                }
            }
        });
        assert_eq!(
            negative.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    #[test]
    fn actual_cold_factory_records_its_attempt_before_issuer_work_and_refuses_unwind() {
        use syn::parse::Parser;
        fn guarded(body: &syn::Block) -> bool {
            if body.stmts.len() != 5 {
                return false;
            }
            let expected: [(usize, syn::Stmt); 4] = [
                (
                    0,
                    syn::parse_quote!(self.require_protected_restore_role(expected)?;),
                ),
                (
                    2,
                    syn::parse_quote!(self.owner.protected_restore_attempted = true;),
                ),
                (3, syn::parse_quote!(self.admit_peer_connection()?;)),
                (
                    4,
                    syn::Stmt::Expr(
                        syn::parse_quote!(self.require_protected_restore_role(expected)),
                        None,
                    ),
                ),
            ];
            if !expected
                .iter()
                .all(|(i, expected)| same(&body.stmts[*i], expected))
            {
                return false;
            }
            let syn::Stmt::Macro(guard) = &body.stmts[1] else {
                return false;
            };
            if !guard.mac.path.is_ident("ensure") {
                return false;
            }
            let Ok(args) =
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(guard.mac.tokens.clone())
            else {
                return false;
            };
            let predicate: syn::Expr = syn::parse_quote!(!self.owner.protected_restore_attempted);
            args.len() == 2
                && args[0].to_token_stream().to_string() == predicate.to_token_stream().to_string()
                && matches!(&args[1], syn::Expr::Lit(expr) if matches!(&expr.lit, syn::Lit::Str(value) if value.value() == "protected_restore_native_attempt_already_started"))
        }
        let actual = method("begin_protected_restore_attempt");
        assert_eq!(actual.block.stmts.len(), 2);
        let body = captured(&actual.block, "result");
        assert!(guarded(&body));
        for index in 0..body.stmts.len() {
            let mut missing = body.clone();
            missing.stmts.remove(index);
            assert!(!guarded(&missing));
        }
        let mut late = body.clone();
        late.stmts.swap(2, 3);
        assert!(!guarded(&late));
        let cleanup: syn::Stmt = syn::parse_quote! {
            match result {
                Ok(result) => { if result.is_err() { self.refuse_serving(); } result }
                Err(payload) => { self.refuse_serving(); std::panic::resume_unwind(payload) }
            }
        };
        assert!(same(actual.block.stmts.last().unwrap(), &cleanup));
        let text = actual.block.to_token_stream().to_string();
        for forbidden in [
            "NativeAcquisition",
            "begin_current",
            "exchange_current_views",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn actual_signer_checks_its_native_statement_and_independent_post_before_returning_bytes() {
        let actual = method("sign_protected_restore_message");
        assert_eq!(actual.block.stmts.len(), 4);
        let body = captured(&actual.block, "requested");
        let expected: syn::Block = syn::parse_quote!({
            let local = self.protected_restore_statement()?;
            let commitment = message.commitment_for(&local)?;
            self.owner.key.sign(message.domain(), &commitment)
        });
        assert_eq!(
            body.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let checked: syn::Stmt = syn::parse_quote!(let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check())););
        assert!(same(&actual.block.stmts[1], &checked));
        let refused: syn::Stmt = syn::parse_quote! {
            if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
                self.refuse_serving();
            }
        };
        assert!(same(&actual.block.stmts[2], &refused));
        let selected: syn::Stmt = syn::parse_quote! {
            match requested {
                Err(payload) => std::panic::resume_unwind(payload),
                Ok(Err(error)) => Err(error),
                Ok(Ok(signature)) => match checked {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(result) => { result?; Ok(signature) }
                },
            }
        };
        assert!(same(&actual.block.stmts[3], &selected));
        let refusal = method_in(include_str!("serving.rs"), "refuse_serving");
        let negative: syn::Block = syn::parse_quote!({
            self.owner.refused = true;
            self.acquisition.refuse();
        });
        assert_eq!(
            refusal.block.to_token_stream().to_string(),
            negative.to_token_stream().to_string()
        );
    }
}
