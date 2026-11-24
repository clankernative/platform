//! The actual Controller request spans Submit authentication and future source
//! and delivery subloans. No receipt, new stage clock or saved socket replaces
//! this whole native role/request interval. Completion publication stays closed.

use super::{AdmittedScheduledBackupRequest, ScheduledBackupSocketListener};
use crate::security_epoch::native_clock::NativeAcquisition;
use crate::security_epoch::native_enrollment::{
    EnrolledCurrentRequest, EnrolledProcessRoleOwner, NativeRole,
};
use anyhow::{Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;

/// Captured once at actual ready Submit entry, before accept/authentication.
/// The role borrow and saved original cannot be independently reused or finished.
pub(in crate::security_epoch) struct PendingScheduledBackupAction<'controller> {
    controller: &'controller mut EnrolledProcessRoleOwner,
    request: EnrolledCurrentRequest,
    original: NativeAcquisition,
    scope: AuthorityScope,
    refused: bool,
}

/// Retains the actual submitted requester AND its same saved Controller frame.
/// This is not a source loan, archive, handoff completion or upload disposition.
/// Its genuine CREATE input is presently uninhabited; no positive factory exists.
pub(in crate::security_epoch) struct RetainedScheduledBackupAction<'controller> {
    parent: PendingScheduledBackupAction<'controller>,
    requester: AdmittedScheduledBackupRequest,
}

/// The listener's one fixed admission entry calls this BEFORE accept. No role
/// or request is reconstructed from a socket, DTO, observation or filename.
pub(super) fn capture_scheduled_backup_action(
    controller: &mut EnrolledProcessRoleOwner,
) -> Result<PendingScheduledBackupAction<'_>> {
    let mut request = controller.begin_current_request()?;
    let (scope, original) = {
        let mut stage = controller.borrow_current_request(&mut request)?;
        let scope = stage.storage()?.scheduled_backup_root_selection()?.scope;
        stage.check_for(&scope, NativeRole::EpochController)?;
        let original = stage.narrow_io_acquisition(5)?;
        (scope, original)
    };
    let mut pending = PendingScheduledBackupAction {
        controller,
        request,
        original,
        scope,
        refused: false,
    };
    pending.check()?;
    Ok(pending)
}

impl<'controller> PendingScheduledBackupAction<'controller> {
    fn check(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "scheduled_backup_action_refused");
            self.check_native()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    // Independent actual native post attempt, even if local refusal was already
    // latched. It must not short-circuit on that local boolean. The genuine
    // saved role/request/original may themselves refuse, which remains terminal.
    fn check_native(&mut self) -> Result<()> {
        let mut stage = self.controller.borrow_current_request(&mut self.request)?;
        stage.check_for(&self.scope, NativeRole::EpochController)?;
        stage.check_serving_acquisition(&mut self.original)
    }

    /// Fixed actual socket/issuer/request admission, never an arbitrary callback
    /// or DATA factory. All steps borrow the SAME saved frame and narrowed view.
    /// Today the last CREATE prerequisite refuses before any source/slot effect.
    pub(super) fn receive(
        mut self,
        listener: &mut ScheduledBackupSocketListener,
    ) -> Result<RetainedScheduledBackupAction<'controller>> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check()?;
            let mut stage = self.controller.borrow_current_request(&mut self.request)?;
            let connection = listener.accept(&mut stage, &mut self.original)?;
            let submitted = connection.receive_submit(&mut stage, &mut self.original)?;
            let observed = submitted.observe_issuer(&mut stage, &mut self.original)?;
            observed.try_admit_request(&mut stage, &mut self.original)
        }));
        let checked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.check_native()));
        if !matches!(&requested, Ok(Ok(_))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
        }
        let requester = settle(requested, checked)?;
        let mut retained = RetainedScheduledBackupAction {
            parent: self,
            requester,
        };
        retained.check()?;
        Ok(retained)
    }

    fn refuse(&mut self) {
        self.refused = true;
        self.original.refuse();
        self.request.refuse();
    }
}

impl Drop for PendingScheduledBackupAction<'_> {
    fn drop(&mut self) {
        // No IO, sampling or fallible work in Drop. No current accepting finish
        // exists; abandoning this whole interval is always shared refusal.
        self.refuse();
    }
}

impl RetainedScheduledBackupAction<'_> {
    pub(in crate::security_epoch) fn check(&mut self) -> Result<()> {
        let requested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.parent.check()?;
            let mut stage = self
                .parent
                .controller
                .borrow_current_request(&mut self.parent.request)?;
            self.requester.check(&mut stage, &mut self.parent.original)
        }));
        let checked =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.parent.check_native()));
        if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
            self.refuse();
        }
        settle(requested, checked)
    }

    fn refuse(&mut self) {
        self.requester.refuse();
        self.parent.refuse();
    }
}

impl Drop for RetainedScheduledBackupAction<'_> {
    fn drop(&mut self) {
        self.refuse();
    }
}

// Both computations have ALREADY run, including the independent actual post.
// Preserve the first original error/panic; no foreign formatting or replacement.
fn settle<T>(
    requested: std::thread::Result<Result<T>>,
    checked: std::thread::Result<Result<()>>,
) -> Result<T> {
    match requested {
        Err(payload) => std::panic::resume_unwind(payload),
        Ok(Err(error)) => Err(error),
        Ok(Ok(value)) => match checked {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(result) => {
                result?;
                Ok(value)
            }
        },
    }
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
    }
    macro_rules! closed {
        ($owner:ty) => {
            assert_not_impl!($owner, Clone);
            assert_not_impl!($owner, Copy);
            assert_not_impl!($owner, Default);
            assert_not_impl!($owner, std::fmt::Debug);
            assert_not_impl!($owner, Send);
            assert_not_impl!($owner, Sync);
            assert_not_impl!($owner, serde::Serialize);
            assert_not_impl!($owner, serde::Deserialize<'static>);
            assert_not_impl!($owner, rustix::fd::AsFd);
            assert_not_impl!($owner, std::os::fd::AsRawFd);
            assert_not_impl!($owner, std::ops::Deref);
        };
    }
    closed!(PendingScheduledBackupAction<'static>);
    closed!(RetainedScheduledBackupAction<'static>);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_outer_settlement_preserves_first_owned_error_or_panic_after_independent_post() {
        let original = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        let address = original.downcast_ref::<std::io::Error>().unwrap() as *const _ as usize;
        let retained = settle::<()>(
            Ok(Err(original)),
            Ok(Err(anyhow::anyhow!("later post refusal"))),
        )
        .unwrap_err();
        assert_eq!(
            retained.downcast_ref::<std::io::Error>().unwrap() as *const _ as usize,
            address
        );
        assert!(settle(Ok(Ok(())), Ok(Err(anyhow::anyhow!("post refusal")))).is_err());
        let raised =
            std::panic::catch_unwind(|| settle::<()>(Err(Box::new(41_u8)), Err(Box::new(42_u8))));
        assert_eq!(*raised.unwrap_err().downcast::<u8>().unwrap(), 41);
    }
}
