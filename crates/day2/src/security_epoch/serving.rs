//! Closed consumer contract only. There is deliberately NO production serving
//! implementation or successful factory yet. Preparation DATA, SQL rows, role
//! membership and old bootstrap receipts cannot instantiate this interface.
//! The actual P3/current-writer/serving owner must be supplied before removing
//! the factory's refusal; simulator consumers remain a separate path.

use crate::{oauth::fresh_auth::FreshIntent, security_epoch::native_enrollment::EnrolledRoleStage};
use anyhow::Result;

/// Purpose selection DATA, not execution permission. Each later irreversible
/// phase needs its own genuine same-stage serving fence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServingUse {
    StartCommit,
    DispatchCommit,
    ProviderSend,
    FinishCommit,
    DisconnectCommit,
    Session,
    Signature,
    Verification,
    Callback,
    Response,
    AppResponseComplete,
    ShellResponseComplete,
}

mod sealed {
    pub trait NativeServingOwner {}
}

/// A scoped borrow of genuine native material, never a DTO or transferable
/// permission. Sealing prevents consumer/simulator code from supplying a mock
/// native implementation. No implementation is registered in this source.
pub(crate) trait CurrentServingPhase: sealed::NativeServingOwner {
    fn check(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()>;

    /// Before the actual mutation/send attempt, not after its possibly lost
    /// result. Failure must leave the actual owner permanently refused.
    fn arm(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()>;

    /// Known result plus current fences. This must not rearm an unknown result
    /// or restore an owner that a previous physical/current check refused.
    /// Recording the known result DOES NOT release the callback's scope: all
    /// subsequent original checks must finish before another consumer enters.
    fn finish_known(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<()>;

    /// Only a known exclusion BEFORE arming, such as a rejected MAC or pure
    /// input. It cannot clear a previously refused owner or attempted effect.
    fn finish_excluded(&mut self) -> Result<()>;

    /// Terminal/unknown disposition works even after expiry or unwinding.
    /// It must require no still-live role, clock or provider request, and must
    /// remain terminal even if finish_known was already recorded.
    fn refuse(&mut self);
}

/// The exact SAME native stage remains available to the caller for its
/// original.check_with_native fence. Neither this scoped borrow nor a native
/// owner may escape as the returned DATA. The absent factory performs no SQL,
/// provider I/O or callback and returns no native permission.
pub(crate) fn with_current_serving<'role, T>(
    _stage: &mut EnrolledRoleStage<'role>,
    _intent: &FreshIntent,
    _purpose: ServingUse,
    _operation: impl FnOnce(&mut dyn CurrentServingPhase, &mut EnrolledRoleStage<'role>) -> Result<T>,
) -> Result<T> {
    anyhow::bail!("native current-serving authority unavailable")
}

/// Terminal lookup of an EXISTING logical response hold on its owning executor.
/// It may only refuse: never create/rebind a hold, settle a paused winner as
/// complete/excluded, release unknown resources, or restore a terminal owner.
/// The future implementation must bind the original hold/incarnation; the
/// intent/purpose DATA alone cannot supply it or a new permission. No native
/// owner/registry implementation exists yet, so no successful refusal receipt
/// is returned here, and no stage/clock/provider request is attempted.
pub(crate) fn refuse_current_serving(_intent: &FreshIntent, _purpose: ServingUse) -> Result<()> {
    anyhow::bail!("native current-serving authority unavailable")
}
