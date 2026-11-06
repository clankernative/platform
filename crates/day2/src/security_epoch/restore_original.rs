//! One retained native original captured before the consuming admin read.
//! This is neither approval, exclusion, a Fenced completion nor writer authority.
//! The reader must retain it with the actual stage through the fixed handoff.

use crate::security_epoch::{
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, NativeRole, SameEnrolledOwner},
    restore_approval::ApprovalRequest,
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{EpochStore, bootstrap::InitialBootstrapPolicy},
};

pub(in crate::security_epoch) struct RestoreOriginalGuard {
    request: ApprovalRequest,
    operation: Digest,
    policy: InitialBootstrapPolicy,
    selection: EpochStore,
    owner: SameEnrolledOwner,
    acquisition: NativeAcquisition,
    refused: bool,
}

/// Actual monotonic-clock DATA only. It cannot construct or replace an
/// original, authenticate approval, qualify UTC, fence a holder or admit a writer.
pub(in crate::security_epoch) struct RestoreObservation {
    domain: Digest,
    origin: u64,
    deadline: u64,
    now: u64,
}

impl RestoreObservation {
    pub(in crate::security_epoch) fn interval_data(&self) -> (&Digest, u64, u64) {
        (&self.domain, self.origin, self.deadline)
    }

    pub(in crate::security_epoch) fn observation_data(&self) -> (u64, u64) {
        (self.now, self.now)
    }
}

impl RestoreOriginalGuard {
    /// Capture from the genuine existing CurrentRole stage BEFORE reader work.
    /// Five seconds is the ordinary action ceiling, not the approval's hour.
    /// Narrowing retains the actual shared observation and all earlier bounds.
    pub(in crate::security_epoch) fn capture(
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        selection: &EpochStore,
        request: ApprovalRequest,
        operation: Digest,
    ) -> Result<Self> {
        let mut acquisition = stage.narrow_io_acquisition(5)?;
        let owner = match stage.capture_same_owner() {
            Ok(owner) => owner,
            Err(error) => {
                acquisition.refuse();
                return Err(error);
            }
        };
        let expected = request.clone();
        let expected_operation = operation.clone();
        let mut guard = Self {
            request,
            operation,
            policy: policy.clone(),
            selection: selection.clone(),
            owner,
            acquisition,
            refused: false,
        };
        guard.check_join(stage, &expected, &expected_operation)?;
        Ok(guard)
    }

    /// This checks the real enrolled owner and joins the real shared clock.
    /// The existing meet rejects another Rc even with identical interval DATA;
    /// it propagates shorter ceilings and terminal refusal in both directions.
    /// No stage, acquisition, descriptor or renewed permission is returned.
    pub(in crate::security_epoch) fn check_join(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        expected: &ApprovalRequest,
        operation: &Digest,
    ) -> Result<RestoreObservation> {
        let result = (|| {
            ensure!(!self.refused, "restore_original_refused");
            self.request.require_exact(expected)?;
            ensure!(
                &self.operation == operation,
                "restore_controller_operation_changed"
            );
            self.selection.validate()?;
            ensure!(
                self.request.target.scope == self.selection.scope
                    && self.request.target.authority == self.selection.authority_key()?
                    && self.request.target.selection == Digest::of(&self.selection)?,
                "restore_controller_selection_changed"
            );
            self.owner
                .meet_current_read_view(stage, &mut self.acquisition)?;
            stage.check_selection(&self.policy, &self.selection, NativeRole::EpochController)?;
            let (origin, deadline) = self.acquisition.interval_data()?;
            let sample = self.acquisition.sample()?;
            Ok(RestoreObservation {
                domain: sample.domain,
                origin: origin.as_nanos().try_into()?,
                deadline: deadline.as_nanos().try_into()?,
                now: sample.elapsed.as_nanos().try_into()?,
            })
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Terminal and infallible, including after expiry; no native I/O or retry.
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.refused = true;
        self.acquisition.refuse();
    }
}

impl Drop for RestoreOriginalGuard {
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
            let _ = <crate::security_epoch::restore_original::RestoreOriginalGuard as Ambiguous<
                _,
            >>::check;
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context as _;
    use quote::ToTokens as _;
    use std::time::Duration;

    fn clock_fixture(origin: Duration, limit: Duration) -> NativeAcquisition {
        NativeAcquisition::fixture(
            Digest::new(b"restore action"),
            std::process::id(),
            origin,
            limit,
        )
    }

    #[test]
    fn actual_shared_view_meet_retains_the_shorter_ceiling_in_both_directions() -> Result<()> {
        let origin = Duration::from_secs(10);
        let mut retained = clock_fixture(origin, Duration::from_secs(5));
        let mut actual = retained.narrow(3, origin + Duration::from_secs(3))?;
        retained.exchange_current_views(&mut actual)?;
        assert_eq!(
            retained.interval_data()?,
            (origin, origin + Duration::from_secs(3))
        );
        assert_eq!(actual.interval_data()?, retained.interval_data()?);
        actual.refuse();
        assert!(retained.remaining().is_err());
        Ok(())
    }

    #[test]
    fn identical_clock_data_cannot_replace_the_actual_shared_original() {
        let origin = Duration::from_secs(10);
        let mut retained = clock_fixture(origin, Duration::from_secs(5));
        let mut other = clock_fixture(origin, Duration::from_secs(5));
        assert_eq!(
            retained.interval_data().unwrap(),
            other.interval_data().unwrap()
        );
        assert_eq!(
            retained.exchange_current_views(&mut other)
                .unwrap_err()
                .to_string(),
            "epoch_native_current_read_clock_changed"
        );
        assert!(retained.remaining().is_err());
        assert!(other.remaining().is_err());
    }

    #[test]
    fn expired_actual_view_cannot_be_replaced_by_a_later_successful_check() {
        let origin = Duration::from_secs(10);
        let mut expired = clock_fixture(origin, Duration::ZERO);
        let mut other = clock_fixture(origin, Duration::from_secs(5));
        // This base exposes the closed internal clock code, not a typed clock
        // enum. Pin that cause so a wrong PID cannot impersonate expiry.
        assert_eq!(
            expired.remaining().unwrap_err().to_string(),
            "epoch_native_clock_rewind_or_expired"
        );
        assert!(expired.exchange_current_views(&mut other).is_err());
        assert!(expired.remaining().is_err());
        assert!(other.remaining().is_err());
    }

    fn source_contract(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let owner = file
            .items
            .iter()
            .find_map(|i| match i {
                syn::Item::Struct(s) if s.ident == "RestoreOriginalGuard" => Some(s),
                _ => None,
            })
            .context("restore_original_guard_missing")?;
        if owner
            .fields
            .iter()
            .any(|f| !matches!(f.vis, syn::Visibility::Inherited))
        {
            return Ok(false);
        }
        let implementation = file.items.iter().find_map(|i| match i {
            syn::Item::Impl(i) if i.trait_.is_none() && matches!(&*i.self_ty, syn::Type::Path(p) if p.path.is_ident("RestoreOriginalGuard")) => Some(i), _ => None,
        }).context("restore_original_guard_impl_missing")?;
        let mut methods = std::collections::BTreeMap::new();
        for item in &implementation.items {
            let syn::ImplItem::Fn(f) = item else {
                return Ok(false);
            };
            methods.insert(
                f.sig.ident.to_string(),
                f.block.to_token_stream().to_string(),
            );
        }
        if methods.len() != 3 {
            return Ok(false);
        }
        let capture = methods
            .get("capture")
            .context("restore_original_capture_missing")?;
        let check = methods
            .get("check_join")
            .context("restore_original_check_missing")?;
        let refuse = methods
            .get("refuse")
            .context("restore_original_refusal_missing")?;
        let drop = file
            .items
            .iter()
            .find_map(|i| match i {
                syn::Item::Impl(i)
                    if i.trait_
                        .as_ref()
                        .is_some_and(|(_, p, _)| p.is_ident("Drop")) =>
                {
                    Some(i.to_token_stream().to_string())
                }
                _ => None,
            })
            .context("restore_original_drop_missing")?;
        Ok(capture.matches("stage . narrow_io_acquisition (5) ?").count() == 1
            && capture.matches("stage . capture_same_owner ()").count() == 1
            && capture.contains("guard . check_join (stage , & expected , & expected_operation) ?")
            && check.matches("self . request . require_exact (expected) ?").count() == 1
            && check.contains("& self . operation == operation")
            && check.matches("self . owner . meet_current_read_view (stage , & mut self . acquisition) ?").count() == 1
            && check.matches("stage . check_selection (& self . policy , & self . selection , NativeRole :: EpochController) ?").count() == 1
            && check.contains("if result . is_err () { self . refuse () ; }")
            && refuse.contains("self . refused = true") && refuse.contains("self . acquisition . refuse ()")
            && drop.contains("self . refuse ()")
            && !capture.contains("NativeAcquisition :: begin")
            && !check.contains("NativeAcquisition :: begin"))
    }

    #[test]
    fn actual_capture_join_and_drop_cannot_be_bypassed_or_retimed() -> Result<()> {
        let source = include_str!("restore_original.rs")
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .unwrap();
        assert!(source_contract(source)?);
        let canonical = syn::parse_file(source)?.to_token_stream().to_string();
        for (from, to) in [
            (
                "stage . narrow_io_acquisition (5) ?",
                "stage . narrow_io_acquisition (60) ?",
            ),
            (
                "guard . check_join (stage , & expected , & expected_operation) ? ;",
                "let _ = stage ;",
            ),
            (
                "self . request . require_exact (expected) ? ;",
                "let _ = expected ;",
            ),
            ("& self . operation == operation", "true"),
            (
                "self . owner . meet_current_read_view (stage , & mut self . acquisition) ? ;",
                "let _ = stage ;",
            ),
            (
                "stage . check_selection (& self . policy , & self . selection , NativeRole :: EpochController) ? ;",
                "let _ = stage ;",
            ),
            (
                "impl Drop for RestoreOriginalGuard { fn drop (& mut self) { self . refuse () ; } }",
                "impl Drop for RestoreOriginalGuard { fn drop (& mut self) { } }",
            ),
        ] {
            assert_eq!(canonical.matches(from).count(), 1);
            assert!(!source_contract(&canonical.replace(from, to))?);
        }
        let mut public_field = syn::parse_file(source)?;
        let Some(syn::Item::Struct(owner)) = public_field
            .items
            .iter_mut()
            .find(|i| matches!(i, syn::Item::Struct(s) if s.ident == "RestoreOriginalGuard"))
        else {
            anyhow::bail!("restore_original_guard_missing")
        };
        owner.fields.iter_mut().next().unwrap().vis = syn::parse_quote!(pub);
        assert!(!source_contract(
            &public_field.to_token_stream().to_string()
        )?);
        Ok(())
    }
}
