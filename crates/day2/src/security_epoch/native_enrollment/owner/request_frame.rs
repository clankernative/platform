//! One actual original and its fixed protected-peer restriction move together.
//! The generic storage only moves ownership; it never checks a guard or grants
//! authority. Model tests may use marker DATA, never a fabricated native guard.

use super::{EnrolledProcessRoleOwner, NativeConsumerOrigin, OwnerIdentity};
use crate::security_epoch::native_clock::{
    NativeAcquisition, NativeConnectionClock, NativeOriginalRefusal,
};
use crate::security_epoch::native_enrollment::{
    NativeRole, protected_restore::ProtectedRestoreActionGuard, protocol::StagePurpose,
};
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::rc::{Rc, Weak};

struct Frame<G> {
    original: NativeAcquisition,
    guard: Option<G>,
}

enum Access<'a, G> {
    Owned(Box<Frame<G>>),
    Borrowed(&'a mut Frame<G>),
}

impl<G> Frame<G> {
    fn new(original: NativeAcquisition) -> Self {
        Self {
            original,
            guard: None,
        }
    }

    fn attach(&mut self, guard: G) -> std::result::Result<(), G> {
        if self.guard.is_some() {
            return Err(guard);
        }
        self.guard = Some(guard);
        Ok(())
    }
}

impl<'a, G> Access<'a, G> {
    fn frame(&self) -> &Frame<G> {
        match self {
            Self::Owned(frame) => frame,
            Self::Borrowed(frame) => frame,
        }
    }

    fn frame_mut(&mut self) -> &mut Frame<G> {
        match self {
            Self::Owned(frame) => frame,
            Self::Borrowed(frame) => frame,
        }
    }

    fn into_owned(self) -> std::result::Result<Box<Frame<G>>, &'a mut Frame<G>> {
        match self {
            Self::Owned(frame) => Ok(frame),
            Self::Borrowed(frame) => Err(frame),
        }
    }
}

pub(super) struct EnrolledRequestFrame {
    inner: Box<Frame<ProtectedRestoreActionGuard>>,
}

pub(super) struct EnrolledStageFrame<'a> {
    source: StageSource<'a>,
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <EnrolledRequestFrame as Ambiguous<_>>::check;
            let _ = <EnrolledStageFrame<'static> as Ambiguous<_>>::check;
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

enum StageSource<'a> {
    Request(Access<'a, ProtectedRestoreActionGuard>),
    // These are the six fixed restored-App suppliers, not another way to
    // borrow a Controller request. The actual owner identity stays bound.
    App {
        original: &'a mut NativeAcquisition,
        owner: Weak<OwnerIdentity>,
        incarnation: Digest,
    },
}

impl EnrolledRequestFrame {
    pub(super) fn new(original: NativeAcquisition) -> Self {
        Self {
            inner: Box::new(Frame::new(original)),
        }
    }

    pub(super) fn original(&self) -> &NativeAcquisition {
        &self.inner.original
    }

    pub(super) fn original_mut(&mut self) -> &mut NativeAcquisition {
        &mut self.inner.original
    }

    pub(super) fn refuse(&mut self) {
        refuse_frame(&mut self.inner);
    }
}

fn refuse_frame(frame: &mut Frame<ProtectedRestoreActionGuard>) {
    if let Some(guard) = &mut frame.guard {
        guard.refuse();
    }
    frame.original.refuse();
}

impl<'a> EnrolledStageFrame<'a> {
    pub(super) fn owned(frame: EnrolledRequestFrame) -> Self {
        Self {
            source: StageSource::Request(Access::Owned(frame.inner)),
        }
    }

    pub(super) fn fresh(original: NativeAcquisition) -> Self {
        Self::owned(EnrolledRequestFrame::new(original))
    }

    pub(super) fn borrowed(frame: &'a mut EnrolledRequestFrame) -> Self {
        Self {
            source: StageSource::Request(Access::Borrowed(&mut frame.inner)),
        }
    }

    pub(super) fn app(
        original: &'a mut NativeAcquisition,
        owner: &EnrolledProcessRoleOwner,
    ) -> Result<Self> {
        if owner.refused
            || owner.role != NativeRole::AppHost
            || owner.process != std::process::id()
            || owner.thread != std::thread::current().id()
        {
            original.refuse();
            anyhow::bail!("native_app_frame_owner_changed");
        }
        Ok(Self {
            source: StageSource::App {
                original,
                owner: Rc::downgrade(&owner.identity),
                incarnation: owner.incarnation.clone(),
            },
        })
    }

    pub(super) fn as_ref(&self) -> &NativeAcquisition {
        match &self.source {
            StageSource::Request(access) => &access.frame().original,
            StageSource::App { original, .. } => original,
        }
    }

    pub(super) fn as_mut(&mut self) -> &mut NativeAcquisition {
        match &mut self.source {
            StageSource::Request(access) => &mut access.frame_mut().original,
            StageSource::App { original, .. } => original,
        }
    }

    pub(super) fn attach(
        &mut self,
        guard: ProtectedRestoreActionGuard,
    ) -> std::result::Result<(), ProtectedRestoreActionGuard> {
        match &mut self.source {
            StageSource::Request(access) => access.frame_mut().attach(guard),
            StageSource::App { .. } => Err(guard),
        }
    }

    pub(super) fn require_guard_slot(&mut self) -> Result<()> {
        if matches!(&self.source,StageSource::Request(access) if access.frame().guard.is_none()) {
            return Ok(());
        }
        self.refuse();
        anyhow::bail!("protected_restore_request_guard_already_attached")
    }

    pub(super) fn require_guard(
        &mut self,
        root: &Rc<std::cell::Cell<bool>>,
        origin: &NativeConsumerOrigin,
        connection: &Digest,
        sequence: u64,
    ) -> Result<()> {
        match &mut self.source {
            StageSource::Request(access) => access
                .frame_mut()
                .guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("protected_restore_request_guard_missing"))?
                .require_binding(root, origin, connection, sequence),
            StageSource::App { .. } => anyhow::bail!("protected_restore_request_guard_missing"),
        }
    }

    pub(super) fn check_guard(
        &mut self,
        owner: &EnrolledProcessRoleOwner,
        purpose: StagePurpose,
    ) -> Result<()> {
        let checked = match &mut self.source {
            StageSource::Request(access) => {
                let frame = access.frame_mut();
                match &mut frame.guard {
                    Some(guard) => guard.check(owner, purpose, &mut frame.original),
                    None => Ok(()),
                }
            }
            StageSource::App {
                owner: actual,
                incarnation,
                ..
            } => {
                let actual = actual
                    .upgrade()
                    .ok_or_else(|| anyhow::anyhow!("native_app_frame_owner_dropped"));
                actual.and_then(|actual| {
                    ensure!(
                        owner.role == NativeRole::AppHost
                            && Rc::ptr_eq(&actual, &owner.identity)
                            && *incarnation == owner.incarnation,
                        "native_app_frame_owner_changed"
                    );
                    Ok(())
                })
            }
        };
        if checked.is_err() {
            self.refuse();
        }
        checked
    }

    pub(super) fn refuse(&mut self) {
        match &mut self.source {
            StageSource::Request(access) => refuse_frame(access.frame_mut()),
            StageSource::App { original, .. } => original.refuse(),
        }
    }

    pub(super) fn into_owned(self) -> Result<EnrolledRequestFrame> {
        match self.source {
            StageSource::Request(access) => match access.into_owned() {
                Ok(inner) => Ok(EnrolledRequestFrame { inner }),
                Err(frame) => {
                    refuse_frame(frame);
                    anyhow::bail!("epoch_native_borrowed_original_cannot_detach")
                }
            },
            StageSource::App { original, .. } => {
                original.refuse();
                anyhow::bail!("epoch_native_borrowed_original_cannot_detach")
            }
        }
    }

    pub(super) fn retire_owned(
        &mut self,
        clock: &mut NativeConnectionClock,
    ) -> Result<NativeOriginalRefusal> {
        match &mut self.source {
            StageSource::Request(Access::Owned(frame)) => {
                if let Some(guard) = &mut frame.guard
                    && let Err(error) = guard.require_retirement()
                {
                    frame.original.refuse();
                    clock.refuse();
                    return Err(error);
                }
                let refusal = frame.original.retained_refusal();
                clock.retire_checked(&mut frame.original)?;
                // Infallible memory-only transition after the last original
                // sample. The retained old guard can never check positively.
                if let Some(guard) = &mut frame.guard {
                    guard.retire();
                }
                Ok(refusal)
            }
            _ => {
                self.refuse();
                clock.refuse();
                anyhow::bail!("epoch_native_borrowed_original_cannot_detach")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::native_clock::{fixture_bootstrap, fixture_observe_at};
    use quote::ToTokens;
    use std::time::Duration;

    fn original() -> NativeAcquisition {
        NativeAcquisition::fixture(
            Digest::new(b"frame-lifetime-fixture"),
            std::process::id(),
            Duration::from_secs(100),
            Duration::from_secs(5),
        )
    }

    #[test]
    fn shared_frame_storage_retains_marker_on_every_borrow_and_owned_move_and_rejects_replacement()
    {
        // Marker DATA cannot inhabit the production EnrolledRequestFrame,
        // whose guard parameter is the actual opaque native guard.
        for seed in 0..64_u64 {
            let mut frame = Box::new(Frame::<u64>::new(original()));
            // The oracle derives expected ownership from a separate event
            // history, rather than reading the implementation's optional slot.
            let mut history: Vec<(u64, u64)> = Vec::new();
            let mut schedule = seed + 1;
            for step in 0..64_u64 {
                schedule ^= schedule << 13;
                schedule ^= schedule >> 7;
                schedule ^= schedule << 17;
                let event = (schedule % 4, seed * 64 + step);
                let first = history
                    .iter()
                    .find_map(|(kind, marker)| (*kind == 0).then_some(*marker));
                match event.0 {
                    0 => {
                        let result = frame.attach(event.1);
                        assert_eq!(
                            result,
                            if first.is_none() {
                                Ok(())
                            } else {
                                Err(event.1)
                            }
                        );
                    }
                    1 => {
                        let borrowed = Access::Borrowed(&mut frame);
                        assert!(borrowed.into_owned().is_err());
                    }
                    2 => {
                        frame = Access::Owned(frame).into_owned().ok().unwrap();
                    }
                    3 => frame.original.refuse(),
                    _ => unreachable!(),
                }
                history.push(event);
                let expected = history
                    .iter()
                    .find_map(|(kind, marker)| (*kind == 0).then_some(*marker));
                assert_eq!(frame.guard, expected);
                assert_eq!(
                    frame.original.sample().is_err(),
                    history.iter().any(|(kind, _)| *kind == 3)
                );
            }
        }
    }

    #[test]
    fn saved_frame_keeps_the_whole_owned_marker_through_result_error_unwind_and_release_cuts() {
        struct CourierMarker(std::rc::Rc<std::cell::Cell<usize>>);
        impl Drop for CourierMarker {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        // The same production storage container, with marker DATA instead of
        // any fabricated opaque native guard or enrolled role.
        for unwind in [false, true] {
            for cut in 0..6 {
                let drops = std::rc::Rc::new(std::cell::Cell::new(0));
                let mut frame = Box::new(Frame::new(original()));
                assert!(
                    frame
                        .attach(Box::new(CourierMarker(std::rc::Rc::clone(&drops))))
                        .is_ok()
                );
                for phase in 0..6 {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || -> anyhow::Result<()> {
                            let mut borrowed = Access::Borrowed(&mut frame);
                            assert!(borrowed.frame().guard.is_some());
                            assert_eq!(drops.get(), 0);
                            if phase == cut {
                                borrowed.frame_mut().original.refuse();
                                if unwind {
                                    panic!("marker cut");
                                } else {
                                    anyhow::bail!("marker Result cut");
                                }
                            }
                            Ok(())
                        },
                    ));
                    assert_eq!(result.is_err(), phase == cut && unwind);
                    assert_eq!(matches!(&result, Ok(Err(_))), phase == cut && !unwind);
                    assert_eq!(drops.get(), 0);
                    if phase >= cut {
                        assert!(frame.original.remaining().is_err());
                    }
                    frame = Access::Owned(frame).into_owned().ok().unwrap();
                }
                assert_eq!(drops.get(), 0);
                drop(frame);
                assert_eq!(drops.get(), 1);
            }
        }
    }

    #[test]
    fn frame_move_preserves_the_actual_original_identity_and_cannot_repair_refusal() {
        let original = original();
        let root = original.retained_refusal();
        let mut frame = Box::new(Frame::<u64>::new(original));
        frame.attach(9).unwrap();
        {
            let mut borrowed = Access::Borrowed(&mut frame);
            root.require_same(&borrowed.frame_mut().original.retained_refusal())
                .unwrap();
            borrowed.frame_mut().original.refuse();
        }
        let mut moved = Access::Owned(frame).into_owned().ok().unwrap();
        assert_eq!(moved.guard, Some(9));
        assert!(moved.original.sample().is_err());
        assert!(
            root.require_same(&moved.original.retained_refusal())
                .is_err()
        );
    }

    #[test]
    fn actual_request_frame_borrows_preserve_the_earliest_cap_and_permanent_refusal() {
        // Actual clock/frame ownership, without an enrolled role or guard.
        let origin = Duration::from_secs(100);
        let mut frame = EnrolledRequestFrame::new(original());
        let identity = frame.original().retained_refusal();
        {
            let mut stage = EnrolledStageFrame::borrowed(&mut frame);
            let mut counter = stage
                .as_mut()
                .narrow(5, origin + Duration::from_secs(2))
                .unwrap();
            stage.as_mut().exchange_current_views(&mut counter).unwrap();
        }
        assert_eq!(
            frame.original_mut().interval_data().unwrap(),
            (origin, origin + Duration::from_secs(2))
        );
        fixture_observe_at(frame.original_mut(), origin + Duration::from_millis(500));
        {
            let mut stage = EnrolledStageFrame::borrowed(&mut frame);
            let mut peer = stage
                .as_mut()
                .narrow(5, origin + Duration::from_secs(5))
                .unwrap();
            assert_eq!(
                peer.interval_data().unwrap(),
                (origin, origin + Duration::from_secs(2))
            );
            peer = peer.narrow(5, origin + Duration::from_secs(1)).unwrap();
            stage.as_mut().exchange_current_views(&mut peer).unwrap();
        }
        assert_eq!(
            frame.original_mut().interval_data().unwrap(),
            (origin, origin + Duration::from_secs(1))
        );
        identity
            .require_same(&frame.original().retained_refusal())
            .unwrap();
        fixture_observe_at(frame.original_mut(), origin + Duration::from_secs(1));
        assert!(
            EnrolledStageFrame::borrowed(&mut frame)
                .as_mut()
                .remaining()
                .is_err()
        );
        fixture_observe_at(frame.original_mut(), origin);
        assert!(
            EnrolledStageFrame::borrowed(&mut frame)
                .as_mut()
                .remaining()
                .is_err()
        );
    }

    #[test]
    fn borrowed_actual_request_frame_cannot_detach_as_an_owned_original() {
        let mut frame = EnrolledRequestFrame::new(original());
        let error = EnrolledStageFrame::borrowed(&mut frame)
            .into_owned()
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "epoch_native_borrowed_original_cannot_detach"
        );
        assert!(frame.original_mut().remaining().is_err());
    }

    #[test]
    fn whole_owned_frame_preserves_completed_authentication_and_the_distinct_bootstrap_bound() {
        let origin = Duration::from_secs(100);
        let original =
            fixture_bootstrap(Digest::new(b"frame bootstrap"), std::process::id(), origin);
        let mut stage = EnrolledStageFrame::fresh(original);
        let ceiling = stage.as_mut().interval_data().unwrap();
        let mut authentication = stage.as_mut().narrow_authentication().unwrap();
        assert_eq!(
            authentication.interval_data().unwrap(),
            (origin, origin + Duration::from_secs(5))
        );
        stage
            .as_mut()
            .complete_authentication(authentication)
            .unwrap();
        let mut frame = stage.into_owned().unwrap();
        assert_eq!(frame.original_mut().interval_data().unwrap(), ceiling);
        fixture_observe_at(frame.original_mut(), origin + Duration::from_secs(6));
        assert!(frame.original_mut().remaining().is_ok());
    }

    fn clock_pair() -> (NativeConnectionClock, NativeAcquisition) {
        let mut request = original();
        let connection = request
            .narrow(5, Duration::from_secs(105))
            .unwrap()
            .into_connection_clock()
            .unwrap();
        (connection, request)
    }

    #[test]
    fn actual_owned_frame_retirement_preserves_connection_and_negative_disposition() {
        let (mut connection, mut original) = clock_pair();
        fixture_observe_at(&mut original, Duration::from_secs(102));
        let mut stage = EnrolledStageFrame::fresh(original);
        let negative = stage.retire_owned(&mut connection).unwrap();
        assert!(stage.as_mut().sample().is_err());
        let mut next = connection
            .bind_captured_current(NativeAcquisition::fixture(
                Digest::new(b"next actual frame"),
                std::process::id(),
                Duration::from_secs(103),
                Duration::from_secs(5),
            ))
            .unwrap();
        next.sample().unwrap();
        negative.refuse();
        assert!(next.sample().is_err());
    }

    #[test]
    fn borrowed_frame_retirement_refuses_both_actual_original_and_supplied_connection() {
        // Also reject a different real clock root: failure may never leave a
        // supplied connection usable just because its identity did not match.
        for foreign in [false, true] {
            let (mut connection, mut original) = clock_pair();
            if foreign {
                original = self::original();
            }
            fixture_observe_at(&mut original, Duration::from_secs(102));
            let mut frame = EnrolledRequestFrame::new(original);
            assert!(
                EnrolledStageFrame::borrowed(&mut frame)
                    .retire_owned(&mut connection)
                    .is_err()
            );
            assert!(frame.original_mut().remaining().is_err());
            assert!(
                connection
                    .bind_captured_current(NativeAcquisition::fixture(
                        Digest::new(b"refused following frame"),
                        std::process::id(),
                        Duration::from_secs(103),
                        Duration::from_secs(5)
                    ))
                    .is_err()
            );
        }
    }

    fn owner_method(owner: &str, method: &str) -> syn::ImplItemFn {
        let source = syn::parse_file(include_str!("../owner.rs")).unwrap();
        let methods = source
            .items
            .into_iter()
            .filter_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                let syn::Type::Path(path) = &*item.self_ty else {
                    return None;
                };
                path.path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == owner)
                    .then_some(item.items)
            })
            .flatten()
            .filter_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == method => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 1);
        methods.into_iter().next().unwrap()
    }

    fn stage_posts(body: &syn::Block) -> bool {
        if body.stmts.len() != 4 {
            return false;
        }
        let expected: syn::Block = syn::parse_quote!({
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.acquisition.check_guard(self.owner, self.purpose)
            }));
            if !matches!(&requested, Ok(Ok(()))) || !matches!(&checked, Ok(Ok(()))) {
                self.owner.refused = true;
                self.acquisition.refuse();
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
        body.stmts[1..]
            .iter()
            .zip(&expected.stmts)
            .all(|(actual, expected)| {
                actual.to_token_stream().to_string() == expected.to_token_stream().to_string()
            })
    }

    #[test]
    fn actual_stage_observes_guard_after_local_error_or_panic_and_retains_primary_and_both_refusals()
     {
        let actual = owner_method("EnrolledRoleStage", "check").block;
        assert!(stage_posts(&actual));
        for index in 1..4 {
            let mut removed = actual.clone();
            removed.stmts.remove(index);
            assert!(!stage_posts(&removed));
        }
        for (target, replacement) in [
            (
                "self . acquisition . check_guard (self . owner , self . purpose)",
                "Ok(())",
            ),
            (
                "self . acquisition . refuse ()",
                "self.acquisition.as_mut().refuse()",
            ),
            (
                "self . owner . refused = true",
                "self.owner.refused = false",
            ),
            (
                "Ok (Err (error)) => Err (error)",
                "Ok(Err(error)) => Ok(())",
            ),
        ] {
            let tokens = actual.to_token_stream().to_string();
            assert_eq!(tokens.matches(target).count(), 1, "{target}");
            let changed: syn::Block =
                syn::parse_str(&tokens.replacen(target, replacement, 1)).unwrap();
            assert!(!stage_posts(&changed));
        }
        let mut early = actual;
        early
            .stmts
            .insert(1, syn::parse_quote!(let _ = requested?;));
        assert!(!stage_posts(&early));
    }

    fn retirement_guard(body: &str) -> bool {
        let terms = [
            "let request_state = Rc :: new (RestoredRequestGate :: new ())",
            "stage . acquisition . check_guard (stage . owner , stage . purpose) ?",
            "stage . acquisition . retire_owned (& mut stage . owner . clock) ?",
        ];
        let mut after = body;
        for term in terms {
            if after.matches(term).count() != 1 {
                return false;
            }
            let position = after.find(term).unwrap();
            after = &after[position + term.len()..];
        }
        !after.contains(". check (")
            && !after.contains(". check_guard (")
            && !after.contains(". sample (")
            && !after.contains("Rc :: new")
    }

    #[test]
    fn actual_controller_retirement_keeps_guard_until_last_sample_then_moves_the_whole_old_stage() {
        let actual = owner_method("EnrolledRoleStage", "retire_controller_native")
            .block
            .to_token_stream()
            .to_string();
        assert!(retirement_guard(&actual));
        let guard = "stage . acquisition . check_guard (stage . owner , stage . purpose) ? ;";
        assert_eq!(actual.matches(guard).count(), 1);
        let removed = actual.replacen(guard, "", 1);
        assert!(!retirement_guard(&removed));
        let retirement = "stage . acquisition . retire_owned (& mut stage . owner . clock) ? ;";
        assert_eq!(removed.matches(retirement).count(), 1);
        assert!(!retirement_guard(&removed.replacen(
            retirement,
            &format!("{retirement} {guard}"),
            1
        )));
    }
}
