//! The whole restored App owner and its capture-time request stay distinct.
//! A synchronous scope borrows the capture; only the final request driver
//! consumes it. The native owner supplies their two distinct settlements.

use super::{NativeProviderUse, NativeSqlUse, RuntimeServingUse};
use crate::oauth::native_management::{NativeConsumerContext, NativeRequestFinalContext};
use crate::security_epoch::native_enrollment::{
    CapturedRestoredAppRequest, EnrolledOriginalClock, NativeConsumerOrigin,
    RestoredAppCurrentPeer, RetiredRestoredAppNative,
};
use anyhow::{Context, Result};

mod sealed {
    pub trait Current {}
}

/// Fixed operations on the actual borrowed scope. This erases only its
/// lifetimes: no implementation outside this module, native/stage/Runtime
/// getter, ownership acquisition or arbitrary callback can be supplied.
pub(crate) trait RestoredCurrent: sealed::Current {
    fn check(&mut self) -> Result<()>;
    fn arm(&mut self) -> Result<()>;
    fn finish_known(&mut self) -> Result<()>;
    fn refuse(&mut self);
}

pub(crate) trait RestoredRuntimeCurrent: RestoredCurrent {
    fn require_runtime(&mut self, runtime: &crate::store::Runtime) -> Result<()>;
    fn prepare_sql(&mut self, runtime: &crate::store::Runtime, access: NativeSqlUse) -> Result<()>;
    fn prepare_provider(
        &mut self,
        runtime: &crate::store::Runtime,
        use_: NativeProviderUse,
    ) -> Result<()>;
}

pub(crate) trait RestoredResponseCurrent: RestoredCurrent {
    fn reobserve(&mut self) -> Result<()>;
    fn response_complete(&mut self) -> Result<()>;
}

/// No Runtime, Arc, metadata or receipt constructor can supply this parent.
/// Only the actual native install/retirement path can move the genuine graph.
pub(crate) struct RestoredAppServingOwner {
    native: Option<RetiredRestoredAppNative>,
}

/// This is the same actual original captured before queueing/role movement.
/// Losing it retains the native capture's armed, permanent refusal behavior.
pub(crate) struct CapturedRestoredServingRequest {
    native: Option<CapturedRestoredAppRequest>,
}

/// The actual native borrowed scope, never a reconstructed owner. It retains
/// its original, context, parent and all native continuity internally, exposing
/// only the fixed operations below and no stage, Runtime or callback getter.
pub(crate) struct RestoredServingScope<'scope, 'request, 'original> {
    current: CurrentView<'scope, 'request, 'original>,
}

// The protected outer material owns completion. This private, unregistered
// operation view contains ONLY its actual native scope, never scalar state,
// copied disposition or a fallback. Its traits cannot construct native owners.
struct CurrentView<'scope, 'request, 'original> {
    native: RestoredAppCurrentPeer<'scope, 'request, 'original>,
}

impl sealed::Current for CurrentView<'_, '_, '_> {}

impl RestoredCurrent for CurrentView<'_, '_, '_> {
    fn check(&mut self) -> Result<()> {
        self.native.check_local()
    }

    fn arm(&mut self) -> Result<()> {
        self.native.arm()
    }

    fn finish_known(&mut self) -> Result<()> {
        self.native.finish_known()
    }

    fn refuse(&mut self) {
        self.native.refuse();
    }
}

impl RestoredRuntimeCurrent for CurrentView<'_, '_, '_> {
    fn require_runtime(&mut self, runtime: &crate::store::Runtime) -> Result<()> {
        self.native.require_runtime(runtime)
    }

    fn prepare_sql(&mut self, runtime: &crate::store::Runtime, access: NativeSqlUse) -> Result<()> {
        self.native.prepare_sql(runtime, access)
    }

    fn prepare_provider(
        &mut self,
        runtime: &crate::store::Runtime,
        use_: NativeProviderUse,
    ) -> Result<()> {
        self.native.prepare_provider(runtime, use_)
    }
}

impl RestoredResponseCurrent for CurrentView<'_, '_, '_> {
    fn reobserve(&mut self) -> Result<()> {
        self.native.reobserve()
    }

    fn response_complete(&mut self) -> Result<()> {
        self.native.response_complete()
    }
}

impl RestoredAppServingOwner {
    pub(in crate::security_epoch) fn from_native(native: RetiredRestoredAppNative) -> Self {
        Self {
            native: Some(native),
        }
    }

    pub(crate) fn capture_request(&mut self) -> Result<CapturedRestoredServingRequest> {
        let result = self
            .native
            .as_mut()
            .context("restored serving owner refused")?
            .capture_request();
        match result {
            Ok(native) => Ok(CapturedRestoredServingRequest {
                native: Some(native),
            }),
            Err(error) => {
                self.refuse();
                Err(error)
            }
        }
    }

    pub(crate) fn refuse(&mut self) {
        // Dropping the WHOLE native parent poisons its request/history/file
        // graph. No live-clock or current-stage check is needed to refuse it.
        drop(self.native.take());
    }
}

impl CapturedRestoredServingRequest {
    /// Move the genuine pre-configuration capture with its armed destructor;
    /// no scalar clock, capture factory or native owner is reconstructed.
    pub(in crate::security_epoch) fn from_native(native: CapturedRestoredAppRequest) -> Self {
        Self {
            native: Some(native),
        }
    }

    /// Negative original identity only, never a native/stage/authority getter.
    pub(crate) fn consumer_origin(&self) -> Result<NativeConsumerOrigin> {
        self.native
            .as_ref()
            .context("restored serving request refused")?
            .consumer_origin()
    }

    pub(crate) fn begin_current<'scope, 'request, 'original>(
        &'scope mut self,
        parent: &'scope mut RestoredAppServingOwner,
        mut context: NativeConsumerContext<'request, 'original>,
    ) -> Result<RestoredServingScope<'scope, 'request, 'original>> {
        if self.native.is_none() || parent.native.is_none() {
            context.refuse();
            self.refuse();
            parent.refuse();
            anyhow::bail!("restored consumer parent or capture refused");
        }
        let native = self
            .native
            .as_mut()
            .expect("actual captured request")
            .begin_current(
                parent.native.as_mut().expect("actual whole parent"),
                context,
            )?;
        Ok(RestoredServingScope {
            current: CurrentView { native },
        })
    }

    pub(crate) fn finish<'request, 'original>(
        mut self,
        parent: &mut RestoredAppServingOwner,
        mut context: NativeRequestFinalContext<'request, 'original>,
    ) -> Result<()> {
        if self.native.is_none() || parent.native.is_none() {
            context.refuse();
            self.refuse();
            parent.refuse();
            anyhow::bail!("restored final parent or capture refused");
        }
        self.native.take().expect("actual captured request").finish(
            parent.native.as_mut().expect("actual whole parent"),
            context,
        )
    }

    pub(crate) fn capture_human_clock(
        &mut self,
        parent: &mut RestoredAppServingOwner,
    ) -> Result<EnrolledOriginalClock> {
        if self.native.is_none() || parent.native.is_none() {
            self.refuse();
            parent.refuse();
            anyhow::bail!("restored human parent or capture refused");
        }
        self.native
            .as_mut()
            .expect("actual captured request")
            .capture_human_clock(parent.native.as_mut().expect("actual whole parent"))
    }

    pub(crate) fn sample_human_clock(
        &mut self,
        parent: &mut RestoredAppServingOwner,
        clock: &mut EnrolledOriginalClock,
    ) -> Result<std::time::Duration> {
        if self.native.is_none() || parent.native.is_none() {
            self.refuse();
            parent.refuse();
            anyhow::bail!("restored human parent or capture refused");
        }
        self.native
            .as_mut()
            .expect("actual captured request")
            .sample_human_clock(parent.native.as_mut().expect("actual whole parent"), clock)
    }

    pub(crate) fn refuse(&mut self) {
        // The native request's own Drop poisons its actual original/history
        // and parent gate even when that parent is currently borrowed.
        drop(self.native.take());
    }
}

impl RestoredServingScope<'_, '_, '_> {
    /// Checked operation loan only. The concrete parent retains completion;
    /// no caller-supplied trait object can stand in for this genuine scope.
    pub(crate) fn borrow_runtime(
        &mut self,
        runtime: &crate::store::Runtime,
        purpose: RuntimeServingUse,
    ) -> Result<&mut dyn RestoredRuntimeCurrent> {
        self.current
            .native
            .require_runtime_purpose(runtime, purpose)?;
        Ok(&mut self.current)
    }

    pub(crate) fn borrow_response(
        &mut self,
        runtime: &crate::store::Runtime,
    ) -> Result<&mut dyn RestoredResponseCurrent> {
        self.current.native.require_response(runtime)?;
        Ok(&mut self.current)
    }

    pub(crate) fn require_human(
        &mut self,
        runtime: &crate::store::Runtime,
        intent: &crate::oauth::fresh_auth::FreshIntent,
        phase: crate::oauth::native_management::Phase,
    ) -> Result<()> {
        self.current.native.require_runtime(runtime)?;
        self.current.native.require_human(intent, phase)
    }

    pub(crate) fn finish_excluded(&mut self) -> Result<()> {
        self.current.native.finish_excluded()
    }

    pub(crate) fn finish(self) -> Result<()> {
        self.current.native.finish()
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$type as Ambiguous<_>>::check;
        }};
    }
    macro_rules! closed {
        ($type:ty) => {
            assert_not_impl!($type, Clone);
            assert_not_impl!($type, Copy);
            assert_not_impl!($type, Default);
            assert_not_impl!($type, std::fmt::Debug);
            assert_not_impl!($type, Send);
            assert_not_impl!($type, Sync);
            assert_not_impl!($type, serde::Serialize);
            assert_not_impl!($type, serde::Deserialize<'static>);
        };
    }
    closed!(RestoredAppServingOwner);
    closed!(CapturedRestoredServingRequest);
    closed!(RestoredServingScope<'static, 'static, 'static>);
};

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens;

    #[test]
    fn protected_scope_has_no_manual_traits_and_private_view_contains_only_the_real_native_scope() {
        let file = syn::parse_file(include_str!("restored.rs")).unwrap();
        let mut view = None;
        for item in &file.items {
            if let syn::Item::Impl(item) = item
                && item.trait_.is_some()
            {
                assert!(!matches!(&*item.self_ty, syn::Type::Path(path)
                    if path.path.segments.last().unwrap().ident == "RestoredServingScope"));
            }
            if let syn::Item::Struct(item) = item
                && item.ident == "CurrentView"
            {
                view = Some(item);
            }
        }
        let view = view.unwrap();
        assert!(matches!(&view.vis, syn::Visibility::Inherited));
        assert_eq!(view.fields.len(), 1);
        let field = view.fields.iter().next().unwrap();
        assert!(matches!(&field.vis, syn::Visibility::Inherited));
        assert!(matches!(&field.ty, syn::Type::Path(path)
            if path.path.segments.last().unwrap().ident == "RestoredAppCurrentPeer"));
    }

    #[test]
    fn concrete_scope_checks_the_exact_context_before_lending_a_fixed_operation_view() {
        let file = syn::parse_file(include_str!("restored.rs")).unwrap();
        for (name, expected) in [
            (
                "borrow_runtime",
                syn::parse_quote!({
                    self.current
                        .native
                        .require_runtime_purpose(runtime, purpose)?;
                    Ok(&mut self.current)
                }),
            ),
            (
                "borrow_response",
                syn::parse_quote!({
                    self.current.native.require_response(runtime)?;
                    Ok(&mut self.current)
                }),
            ),
        ] {
            let expected: syn::Block = expected;
            let actual = file
                .items
                .iter()
                .find_map(|item| {
                    let syn::Item::Impl(item) = item else {
                        return None;
                    };
                    if !matches!(&*item.self_ty, syn::Type::Path(path)
                    if path.path.segments.last().unwrap().ident == "RestoredServingScope")
                    {
                        return None;
                    }
                    item.items.iter().find_map(|item| match item {
                        syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                        _ => None,
                    })
                })
                .unwrap();
            let guarded = |body: &syn::Block| {
                body.to_token_stream().to_string() == expected.to_token_stream().to_string()
            };
            assert!(guarded(&actual.block));
            let mut omitted = actual.block.clone();
            omitted.stmts.remove(0);
            assert!(!guarded(&omitted));
            let mut relabelled = actual.block.clone();
            relabelled.stmts[0] = syn::parse_quote!(self.current.native.check_local()?;);
            assert!(!guarded(&relabelled));
        }
    }

    fn method(name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("restored.rs")).unwrap();
        file.items
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty,
                syn::Type::Path(path) if path.path.is_ident("CapturedRestoredServingRequest")) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .flat_map(|item| item.items)
            .find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
            .unwrap()
    }

    fn whole_request_forwarding(method: &syn::ImplItemFn) -> bool {
        let actual = method.block.to_token_stream().to_string();
        let begin: syn::Block = syn::parse_quote!({
            if self.native.is_none() || parent.native.is_none() {
                context.refuse();
                self.refuse();
                parent.refuse();
                anyhow::bail!("restored consumer parent or capture refused");
            }
            let native = self
                .native
                .as_mut()
                .expect("actual captured request")
                .begin_current(
                    parent.native.as_mut().expect("actual whole parent"),
                    context,
                )?;
            Ok(RestoredServingScope {
                current: CurrentView { native },
            })
        });
        let final_request: syn::Block = syn::parse_quote!({
            if self.native.is_none() || parent.native.is_none() {
                context.refuse();
                self.refuse();
                parent.refuse();
                anyhow::bail!("restored final parent or capture refused");
            }
            self.native.take().expect("actual captured request").finish(
                parent.native.as_mut().expect("actual whole parent"),
                context,
            )
        });
        actual == begin.to_token_stream().to_string()
            || actual == final_request.to_token_stream().to_string()
    }

    #[test]
    fn actual_borrow_and_final_settlement_forward_the_whole_capture_parent_and_context() {
        for name in ["begin_current", "finish"] {
            let actual = method(name);
            assert!(whole_request_forwarding(&actual));
            for index in 0..actual.block.stmts.len() {
                let mut bypass = actual.clone();
                bypass.block.stmts.remove(index);
                assert!(!whole_request_forwarding(&bypass));
            }
            let mut accepting = actual.clone();
            *accepting.block.stmts.last_mut().unwrap() =
                syn::Stmt::Expr(syn::parse_quote!(Ok(())), None);
            assert!(!whole_request_forwarding(&accepting));
            let mut old_scope = actual.clone();
            old_scope.block.stmts.insert(
                0,
                syn::parse_quote!(
                    self.native.take().unwrap().begin_current(parent, request)?;
                ),
            );
            assert!(!whole_request_forwarding(&old_scope));
        }
    }

    #[test]
    fn absent_whole_parent_and_capture_cannot_become_native_material() {
        let mut parent = RestoredAppServingOwner { native: None };
        assert!(parent.capture_request().is_err());
        parent.refuse();
        assert!(parent.capture_request().is_err());
        let mut request = CapturedRestoredServingRequest { native: None };
        assert!(request.consumer_origin().is_err());
        request.refuse();
        assert!(request.consumer_origin().is_err());
    }
}
