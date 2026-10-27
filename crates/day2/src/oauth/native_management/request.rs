//! One accepted operation original. Routing clones share the actual slot;
//! no selection DATA or later callback can replace its clock or native owner.

use super::{NativeSelection, OWNERS};
use crate::security_epoch::native_enrollment::{
    EnrolledCurrentRequest, EnrolledProcessRoleOwner, EnrolledRoleStage, NativeRole,
    UnselectedShellRequest,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

// Capturing is already an attempt. Failure or unwind cannot return to Empty
// and obtain a later origin for the same accepted operation.
enum Slot<T> {
    Empty,
    Capturing,
    Live(T),
    Leased,
    Complete,
    Refused,
}

impl<T> Slot<T> {
    fn begin(&mut self) -> Result<()> {
        ensure!(
            matches!(self, Self::Empty),
            "native request already attempted"
        );
        *self = Self::Capturing;
        Ok(())
    }

    fn install(&mut self, value: T) -> Result<()> {
        ensure!(
            matches!(self, Self::Capturing),
            "native request capture refused"
        );
        *self = Self::Live(value);
        Ok(())
    }

    fn take(&mut self) -> Result<T> {
        ensure!(matches!(self, Self::Live(_)), "native request unavailable");
        let Self::Live(value) = std::mem::replace(self, Self::Leased) else {
            unreachable!("exclusive checked live slot")
        };
        Ok(value)
    }

    fn complete(&mut self) -> Result<()> {
        ensure!(
            matches!(self, Self::Leased),
            "native request completion refused"
        );
        *self = Self::Complete;
        Ok(())
    }

    fn refuse(&mut self) {
        if !matches!(self, Self::Complete) {
            *self = Self::Refused;
        }
    }
}

enum Original {
    Selected {
        scope: AuthorityScope,
        kind: NativeRole,
        current: EnrolledCurrentRequest,
    },
    Shell(UnselectedShellRequest),
    // A sealed literal producer supplies no application or native authority.
    LiteralHealth,
    // An explicitly non-native profile has no enrolled role to borrow. This
    // records transport lifetime only and can never bind or lease authority.
    NonNative,
    #[cfg(test)]
    Model(ModelOriginal),
}

impl Original {
    fn require(&self, scope: &AuthorityScope, kind: NativeRole) -> Result<()> {
        let Self::Selected {
            scope: selected,
            kind: actual,
            ..
        } = self
        else {
            anyhow::bail!("native request not bound")
        };
        ensure!(
            selected == scope && *actual == kind,
            "native request scope changed"
        );
        Ok(())
    }
}

/// A routing handle to one slot, never a clone of its actual native original.
/// A second callback cannot take an original held by the response lease.
pub(super) struct Request {
    slot: Rc<RefCell<Slot<Original>>>,
    refused: Rc<Cell<bool>>,
}

impl Clone for Request {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
            refused: self.refused.clone(),
        }
    }
}

impl Request {
    pub(super) fn new() -> Self {
        Self {
            slot: Rc::new(RefCell::new(Slot::Empty)),
            refused: Rc::new(Cell::new(false)),
        }
    }

    pub(super) fn capture_app(&self, scope: &AuthorityScope) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        let acquired = OWNERS.with(|owners| {
            let mut owners = owners.try_borrow_mut()?;
            let owners = owners
                .get_mut(scope.app.as_str())
                .context("native request App missing")?;
            ensure!(
                owners.kind == NativeRole::AppHost && owners.selection.scope() == scope,
                "native request App selection changed"
            );
            let mut role = owners.role.try_borrow_mut()?;
            role.begin_current_request()
        });
        match acquired {
            Ok(current) => slot.install(Original::Selected {
                scope: scope.clone(),
                kind: NativeRole::AppHost,
                current,
            }),
            Err(error) => {
                slot.refuse();
                Err(error)
            }
        }
    }

    pub(super) fn capture_shell(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        match UnselectedShellRequest::capture() {
            Ok(start) => slot.install(Original::Shell(start)),
            Err(error) => {
                slot.refuse();
                Err(error)
            }
        }
    }

    pub(super) fn capture_literal_health(
        &self,
        response: &crate::web::NativeResponse,
    ) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        ensure!(
            response.is_literal_health(),
            "native literal response required"
        );
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        slot.install(Original::LiteralHealth)
    }

    pub(super) fn capture_non_native(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        slot.install(Original::NonNative)
    }

    pub(super) fn with_stage<T>(
        &self,
        role: &mut EnrolledProcessRoleOwner,
        selection: &NativeSelection,
        kind: NativeRole,
        operation: impl FnOnce(EnrolledRoleStage<'_>) -> Result<T>,
    ) -> Result<T> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        if matches!(*slot, Slot::Live(Original::Shell(_))) {
            ensure!(
                kind == NativeRole::SecurityShell,
                "native Shell request role changed"
            );
            let Original::Shell(start) = slot.take()? else {
                unreachable!("exclusive checked Shell original")
            };
            let current = match role.bind_shell_request(start) {
                Ok(current) => current,
                Err(error) => {
                    slot.refuse();
                    return Err(error);
                }
            };
            *slot = Slot::Live(Original::Selected {
                scope: selection.scope().clone(),
                kind,
                current,
            });
        }
        let Slot::Live(original) = &mut *slot else {
            anyhow::bail!("native request unavailable")
        };
        // Exclude a foreign caller before observing or poisoning the winner.
        original.require(selection.scope(), kind)?;
        let Original::Selected { current, .. } = original else {
            unreachable!("checked selected request")
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut stage = role.borrow_current_request(current)?;
            stage.check_selection(&selection.policy, &selection.store, kind)?;
            let value = operation(stage)?;
            ensure!(
                !self.refused.get(),
                "native request refused during callback"
            );
            // Reborrow the SAME original for final identity/clock checks. The
            // prior callback's actual stage has ended; no new clock is begun.
            role.borrow_current_request(current)?.check_selection(
                &selection.policy,
                &selection.store,
                kind,
            )?;
            Ok(value)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    slot.refuse();
                }
                result
            }
            Err(panic) => {
                slot.refuse();
                std::panic::resume_unwind(panic)
            }
        }
    }

    pub(super) fn take(&self, scope: &AuthorityScope, kind: NativeRole) -> Result<Lease> {
        ensure!(!self.refused.get(), "native request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        let Slot::Live(original) = &*slot else {
            anyhow::bail!("native request unavailable")
        };
        original.require(scope, kind)?;
        let Original::Selected { current, .. } = slot.take()? else {
            unreachable!("checked selected request")
        };
        Ok(Lease {
            held: Held {
                slot: self.slot.clone(),
                refused: self.refused.clone(),
                current: Some(current),
            },
        })
    }

    pub(super) fn finish(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request refused");
        let original = self.slot.try_borrow_mut()?.take()?;
        let result = match original {
            Original::LiteralHealth | Original::NonNative => Ok(()),
            Original::Shell(start) => start.finish(),
            Original::Selected {
                scope,
                kind,
                current,
            } => OWNERS.with(|owners| {
                let mut owners = owners.try_borrow_mut()?;
                let owners = owners
                    .get_mut(scope.app.as_str())
                    .context("native request owner missing")?;
                ensure!(
                    owners.kind == kind && owners.selection.scope() == &scope,
                    "native request final owner changed"
                );
                let mut role = owners.role.try_borrow_mut()?;
                current.finish(&mut role)
            }),
            #[cfg(test)]
            Original::Model(mut model) => model.check(),
        };
        let mut slot = self.slot.try_borrow_mut()?;
        if let Err(error) = result {
            slot.refuse();
            return Err(error);
        }
        ensure!(
            !self.refused.get(),
            "native request refused during completion"
        );
        slot.complete()
    }

    pub(super) fn refuse(&self) {
        // This latch must work even while a synchronous consumer holds the
        // actual original's RefCell borrow and catches an inner abort error.
        self.refused.set(true);
        if let Ok(mut slot) = self.slot.try_borrow_mut() {
            slot.refuse();
        }
    }

    #[cfg(test)]
    pub(super) fn has_started(&self) -> Result<bool> {
        Ok(!matches!(*self.slot.try_borrow()?, Slot::Empty))
    }

    /// DATA-only test port. It cannot be borrowed as an EnrolledRoleStage.
    #[cfg(test)]
    pub(super) fn capture_model(&self) -> Result<()> {
        ensure!(!self.refused.get(), "scripted request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        slot.begin()?;
        slot.install(Original::Model(ModelOriginal::new()))
    }

    #[cfg(test)]
    pub(super) fn model_origin(&self) -> Result<Option<std::time::Duration>> {
        ensure!(!self.refused.get(), "scripted request refused");
        let mut slot = self.slot.try_borrow_mut()?;
        match &mut *slot {
            Slot::Live(Original::Model(model)) => {
                model.check()?;
                model.origin()
            }
            // Lower model tests need not claim an HTTP request. They still
            // cannot construct any actual enrolled role or original.
            Slot::Empty => Ok(None),
            _ => anyhow::bail!("scripted request unavailable"),
        }
    }
}

/// The response future owns this actual original alongside the actual role.
/// No RefCell borrow survives an await and cancellation drops this original.
pub(super) struct Lease {
    held: Held<Original, EnrolledCurrentRequest>,
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
    assert_not_impl!(Lease, Clone);
    assert_not_impl!(Lease, Copy);
    assert_not_impl!(Lease, Default);
    assert_not_impl!(Lease, std::fmt::Debug);
    assert_not_impl!(Lease, Send);
    assert_not_impl!(Lease, Sync);
    assert_not_impl!(Lease, serde::Serialize);
    assert_not_impl!(Lease, serde::Deserialize<'static>);
    // Routing clones share the same actual value and terminal latch. They
    // cannot cross executors, serialize an original or manufacture a default.
    assert_not_impl!(Request, Default);
    assert_not_impl!(Request, std::fmt::Debug);
    assert_not_impl!(Request, Send);
    assert_not_impl!(Request, Sync);
    assert_not_impl!(Request, serde::Serialize);
    assert_not_impl!(Request, serde::Deserialize<'static>);
};

// Common move/cancellation code is tested with non-authority material. Only
// the native Lease wrapper can expose a stage, and only with a genuine role.
struct Held<S, T> {
    slot: Rc<RefCell<Slot<S>>>,
    refused: Rc<Cell<bool>>,
    current: Option<T>,
}

impl<S, T> Held<S, T> {
    fn check(&self) -> Result<()> {
        ensure!(!self.refused.get(), "native request lease refused");
        ensure!(
            matches!(*self.slot.try_borrow()?, Slot::Leased),
            "native request lease refused"
        );
        Ok(())
    }

    fn complete(&mut self) -> Result<()> {
        self.check()?;
        ensure!(self.current.is_none(), "native request still owned");
        self.slot.try_borrow_mut()?.complete()
    }
}

impl Lease {
    pub(super) fn borrow<'a>(
        &'a mut self,
        role: &'a mut EnrolledProcessRoleOwner,
    ) -> Result<EnrolledRoleStage<'a>> {
        self.held.check()?;
        role.borrow_current_request(
            self.held
                .current
                .as_mut()
                .context("native request consumed")?,
        )
    }

    pub(super) fn finish(mut self, role: &mut EnrolledProcessRoleOwner) -> Result<()> {
        self.held.check()?;
        self.held
            .current
            .take()
            .context("native request consumed")?
            .finish(role)?;
        self.held.complete()
    }
}

impl<S, T> Drop for Held<S, T> {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.try_borrow_mut() {
            if !matches!(*slot, Slot::Complete) {
                self.refused.set(true);
            }
            slot.refuse();
        } else {
            self.refused.set(true);
        }
    }
}

#[cfg(test)]
struct ModelOriginal {
    origin: crate::oauth::effects::Instant,
    latest: crate::oauth::effects::Instant,
    thread: std::thread::ThreadId,
    refused: bool,
}

#[cfg(test)]
impl ModelOriginal {
    fn new() -> Self {
        let origin = crate::oauth::effects::Instant::now();
        Self {
            origin,
            latest: origin,
            thread: std::thread::current().id(),
            refused: false,
        }
    }

    fn check(&mut self) -> Result<()> {
        let now = crate::oauth::effects::Instant::now();
        let elapsed = now.checked_duration_since(self.origin);
        if self.refused
            || self.thread != std::thread::current().id()
            || now.checked_duration_since(self.latest).is_none()
            || elapsed.is_none_or(|elapsed| elapsed >= std::time::Duration::from_secs(5))
        {
            self.refused = true;
            anyhow::bail!("scripted HTTP original expired or changed")
        }
        self.latest = now;
        Ok(())
    }

    fn origin(&self) -> Result<Option<std::time::Duration>> {
        match self.origin {
            crate::oauth::effects::Instant::Simulated { ticks, .. } => Ok(Some(ticks)),
            crate::oauth::effects::Instant::Live(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::effects;
    use std::{
        cell::Cell,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    struct Time {
        domain: u64,
        millis: AtomicU64,
    }
    impl effects::Hooks for Time {
        fn domain(&self) -> u64 {
            self.domain
        }
        fn wall_time(&self) -> Result<i64> {
            Ok(100)
        }
        fn monotonic(&self) -> Duration {
            Duration::from_millis(self.millis.load(Ordering::SeqCst))
        }
        fn fill(&self, _: &mut [u8]) -> Result<()> {
            anyhow::bail!("clock model has no entropy")
        }
        fn send(&self, _: reqwest::blocking::Request) -> Result<effects::Response> {
            anyhow::bail!("clock model has no network")
        }
        fn provider_observation(
            &self,
            _: crate::oauth::shell_oidc::ProviderObservationData,
        ) -> Result<()> {
            anyhow::bail!("clock model has no provider")
        }
    }

    fn absent_scope() -> AuthorityScope {
        AuthorityScope {
            installation: "unenrolled-test".to_owned().try_into().unwrap(),
            environment: "test".to_owned().try_into().unwrap(),
            app: "no-native-owner".to_owned().try_into().unwrap(),
        }
    }

    #[test]
    fn non_native_transport_cannot_supply_or_reclassify_native_authority() -> Result<()> {
        for abort in [false, true] {
            let request = Request::new();
            request.capture_non_native()?;
            for role in [NativeRole::AppHost, NativeRole::SecurityShell] {
                assert!(request.take(&absent_scope(), role).is_err());
            }
            assert!(request.capture_app(&absent_scope()).is_err());
            assert!(request.capture_shell().is_err());
            assert!(request.capture_model().is_err());
            if abort {
                request.refuse();
                assert!(request.finish().is_err());
            } else {
                request.finish()?;
                assert!(request.finish().is_err());
            }
            assert!(request.capture_non_native().is_err());
        }
        Ok(())
    }

    #[test]
    fn missing_native_supplier_cannot_downgrade_to_non_native_transport() {
        let request = Request::new();
        assert!(request.capture_app(&absent_scope()).is_err());
        assert!(request.capture_non_native().is_err());
        assert!(request.capture_model().is_err());
        assert!(request.finish().is_err());
    }

    #[test]
    fn later_callbacks_spend_the_original_interval_and_exact_expiry_cannot_recover() -> Result<()> {
        let time = Arc::new(Time {
            domain: 71,
            millis: AtomicU64::new(10_000),
        });
        effects::scope(time.clone(), || -> Result<()> {
            let request = Request::new();
            request.capture_model()?;
            assert_eq!(request.model_origin()?, Some(Duration::from_secs(10)));
            time.millis.store(14_999, Ordering::SeqCst);
            assert_eq!(request.model_origin()?, Some(Duration::from_secs(10)));
            time.millis.store(15_000, Ordering::SeqCst);
            assert!(request.model_origin().is_err());
            time.millis.store(10_001, Ordering::SeqCst);
            assert!(request.model_origin().is_err());
            assert!(request.capture_model().is_err());
            assert!(request.finish().is_err());
            Ok(())
        })
    }

    #[test]
    fn rewind_or_foreign_domain_refuses_the_same_original_after_restoration() -> Result<()> {
        for foreign in [false, true] {
            let time = Arc::new(Time {
                domain: 72,
                millis: AtomicU64::new(10_000),
            });
            let other = Arc::new(Time {
                domain: 73,
                millis: AtomicU64::new(10_001),
            });
            effects::scope(time.clone(), || -> Result<()> {
                let request = Request::new();
                request.capture_model()?;
                time.millis.store(10_002, Ordering::SeqCst);
                request.model_origin()?;
                if foreign {
                    effects::scope(other, || assert!(request.model_origin().is_err()));
                } else {
                    time.millis.store(10_001, Ordering::SeqCst);
                    assert!(request.model_origin().is_err());
                }
                time.millis.store(10_003, Ordering::SeqCst);
                assert!(request.model_origin().is_err());
                assert!(request.finish().is_err());
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn abort_is_sticky_even_when_the_original_is_borrowed_and_the_error_is_caught() -> Result<()> {
        let request = Request::new();
        request.capture_model()?;
        let borrowed = request.slot.borrow_mut();
        request.clone().refuse();
        assert!(request.refused.get());
        drop(borrowed);
        assert!(request.model_origin().is_err());
        assert!(request.finish().is_err());
        assert!(request.capture_model().is_err());
        Ok(())
    }

    struct Material {
        identity: Rc<()>,
        refused: Rc<Cell<bool>>,
        complete: bool,
    }
    impl Material {
        fn finish(mut self) {
            self.complete = true;
        }
    }
    impl Drop for Material {
        fn drop(&mut self) {
            if !self.complete {
                self.refused.set(true);
            }
        }
    }

    #[test]
    fn suspension_moves_the_original_and_cancel_refuses_without_a_second_owner() {
        let slot = Rc::new(RefCell::new(Slot::Empty));
        let identity = Rc::new(());
        let refused = Rc::new(Cell::new(false));
        slot.borrow_mut().begin().unwrap();
        slot.borrow_mut()
            .install(Material {
                identity: identity.clone(),
                refused: refused.clone(),
                complete: false,
            })
            .unwrap();
        let actual = slot.borrow_mut().take().unwrap();
        let held = Held {
            slot: slot.clone(),
            refused: Rc::new(Cell::new(false)),
            current: Some(actual),
        };
        let mut pending = Box::pin(async move {
            held.check().unwrap();
            assert!(Rc::ptr_eq(
                &held.current.as_ref().unwrap().identity,
                &identity
            ));
            std::future::pending::<()>().await;
            drop(held);
        });
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(std::future::Future::poll(pending.as_mut(), &mut cx).is_pending());
        assert!(
            slot.try_borrow_mut().is_ok(),
            "no borrowed RefCell crosses suspension"
        );
        assert!(slot.borrow_mut().take().is_err());
        drop(pending);
        assert!(refused.get());
        assert!(slot.borrow_mut().begin().is_err());
        assert!(slot.borrow_mut().complete().is_err());
    }

    #[test]
    fn only_the_finished_actual_value_can_publish_completion() {
        let slot = Rc::new(RefCell::new(Slot::Empty));
        let refused = Rc::new(Cell::new(false));
        slot.borrow_mut().begin().unwrap();
        slot.borrow_mut()
            .install(Material {
                identity: Rc::new(()),
                refused: refused.clone(),
                complete: false,
            })
            .unwrap();
        let actual = slot.borrow_mut().take().unwrap();
        let mut held = Held {
            slot: slot.clone(),
            refused: Rc::new(Cell::new(false)),
            current: Some(actual),
        };
        assert!(held.complete().is_err());
        held.current.take().unwrap().finish();
        held.complete().unwrap();
        drop(held);
        assert!(!refused.get());
        assert!(matches!(*slot.borrow(), Slot::Complete));
        assert!(slot.borrow_mut().begin().is_err());
    }

    fn selected_body(source: &str, owner: Option<&str>, name: &str) -> syn::Block {
        let file = syn::parse_file(source).unwrap();
        let mut bodies = Vec::new();
        for item in file.items {
            match item {
                syn::Item::Fn(item) if owner.is_none() && item.sig.ident == name => bodies.push(*item.block),
                syn::Item::Impl(item) if owner.is_some_and(|owner| matches!(&*item.self_ty,
                    syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == owner))) => {
                    for item in item.items {
                        if let syn::ImplItem::Fn(item) = item && item.sig.ident == name { bodies.push(item.block); }
                    }
                }
                _ => {}
            }
        }
        assert_eq!(
            bodies.len(),
            1,
            "exact production owner/method must remain unique"
        );
        bodies.pop().unwrap()
    }

    fn methods(body: &syn::Block) -> Vec<String> {
        use syn::visit::Visit;
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.0.push(call.method.to_string());
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let mut calls = Calls(Vec::new());
        calls.visit_block(body);
        calls.0
    }

    fn operation_capture_is_preserved(source: &str) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Service {
            checked: usize,
            valid: bool,
        }
        impl Service {
            fn tokens(&mut self, tokens: proc_macro2::TokenStream) {
                for token in tokens {
                    let proc_macro2::TokenTree::Group(group) = token else {
                        continue;
                    };
                    if group.delimiter() == proc_macro2::Delimiter::Brace {
                        let grouped = proc_macro2::TokenStream::from(
                            proc_macro2::TokenTree::Group(group.clone()),
                        );
                        if let Ok(block) = syn::parse2::<syn::Block>(grouped) {
                            self.visit_block(&block);
                            continue;
                        }
                    }
                    self.tokens(group.stream());
                }
            }
        }
        impl<'ast> Visit<'ast> for Service {
            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                // select! owns the real connection/service block. Descend its
                // syntax groups without pretending to expand arbitrary macros.
                self.tokens(mac.tokens.clone());
            }

            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if !matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("service_fn"))
                {
                    syn::visit::visit_expr_call(self, call);
                    return;
                }
                self.checked += 1;
                let Some(syn::Expr::Closure(closure)) = call.args.first() else {
                    return;
                };
                let syn::Expr::Block(block) = &*closure.body else {
                    return;
                };
                let mut captured = false;
                for statement in &block.block.stmts {
                    match statement {
                        syn::Stmt::Local(local) => {
                            let Some(init) = &local.init else {
                                return;
                            };
                            let syn::Expr::MethodCall(call) = &*init.expr else {
                                return;
                            };
                            if call.method == "capture_request" {
                                if captured
                                    || call.args.len() != 2
                                    || !matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("endpoint"))
                                    || !matches!(&call.args[0], syn::Expr::Reference(reference) if matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident("sink")))
                                    || !matches!(&call.args[1], syn::Expr::Reference(reference) if matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident("request")))
                                {
                                    return;
                                }
                                captured = true;
                            } else if call.method != "clone" {
                                return;
                            }
                        }
                        syn::Stmt::Expr(syn::Expr::Async(_), _) => {
                            self.valid = captured;
                            return;
                        }
                        _ => return,
                    }
                }
            }
        }
        let body = selected_body(source, None, "run");
        let mut service = Service::default();
        service.visit_block(&body);
        service.checked == 1 && service.valid
    }

    #[test]
    fn production_capture_precedes_async_dispatch_and_removal_or_delayed_capture_is_detected() {
        let source = include_str!("../native_http.rs");
        assert!(operation_capture_is_preserved(source));
        let removed = source.replacen(
            "let captured = endpoint.capture_request(&sink, &request);",
            "let captured = None;",
            1,
        );
        assert_ne!(removed, source);
        assert!(!operation_capture_is_preserved(&removed));
        let moved = source.replacen("let captured = endpoint.capture_request(&sink, &request);", "", 1)
            .replacen("let response = match captured", "let captured = endpoint.capture_request(&sink, &request); let response = match captured", 1);
        assert!(!operation_capture_is_preserved(&moved));
        let wrong = source.replacen(
            "endpoint.capture_request(&sink, &request)",
            "endpoint.capture_request(&other_sink, &request)",
            1,
        );
        assert!(!operation_capture_is_preserved(&wrong));
    }

    #[test]
    fn lexical_consumers_reborrow_the_actual_request_without_an_original_factory() {
        let source = include_str!("../native_management.rs");
        for (owner, name) in [
            (Some("EnrolledClock"), "sample"),
            (None, "with_app_participant"),
            (None, "with_current_for_role"),
            (None, "with_runtime_response"),
        ] {
            let body = selected_body(source, owner, name);
            let calls = methods(&body);
            assert!(!calls.iter().any(|name| name == "begin_current_stage"));
            assert_eq!(calls.iter().filter(|name| *name == "with_stage").count(), 1);
        }
        let source = include_str!("request.rs");
        let body = selected_body(source, Some("Request"), "with_stage");
        let calls = methods(&body);
        assert_eq!(
            calls
                .iter()
                .filter(|name| *name == "borrow_current_request")
                .count(),
            2
        );
        assert!(!calls.iter().any(|name| name == "begin_current_stage"));
        let restored = source.replacen(
            "role.borrow_current_request(current)?",
            "role.begin_current_stage()?",
            1,
        );
        let calls = methods(&selected_body(&restored, Some("Request"), "with_stage"));
        assert_eq!(
            calls
                .iter()
                .filter(|name| *name == "borrow_current_request")
                .count(),
            1
        );
        assert!(calls.iter().any(|name| name == "begin_current_stage"));
    }

    #[test]
    fn finite_response_moves_the_same_request_and_finishes_before_result_publication() {
        let source = include_str!("response.rs");
        let calls = methods(&selected_body(source, Some("Sink"), "drive_response"));
        assert!(!calls.iter().any(|name| name == "begin_current_stage"));
        let borrow = calls.iter().position(|name| name == "borrow").unwrap();
        let prepare = calls
            .iter()
            .position(|name| name == "prepare_current")
            .unwrap();
        assert!(borrow < prepare);
        let finish = calls.iter().rposition(|name| name == "finish").unwrap();
        let complete = calls.iter().rposition(|name| name == "complete").unwrap();
        assert!(finish < complete);
        let removed = source.replacen("request_owner.finish(role.owner())?;", "", 1);
        let calls = methods(&selected_body(&removed, Some("Sink"), "drive_response"));
        assert!(!calls.iter().any(|name| name == "finish"));
    }

    fn pump_entry_is_scoped(body: &syn::Block) -> bool {
        let Some(syn::Stmt::Local(local)) = body.stmts.first() else {
            return false;
        };
        let Some(init) = &local.init else {
            return false;
        };
        let syn::Expr::Call(call) = &*init.expr else {
            return false;
        };
        matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "with_runtime_operation"))
            && call.args.len() == 2
            && matches!(&call.args[1], syn::Expr::Closure(closure) if matches!(&*closure.body, syn::Expr::Match(_)))
    }

    #[test]
    fn all_pump_work_including_wall_time_starts_inside_the_one_operation_owner() {
        let source = include_str!("../../host_loop.rs");
        let actual = selected_body(source, Some("NativeWork"), "execute");
        assert!(pump_entry_is_scoped(&actual));
        let removed = source.replacen("with_runtime_operation", "unscoped_operation", 1);
        assert_ne!(source, removed);
        assert!(!pump_entry_is_scoped(&selected_body(
            &removed,
            Some("NativeWork"),
            "execute"
        )));
        let mut delayed = actual;
        delayed
            .stmts
            .insert(0, syn::parse_quote!(let _early = self.clock.wall_time();));
        assert!(!pump_entry_is_scoped(&delayed));
    }

    fn busy_exclusion_precedes_owner_lookup(body: &syn::Block) -> bool {
        use syn::visit::Visit;
        #[derive(Default)]
        struct EarlyScope(bool);
        impl<'ast> Visit<'ast> for EarlyScope {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|part| part.ident == "runtime_response_scope"))
                {
                    self.0 = true;
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut early = EarlyScope::default();
        early.visit_block(body);
        let calls = methods(body);
        !early.0
            && calls
                .iter()
                .filter(|name| *name == "excludes_unstarted_operation")
                .count()
                == 1
            && matches!((calls.iter().position(|name| name == "excludes_unstarted_operation"),
                calls.iter().position(|name| name == "get")), (Some(exclude), Some(lookup)) if exclude < lookup)
    }

    #[test]
    fn a_leased_response_excludes_background_work_before_the_absent_owner_lookup() {
        let source = include_str!("../native_management.rs");
        let actual = selected_body(source, None, "with_runtime_operation");
        assert!(busy_exclusion_precedes_owner_lookup(&actual));
        let mut early = actual;
        early.stmts.insert(
            0,
            syn::parse_quote!(let _early = runtime_response_scope(runtime)?;),
        );
        assert!(!busy_exclusion_precedes_owner_lookup(&early));
        let removed = source.replacen(
            "owners.excludes_unstarted_operation(runtime.app())?",
            "false",
            1,
        );
        assert_ne!(source, removed);
        assert!(!busy_exclusion_precedes_owner_lookup(&selected_body(
            &removed,
            None,
            "with_runtime_operation"
        )));
    }

    fn startup_host_is_scoped(body: &syn::Block) -> bool {
        let Some(position) = body.stmts.iter().position(|statement| matches!(statement,
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "prepare_host"))) else {
            return false;
        };
        let syn::Stmt::Local(prepared) = &body.stmts[position] else {
            return false;
        };
        let Some(initializer) = &prepared.init else {
            return false;
        };
        let syn::Expr::Closure(closure) = &*initializer.expr else {
            return false;
        };
        let syn::Expr::Block(host) = &*closure.body else {
            return false;
        };
        let calls = methods(&host.block);
        fn propagated_call(statement: &syn::Stmt) -> Option<&syn::ExprCall> {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let initializer = local.init.as_ref()?;
            let syn::Expr::Try(result) = &*initializer.expr else {
                return None;
            };
            let syn::Expr::Call(call) = &*result.expr else {
                return None;
            };
            Some(call)
        }
        let directly_configures = host
            .block
            .stmts
            .iter()
            .filter_map(propagated_call)
            .any(|call| {
                let syn::Expr::Paren(function) = &*call.func else {
                    return false;
                };
                let syn::Expr::Field(field) = &*function.expr else {
                    return false;
                };
                matches!(&field.member, syn::Member::Named(name) if name == "configure")
                    && matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("self"))
            });
        let directly_binds = host
            .block
            .stmts
            .iter()
            .filter_map(propagated_call)
            .filter(|call| {
                matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "bind_edge_listener"))
            })
            .count();
        if !directly_configures
            || directly_binds != 1
            || !calls.iter().any(|name| name == "into_native_parts")
            || calls.iter().any(|name| name == "complete")
        {
            return false;
        }
        let [
            syn::Stmt::Local(parts),
            syn::Stmt::Expr(completed, Some(_)),
            syn::Stmt::Expr(_, None),
        ] = &body.stmts[position + 1..]
        else {
            return false;
        };
        let Some(initializer) = &parts.init else {
            return false;
        };
        let syn::Expr::Try(result) = &*initializer.expr else {
            return false;
        };
        let syn::Expr::If(branch) = &*result.expr else {
            return false;
        };
        if !matches!(&*branch.cond, syn::Expr::Path(path) if path.path.is_ident("native_initial")) {
            return false;
        }
        let Some(syn::Stmt::Expr(syn::Expr::Call(call), None)) = branch.then_branch.stmts.last()
        else {
            return false;
        };
        matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "with_app_request"))
            && call.args.len() == 2
            && matches!(&call.args[0], syn::Expr::Path(path) if path.path.is_ident("scope"))
            && matches!(&call.args[1], syn::Expr::Path(path) if path.path.is_ident("prepare_host"))
            && matches!(completed, syn::Expr::MethodCall(call) if call.method == "complete"
                && call.args.is_empty()
                && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("observed")))
    }

    #[test]
    fn native_host_construction_shares_one_original_and_only_reports_completed_after_settlement() {
        let source = include_str!("../../deployment.rs");
        assert!(startup_host_is_scoped(&selected_body(
            source,
            Some("NativeAppStartup"),
            "prepare"
        )));
        for (before, after) in [
            (
                "crate::oauth::native_management::with_app_request(scope, prepare_host)",
                "prepare_host()",
            ),
            ("let parts = if native_initial {", "let parts = if false {"),
            (
                "        let parts = if native_initial {",
                "        observed.complete();\n        let parts = if native_initial {",
            ),
        ] {
            let changed = source.replacen(before, after, 1);
            assert_ne!(source, changed);
            assert!(!startup_host_is_scoped(&selected_body(
                &changed,
                Some("NativeAppStartup"),
                "prepare"
            )));
        }
    }

    #[test]
    fn capture_failure_or_unwind_never_reopens_the_original() {
        for refuse in [false, true] {
            let mut slot: Slot<()> = Slot::Empty;
            slot.begin().unwrap();
            if refuse {
                slot.refuse();
            }
            assert!(slot.begin().is_err());
            if refuse {
                assert!(slot.install(()).is_err());
            }
        }
    }

    #[test]
    fn original_moves_once_and_refusal_cannot_restore_it() {
        let mut slot = Slot::Empty;
        let original = std::rc::Rc::new(());
        slot.begin().unwrap();
        slot.install(original.clone()).unwrap();
        assert!(slot.begin().is_err());
        let held = slot.take().unwrap();
        assert!(std::rc::Rc::ptr_eq(&held, &original));
        assert!(slot.take().is_err());
        slot.refuse();
        assert!(slot.complete().is_err());
        assert!(slot.install(held).is_err());
        assert!(slot.take().is_err());
    }

    #[test]
    fn only_the_taken_original_can_complete_and_completion_is_terminal() {
        let mut slot = Slot::Empty;
        assert!(slot.complete().is_err());
        assert!(slot.install(17).is_err());
        slot.begin().unwrap();
        slot.install(17).unwrap();
        assert!(slot.complete().is_err());
        assert_eq!(slot.take().unwrap(), 17);
        slot.complete().unwrap();
        slot.refuse();
        assert!(matches!(slot, Slot::Complete));
        assert!(slot.begin().is_err());
        assert!(slot.install(18).is_err());
        assert!(slot.take().is_err());
    }
}
