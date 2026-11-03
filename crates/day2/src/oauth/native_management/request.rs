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

    // This fixture cannot pass Original::require or produce a native Lease.
    // It schedules the actual generic move/Drop decisions alongside the
    // independently checked real SQLite storage fixture.
    mod slot_lifecycle {
        use super::*;
        use crate::security_epoch::{ConsumerEvent, ConsumerLifecycle, ConsumerModelError};
        use serde::{Deserialize, Serialize};
        use serde_json::{Value, json};

        // Complete original and reduced observations share the existing 4 MiB
        // evidence contract. Reject larger programs before creating a world;
        // the longest-prefix control pins this declared supported limit.
        const MAX_EVENTS: usize = 12;
        const MAX_BUNDLE: usize = 4 * 1024 * 1024;

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
        enum Event {
            Capture { request: u8 },
            FailedCapture { request: u8 },
            Lease { request: u8 },
            Check { request: u8 },
            Finish { request: u8 },
            Cancel { request: u8, contended: bool },
            Refuse { request: u8 },
            NativeProbe { request: u8 },
            ForeignClock { request: u8 },
            Advance { millis: u64 },
            Rewind { millis: u64 },
            RevokeStorage {},
            ReopenAndRestoreClock {},
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Control {
            None,
            SlotOracle,
            StorageOracle,
        }

        fn source() -> String {
            source_with(ConsumerLifecycle::source())
        }

        fn source_with(storage: day2_capabilities::Digest) -> String {
            day2_capabilities::Digest::of(&(
                "request-slot-lifecycle-v1",
                crate::oauth::simulation::implementation(),
                storage,
            ))
            .unwrap()
            .as_str()
            .to_owned()
        }

        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Program {
            version: u32,
            seed: u64,
            events: Vec<Event>,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Phase {
            Empty,
            Capturing,
            Live,
            Leased,
            Complete,
            Refused,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Clock {
            domain: u64,
            origin: u64,
            latest: u64,
            refused: bool,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RequestState {
            phase: Phase,
            refused: bool,
            held: bool,
            current: Option<Clock>,
            captured: Option<(u64, u64)>,
            routing_clones_share_slot_and_latch: bool,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct State {
            requests: [RequestState; 2],
            distinct_slots: bool,
            storage_live: bool,
            now: u64,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Record {
            accepted: bool,
            state: State,
            storage: Value,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FailedStep {
            index: usize,
            actual_outcome: Option<bool>,
            observation: Record,
            independently_predicted: Value,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Divergence {
            category: String,
            index: usize,
            records: Vec<Record>,
            expected: Value,
            failed_step: Option<Box<FailedStep>>,
        }

        struct World {
            requests: [Request; 2],
            held: [Option<Held<Original, ModelOriginal>>; 2],
            captured: [Option<(u64, u64)>; 2],
            time: Arc<Time>,
            scope: AuthorityScope,
            storage: ConsumerLifecycle,
        }

        fn clock(value: &ModelOriginal) -> Result<Clock> {
            let effects::Instant::Simulated {
                domain,
                ticks: origin,
            } = value.origin
            else {
                anyhow::bail!("request history requires controlled original");
            };
            let effects::Instant::Simulated {
                domain: latest_domain,
                ticks: latest,
            } = value.latest
            else {
                anyhow::bail!("request history requires controlled latest sample");
            };
            ensure!(
                domain == latest_domain,
                "original domain changed in retained material"
            );
            Ok(Clock {
                domain,
                origin: origin.as_millis().try_into()?,
                latest: latest.as_millis().try_into()?,
                refused: value.refused,
            })
        }

        impl World {
            fn new(seed: u64) -> Result<Self> {
                let scope = absent_scope();
                let mut storage = ConsumerLifecycle::new(seed, &scope)?;
                storage.step(ConsumerEvent::FirstHolder { death_cut: None })?;
                for activation in [false, true] {
                    storage.step(ConsumerEvent::Reserve { activation })?;
                    storage.step(ConsumerEvent::Dispatch { activation })?;
                    storage.step(ConsumerEvent::Settle { activation })?;
                }
                storage.step(ConsumerEvent::Current {
                    death_cut: None,
                    rewrite_provider: false,
                })?;
                Ok(Self {
                    requests: [Request::new(), Request::new()],
                    held: [None, None],
                    captured: [None, None],
                    time: Arc::new(Time {
                        domain: seed.wrapping_add(700_000),
                        millis: AtomicU64::new(10_000),
                    }),
                    scope,
                    storage,
                })
            }

            fn check(&mut self, index: usize, finish: bool) -> Result<()> {
                let held = self.held[index]
                    .as_mut()
                    .context("request value not held")?;
                let result = (|| {
                    held.check()?;
                    held.current
                        .as_mut()
                        .context("request material consumed")?
                        .check()?;
                    let requested = self.storage.check(&self.scope, false);
                    // Evaluate the same original after the real storage I/O,
                    // even on refusal. Never replace the primary error.
                    let checked = held
                        .current
                        .as_mut()
                        .context("request material consumed")?
                        .check();
                    requested?;
                    checked?;
                    held.check()?;
                    if finish {
                        let _ = held.current.take().context("request material consumed")?;
                        held.complete()?;
                    }
                    Ok(())
                })();
                if result.is_err() || finish {
                    drop(self.held[index].take());
                }
                result
            }

            fn step(&mut self, event: Event) -> Result<Record> {
                let result = match event {
                    Event::Capture { request } => {
                        let i = usize::from(request);
                        self.requests[i].capture_model().and_then(|()| {
                            let slot = self.requests[i].slot.borrow();
                            let Slot::Live(Original::Model(value)) = &*slot else {
                                anyhow::bail!("captured non-model material");
                            };
                            let value = clock(value)?;
                            self.captured[i] = Some((value.domain, value.origin));
                            Ok(())
                        })
                    }
                    Event::FailedCapture { request } => {
                        self.requests[usize::from(request)].capture_app(&self.scope)
                    }
                    Event::Lease { request } => {
                        let i = usize::from(request);
                        (|| {
                            ensure!(
                                !self.requests[i].refused.get(),
                                "request permanently refused"
                            );
                            let original = self.requests[i].slot.try_borrow_mut()?.take()?;
                            let Original::Model(value) = original else {
                                anyhow::bail!("non-model authority entered request history");
                            };
                            ensure!(self.held[i].is_none(), "duplicate held request value");
                            self.held[i] = Some(Held {
                                slot: self.requests[i].slot.clone(),
                                refused: self.requests[i].refused.clone(),
                                current: Some(value),
                            });
                            Ok(())
                        })()
                    }
                    Event::Check { request } => self.check(usize::from(request), false),
                    Event::Finish { request } => self.check(usize::from(request), true),
                    Event::Cancel { request, contended } => {
                        let i = usize::from(request);
                        if let Some(held) = self.held[i].take() {
                            if contended {
                                let borrowed = self.requests[i].slot.borrow_mut();
                                drop(held);
                                drop(borrowed);
                            } else {
                                drop(held);
                            }
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!("no held response to cancel"))
                        }
                    }
                    Event::Refuse { request } => {
                        self.requests[usize::from(request)].refuse();
                        Ok(())
                    }
                    Event::NativeProbe { request } => self.requests[usize::from(request)]
                        .take(&self.scope, NativeRole::AppHost)
                        .map(drop),
                    Event::ForeignClock { request } => {
                        let other = Arc::new(Time {
                            domain: self.time.domain.wrapping_add(1),
                            millis: AtomicU64::new(self.time.millis.load(Ordering::SeqCst)),
                        });
                        effects::scope(other, || self.check(usize::from(request), false))
                    }
                    Event::Advance { millis } => {
                        let now = self
                            .time
                            .millis
                            .load(Ordering::SeqCst)
                            .checked_add(millis)
                            .context("history clock overflow")?;
                        self.time.millis.store(now, Ordering::SeqCst);
                        Ok(())
                    }
                    Event::Rewind { millis } => {
                        let now = self
                            .time
                            .millis
                            .load(Ordering::SeqCst)
                            .checked_sub(millis)
                            .context("history clock underflow")?;
                        self.time.millis.store(now, Ordering::SeqCst);
                        Ok(())
                    }
                    Event::RevokeStorage {} => self
                        .storage
                        .step(ConsumerEvent::Current {
                            death_cut: None,
                            rewrite_provider: true,
                        })
                        .map(|_| ()),
                    Event::ReopenAndRestoreClock {} => {
                        self.storage.step(ConsumerEvent::Reopen)?;
                        self.storage.step(ConsumerEvent::RestoreClock).map(|_| ())
                    }
                };
                let accepted = match result {
                    Ok(()) => true,
                    Err(error) if error.is::<ConsumerModelError>() => return Err(error),
                    Err(_) => false,
                };
                self.record(accepted)
            }

            fn record(&self, accepted: bool) -> Result<Record> {
                let mut states = Vec::new();
                for i in 0..2 {
                    let slot = self.requests[i].slot.try_borrow()?;
                    let (phase, live) = match &*slot {
                        Slot::Empty => (Phase::Empty, None),
                        Slot::Capturing => (Phase::Capturing, None),
                        Slot::Live(Original::Model(value)) => (Phase::Live, Some(clock(value)?)),
                        Slot::Live(_) => anyhow::bail!("non-model request history state"),
                        Slot::Leased => (Phase::Leased, None),
                        Slot::Complete => (Phase::Complete, None),
                        Slot::Refused => (Phase::Refused, None),
                    };
                    let current = self.held[i]
                        .as_ref()
                        .and_then(|held| held.current.as_ref())
                        .map(clock)
                        .transpose()?
                        .or(live);
                    let cloned = self.requests[i].clone();
                    states.push(RequestState {
                        phase,
                        refused: self.requests[i].refused.get(),
                        held: self.held[i].is_some(),
                        current,
                        captured: self.captured[i],
                        routing_clones_share_slot_and_latch: Rc::ptr_eq(
                            &cloned.slot,
                            &self.requests[i].slot,
                        ) && Rc::ptr_eq(
                            &cloned.refused,
                            &self.requests[i].refused,
                        ),
                    });
                }
                let storage = self.storage.observation()?;
                let state = &storage["storage"]["state"];
                let storage_live = state["continuation"] == true && state["first_holder"] == true;
                Ok(Record {
                    accepted,
                    state: State {
                        requests: states
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("request history slot count"))?,
                        distinct_slots: !Rc::ptr_eq(&self.requests[0].slot, &self.requests[1].slot),
                        storage_live,
                        now: self.time.millis.load(Ordering::SeqCst),
                    },
                    storage,
                })
            }
        }

        // Independent scalar model: it never calls Slot/Held/ModelOriginal,
        // reads their state, or predicts readiness from actual storage DATA.
        #[derive(Clone)]
        struct Reference {
            state: State,
            domain: u64,
        }
        impl Reference {
            fn new(seed: u64) -> Self {
                let empty = RequestState {
                    phase: Phase::Empty,
                    refused: false,
                    held: false,
                    current: None,
                    captured: None,
                    routing_clones_share_slot_and_latch: true,
                };
                Self {
                    state: State {
                        requests: [empty.clone(), empty],
                        distinct_slots: true,
                        storage_live: true,
                        now: 10_000,
                    },
                    domain: seed.wrapping_add(700_000),
                }
            }
            fn step(&mut self, event: Event) -> Result<bool> {
                let id = match event {
                    Event::Capture { request }
                    | Event::FailedCapture { request }
                    | Event::Lease { request }
                    | Event::Check { request }
                    | Event::Finish { request }
                    | Event::Cancel { request, .. }
                    | Event::Refuse { request }
                    | Event::NativeProbe { request }
                    | Event::ForeignClock { request } => Some(usize::from(request)),
                    _ => None,
                };
                let now = self.state.now;
                let storage = self.state.storage_live;
                let accepted = if let Some(i) = id {
                    let s = &mut self.state.requests[i];
                    match event {
                        Event::Capture { .. } if !s.refused && s.phase == Phase::Empty => {
                            s.phase = Phase::Live;
                            s.current = Some(Clock {
                                domain: self.domain,
                                origin: now,
                                latest: now,
                                refused: false,
                            });
                            s.captured = Some((self.domain, now));
                            true
                        }
                        Event::FailedCapture { .. } if !s.refused && s.phase == Phase::Empty => {
                            s.phase = Phase::Refused;
                            false
                        }
                        Event::Lease { .. } if !s.refused && s.phase == Phase::Live => {
                            s.phase = Phase::Leased;
                            s.held = true;
                            true
                        }
                        Event::Check { .. } | Event::Finish { .. } if s.held => {
                            let valid = !s.refused
                                && s.phase == Phase::Leased
                                && s.current.as_ref().is_some_and(|c| {
                                    !c.refused
                                        && now >= c.latest
                                        && now
                                            .checked_sub(c.origin)
                                            .is_some_and(|elapsed| elapsed < 5_000)
                                })
                                && storage;
                            if valid {
                                s.current.as_mut().unwrap().latest = now;
                                if matches!(event, Event::Finish { .. }) {
                                    s.current = None;
                                    s.held = false;
                                    s.phase = Phase::Complete;
                                }
                            } else {
                                s.refused = true;
                                s.phase = Phase::Refused;
                                s.held = false;
                                s.current = None;
                            }
                            valid
                        }
                        Event::Cancel { contended, .. } if s.held => {
                            s.refused = true;
                            if !contended && s.phase != Phase::Complete {
                                s.phase = Phase::Refused;
                            }
                            s.held = false;
                            s.current = None;
                            true
                        }
                        Event::ForeignClock { .. } if s.held => {
                            s.refused = true;
                            s.phase = Phase::Refused;
                            s.held = false;
                            s.current = None;
                            false
                        }
                        Event::Refuse { .. } => {
                            s.refused = true;
                            if s.phase != Phase::Complete {
                                s.phase = Phase::Refused;
                                if !s.held {
                                    s.current = None;
                                }
                            }
                            true
                        }
                        _ => false,
                    }
                } else {
                    match event {
                        Event::Advance { millis } => {
                            self.state.now = now
                                .checked_add(millis)
                                .context("reference clock overflow")?;
                            true
                        }
                        Event::Rewind { millis } => {
                            self.state.now = now
                                .checked_sub(millis)
                                .context("reference clock underflow")?;
                            true
                        }
                        Event::RevokeStorage {} => {
                            self.state.storage_live = false;
                            true
                        }
                        Event::ReopenAndRestoreClock {} => true,
                        _ => unreachable!(),
                    }
                };
                Ok(accepted)
            }
        }

        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Bundle {
            version: u32,
            source: String,
            original: Program,
            reduced: Program,
            records: Vec<Record>,
            category: String,
            index: usize,
            expected: Value,
            oracle_control: Control,
            failed_step: Option<Box<FailedStep>>,
            reduced_observation: Option<Divergence>,
        }

        fn run(
            program: &Program,
            control: Control,
        ) -> std::result::Result<Vec<Record>, Divergence> {
            let mut records = Vec::new();
            let mut index = 0;
            let mut category = "input";
            let mut expected = json!({"rule":"valid bounded input"});
            let mut failed_step = None;
            let execute = (|| -> Result<Vec<Record>> {
                ensure!(
                    program.version == 1
                        && !program.events.is_empty()
                        && program.events.len() <= MAX_EVENTS,
                    "request history input bound"
                );
                for event in &program.events {
                    match *event {
                        Event::Capture { request }
                        | Event::FailedCapture { request }
                        | Event::Lease { request }
                        | Event::Check { request }
                        | Event::Finish { request }
                        | Event::Cancel { request, .. }
                        | Event::Refuse { request }
                        | Event::NativeProbe { request }
                        | Event::ForeignClock { request } => {
                            ensure!(request < 2, "request history identity bound")
                        }
                        _ => {}
                    }
                }
                category = "setup";
                let mut world = World::new(program.seed)?;
                let time = world.time.clone();
                let mut reference = Reference::new(program.seed);
                effects::scope(time, || -> Result<Vec<Record>> {
                    for (at, &event) in program.events.iter().enumerate() {
                        index = at;
                        category = "execution";
                        if control == Control::StorageOracle && matches!(event, Event::Check { .. })
                        {
                            world
                                .storage
                                .corrupt_enrollment_reference_for_slot_control();
                        }
                        let actual = match world.step(event) {
                            Ok(actual) => actual,
                            Err(error) => {
                                let mut prediction = reference.clone();
                                expected = match prediction.step(event) {
                                    Ok(accepted) => {
                                        json!({"accepted":accepted,"state":prediction.state})
                                    }
                                    Err(_) => {
                                        json!({"observation":"independent prediction unavailable"})
                                    }
                                };
                                if let Ok(observation) = world.record(false) {
                                    failed_step = Some(Box::new(FailedStep {
                                        index: at,
                                        actual_outcome: None,
                                        observation,
                                        independently_predicted: expected.clone(),
                                    }));
                                }
                                return Err(error);
                            }
                        };
                        records.push(actual.clone());
                        category = "oracle";
                        let accepted = reference.step(event)?;
                        if control == Control::SlotOracle
                            && matches!(event, Event::Cancel { request: 0, .. })
                            && accepted
                        {
                            // Negative harness control only. The actual path
                            // never receives this parameter or altered model.
                            reference.state.requests[0].refused = false;
                        }
                        category = "model";
                        expected = json!({"accepted":accepted,"state":reference.state});
                        ensure!(
                            (actual.accepted, &actual.state) == (accepted, &reference.state),
                            "request history model disagreement"
                        );
                    }
                    Ok(records.clone())
                })
            })();
            execute.map_err(|error| Divergence {
                category: if error.is::<ConsumerModelError>() {
                    "storage_oracle".to_owned()
                } else {
                    category.to_owned()
                },
                index,
                records,
                expected,
                failed_step,
            })
        }

        fn replayed(
            program: &Program,
            control: Control,
        ) -> std::result::Result<Vec<Record>, Divergence> {
            let first = run(program, control);
            let second = run(program, control);
            match (first, second) {
                (Ok(first), Ok(second)) if first == second => Ok(first),
                (Err(first), Err(second)) if first == second => Err(first),
                (first, second) => {
                    let (records, failed_step) = match &first {
                        Ok(records) => (records.clone(), None),
                        Err(failure) => (failure.records.clone(), failure.failed_step.clone()),
                    };
                    Err(Divergence {
                        category: "replay".to_owned(),
                        index: 0,
                        records,
                        failed_step,
                        expected: json!({"first":first,"second":second}),
                    })
                }
            }
        }

        fn retain_at(
            root: &std::path::Path,
            program: &Program,
            failure: Divergence,
            oracle_control: Control,
        ) -> Result<std::path::PathBuf> {
            let category = failure.category.clone();
            let (events, observed) = crate::oauth::simulation::reduce_steps(
                &program.events,
                96,
                &category,
                |error| {
                    error
                        .downcast_ref::<RetainedFailure>()
                        .map_or("execution", |e| e.0.category.as_str())
                        .to_owned()
                },
                |events| {
                    replayed(
                        &Program {
                            events: events.to_vec(),
                            ..program.clone()
                        },
                        oracle_control,
                    )
                    .map(|_| ())
                    .map_err(|e| anyhow::Error::new(RetainedFailure(e)))
                },
            );
            let reduced_observation = observed.and_then(|error| {
                error
                    .downcast::<RetainedFailure>()
                    .ok()
                    .map(|failure| failure.0)
            });
            let bundle = Bundle {
                version: 1,
                source: source(),
                original: program.clone(),
                reduced: Program {
                    events,
                    ..program.clone()
                },
                records: failure.records,
                category,
                index: failure.index,
                expected: failure.expected,
                oracle_control,
                failed_step: failure.failed_step,
                reduced_observation,
            };
            let bytes = serde_json::to_vec(&bundle)?;
            ensure!(bytes.len() <= MAX_BUNDLE, "request history evidence bound");
            // Writer and reader share the existing evidence byte/node/depth
            // budgets and duplicate-key checks. Never persist unreadable DATA.
            let _: Bundle = crate::json::decode_evidence(&bytes)?;
            std::fs::create_dir_all(root)?;
            let directory = tempfile::Builder::new()
                .prefix("failure-")
                .tempdir_in(root)?
                .keep();
            let path = directory.join("failure.json");
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(path)
        }

        #[derive(Debug)]
        struct RetainedFailure(Divergence);
        impl std::fmt::Display for RetainedFailure {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0.category)
            }
        }
        impl std::error::Error for RetainedFailure {}

        fn verify(program: &Program) -> Result<Vec<Record>> {
            match replayed(program, Control::None) {
                Ok(records) => Ok(records),
                Err(failure) => {
                    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../artifacts/request-slot-lifecycle");
                    let path = retain_at(&root, program, failure, Control::None)?;
                    anyhow::bail!(
                        "request history disagreed; retained bounded DATA at {}",
                        path.display()
                    )
                }
            }
        }

        fn next(seed: &mut u64) -> u64 {
            *seed = seed.wrapping_add(0x9e3779b97f4a7c15);
            let mut value = *seed;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
            value ^ (value >> 31)
        }

        #[test]
        fn generated_request_slots_replay_actual_moves_latches_and_storage_reads() -> Result<()> {
            for seed in 0..32 {
                let mut random = seed;
                let mut events = vec![
                    Event::Capture { request: 0 },
                    Event::Lease { request: 0 },
                    Event::Check { request: 0 },
                    Event::NativeProbe { request: 0 },
                    Event::Capture { request: 1 },
                    Event::Lease { request: 1 },
                    Event::Finish { request: 1 },
                ];
                for _ in 0..MAX_EVENTS - events.len() {
                    let request = (next(&mut random) % 2) as u8;
                    events.push(match next(&mut random) % 13 {
                        0 => Event::Capture { request },
                        1 => Event::Lease { request },
                        2 => Event::Check { request },
                        3 => Event::Finish { request },
                        4 => Event::Cancel {
                            request,
                            contended: false,
                        },
                        5 => Event::Cancel {
                            request,
                            contended: true,
                        },
                        6 => Event::Refuse { request },
                        7 => Event::NativeProbe { request },
                        8 => Event::Advance {
                            millis: if seed % 2 == 0 { 5_000 } else { 1 },
                        },
                        9 => Event::ForeignClock { request },
                        10 => Event::RevokeStorage {},
                        11 => Event::ReopenAndRestoreClock {},
                        _ => Event::FailedCapture { request },
                    });
                }
                let records = verify(&Program {
                    version: 1,
                    seed,
                    events,
                })?;
                assert!(records[2].accepted && !records[3].accepted);
                assert_eq!(records[6].state.requests[1].phase, Phase::Complete);
                assert!(records.iter().all(|record| {
                    record.state.distinct_slots
                        && record
                            .state
                            .requests
                            .iter()
                            .all(|request| request.routing_clones_share_slot_and_latch)
                }));
            }
            Ok(())
        }

        #[test]
        fn failed_native_capture_stays_refused_after_storage_restore_and_other_completion()
        -> Result<()> {
            let records = verify(&Program {
                version: 1,
                seed: 71,
                events: vec![
                    Event::FailedCapture { request: 0 },
                    Event::ReopenAndRestoreClock {},
                    Event::Capture { request: 0 },
                    Event::Lease { request: 0 },
                    Event::Finish { request: 0 },
                    Event::NativeProbe { request: 0 },
                    Event::Capture { request: 1 },
                    Event::Lease { request: 1 },
                    Event::Finish { request: 1 },
                ],
            })?;
            assert!(!records[0].accepted);
            assert!(records.iter().all(|record| {
                let request = &record.state.requests[0];
                request.phase == Phase::Refused
                    && !request.held
                    && request.current.is_none()
                    && request.captured.is_none()
            }));
            assert!(records[2..6].iter().all(|record| !record.accepted));
            let last = records.last().unwrap();
            assert!(last.accepted && last.state.storage_live && last.state.distinct_slots);
            assert_eq!(last.state.requests[1].phase, Phase::Complete);
            Ok(())
        }

        #[test]
        fn cancelling_an_empty_or_completed_slot_is_an_observed_refusal() -> Result<()> {
            for mut events in [
                Vec::new(),
                vec![
                    Event::Capture { request: 0 },
                    Event::Lease { request: 0 },
                    Event::Finish { request: 0 },
                ],
            ] {
                events.push(Event::Cancel {
                    request: 0,
                    contended: false,
                });
                let records = verify(&Program {
                    version: 1,
                    seed: 71,
                    events,
                })?;
                let last = records.last().unwrap();
                assert!(!last.accepted);
                assert!(matches!(
                    last.state.requests[0].phase,
                    Phase::Empty | Phase::Complete
                ));
                assert!(!last.state.requests[0].refused);
            }
            Ok(())
        }

        #[test]
        fn one_cancelled_request_cannot_be_settled_by_another_completed_slot() -> Result<()> {
            for contended in [false, true] {
                let program = Program {
                    version: 1,
                    seed: 71,
                    events: vec![
                        Event::Capture { request: 0 },
                        Event::Lease { request: 0 },
                        Event::Check { request: 0 },
                        Event::Lease { request: 0 },
                        Event::Cancel {
                            request: 0,
                            contended,
                        },
                        Event::Capture { request: 1 },
                        Event::Lease { request: 1 },
                        Event::Finish { request: 1 },
                        Event::ReopenAndRestoreClock {},
                        Event::Capture { request: 0 },
                        Event::Finish { request: 0 },
                        Event::NativeProbe { request: 0 },
                    ],
                };
                let records = verify(&program)?;
                let final_state = &records.last().unwrap().state;
                assert!(final_state.requests[0].refused && !final_state.requests[0].held);
                assert_eq!(final_state.requests[1].phase, Phase::Complete);
                assert!(final_state.storage_live && final_state.distinct_slots);
                assert!(
                    records[3].state.requests[0].held,
                    "failed second take poisoned the winner"
                );
            }
            Ok(())
        }

        #[test]
        fn original_expiry_rewind_and_storage_refusal_do_not_rearm_after_restore() -> Result<()> {
            for cut in [
                Event::Advance { millis: 5_000 },
                Event::Rewind { millis: 1 },
                Event::ForeignClock { request: 0 },
                Event::RevokeStorage {},
            ] {
                let mut events = vec![
                    Event::Capture { request: 0 },
                    Event::Lease { request: 0 },
                    Event::Check { request: 0 },
                    cut,
                    Event::Check { request: 0 },
                ];
                if matches!(cut, Event::Advance { .. }) {
                    events.push(Event::Rewind { millis: 5_000 });
                }
                if matches!(cut, Event::Rewind { .. }) {
                    events.push(Event::Advance { millis: 1 });
                }
                events.extend([
                    Event::ReopenAndRestoreClock {},
                    Event::Capture { request: 0 },
                    Event::Finish { request: 0 },
                ]);
                let records = verify(&Program {
                    version: 1,
                    seed: 17,
                    events,
                })?;
                assert!(records.last().unwrap().state.requests[0].refused);
                assert_ne!(
                    records.last().unwrap().state.requests[0].phase,
                    Phase::Complete
                );
            }
            Ok(())
        }

        #[test]
        fn slot_oracle_divergence_is_not_an_expected_cancelled_response() {
            let program = Program {
                version: 1,
                seed: 17,
                events: vec![
                    Event::Capture { request: 0 },
                    Event::Lease { request: 0 },
                    Event::Cancel {
                        request: 0,
                        contended: true,
                    },
                ],
            };
            assert!(replayed(&program, Control::None).is_ok());
            let failure = replayed(&program, Control::SlotOracle)
                .expect_err("corrupt slot oracle became ordinary refusal");
            assert_eq!(failure.category, "model");
            assert_eq!(failure.index, 2);
            assert_eq!(failure.records.len(), 3);
        }

        fn fields(value: &Value, names: &[&str]) -> Result<()> {
            let object = value
                .as_object()
                .context("request evidence object required")?;
            ensure!(
                object.len() == names.len() && names.iter().all(|name| object.contains_key(*name)),
                "incomplete request evidence object"
            );
            Ok(())
        }

        fn record_shape(value: &Value) -> Result<()> {
            fields(value, &["accepted", "state", "storage"])?;
            let state = &value["state"];
            fields(
                state,
                &["requests", "distinct_slots", "storage_live", "now"],
            )?;
            for request in state["requests"]
                .as_array()
                .context("request array required")?
            {
                fields(
                    request,
                    &[
                        "phase",
                        "refused",
                        "held",
                        "current",
                        "captured",
                        "routing_clones_share_slot_and_latch",
                    ],
                )?;
                if !request["current"].is_null() {
                    fields(
                        &request["current"],
                        &["domain", "origin", "latest", "refused"],
                    )?;
                }
            }
            Ok(())
        }

        fn failure_shape(value: &Value) -> Result<()> {
            fields(
                value,
                &["category", "index", "records", "expected", "failed_step"],
            )?;
            for record in value["records"]
                .as_array()
                .context("request records required")?
            {
                record_shape(record)?;
            }
            if !value["failed_step"].is_null() {
                fields(
                    &value["failed_step"],
                    &[
                        "index",
                        "actual_outcome",
                        "observation",
                        "independently_predicted",
                    ],
                )?;
                record_shape(&value["failed_step"]["observation"])?;
            }
            Ok(())
        }

        fn replay_retained(path: &std::path::Path) -> Result<()> {
            use std::io::Read;
            let file = std::fs::File::open(path)?;
            ensure!(
                file.metadata()?.len() <= MAX_BUNDLE as u64,
                "request bundle byte bound"
            );
            let mut bytes = Vec::new();
            file.take((MAX_BUNDLE as u64) + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= MAX_BUNDLE,
                "request bundle grew beyond bound"
            );
            let value: Value = crate::json::decode_evidence(&bytes)?;
            fields(
                &value,
                &[
                    "version",
                    "source",
                    "original",
                    "reduced",
                    "records",
                    "category",
                    "index",
                    "expected",
                    "oracle_control",
                    "failed_step",
                    "reduced_observation",
                ],
            )?;
            for program in [&value["original"], &value["reduced"]] {
                fields(program, &["version", "seed", "events"])?;
                ensure!(
                    program["events"]
                        .as_array()
                        .is_some_and(|events| events.iter().all(Value::is_object)),
                    "request events require objects"
                );
            }
            failure_shape(&json!({
                "category":value["category"], "index":value["index"], "records":value["records"],
                "expected":value["expected"], "failed_step":value["failed_step"],
            }))?;
            if !value["reduced_observation"].is_null() {
                failure_shape(&value["reduced_observation"])?;
            }
            let bundle: Bundle = serde_json::from_value(value)?;
            ensure!(
                bundle.version == 1 && bundle.source == source(),
                "request bundle source changed"
            );
            ensure!(
                bundle.original.seed == bundle.reduced.seed
                    && bundle.original.version == bundle.reduced.version,
                "reduced request input changed"
            );
            let mut after = 0;
            for event in &bundle.reduced.events {
                let found = bundle.original.events[after..]
                    .iter()
                    .position(|old| {
                        serde_json::to_value(old).unwrap() == serde_json::to_value(event).unwrap()
                    })
                    .context("reduction is not deletion-only")?;
                after += found + 1;
            }
            let original = replayed(&bundle.original, bundle.oracle_control)
                .err()
                .context("saved disagreement no longer reproduced")?;
            ensure!(
                original.category == bundle.category
                    && original.index == bundle.index
                    && original.records == bundle.records
                    && original.expected == bundle.expected
                    && serde_json::to_value(&original.failed_step)?
                        == serde_json::to_value(&bundle.failed_step)?,
                "saved request observations changed"
            );
            if let Some(expected) = bundle.reduced_observation {
                let actual = replayed(&bundle.reduced, bundle.oracle_control)
                    .err()
                    .context("reduced disagreement did not reproduce")?;
                ensure!(
                    actual.category == expected.category
                        && actual.index == expected.index
                        && actual.records == expected.records
                        && actual.expected == expected.expected
                        && serde_json::to_value(&actual.failed_step)?
                            == serde_json::to_value(&expected.failed_step)?,
                    "reduced request observations changed"
                );
            } else {
                ensure!(
                    bundle.original.events.len() == bundle.reduced.events.len(),
                    "unobserved request reduction"
                );
            }
            Ok(())
        }

        fn replay_selected(path: &std::path::Path) -> Result<()> {
            replay_retained(path).map_err(|_| anyhow::anyhow!("request slot replay refused"))
        }

        #[test]
        fn replay_saved_request_slot_history() -> Result<()> {
            let Some(path) = std::env::var_os("DAY2_REQUEST_SLOT_REPLAY") else {
                return Ok(());
            };
            replay_selected(std::path::Path::new(&path))
        }

        #[test]
        fn retained_request_slot_counterexample_replays_whole_observations_and_source() -> Result<()>
        {
            let program = Program {
                version: 1,
                seed: 17,
                events: vec![
                    Event::Advance { millis: 1 },
                    Event::Capture { request: 0 },
                    Event::Lease { request: 0 },
                    Event::Cancel {
                        request: 0,
                        contended: true,
                    },
                    Event::ReopenAndRestoreClock {},
                ],
            };
            let failure = replayed(&program, Control::SlotOracle)
                .expect_err("negative model control did not fail");
            let directory = tempfile::tempdir()?;
            let path = retain_at(directory.path(), &program, failure, Control::SlotOracle)?;
            replay_selected(&path)?;
            let original = std::fs::read(&path)?;
            let mut value: Value = crate::json::decode_evidence(&original)?;
            value["source"] = json!("different-source");
            let changed = directory.path().join("changed.json");
            std::fs::write(&changed, serde_json::to_vec(&value)?)?;
            assert!(replay_retained(&changed).is_err());
            let mut value: Value = crate::json::decode_evidence(&original)?;
            let changed_storage =
                source_with(day2_capabilities::Digest::new(b"changed-storage-only"));
            assert_ne!(changed_storage, source());
            value["source"] = json!(changed_storage);
            std::fs::write(&changed, serde_json::to_vec(&value)?)?;
            assert!(replay_retained(&changed).is_err());
            let mut value: Value = crate::json::decode_evidence(&original)?;
            value["records"].as_array_mut().unwrap().pop();
            std::fs::write(&changed, serde_json::to_vec(&value)?)?;
            assert!(replay_retained(&changed).is_err());
            let mut value: Value = crate::json::decode_evidence(&original)?;
            value["reduced"]["seed"] = json!(18);
            std::fs::write(&changed, serde_json::to_vec(&value)?)?;
            assert!(replay_retained(&changed).is_err());
            for pointer in [
                "/failed_step",
                "/records/0/state/requests/1/current",
                "/records/0/state/requests/1/captured",
            ] {
                let mut value: Value = crate::json::decode_evidence(&original)?;
                let (parent, key) = pointer.rsplit_once('/').unwrap();
                assert!(
                    value
                        .pointer_mut(parent)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(key)
                        .is_some()
                );
                std::fs::write(&changed, serde_json::to_vec(&value)?)?;
                assert!(
                    replay_retained(&changed).is_err(),
                    "missing field accepted: {pointer}"
                );
            }
            let duplicate = String::from_utf8(original.clone())?.replacen(
                "\"version\":1",
                "\"version\":1,\"version\":1",
                1,
            );
            assert_ne!(duplicate.as_bytes(), original.as_slice());
            std::fs::write(&changed, duplicate)?;
            assert!(replay_retained(&changed).is_err());
            std::fs::write(&changed, vec![b' '; MAX_BUNDLE + 1])?;
            assert!(replay_retained(&changed).is_err());
            let mut value: Value = crate::json::decode_evidence(&original)?;
            value["original"]["events"][0] = json!({"event":"PRIVATE-INVALID-EVENT"});
            std::fs::write(&changed, serde_json::to_vec(&value)?)?;
            let refused = replay_selected(&changed).unwrap_err();
            assert_eq!(refused.chain().count(), 1);
            assert_eq!(refused.to_string(), "request slot replay refused");
            Ok(())
        }

        #[test]
        fn nested_storage_oracle_failure_keeps_the_actual_failed_step_separate() -> Result<()> {
            let program = Program {
                version: 1,
                seed: 17,
                events: vec![
                    Event::Capture { request: 0 },
                    Event::Lease { request: 0 },
                    Event::Check { request: 0 },
                ],
            };
            let failure = replayed(&program, Control::StorageOracle)
                .expect_err("storage model corruption became refusal");
            assert_eq!(failure.category, "storage_oracle");
            assert_eq!(failure.records.len(), 2);
            let actual = failure
                .failed_step
                .as_ref()
                .expect("actual failed-step observation lost");
            assert_eq!(actual.index, 2);
            assert_eq!(actual.actual_outcome, None);
            assert!(actual.observation.state.requests[0].refused);
            assert_eq!(actual.independently_predicted["accepted"], true);
            let root = tempfile::tempdir()?;
            let path = retain_at(root.path(), &program, failure, Control::StorageOracle)?;
            replay_retained(&path)?;
            Ok(())
        }

        #[test]
        fn longest_supported_request_prefix_writes_evidence_the_reader_accepts() -> Result<()> {
            let mut events = vec![Event::Capture { request: 0 }, Event::Lease { request: 0 }];
            events.extend((0..MAX_EVENTS - 3).map(|_| Event::Check { request: 0 }));
            events.push(Event::Cancel {
                request: 0,
                contended: true,
            });
            assert_eq!(events.len(), MAX_EVENTS);
            let program = Program {
                version: 1,
                seed: 71,
                events,
            };
            let failure = replayed(&program, Control::SlotOracle)
                .expect_err("long-prefix control did not diverge");
            assert_eq!(failure.records.len(), MAX_EVENTS);
            let root = tempfile::tempdir()?;
            let path = retain_at(root.path(), &program, failure, Control::SlotOracle)?;
            assert!(std::fs::metadata(&path)?.len() <= MAX_BUNDLE as u64);
            replay_retained(&path)?;
            let mut invalid = program.clone();
            invalid.events.push(Event::ReopenAndRestoreClock {});
            assert_eq!(run(&invalid, Control::None).unwrap_err().category, "input");
            Ok(())
        }
    }
}
