//! Actual request lifetimes exclude idle credential admission. Caller queues,
//! response leases and serialized counters never enter this state machine.

use super::{EnrolledProcessRoleOwner, EnrolledRoleStage, OwnerIdentity};
use crate::security_epoch::native_clock::NativeAcquisition;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use std::{
    cell::Cell,
    rc::{Rc, Weak},
    thread::ThreadId,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Requests(u64),
    IdleAdmission,
    Refused,
}

pub(super) struct RequestRegistry {
    state: Cell<State>,
}

impl RequestRegistry {
    pub(super) fn new() -> Rc<Self> {
        Rc::new(Self {
            state: Cell::new(State::Requests(0)),
        })
    }

    pub(super) fn allow_request(&self) -> Result<()> {
        match self.state.get() {
            State::Requests(_) => Ok(()),
            State::IdleAdmission => Err(super::super::IdleCredentialBusy { _private: () }.into()),
            State::Refused => anyhow::bail!("native_enrollment_request_registry_refused"),
        }
    }

    fn require_idle(&self) -> Result<()> {
        // In particular, busy is returned before any clock or handle check and
        // does not refuse the unrelated actual request already in progress.
        match self.state.get() {
            State::Requests(0) => Ok(()),
            State::Requests(_) | State::IdleAdmission => {
                Err(super::super::IdleCredentialBusy { _private: () }.into())
            }
            State::Refused => anyhow::bail!("native_enrollment_request_registry_refused"),
        }
    }

    fn exclude(&self) -> Result<()> {
        self.require_idle()?;
        self.state.set(State::IdleAdmission);
        Ok(())
    }

    fn finish_published(&self) {
        if self.state.get() == State::IdleAdmission {
            self.state.set(State::Requests(0));
        }
    }

    pub(super) fn require_not_refused(&self) -> Result<()> {
        ensure!(
            self.state.get() != State::Refused,
            "native_enrollment_request_registry_refused"
        );
        Ok(())
    }

    pub(super) fn start(self: &Rc<Self>) -> Result<LiveRequest> {
        let State::Requests(count) = self.state.get() else {
            anyhow::bail!("native_enrollment_request_excluded_or_refused");
        };
        let Some(count) = count.checked_add(1) else {
            self.refuse();
            anyhow::bail!("native_enrollment_actual_request_count_exhausted");
        };
        self.state.set(State::Requests(count));
        Ok(LiveRequest {
            registry: Rc::clone(self),
        })
    }

    fn refuse(&self) {
        self.state.set(State::Refused);
    }
}

/// Moved with the actual request, including body waits and lexical callbacks.
/// Its constructor is inaccessible to consumer code and takes no scalar count.
pub(super) struct LiveRequest {
    registry: Rc<RequestRegistry>,
}

impl LiveRequest {
    pub(super) fn refuse(&self) {
        self.registry.refuse();
    }
}

impl Drop for LiveRequest {
    fn drop(&mut self) {
        if let State::Requests(count) = self.registry.state.get() {
            match count.checked_sub(1) {
                Some(count) => self.registry.state.set(State::Requests(count)),
                None => self.registry.refuse(),
            }
        }
    }
}

/// Owns idle exclusion through physical completion and final material
/// publication, even after that physical phase consumes its actual stage.
pub(crate) struct IdleCredentialPublication {
    registry: Rc<RequestRegistry>,
    identity: Weak<OwnerIdentity>,
    incarnation: Digest,
    process: u32,
    thread: ThreadId,
    original: NativeAcquisition,
    published: bool,
}

/// A temporary exclusive borrow of the same actual stage and publication
/// guard. This grants no provider, physical, writer or credential permission.
pub(crate) struct IdleCredentialAdmission<'stage, 'role> {
    publication: &'stage mut IdleCredentialPublication,
    stage: &'stage mut EnrolledRoleStage<'role>,
    completion: ViewCompletion,
}

/// A nongeneric owned refusal guard can remain fully pinned by the destructor
/// checker while the temporary view borrows its actual role stage.
struct ViewCompletion {
    registry: Rc<RequestRegistry>,
    original: NativeAcquisition,
    known: bool,
}

impl EnrolledProcessRoleOwner {
    pub(crate) fn begin_idle_credential_admission(
        &mut self,
    ) -> Result<(EnrolledRoleStage<'_>, IdleCredentialPublication)> {
        // There is no observation, clock factory, callback or fallible I/O
        // before this actual-owner preflight. The owner is thread-bound.
        self.requests.require_idle()?;
        let mut stage = self.begin_current_stage()?;
        stage.owner.requests.require_idle()?;
        let original = stage.acquisition.as_mut().narrow(5, stage.deadline)?;
        stage.owner.requests.exclude()?;
        let publication = IdleCredentialPublication {
            registry: Rc::clone(&stage.owner.requests),
            identity: Rc::downgrade(&stage.owner.identity),
            incarnation: stage.owner.incarnation.clone(),
            process: stage.owner.process,
            thread: stage.owner.thread,
            original,
            published: false,
        };
        Ok((stage, publication))
    }
}

impl IdleCredentialPublication {
    pub(crate) fn borrow_stage<'stage, 'role>(
        &'stage mut self,
        stage: &'stage mut EnrolledRoleStage<'role>,
    ) -> Result<IdleCredentialAdmission<'stage, 'role>> {
        let result = (|| {
            self.check()?;
            let identity = self
                .identity
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("native_enrollment_idle_owner_dropped"))?;
            ensure!(
                Rc::ptr_eq(&identity, &stage.owner.identity)
                    && self.incarnation == stage.owner.incarnation,
                "native_enrollment_idle_owner_changed"
            );
            stage.require_current_role()?;
            stage
                .acquisition
                .as_mut()
                .exchange_current_views(&mut self.original)?;
            stage.check()?;
            let (_, deadline) = self.original.interval_data()?;
            self.original.narrow(5, deadline)
        })();
        let original = match result {
            Ok(original) => original,
            Err(error) => {
                self.refuse();
                return Err(error);
            }
        };
        let completion = ViewCompletion {
            registry: Rc::clone(&self.registry),
            original,
            known: false,
        };
        Ok(IdleCredentialAdmission {
            publication: self,
            stage,
            completion,
        })
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.published && self.registry.state.get() == State::IdleAdmission,
                "native_enrollment_idle_publication_refused"
            );
            ensure!(
                self.identity.upgrade().is_some()
                    && self.process == std::process::id()
                    && self.thread == std::thread::current().id(),
                "native_enrollment_idle_executor_changed"
            );
            self.original.remaining()?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Join the actual prepared replacement to this same original before final
    /// publication. A different idle scope or saved scalar cannot settle it.
    pub(in crate::security_epoch) fn check_acquisition(
        &mut self,
        prepared: &mut NativeAcquisition,
    ) -> Result<()> {
        let result = (|| {
            self.check()?;
            self.original.exchange_current_views(prepared)?;
            self.check()
        })();
        if result.is_err() {
            self.refuse();
            prepared.refuse();
        }
        result
    }

    /// Only after the caller's final old-cap check and infallible material
    /// publication. No extra I/O, renewed clock or refusal reset occurs here.
    pub(crate) fn finish_published(mut self) {
        self.registry.finish_published();
        self.published = true;
    }

    fn refuse(&mut self) {
        self.registry.refuse();
        self.original.refuse();
    }
}

impl Drop for IdleCredentialPublication {
    fn drop(&mut self) {
        if !self.published {
            self.refuse();
        }
    }
}

impl<'role> IdleCredentialAdmission<'_, 'role> {
    pub(crate) fn stage(&mut self) -> Result<&mut EnrolledRoleStage<'role>> {
        self.publication.check()?;
        self.stage.require_current_role()?;
        self.stage
            .acquisition
            .as_mut()
            .exchange_current_views(&mut self.publication.original)?;
        self.stage.check()?;
        Ok(self.stage)
    }

    /// Completes only this temporary view. The owned publication exclusion
    /// remains armed through every enclosing physical and final cap check.
    pub(crate) fn finish_known(mut self) -> Result<()> {
        self.stage()?;
        self.completion.known = true;
        Ok(())
    }
}

impl Drop for ViewCompletion {
    fn drop(&mut self) {
        if !self.known {
            self.registry.refuse();
            self.original.refuse();
        }
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
    assert_not_impl!(IdleCredentialPublication, Clone);
    assert_not_impl!(IdleCredentialPublication, Copy);
    assert_not_impl!(IdleCredentialPublication, Default);
    assert_not_impl!(IdleCredentialPublication, std::fmt::Debug);
    assert_not_impl!(IdleCredentialPublication, Send);
    assert_not_impl!(IdleCredentialPublication, Sync);
    assert_not_impl!(IdleCredentialPublication, serde::Serialize);
    assert_not_impl!(IdleCredentialPublication, serde::Deserialize<'static>);
    assert_not_impl!(IdleCredentialAdmission<'static, 'static>, Clone);
    assert_not_impl!(IdleCredentialAdmission<'static, 'static>, Copy);
    assert_not_impl!(IdleCredentialAdmission<'static, 'static>, Default);
    assert_not_impl!(IdleCredentialAdmission<'static, 'static>, std::fmt::Debug);
    assert_not_impl!(IdleCredentialAdmission<'static, 'static>, Send);
    assert_not_impl!(IdleCredentialAdmission<'static, 'static>, Sync);
    assert_not_impl!(IdleCredentialAdmission<'static, 'static>, serde::Serialize);
    assert_not_impl!(
        IdleCredentialAdmission<'static, 'static>,
        serde::Deserialize<'static>
    );
    assert_not_impl!(LiveRequest, Clone);
    assert_not_impl!(LiveRequest, Copy);
    assert_not_impl!(LiveRequest, Default);
    assert_not_impl!(LiveRequest, std::fmt::Debug);
    assert_not_impl!(LiveRequest, Send);
    assert_not_impl!(LiveRequest, Sync);
    assert_not_impl!(LiveRequest, serde::Serialize);
    assert_not_impl!(LiveRequest, serde::Deserialize<'static>);
};

#[cfg(test)]
mod tests {
    use super::{IdleCredentialPublication, RequestRegistry, State, ViewCompletion};

    fn publication_fixture() -> (std::rc::Rc<super::OwnerIdentity>, IdleCredentialPublication) {
        // Only the exclusion/clock guard is exercised here. This creates no
        // enrolled process/role, native stage, provider or storage authority.
        let identity = std::rc::Rc::new(super::OwnerIdentity);
        let registry = RequestRegistry::new();
        registry.exclude().unwrap();
        let publication = IdleCredentialPublication {
            registry,
            identity: std::rc::Rc::downgrade(&identity),
            incarnation: day2_capabilities::Digest::new(b"idle guard fixture DATA"),
            process: std::process::id(),
            thread: std::thread::current().id(),
            original: crate::security_epoch::native_clock::NativeAcquisition::fixture(
                day2_capabilities::Digest::new(b"idle original fixture"),
                std::process::id(),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(5),
            ),
            published: false,
        };
        (identity, publication)
    }

    #[test]
    fn publication_joins_actual_same_original_and_never_widens_the_prepared_cap() {
        use std::time::Duration;
        let (_identity, mut publication) = publication_fixture();
        let mut prepared = publication
            .original
            .narrow(5, Duration::from_secs(3))
            .unwrap();
        publication.check_acquisition(&mut prepared).unwrap();
        assert_eq!(
            publication.original.interval_data().unwrap(),
            (Duration::from_secs(1), Duration::from_secs(3))
        );
        assert_eq!(
            prepared.interval_data().unwrap(),
            (Duration::from_secs(1), Duration::from_secs(3))
        );
        assert!(publication.registry.start().is_err());
        let registry = std::rc::Rc::clone(&publication.registry);
        publication.finish_published();
        assert!(matches!(registry.state.get(), State::Requests(0)));
        prepared.remaining().unwrap();
    }

    #[test]
    fn wrong_prepared_original_and_owner_loss_refuse_without_publication_revival() {
        use crate::security_epoch::native_clock::NativeAcquisition;
        use std::time::Duration;
        let (_identity, mut publication) = publication_fixture();
        let mut unrelated = NativeAcquisition::fixture(
            day2_capabilities::Digest::new(b"unrelated actual original fixture"),
            std::process::id(),
            Duration::from_secs(1),
            Duration::from_secs(5),
        );
        assert!(publication.check_acquisition(&mut unrelated).is_err());
        assert!(publication.check().is_err());
        assert!(unrelated.remaining().is_err());
        let registry = std::rc::Rc::clone(&publication.registry);
        publication.finish_published();
        assert!(registry.start().is_err());
        assert!(registry.exclude().is_err());

        let (identity, mut publication) = publication_fixture();
        drop(identity);
        assert!(publication.check().is_err());
        assert!(matches!(publication.registry.state.get(), State::Refused));
        assert!(publication.original.remaining().is_err());
    }

    #[test]
    fn unfinished_temporary_view_poison_is_owned_after_the_stage_borrow_disappears() {
        use std::time::Duration;
        for known in [false, true] {
            let (_identity, mut publication) = publication_fixture();
            let view = ViewCompletion {
                registry: std::rc::Rc::clone(&publication.registry),
                original: publication
                    .original
                    .narrow(5, Duration::from_secs(6))
                    .unwrap(),
                known,
            };
            drop(view);
            assert_eq!(publication.check().is_ok(), known);
            assert!(publication.registry.start().is_err());
            let registry = std::rc::Rc::clone(&publication.registry);
            drop(publication);
            assert!(matches!(registry.state.get(), State::Refused));
        }
    }

    #[test]
    fn busy_is_typed_and_distinct_from_terminal_refusal() {
        let registry = RequestRegistry::new();
        let request = registry.start().unwrap();
        let error = registry.require_idle().unwrap_err();
        assert!(
            error
                .downcast_ref::<super::super::super::IdleCredentialBusy>()
                .is_some()
        );
        assert!(registry.require_not_refused().is_ok());
        request.refuse();
        let error = registry.require_idle().unwrap_err();
        assert!(
            error
                .downcast_ref::<super::super::super::IdleCredentialBusy>()
                .is_none()
        );
        drop(request);
        assert!(registry.require_not_refused().is_err());
    }

    fn first_guard(source: &str, name: &str, method: &str) -> bool {
        let syntax = syn::parse_file(source).unwrap();
        syntax.items.iter().filter_map(|item| match item { syn::Item::Impl(value) => Some(value), _ => None })
            .flat_map(|implementation| &implementation.items).find_map(|item| {
                let syn::ImplItem::Fn(function) = item else { return None; };
                if function.sig.ident != name { return None; }
                let Some(syn::Stmt::Expr(syn::Expr::Try(value), Some(_))) = function.block.stmts.first() else { return Some(false); };
                let syn::Expr::MethodCall(call) = &*value.expr else { return Some(false); };
                let syn::Expr::Field(receiver) = &*call.receiver else { return Some(false); };
                Some(call.method == method && call.args.is_empty()
                    && matches!(&receiver.member, syn::Member::Named(field) if field == "requests")
                    && matches!(&*receiver.base, syn::Expr::Path(path) if path.path.is_ident("self")))
            }).unwrap_or(false)
    }

    #[test]
    fn idle_and_request_preflight_precedes_every_original_or_handle_observation() {
        let owner = include_str!("../owner.rs");
        let idle = include_str!("request_exclusion.rs");
        for name in [
            "begin_stage",
            "borrow_current_request",
            "bind_shell_request",
            "capture_original_clock",
        ] {
            assert!(first_guard(owner, name, "allow_request"));
            let marker = format!("fn {name}");
            let (prefix, body) = owner.split_once(&marker).unwrap();
            let changed =
                body.replacen("self.requests.allow_request()?;", "self.check_local()?;", 1);
            assert!(!first_guard(
                &format!("{prefix}{marker}{changed}"),
                name,
                "allow_request"
            ));
        }
        assert!(first_guard(
            idle,
            "begin_idle_credential_admission",
            "require_idle"
        ));
        let changed = idle.replacen("self.requests.require_idle()?;", "self.check_local()?;", 1);
        assert!(!first_guard(
            &changed,
            "begin_idle_credential_admission",
            "require_idle"
        ));
    }

    #[test]
    fn request_guard_is_owned_in_both_real_constructors_and_refused_before_original_drop() {
        use syn::visit::Visit;
        #[derive(Default)]
        struct Actual {
            constructors: usize,
            guarded: usize,
            retained: bool,
            bound_guard: bool,
        }
        fn fields(expression: &syn::Expr, names: &[&str]) -> bool {
            match (expression, names.split_last()) {
                (syn::Expr::Path(path), Some((name, []))) => path.path.is_ident(name),
                (syn::Expr::Field(field), Some((name, rest))) => {
                    matches!(&field.member, syn::Member::Named(actual) if actual == name)
                        && fields(&field.base, rest)
                }
                _ => false,
            }
        }
        fn starts(expression: &syn::Expr, receiver: &[&str]) -> bool {
            let syn::Expr::Try(value) = expression else {
                return false;
            };
            let syn::Expr::MethodCall(call) = &*value.expr else {
                return false;
            };
            call.method == "start" && call.args.is_empty() && fields(&call.receiver, receiver)
        }
        impl<'ast> Visit<'ast> for Actual {
            fn visit_local(&mut self, value: &'ast syn::Local) {
                if matches!(&value.pat, syn::Pat::Ident(name) if name.ident == "live_request") {
                    self.bound_guard |= value.init.as_ref().is_some_and(|initializer| {
                        starts(&initializer.expr, &["stage", "owner", "requests"])
                    });
                }
                syn::visit::visit_local(self, value);
            }
            fn visit_item_struct(&mut self, value: &'ast syn::ItemStruct) {
                if value.ident == "EnrolledCurrentRequest" {
                    self.retained = value.fields.iter().any(|field|
                        field.ident.as_ref().is_some_and(|name| name == "live_request")
                        && matches!(&field.ty, syn::Type::Path(path) if path.path.is_ident("LiveRequest")));
                }
                syn::visit::visit_item_struct(self, value);
            }
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                if value.path.is_ident("EnrolledCurrentRequest") {
                    self.constructors += 1;
                    self.guarded += usize::from(value.fields.iter().any(|field|
                        matches!(&field.member, syn::Member::Named(name) if name == "live_request")
                        && (matches!(&field.expr, syn::Expr::Path(path) if path.path.is_ident("live_request"))
                            || starts(&field.expr, &["self", "requests"]))));
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let source = include_str!("../owner.rs");
        let mut actual = Actual::default();
        actual.visit_file(&syn::parse_file(source).unwrap());
        assert_eq!(
            (
                actual.constructors,
                actual.guarded,
                actual.retained,
                actual.bound_guard
            ),
            (2, 2, true, true)
        );
        let drop_start = source
            .split_once("impl Drop for EnrolledCurrentRequest")
            .unwrap()
            .1;
        let drop_body = drop_start
            .split_once("impl EnrolledCurrentRequest")
            .unwrap()
            .0;
        assert!(
            drop_body.find("self.live_request.refuse()").unwrap()
                < drop_body.find("self.acquisition.refuse()").unwrap()
        );
        // Removing a real owning field from either factory cannot be hidden by
        // an unrelated response-lease or request-count DATA assertion.
        let changed = source.replacen(
            "live_request: self.requests.start()?",
            "live_request: other.requests.start()?",
            1,
        );
        let mut mutated = Actual::default();
        mutated.visit_file(&syn::parse_file(&changed).unwrap());
        assert_eq!(mutated.guarded, 1);
        let changed = source.replacen(
            "stage.owner.requests.start()?",
            "other.requests.start()?",
            1,
        );
        let mut mutated = Actual::default();
        mutated.visit_file(&syn::parse_file(&changed).unwrap());
        assert!(!mutated.bound_guard);
    }

    #[test]
    fn actual_request_move_and_body_wait_exclude_idle_without_refusing_the_winner() {
        let owner = RequestRegistry::new();
        let request = owner.start().unwrap();
        // A moved request need not have a response lease or a current callback.
        let body_wait = Some(request);
        for _ in 0..3 {
            assert!(owner.require_idle().is_err());
            assert!(owner.exclude().is_err());
            assert!(owner.allow_request().is_ok());
            assert!(matches!(owner.state.get(), State::Requests(1)));
        }
        drop(body_wait);
        owner.exclude().unwrap();
        assert!(owner.start().is_err());
        assert!(owner.allow_request().is_err());
        owner.finish_published();
        assert!(owner.start().is_ok());
    }

    #[test]
    fn unfinished_request_refusal_survives_last_guard_drop_and_publication_attempt() {
        let owner = RequestRegistry::new();
        let request = owner.start().unwrap();
        request.refuse();
        drop(request);
        owner.finish_published();
        assert!(matches!(owner.state.get(), State::Refused));
        assert!(owner.start().is_err());
        assert!(owner.exclude().is_err());
    }

    #[test]
    fn idle_registry_replays_generated_request_move_finish_and_refusal_histories() {
        // Pure production lifecycle state and actual owning guards only. This
        // never manufactures a native stage, enrollment or provider permission.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        enum Model {
            Open(usize),
            Idle,
            Closed,
        }
        for seed in 0_u64..128 {
            let owner = RequestRegistry::new();
            let mut requests = Vec::new();
            let mut model = Model::Open(0);
            let mut schedule = seed;
            let mut trace = Vec::new();
            for _ in 0..64 {
                schedule = schedule
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let operation = (schedule >> 32) % 6;
                trace.push(operation);
                match operation {
                    0 => {
                        let result = owner.start();
                        assert_eq!(
                            result.is_ok(),
                            matches!(model, Model::Open(_)),
                            "seed={seed} trace={trace:?}"
                        );
                        if let Ok(request) = result {
                            requests.push(request);
                            let Model::Open(n) = model else {
                                unreachable!()
                            };
                            model = Model::Open(n + 1);
                        }
                    }
                    1 => {
                        if let Some(request) = requests.pop() {
                            drop(request);
                            if let Model::Open(n) = model {
                                model = Model::Open(n - 1);
                            }
                        }
                    }
                    2 => {
                        assert_eq!(
                            owner.exclude().is_ok(),
                            model == Model::Open(0),
                            "seed={seed} trace={trace:?}"
                        );
                        if model == Model::Open(0) {
                            model = Model::Idle;
                        }
                    }
                    3 => {
                        owner.finish_published();
                        if model == Model::Idle {
                            model = Model::Open(0);
                        }
                    }
                    4 => {
                        if let Some(request) = requests.last() {
                            request.refuse();
                            model = Model::Closed;
                        }
                    }
                    5 => assert_eq!(
                        owner.allow_request().is_ok(),
                        matches!(model, Model::Open(_)),
                        "seed={seed} trace={trace:?}"
                    ),
                    _ => unreachable!(),
                }
                let actual = match owner.state.get() {
                    State::Requests(n) => Model::Open(usize::try_from(n).unwrap()),
                    State::IdleAdmission => Model::Idle,
                    State::Refused => Model::Closed,
                };
                assert_eq!(actual, model, "seed={seed} trace={trace:?}");
            }
        }
    }

    #[test]
    fn request_count_exhaustion_and_underflow_refuse_permanently() {
        let owner = RequestRegistry::new();
        owner.state.set(State::Requests(u64::MAX));
        assert!(owner.start().is_err());
        assert!(matches!(owner.state.get(), State::Refused));
        let owner = RequestRegistry::new();
        let request = owner.start().unwrap();
        owner.state.set(State::Requests(0));
        drop(request);
        assert!(matches!(owner.state.get(), State::Refused));
    }
}
