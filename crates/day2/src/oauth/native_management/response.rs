//! Actual finite App response ownership. Registry entries are moved, never
//! reconstructed from DATA. The pinned driver keeps lexical native borrows;
//! the registry contains only a negative busy/abort marker while it waits.

#[cfg(test)]
use super::fixtures;
use super::{AppStorage, OWNERS, OriginalPhase, Owners, Phase, PhaseOriginal, Sink, SinkState};
use crate::oauth::fresh_auth::FreshIntent;
use crate::oauth::native_http::response_io::{HostReplySlot, Operation, Transport};
use crate::security_epoch::{
    native_enrollment::{EnrolledRoleStage, NativeRole},
    serving::{CurrentServingPhase, ResponseIdentity},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;
use std::{
    cell::{Cell, RefCell, RefMut},
    collections::BTreeMap,
    rc::Rc,
};

/// A shared routing handle to one actual value, not a clone of that value.
/// Synchronous callers borrow it; response delivery moves it into a lease so
/// no RefCell borrow guard survives an async suspension. Only an existing T
/// can initialize this slot; the native instantiation requires a real owner.
pub(super) struct Role<T> {
    slot: Rc<RefCell<RoleSlot<T>>>,
}

struct RoleSlot<T> {
    owner: Option<T>,
    reservation: Option<Rc<()>>,
}

impl<T> Clone for Role<T> {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
        }
    }
}

impl<T> Role<T> {
    pub(super) fn new(owner: T) -> Self {
        Self {
            slot: Rc::new(RefCell::new(RoleSlot {
                owner: Some(owner),
                reservation: None,
            })),
        }
    }

    pub(super) fn try_borrow_mut(&self) -> Result<RefMut<'_, T>> {
        let slot = self.slot.try_borrow_mut()?;
        ensure!(slot.reservation.is_none(), "native role already leased");
        RefMut::filter_map(slot, |slot| slot.owner.as_mut())
            .map_err(|_| anyhow::anyhow!("native role already leased"))
    }

    fn take(&self) -> Result<HeldRole<T>> {
        let mut held = HeldRole {
            slot: self.slot.clone(),
            owner: None,
            reservation: Rc::new(()),
            known: false,
        };
        {
            let mut slot = self.slot.try_borrow_mut()?;
            ensure!(
                slot.owner.is_some() && slot.reservation.is_none(),
                "native role already leased"
            );
            slot.reservation = Some(held.reservation.clone());
            held.owner = slot.owner.take();
        }
        Ok(held)
    }
}

struct HeldRole<T> {
    slot: Rc<RefCell<RoleSlot<T>>>,
    owner: Option<T>,
    reservation: Rc<()>,
    known: bool,
}

impl<T> HeldRole<T> {
    fn owner(&mut self) -> &mut T {
        self.owner.as_mut().expect("actual retained role")
    }
}

impl<T> Drop for HeldRole<T> {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        if !self.known {
            // Unknown delivery retires this actual owner. Original clock
            // handles retain the empty slot and cannot reacquire it.
            return;
        }
        let Ok(mut slot) = self.slot.try_borrow_mut() else {
            // Never panic, overwrite a replacement or synthesize a role.
            // Dropping the actual value leaves the old slot unavailable.
            return;
        };
        if slot.owner.is_none()
            && slot
                .reservation
                .as_ref()
                .is_some_and(|same| Rc::ptr_eq(same, &self.reservation))
        {
            slot.reservation = None;
            slot.owner = Some(owner);
        }
    }
}

pub(super) struct Registry<T> {
    available: BTreeMap<String, T>,
    reserved: BTreeMap<String, Reservation>,
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self {
            available: BTreeMap::new(),
            reserved: BTreeMap::new(),
        }
    }
}

impl<T> std::ops::Deref for Registry<T> {
    type Target = BTreeMap<String, T>;
    fn deref(&self) -> &Self::Target {
        &self.available
    }
}

impl<T> std::ops::DerefMut for Registry<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.available
    }
}

impl<T> Registry<T> {
    /// Negative admission DATA only. The actual owner must still be acquired
    /// and checked; a retired reservation cannot become a retryable busy one.
    pub(super) fn excludes_unstarted_operation(&self, key: &str) -> Result<bool> {
        match self.reserved.get(key) {
            Some(reservation) => {
                ensure!(!reservation.refused.get(), "native operation owner refused");
                Ok(true)
            }
            None => Ok(false),
        }
    }

    pub(super) fn clear(&mut self) {
        for reservation in self.reserved.values() {
            reservation.refused.set(true);
        }
        self.reserved.clear();
        self.available.clear();
    }

    fn refuse_for(&self, identity: &ResponseIdentity) {
        for reservation in self.reserved.values() {
            if reservation.identity.same(identity) {
                reservation.refused.set(true);
            }
        }
    }
}

struct Reservation {
    identity: ResponseIdentity,
    refused: Rc<Cell<bool>>,
}

mod sealed {
    pub trait Material {}
}

trait LeaseMaterial: sealed::Material {
    fn refuse_lease(&mut self, attempt: Option<&str>);
}

impl sealed::Material for Owners {}
impl LeaseMaterial for Owners {
    fn refuse_lease(&mut self, attempt: Option<&str>) {
        self.storage.refuse();
        if let Some(stored) = attempt.and_then(|attempt| self.originals.get_mut(attempt)) {
            stored.original.refuse();
        }
    }
}

struct Lease<T: LeaseMaterial> {
    registry: Rc<RefCell<Registry<T>>>,
    key: String,
    identity: ResponseIdentity,
    refused: Rc<Cell<bool>>,
    owners: Option<T>,
    attempt: Option<String>,
    known: bool,
}

pub(super) fn is_empty() -> bool {
    OWNERS.with(|owners| owners.borrow().reserved.is_empty())
}

pub(super) fn refuse_leased(sink: &Sink) {
    // Identity is the SAME creator-allocated Rc, never a request-provided ID.
    OWNERS.with(|owners| {
        if let Ok(owners) = owners.try_borrow() {
            owners.refuse_for(&sink.identity);
        }
    });
}

pub(super) fn require_finite_binding(sink: &Sink) -> Result<()> {
    let bindings = sink.bindings.try_borrow()?;
    ensure!(
        bindings.len() == 1 && sink.runtime.try_borrow()?.is_none(),
        "native finite response ownership conflict"
    );
    let ((role, _), binding) = bindings
        .iter()
        .next()
        .context("native response binding missing")?;
    ensure!(
        *role == NativeRole::AppHost,
        "native finite response requires App owner"
    );
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::require_response(&binding.intent, *role, &sink.identity);
    }
    OWNERS.with(|entries| {
        let mut entries = entries.try_borrow_mut()?;
        let owners = entries
            .get_mut(binding.intent.app())
            .context("native response executor missing")?;
        ensure!(owners.kind == *role, "native response role changed");
        owners
            .originals
            .get(binding.intent.attempt())
            .context("native response original missing")?
            .response
            .require_bound(&binding.intent, &sink.identity)?;
        let AppStorage::Participant(participant) = &mut owners.storage else {
            anyhow::bail!("native response participant missing")
        };
        crate::security_epoch::serving::require_app_response(
            participant,
            owners.selection.scope(),
            Some(&binding.intent),
            &sink.identity,
        )
    })
}

impl<T: LeaseMaterial> Lease<T> {
    fn acquire(
        registry: Rc<RefCell<Registry<T>>>,
        key: &str,
        identity: &ResponseIdentity,
        attempt: Option<&str>,
    ) -> Result<Self> {
        // Prepare all allocated routing DATA before moving actual material.
        let mut lease = Self {
            registry,
            key: key.into(),
            identity: identity.clone(),
            refused: Rc::new(Cell::new(false)),
            owners: None,
            attempt: attempt.map(str::to_owned),
            known: false,
        };
        {
            let mut entries = lease.registry.try_borrow_mut()?;
            ensure!(
                !entries.reserved.contains_key(key),
                "native response owner busy"
            );
            ensure!(
                entries.available.contains_key(key),
                "native response owner absent"
            );
            entries.reserved.insert(
                lease.key.clone(),
                Reservation {
                    identity: identity.clone(),
                    refused: lease.refused.clone(),
                },
            );
            lease.owners = entries.available.remove(key);
        }
        Ok(lease)
    }
}

impl Lease<Owners> {
    fn take(
        sink: &Sink,
        app: &str,
        intent: Option<&FreshIntent>,
        scope: Option<&AuthorityScope>,
        entry: &ResponseStart,
    ) -> Result<Self> {
        match entry {
            ResponseStart::Prepared(_) => ensure!(
                sink.is_open() && sink.prepared.get() && sink.uses_retained_app_io(),
                "native response not selected"
            ),
            ResponseStart::Host { .. } => {
                ensure!(intent.is_none(), "native host cannot borrow human original");
                sink.require_host_preparing(
                    scope.context("native host scope missing")?,
                    &sink.identity,
                )?;
            }
        }
        let registry = OWNERS.with(Rc::clone);
        {
            let mut entries = registry.try_borrow_mut()?;
            ensure!(
                !entries.reserved.contains_key(app),
                "native response owner busy"
            );
            let owner = entries
                .get_mut(app)
                .context("native response original executor absent")?;
            ensure!(
                owner.kind == NativeRole::AppHost,
                "native retained response role changed"
            );
            if let Some(scope) = scope {
                ensure!(
                    owner.selection.scope() == scope,
                    "native response scope changed"
                );
            }
            if let Some(intent) = intent {
                owner
                    .originals
                    .get(intent.attempt())
                    .context("native response original missing")?
                    .response
                    .require_bound(intent, &sink.identity)?;
            }
            let AppStorage::Participant(participant) = &mut owner.storage else {
                anyhow::bail!("native response participant unavailable")
            };
            crate::security_epoch::serving::require_app_response(
                participant,
                owner.selection.scope(),
                intent,
                &sink.identity,
            )?;
        }
        // The common lease core can move only the already present typed value;
        // it has no constructor or conversion from routing/configuration DATA.
        Self::acquire(
            registry,
            app,
            &sink.identity,
            intent.map(|intent| intent.attempt()),
        )
    }
}

impl<T: LeaseMaterial> Drop for Lease<T> {
    fn drop(&mut self) {
        let Some(mut owners) = self.owners.take() else {
            return;
        };
        let Ok(mut registry) = self.registry.try_borrow_mut() else {
            self.refused.set(true);
            owners.refuse_lease(self.attempt.as_deref());
            return;
        };
        let same = registry.reserved.get(&self.key).is_some_and(|reservation| {
            reservation.identity.same(&self.identity)
                && Rc::ptr_eq(&reservation.refused, &self.refused)
        });
        if !self.known || self.refused.get() || !same || registry.available.contains_key(&self.key)
        {
            owners.refuse_lease(self.attempt.as_deref());
        }
        if same {
            registry.reserved.remove(&self.key);
            // A cleared/replaced executor never receives the old original.
            if let std::collections::btree_map::Entry::Vacant(entry) =
                registry.available.entry(self.key.clone())
            {
                entry.insert(owners);
            }
        }
    }
}

struct ResponseBorrow<'scope, 'role, 'original> {
    stage: &'scope mut EnrolledRoleStage<'role>,
    current: &'scope mut dyn CurrentServingPhase,
    original: Option<&'scope mut OriginalPhase<'original>>,
    policy: &'scope day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
    store: &'scope day2_capabilities::security_epoch::EpochStore,
    refused: Rc<Cell<bool>>,
    known: bool,
}

/// A lexical SQL loan from the actual ordinary-host response parent. The
/// constructor is private to this pinned owner implementation; DATA cannot
/// construct a Current, stage, response identity or replacement Runtime.
pub(crate) struct HostSql<'scope, 'role> {
    runtime: &'scope crate::store::Runtime,
    stage: &'scope mut EnrolledRoleStage<'role>,
    current: &'scope mut dyn CurrentServingPhase,
    policy: &'scope day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
    store: &'scope day2_capabilities::security_epoch::EpochStore,
    scope: &'scope AuthorityScope,
    sink: &'scope Sink,
    identity: &'scope ResponseIdentity,
    refused: Rc<Cell<bool>>,
}

impl HostSql<'_, '_> {
    pub(super) fn prepare_sql(&mut self, runtime: &crate::store::Runtime) -> Result<()> {
        ensure!(
            std::ptr::eq(self.runtime, runtime)
                && runtime.uses_native_storage()
                && super::sql_runtime_scope(runtime)? == *self.scope,
            "native host SQL Runtime changed"
        );
        // The genuine parent was armed before this loan, including SQLite
        // open/recovery. No per-loan arm or finish_known is permitted.
        self.check_sql()
    }

    pub(super) fn check_sql(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused.get(), "native host SQL parent refused");
            self.sink
                .require_host_preparing(self.scope, self.identity)?;
            self.stage.check_for(self.scope, NativeRole::AppHost)?;
            self.stage
                .check_selection(self.policy, self.store, NativeRole::AppHost)?;
            // Transaction-safe native/retained-observation checks only. In
            // particular DO NOT call ResponseBorrow::check/reobserve here.
            self.current.check(self.stage)?;
            ensure!(!self.refused.get(), "native host SQL parent refused");
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(super) fn refuse(&mut self) {
        self.refused.set(true);
        self.current.refuse();
    }

    fn reobserve_outside_sql(&mut self) -> Result<()> {
        let result = (|| {
            self.check_sql()?;
            self.current.reobserve(self.stage)?;
            self.check_sql()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn read<T>(
        &mut self,
        operation: impl for<'db> FnOnce(&'db rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        self.reobserve_outside_sql()?;
        let runtime = self.runtime;
        let result = crate::store::RuntimeSql::with_owner(
            runtime,
            super::SqlOwner::host_response(self),
            |sql| sql.read(operation),
        );
        match result {
            Ok(value) => {
                self.reobserve_outside_sql()?;
                Ok(value)
            }
            Err(error) => {
                self.refuse();
                Err(error)
            }
        }
    }

    pub(crate) fn write<T>(
        &mut self,
        operation: impl for<'db> FnOnce(
            &'db rusqlite::Transaction<'_>,
        ) -> Result<crate::store::SqlDecision<T>>,
    ) -> Result<T> {
        self.reobserve_outside_sql()?;
        let runtime = self.runtime;
        let result = crate::store::RuntimeSql::with_owner(
            runtime,
            super::SqlOwner::host_response(self),
            |sql| sql.write(operation),
        );
        // RuntimeSql has closed the actual connection and transaction before
        // this provider reobservation or any result can escape.
        match result {
            Ok(value) => {
                self.reobserve_outside_sql()?;
                Ok(value)
            }
            Err(error) => {
                self.refuse();
                Err(error)
            }
        }
    }
}

impl ResponseBorrow<'_, '_, '_> {
    fn check(&mut self) -> Result<()> {
        ensure!(!self.refused.get(), "native response aborted");
        self.stage
            .check_selection(self.policy, self.store, NativeRole::AppHost)?;
        // A real counter read on the SAME authentication, not a cached
        // observation.remaining check or a new role/read acquisition.
        self.current.reobserve(self.stage)?;
        if let Some(original) = &mut self.original {
            // This remains the last consuming check before the actual I/O,
            // including a human original shorter than the role interval.
            original.check_with_native(self.stage, original.wall)?;
        }
        ensure!(!self.refused.get(), "native response aborted");
        Ok(())
    }

    fn complete(&mut self) -> Result<()> {
        self.check()?;
        if let Some(original) = &mut self.original {
            original.phase = Phase::ResponseComplete;
            original.check_with_native(self.stage, original.wall)?;
        }
        self.stage
            .check_selection(self.policy, self.store, NativeRole::AppHost)?;
        self.current.finish_known(self.stage)?;
        if let Some(original) = &mut self.original {
            original.check_with_native(self.stage, original.wall)?;
        }
        ensure!(!self.refused.get(), "native response aborted");
        self.known = true;
        Ok(())
    }
}

impl Drop for ResponseBorrow<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.known {
            self.current.refuse();
            if let Some(original) = &mut self.original {
                original.refuse();
            }
            self.refused.set(true);
        }
    }
}

enum ResponseStart {
    Prepared((u64, Operation)),
    Host {
        host: std::sync::Arc<crate::web::Host>,
        request: Box<crate::web::PreparedHostRequest>,
        reply: HostReplySlot,
    },
}

impl Sink {
    pub(in crate::oauth) async fn drive_response<T: hyper::rt::Write + Unpin>(
        &self,
        mut transport: Transport<T>,
    ) -> Result<()> {
        let first = transport.next().await?;
        ensure!(
            self.prepared.get() && self.uses_retained_app_io(),
            "native response barrier not prepared"
        );
        crate::oauth::native_http::response_io::require_first_io(&first.1)?;
        self.drive_response_owner(transport, ResponseStart::Prepared(first))
            .await
    }

    pub(in crate::oauth) async fn drive_host_request<T: hyper::rt::Write + Unpin>(
        &self,
        host: std::sync::Arc<crate::web::Host>,
        request: crate::web::PreparedHostRequest,
        transport: Transport<T>,
        reply: HostReplySlot,
    ) -> Result<()> {
        self.drive_response_owner(
            transport,
            ResponseStart::Host {
                host,
                request: Box::new(request),
                reply,
            },
        )
        .await
    }

    async fn drive_response_owner<T: hyper::rt::Write + Unpin>(
        &self,
        mut transport: Transport<T>,
        start: ResponseStart,
    ) -> Result<()> {
        let binding = {
            let bindings = self.bindings.try_borrow()?;
            ensure!(bindings.len() <= 1, "native response owner changed");
            bindings
                .iter()
                .next()
                .map(|((role, _), binding)| (*role, binding.clone()))
        };
        let runtime = self.runtime.try_borrow()?.clone();
        let (intent, scope, effects) = match (binding, runtime) {
            (Some((NativeRole::AppHost, binding)), None) => {
                (Some(binding.intent), None, binding.effects)
            }
            (None, Some(binding)) => (None, Some(binding.scope), binding.effects),
            _ => anyhow::bail!("native retained response owner conflict"),
        };
        let app = intent
            .as_ref()
            .map(|intent| intent.app())
            .or_else(|| scope.as_ref().map(|scope| scope.app.as_str()))
            .context("native response App missing")?;
        let mut lease = Lease::take(self, app, intent.as_ref(), scope.as_ref(), &start)?;
        let refused = lease.refused.clone();
        let owners = lease.owners.as_mut().expect("actual leased owner");
        let scope = owners.selection.scope().clone();
        let policy = owners.selection.policy.clone();
        let store = owners.selection.store.clone();
        let mut role = owners.role.take()?;
        let mut request_owner = self.request.take(&scope, NativeRole::AppHost)?;
        let result = effects
            .run_async(async {
                let role = role.owner();
                let AppStorage::Participant(participant) = &mut owners.storage else {
                    anyhow::bail!("native response participant unavailable")
                };
                transport.scope_attempt();
                let mut stage = request_owner.borrow(role)?;
                participant.prepare_current()?;
                stage.check_selection(
                    &owners.selection.policy,
                    &owners.selection.store,
                    owners.kind,
                )?;
                let mut original = match &intent {
                    Some(intent) => Some(OriginalPhase {
                        original: PhaseOriginal::Native(
                            &mut owners
                                .originals
                                .get_mut(intent.attempt())
                                .context("native response original absent")?
                                .original,
                        ),
                        intent,
                        wall: super::super::effects::wall_time()?,
                        phase: Phase::Response,
                    }),
                    None => None,
                };
                if let Some(original) = &mut original {
                    original.check_with_native(&mut stage, original.wall)?;
                }
                let sequence = crate::security_epoch::serving::with_app_response(
                    participant,
                    &mut stage,
                    &scope,
                    intent.as_ref(),
                    &self.identity,
                    async |current, same| {
                        transport.scope_entered();
                        let mut guard = ResponseBorrow {
                            stage: same,
                            current,
                            original: original.as_mut(),
                            policy: &policy,
                            store: &store,
                            refused,
                            known: false,
                        };
                        guard.check()?;
                        guard.current.arm(guard.stage)?;
                        let mut request = match start {
                            ResponseStart::Prepared(first) => first,
                            ResponseStart::Host {
                                host,
                                request,
                                reply,
                            } => {
                                ensure!(guard.original.is_none(), "native host original conflict");
                                let response = {
                                    let mut sql = HostSql {
                                        runtime: host.prepared_host_runtime(),
                                        stage: guard.stage,
                                        current: guard.current,
                                        policy: guard.policy,
                                        store: guard.store,
                                        scope: &scope,
                                        sink: self,
                                        identity: &self.identity,
                                        refused: guard.refused.clone(),
                                    };
                                    host.execute_host_request(*request, &mut sql)?
                                };
                                // No SQL loan or connection survives body preparation,
                                // provider reobservation or a transport suspension.
                                self.host_body_selected(&scope)?;
                                let response = crate::oauth::native_http::prepare_finite_app_body(
                                    response, self,
                                )
                                .await?;
                                ensure!(
                                    self.uses_retained_app_io(),
                                    "native host body must be finite"
                                );
                                guard.check()?;
                                self.host_reply_ready()?;
                                reply.publish(response)?;
                                // DATA publication is not settlement. The same
                                // future retains all actual native borrows here.
                                transport.next().await?
                            }
                        };
                        crate::oauth::native_http::response_io::require_first_io(&request.1)?;
                        loop {
                            if request.1 == Operation::Complete {
                                guard.complete()?;
                                break Ok(request.0);
                            }
                            transport
                                .execute(request.0, request.1, || guard.check())
                                .await?;
                            request = transport.next().await?;
                        }
                    },
                )
                .await?;
                stage.check_selection(
                    &owners.selection.policy,
                    &owners.selection.store,
                    owners.kind,
                )?;
                if let Some(original) = &mut original {
                    original.check_with_native(&mut stage, original.wall)?;
                }
                Ok::<_, anyhow::Error>(sequence)
            })
            .await;
        let sequence = result?;
        ensure!(
            self.is_open() && !lease.refused.get(),
            "native response finalization aborted"
        );
        if let Some(intent) = &intent {
            owners
                .originals
                .get_mut(intent.attempt())
                .context("native response original absent at completion")?
                .response
                .connection = None;
        }
        // The actual request is consumed only after physical completion and
        // all Current/original postchecks. The role/storage leases remain
        // unknown unless the following result publication also succeeds.
        request_owner.finish(role.owner())?;
        // A rejected/lost result publication remains terminally unknown.
        // No await or fallible operation follows the positive disposition.
        transport.complete(sequence)?;
        role.known = true;
        lease.known = true;
        self.state.set(SinkState::Complete);
        Ok(())
    }
}

#[cfg(test)]
mod host_source_tests {
    use syn::parse::Parser;
    use syn::visit::{self, Visit};

    #[derive(Default)]
    struct Calls {
        ordered: Vec<String>,
    }

    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.ordered.push(call.method.to_string());
            visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.ordered.push(
                    path.path
                        .segments
                        .iter()
                        .map(|part| part.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::"),
                );
            }
            visit::visit_expr_call(self, call);
        }

        fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
            if value.path.is_ident("HostSql") {
                self.ordered.push("HostSql".into());
            }
            visit::visit_expr_struct(self, value);
        }

        fn visit_macro(&mut self, value: &'ast syn::Macro) {
            // syn keeps ensure!'s condition as tokens. Parse its actual
            // expression arguments so Runtime/native checks in that condition
            // participate in the same AST mutation control.
            if value.path.is_ident("ensure") {
                let arguments =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                        .parse2(value.tokens.clone())
                        .expect("production ensure arguments");
                for argument in &arguments {
                    let mut nested = Calls::default();
                    nested.visit_expr(argument);
                    self.ordered.extend(nested.ordered);
                }
            }
            visit::visit_macro(self, value);
        }
    }

    #[test]
    fn production_macro_visitor_covers_semicolon_statements_and_expression_arguments_once() {
        let file = syn::parse_file(
            r#"fn example() {
            ensure!(std::ptr::eq(left, right), "statement");
            let _ = ensure!(runtime.uses_native_storage(), "expression");
        }"#,
        )
        .unwrap();
        let syn::Item::Fn(function) = &file.items[0] else {
            panic!("fixture function");
        };
        assert!(
            matches!(function.block.stmts[0], syn::Stmt::Macro(_)),
            "retain the actual production statement shape"
        );
        let mut calls = Calls::default();
        calls.visit_file(&file);
        assert_eq!(calls.ordered, ["std::ptr::eq", "uses_native_storage"]);
    }

    fn methods(source: &str, owner: &str, name: &str) -> Vec<Vec<String>> {
        let Ok(file) = syn::parse_file(source) else {
            return Vec::new();
        };
        let mut result = Vec::new();
        for item in file.items {
            if let syn::Item::Impl(item) = item
                && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|part| part.ident == owner))
            {
                for member in item.items {
                    if let syn::ImplItem::Fn(function) = member
                        && function.sig.ident == name
                    {
                        let mut calls = Calls::default();
                        calls.visit_block(&function.block);
                        result.push(calls.ordered);
                    }
                }
            }
        }
        result
    }

    fn one_method(source: &str, owner: &str, name: &str) -> Option<Vec<String>> {
        let mut methods = methods(source, owner, name);
        (methods.len() == 1).then(|| methods.remove(0))
    }

    fn before(calls: &[String], first: &str, last: &str) -> bool {
        matches!((calls.iter().position(|call| call == first), calls.iter().position(|call| call == last)), (Some(first), Some(last)) if first < last)
    }

    fn wiring(source: &str) -> bool {
        let Some(owner) = one_method(source, "Sink", "drive_response_owner") else {
            return false;
        };
        let Some(prepared) = one_method(source, "Sink", "drive_response") else {
            return false;
        };
        if !before(
            &prepared,
            "crate::oauth::native_http::response_io::require_first_io",
            "drive_response_owner",
        ) {
            return false;
        }
        let count = |calls: &[String], name: &str| {
            calls.iter().filter(|call| call.as_str() == name).count()
        };
        if count(&owner, "arm") != 1
            || count(&owner, "HostSql") != 1
            || count(&owner, "crate::security_epoch::serving::with_app_response") != 1
            || !before(&owner, "arm", "HostSql")
            || !before(&owner, "execute_host_request", "host_body_selected")
            || !before(
                &owner,
                "host_body_selected",
                "crate::oauth::native_http::prepare_finite_app_body",
            )
            || !before(
                &owner,
                "crate::oauth::native_http::prepare_finite_app_body",
                "publish",
            )
            || !before(
                &owner,
                "crate::oauth::native_http::response_io::require_first_io",
                "complete",
            )
        {
            return false;
        }
        let Some(check) = one_method(source, "HostSql", "check_sql") else {
            return false;
        };
        if count(&check, "check") != 1
            || count(&check, "reobserve") != 0
            || count(&check, "require_host_preparing") != 1
            || count(&check, "check_for") != 1
            || count(&check, "check_selection") != 1
        {
            return false;
        }
        let Some(prepare) = one_method(source, "HostSql", "prepare_sql") else {
            return false;
        };
        if count(&prepare, "std::ptr::eq") != 1
            || count(&prepare, "uses_native_storage") != 1
            || count(&prepare, "super::sql_runtime_scope") != 1
            || count(&prepare, "check_sql") != 1
        {
            return false;
        }
        for name in ["read", "write"] {
            let Some(loan) = one_method(source, "HostSql", name) else {
                return false;
            };
            if count(&loan, "reobserve_outside_sql") != 2
                || !before(
                    &loan,
                    "reobserve_outside_sql",
                    "crate::store::RuntimeSql::with_owner",
                )
                || count(&loan, "super::SqlOwner::host_response") != 1
                || count(&loan, "refuse") != 1
                || count(&loan, "arm") != 0
                || count(&loan, "finish_known") != 0
                || !matches!((loan.iter().position(|call| call == "crate::store::RuntimeSql::with_owner"), loan.iter().rposition(|call| call == "reobserve_outside_sql")), (Some(open), Some(reobserve)) if open < reobserve)
            {
                return false;
            }
        }
        true
    }

    #[test]
    fn production_host_owner_wiring_mutants_cannot_remove_arm_identity_or_first_io_checks() {
        let source = include_str!("response.rs")
            .split("\n#[cfg(test)]\nmod host_source_tests")
            .next()
            .unwrap();
        assert!(wiring(source));
        for (from, to) in [
            ("guard.current.arm(guard.stage)?;", ""),
            (
                "self.current.check(self.stage)?;",
                "self.current.reobserve(self.stage)?;",
            ),
            ("require_host_preparing", "removed_host_identity_check"),
            ("require_first_io", "removed_first_io_check"),
            ("std::ptr::eq", "removed_runtime_identity_check"),
            (
                "super::SqlOwner::host_response(self)",
                "super::SqlOwner::runtime(self)",
            ),
        ] {
            assert_eq!(
                source.matches(from).count(),
                if matches!(
                    from,
                    "super::SqlOwner::host_response(self)"
                        | "require_host_preparing"
                        | "require_first_io"
                ) {
                    2
                } else {
                    1
                },
                "mutation must bind actual production source"
            );
            assert!(
                !wiring(&source.replace(from, to)),
                "missing guard must fail: {from}"
            );
        }
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    use std::future::Future;

    // Non-authority material exercises the SAME move/reservation/Drop code.
    // It has no conversion to Owners, a native stage, peer or serving phase.
    struct Material {
        incarnation: u32,
        refused: Rc<Cell<bool>>,
        dropped: Rc<Cell<u32>>,
    }
    impl sealed::Material for Material {}
    impl LeaseMaterial for Material {
        fn refuse_lease(&mut self, _: Option<&str>) {
            self.refused.set(true);
        }
    }
    impl Drop for Material {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
        }
    }

    struct Fixture {
        registry: Rc<RefCell<Registry<Material>>>,
        refused: Rc<Cell<bool>>,
        dropped: Rc<Cell<u32>>,
    }

    fn fixture() -> Fixture {
        let registry = Rc::new(RefCell::new(Registry::default()));
        let refused = Rc::new(Cell::new(false));
        let dropped = Rc::new(Cell::new(0));
        registry.borrow_mut().insert(
            "calendar".into(),
            Material {
                incarnation: 1,
                refused: refused.clone(),
                dropped: dropped.clone(),
            },
        );
        Fixture {
            registry,
            refused,
            dropped,
        }
    }

    #[test]
    fn unstarted_work_is_excluded_by_the_live_response_but_abort_is_not_retryable_busy() {
        let Fixture {
            registry, refused, ..
        } = fixture();
        assert!(
            !registry
                .borrow()
                .excludes_unstarted_operation("calendar")
                .unwrap()
        );
        let winner = ResponseIdentity::new();
        let loser = ResponseIdentity::new();
        let lease = Lease::acquire(registry.clone(), "calendar", &winner, None).unwrap();
        assert!(registry.borrow().get("calendar").is_none());
        assert!(
            registry
                .borrow()
                .excludes_unstarted_operation("calendar")
                .unwrap()
        );
        registry.borrow().refuse_for(&loser);
        assert!(
            registry
                .borrow()
                .excludes_unstarted_operation("calendar")
                .unwrap()
        );
        assert!(!lease.refused.get() && !refused.get());
        registry.borrow().refuse_for(&winner);
        assert!(
            registry
                .borrow()
                .excludes_unstarted_operation("calendar")
                .is_err()
        );
        assert!(Lease::acquire(registry.clone(), "calendar", &loser, None).is_err());
        assert!(
            registry
                .borrow()
                .excludes_unstarted_operation("calendar")
                .is_err()
        );
        drop(lease);
        assert!(refused.get());
    }

    #[test]
    fn actual_role_slot_moves_once_and_returns_the_same_value_to_original_handles() {
        let role = Role::new(7_u32);
        let original = role.clone();
        let mut held = role.take().unwrap();
        assert!(original.try_borrow_mut().is_err());
        assert!(original.take().is_err());
        *held.owner() = 11;
        held.known = true;
        drop(held);
        assert_eq!(*original.try_borrow_mut().unwrap(), 11);
        assert!(Rc::ptr_eq(&role.slot, &original.slot));
        assert!(role.slot.borrow().reservation.is_none());
    }

    #[test]
    fn suspension_holds_actual_role_without_a_refcell_borrow_and_cancel_stays_unknown() {
        let role = Role::new(7_u32);
        let captured = role.clone();
        let Fixture {
            registry, refused, ..
        } = fixture();
        let identity = ResponseIdentity::new();
        let mut future = Box::pin(async move {
            let _lease = Lease::acquire(registry, "calendar", &identity, None).unwrap();
            let mut held = captured.take().unwrap();
            assert_eq!(*held.owner(), 7);
            std::future::pending::<()>().await;
        });
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        // The slot itself is freely borrowable while the ACTUAL value is
        // retained. It supplies no second owner or renewed native stage.
        assert!(role.slot.try_borrow_mut().is_ok());
        assert!(role.try_borrow_mut().is_err());
        drop(future);
        assert!(role.try_borrow_mut().is_err());
        assert!(role.take().is_err());
        assert!(refused.get(), "cancelled delivery never settles storage");
    }

    #[test]
    fn role_slot_drop_never_overwrites_replacement_or_recovers_from_a_borrow_collision() {
        for replacement in [false, true] {
            let dropped = Rc::new(Cell::new(0));
            let role = Role::new(Material {
                incarnation: 1,
                refused: Rc::new(Cell::new(false)),
                dropped: dropped.clone(),
            });
            let mut held = role.take().unwrap();
            held.known = true;
            if replacement {
                *role.slot.borrow_mut() = RoleSlot {
                    owner: Some(Material {
                        incarnation: 2,
                        refused: Rc::new(Cell::new(false)),
                        dropped: Rc::new(Cell::new(0)),
                    }),
                    reservation: None,
                };
            } else {
                role.slot.borrow_mut().reservation = Some(Rc::new(()));
            }
            drop(held);
            assert_eq!(dropped.get(), 1);
            if replacement {
                assert_eq!(role.try_borrow_mut().unwrap().incarnation, 2);
            } else {
                assert!(role.try_borrow_mut().is_err());
                assert!(role.take().is_err());
            }
        }
        let dropped = Rc::new(Cell::new(0));
        let role = Role::new(Material {
            incarnation: 1,
            refused: Rc::new(Cell::new(false)),
            dropped: dropped.clone(),
        });
        let mut held = role.take().unwrap();
        held.known = true;
        let busy = role.slot.borrow();
        drop(held);
        assert_eq!(dropped.get(), 1);
        drop(busy);
        assert!(role.try_borrow_mut().is_err());
        assert!(role.take().is_err());
    }

    #[test]
    fn actual_lease_core_moves_once_and_pending_loser_cannot_touch_the_winner() {
        let Fixture {
            registry,
            refused,
            dropped,
        } = fixture();
        let winner = ResponseIdentity::new();
        let loser = ResponseIdentity::new();
        let lease = Lease::acquire(registry.clone(), "calendar", &winner, None).unwrap();
        assert!(registry.borrow().available.is_empty());
        assert_eq!(lease.owners.as_ref().unwrap().incarnation, 1);
        assert!(Lease::acquire(registry.clone(), "calendar", &loser, None).is_err());
        registry.borrow().refuse_for(&loser);
        assert!(!lease.refused.get() && !refused.get());
        assert_eq!(dropped.get(), 0);
        drop(lease); // Pending cancellation: no clock or new stage required.
        assert!(refused.get());
        assert!(registry.borrow().reserved.is_empty());
        assert_eq!(registry.borrow()["calendar"].incarnation, 1);
        assert_eq!(
            dropped.get(),
            0,
            "the actual refused material is retained, not recreated"
        );
    }

    #[test]
    fn double_abort_and_recorded_scope_without_published_completion_stay_terminal() {
        let Fixture {
            registry, refused, ..
        } = fixture();
        let winner = ResponseIdentity::new();
        let lease =
            Lease::acquire(registry.clone(), "calendar", &winner, Some("original")).unwrap();
        registry.borrow().refuse_for(&winner);
        registry.borrow().refuse_for(&winner);
        assert!(lease.refused.get());
        drop(lease);
        assert!(refused.get());

        let Fixture {
            registry, refused, ..
        } = fixture();
        let lease = Lease::acquire(registry.clone(), "calendar", &winner, None).unwrap();
        let scope_recorded = true; // Historical native-scope DATA is not publication.
        assert!(scope_recorded && !lease.known);
        drop(lease);
        assert!(refused.get());
    }

    #[test]
    fn settled_drop_retains_same_material_and_retired_identity_cannot_abort_replacement() {
        let Fixture {
            registry,
            refused,
            dropped,
        } = fixture();
        let old = ResponseIdentity::new();
        let mut lease = Lease::acquire(registry.clone(), "calendar", &old, None).unwrap();
        // Test the state AFTER the production matching publication succeeds.
        // There is no public setter or permission factory for this state.
        lease.known = true;
        drop(lease);
        assert!(!refused.get());
        assert_eq!(dropped.get(), 0);
        let fresh = ResponseIdentity::new();
        let mut replacement = Lease::acquire(registry.clone(), "calendar", &fresh, None).unwrap();
        registry.borrow().refuse_for(&old);
        assert!(!replacement.refused.get());
        replacement.known = true;
        drop(replacement);
        assert!(!refused.get());
    }

    #[test]
    fn clear_and_replacement_never_restore_old_material_or_burn_new_incarnation() {
        for clear in [false, true] {
            let Fixture {
                registry,
                refused: old_refused,
                dropped: old_dropped,
            } = fixture();
            let winner = ResponseIdentity::new();
            let lease = Lease::acquire(registry.clone(), "calendar", &winner, None).unwrap();
            if clear {
                registry.borrow_mut().clear();
            }
            let fresh_refused = Rc::new(Cell::new(false));
            registry.borrow_mut().insert(
                "calendar".into(),
                Material {
                    incarnation: 2,
                    refused: fresh_refused.clone(),
                    dropped: Rc::new(Cell::new(0)),
                },
            );
            drop(lease);
            assert!(old_refused.get());
            assert_eq!(old_dropped.get(), 1);
            assert!(!fresh_refused.get());
            assert_eq!(registry.borrow()["calendar"].incarnation, 2);
        }
    }

    #[test]
    fn reservation_incarnation_and_borrowed_registry_fail_closed_without_panicking() {
        let Fixture {
            registry,
            refused,
            dropped,
        } = fixture();
        let identity = ResponseIdentity::new();
        let lease = Lease::acquire(registry.clone(), "calendar", &identity, None).unwrap();
        let marker = Rc::new(Cell::new(false));
        registry.borrow_mut().reserved.insert(
            "calendar".into(),
            Reservation {
                identity: identity.clone(),
                refused: marker.clone(),
            },
        );
        drop(lease);
        assert!(refused.get());
        assert_eq!(dropped.get(), 1);
        assert!(registry.borrow().available.is_empty());
        assert!(
            !marker.get(),
            "old Drop cannot act on a different reservation incarnation"
        );

        let Fixture {
            registry,
            refused,
            dropped,
        } = fixture();
        let lease = Lease::acquire(registry.clone(), "calendar", &identity, None).unwrap();
        let busy = registry.borrow();
        drop(lease);
        assert!(refused.get());
        assert_eq!(dropped.get(), 1);
        drop(busy);
        assert!(Lease::acquire(registry.clone(), "calendar", &identity, None).is_err());
        registry.borrow_mut().clear();
    }
}
