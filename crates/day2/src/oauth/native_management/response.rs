//! Actual finite App response ownership. Registry entries are moved, never
//! reconstructed from DATA. The pinned driver keeps lexical native borrows;
//! the registry contains only a negative busy/abort marker while it waits.

#[cfg(test)]
use super::fixtures;
use super::{AppStorage, OWNERS, OriginalPhase, Owners, Phase, PhaseOriginal, Sink, SinkState};
use crate::oauth::fresh_auth::FreshIntent;
use crate::oauth::native_http::response_io::{Operation, Transport};
use crate::security_epoch::{
    native_enrollment::{EnrolledRoleStage, NativeRole},
    serving::{CurrentServingPhase, ResponseIdentity, RestoredResponseCurrent},
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;
use std::{
    cell::{Cell, RefCell, RefMut},
    collections::BTreeMap,
    rc::{Rc, Weak},
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
    pub(super) fn require_unleased(&self) -> Result<()> {
        ensure!(self.reserved.is_empty(), "response_rights_scope_leased");
        Ok(())
    }

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
    live: Rc<Cell<bool>>,
    owners: Option<T>,
    attempt: Option<String>,
    known: bool,
}

/// Negative identity of one actual retained response lease. Sharing it grants
/// nothing: it only joins the same Sink and observes the actual abort latch.
pub(super) struct ConsumerLeaseOrigin {
    identity: ResponseIdentity,
    refused: Rc<Cell<bool>>,
    live: Weak<Cell<bool>>,
    consumer: LeaseConsumer,
}

enum LeaseConsumer {
    Human(day2_capabilities::Digest),
    Runtime,
}

impl ConsumerLeaseOrigin {
    pub(super) fn require_human(&self, sink: &Sink, intent: &FreshIntent) -> Result<()> {
        let result = (|| {
            self.check(sink)?;
            let expected = intent.commitment()?;
            ensure!(
                matches!(&self.consumer, LeaseConsumer::Human(actual) if actual == &expected),
                "native response lease human original changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse_sink(sink);
        }
        result
    }

    pub(super) fn require_runtime(&self, sink: &Sink) -> Result<()> {
        self.check(sink)?;
        if !matches!(&self.consumer, LeaseConsumer::Runtime) {
            self.refuse_sink(sink);
            anyhow::bail!("native human response cannot become Runtime");
        }
        Ok(())
    }

    pub(super) fn check(&self, sink: &Sink) -> Result<()> {
        if !self.identity.same(&sink.identity) || self.live.upgrade().is_none_or(|live| !live.get())
        {
            // An old/foreign negative projection has no right to burn the
            // other Sink or a replacement lease on that same routing identity.
            self.refuse();
            anyhow::bail!("native response lease origin changed or refused");
        }
        if self.refused.get() || !sink.is_open() {
            self.refuse_sink(sink);
            anyhow::bail!("native response lease origin changed or refused");
        }
        Ok(())
    }

    pub(super) fn refuse(&self) {
        self.refused.set(true);
    }

    pub(super) fn refuse_sink(&self, sink: &Sink) {
        let same_live = self.identity.same(&sink.identity)
            && self.live.upgrade().is_some_and(|live| live.get());
        self.refuse();
        if same_live {
            sink.state.set(SinkState::Refused);
            sink.request.refuse();
            sink.response_tickets.refuse();
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
            let _ = <ConsumerLeaseOrigin as Ambiguous<_>>::check;
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
            live: Rc::new(Cell::new(true)),
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
    fn consumer_origin(&self) -> Result<ConsumerLeaseOrigin> {
        ensure!(
            self.owners.is_some() && !self.known && !self.refused.get() && self.live.get(),
            "native response lease unavailable"
        );
        let owners = self
            .owners
            .as_ref()
            .context("native response lease owner missing")?;
        let consumer = match &self.attempt {
            Some(attempt) => {
                let original = owners
                    .originals
                    .get(attempt)
                    .context("native response lease original missing")?;
                original
                    .response
                    .require_bound(&original.response.intent, &self.identity)?;
                LeaseConsumer::Human(original.response.intent.commitment()?)
            }
            None => LeaseConsumer::Runtime,
        };
        Ok(ConsumerLeaseOrigin {
            identity: self.identity.clone(),
            refused: self.refused.clone(),
            live: Rc::downgrade(&self.live),
            consumer,
        })
    }

    fn take(
        sink: &Sink,
        app: &str,
        intent: Option<&FreshIntent>,
        scope: Option<&AuthorityScope>,
    ) -> Result<Self> {
        ensure!(
            sink.is_open() && sink.prepared.get() && sink.uses_retained_app_io(),
            "native response not selected"
        );
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
        // Every disposition, including known return and a missing owner,
        // retires this exact lease incarnation before any early return.
        self.live.set(false);
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
    source: ResponseSource<'scope, 'role, 'original>,
    refused: Rc<Cell<bool>>,
    known: bool,
}

enum ResponseSource<'scope, 'role, 'original> {
    Initial {
        stage: &'scope mut EnrolledRoleStage<'role>,
        current: &'scope mut dyn CurrentServingPhase,
        original: Option<&'scope mut OriginalPhase<'original>>,
        policy: &'scope day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
        store: &'scope day2_capabilities::security_epoch::EpochStore,
    },
    Restored(&'scope mut dyn RestoredResponseCurrent),
}

impl<'scope, 'role, 'original> ResponseBorrow<'scope, 'role, 'original> {
    // The actual fixed driver supplies the SAME native scope and its actual
    // lease latch. Arc/Runtime/identity DATA cannot construct the sealed view.
    // The scope additionally checks its own saved request-routing latch.
    fn from_restored<'parent, 'request, 'saved>(
        current: &'scope mut crate::security_epoch::serving::RestoredServingScope<
            'parent,
            'request,
            'saved,
        >,
        runtime: &crate::store::Runtime,
        refused: Rc<Cell<bool>>,
    ) -> Result<Self> {
        let current = current.borrow_response(runtime)?;
        if refused.get() {
            current.refuse();
            anyhow::bail!("native response aborted");
        }
        Ok(Self {
            source: ResponseSource::Restored(current),
            refused,
            known: false,
        })
    }
}

impl ResponseBorrow<'_, '_, '_> {
    async fn drive<T: hyper::rt::Write + Unpin>(
        &mut self,
        transport: &mut Transport<T>,
        mut request: (u64, Operation),
    ) -> Result<u64> {
        ensure!(
            request.1 != Operation::Complete,
            "native response completed before first I/O"
        );
        self.check()?;
        self.arm()?;
        loop {
            if request.1 == Operation::Complete {
                self.complete()?;
                break Ok(request.0);
            }
            transport
                .execute(request.0, request.1, || self.check())
                .await?;
            request = transport.next().await?;
        }
    }

    fn check(&mut self) -> Result<()> {
        ensure!(!self.refused.get(), "native response aborted");
        match &mut self.source {
            ResponseSource::Initial {
                stage,
                current,
                original,
                policy,
                store,
            } => {
                stage.check_selection(policy, store, NativeRole::AppHost)?;
                // A real counter read on the SAME authentication, not a cached
                // observation.remaining check or a new role/read acquisition.
                current.reobserve(stage)?;
                if let Some(original) = original {
                    // Last consuming original check before actual I/O.
                    original.check_with_native(stage, original.wall)?;
                }
            }
            ResponseSource::Restored(current) => {
                // The concrete scope owns the saved native stage and mandatory
                // human original. Its reobserve checks the old observation and
                // performs all independent posts, ending at that same original.
                current.reobserve()?;
            }
        }
        ensure!(!self.refused.get(), "native response aborted");
        Ok(())
    }

    fn arm(&mut self) -> Result<()> {
        match &mut self.source {
            ResponseSource::Initial { current, stage, .. } => current.arm(stage),
            ResponseSource::Restored(current) => current.arm(),
        }
    }

    fn complete(&mut self) -> Result<()> {
        self.check()?;
        match &mut self.source {
            ResponseSource::Initial {
                stage,
                current,
                original,
                policy,
                store,
            } => {
                if let Some(original) = original.as_mut() {
                    original.phase = Phase::ResponseComplete;
                    original.check_with_native(stage, original.wall)?;
                }
                stage.check_selection(policy, store, NativeRole::AppHost)?;
                current.finish_known(stage)?;
                if let Some(original) = original.as_mut() {
                    original.check_with_native(stage, original.wall)?;
                }
            }
            ResponseSource::Restored(current) => {
                current.response_complete()?;
                current.finish_known()?;
                current.check()?;
            }
        }
        ensure!(!self.refused.get(), "native response aborted");
        self.known = true;
        Ok(())
    }
}

impl Drop for ResponseBorrow<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.known {
            match &mut self.source {
                ResponseSource::Initial {
                    current, original, ..
                } => {
                    current.refuse();
                    if let Some(original) = original {
                        original.refuse();
                    }
                }
                ResponseSource::Restored(current) => current.refuse(),
            }
            self.refused.set(true);
        }
    }
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
        ensure!(
            first.1 != Operation::Complete,
            "native response completed before first I/O"
        );
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
        let mut lease = Lease::take(self, app, intent.as_ref(), scope.as_ref())?;
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
                            source: ResponseSource::Initial {
                                stage: same,
                                current,
                                original: original.as_mut(),
                                policy: &policy,
                                store: &store,
                            },
                            refused,
                            known: false,
                        };
                        guard.drive(&mut transport, first).await
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
        let terminal = self
            .response_tickets
            .prepare_native(&self.identity, &owners.response_rights)?;
        request_owner.finish(role.owner())?;
        // A rejected/lost result publication remains terminally unknown.
        // No await or fallible operation follows the positive disposition.
        transport.complete(sequence)?;
        role.known = true;
        lease.known = true;
        self.state.set(SinkState::Complete);
        terminal.complete();
        Ok(())
    }
}

#[cfg(test)]
mod restored_response_source_tests {
    use super::*;
    use quote::ToTokens;

    #[test]
    fn actual_lease_projection_derives_human_binding_only_from_its_retained_owner() {
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let actual = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if item.self_ty.to_token_stream().to_string() != "Lease < Owners >" {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "consumer_origin" => Some(item),
                    _ => None,
                })
            })
            .unwrap();
        let expected: syn::Block = syn::parse_quote!({
            ensure!(
                self.owners.is_some() && !self.known && !self.refused.get() && self.live.get(),
                "native response lease unavailable"
            );
            let owners = self
                .owners
                .as_ref()
                .context("native response lease owner missing")?;
            let consumer = match &self.attempt {
                Some(attempt) => {
                    let original = owners
                        .originals
                        .get(attempt)
                        .context("native response lease original missing")?;
                    original
                        .response
                        .require_bound(&original.response.intent, &self.identity)?;
                    LeaseConsumer::Human(original.response.intent.commitment()?)
                }
                None => LeaseConsumer::Runtime,
            };
            Ok(ConsumerLeaseOrigin {
                identity: self.identity.clone(),
                refused: self.refused.clone(),
                live: Rc::downgrade(&self.live),
                consumer,
            })
        });
        fn normalize(stream: proc_macro2::TokenStream) -> String {
            let mut tokens = stream.into_iter().collect::<Vec<_>>();
            if matches!(tokens.last(), Some(proc_macro2::TokenTree::Punct(punct)) if punct.as_char() == ',')
            {
                tokens.pop();
            }
            tokens
                .into_iter()
                .map(|token| match token {
                    proc_macro2::TokenTree::Group(group) => {
                        format!("{:?}[{}]", group.delimiter(), normalize(group.stream()))
                    }
                    token => token.to_string(),
                })
                .collect::<Vec<_>>()
                .join(" ")
        }
        let guarded = |block: &syn::Block| {
            normalize(block.to_token_stream()) == normalize(expected.to_token_stream())
        };
        assert!(guarded(&actual.block));
        for cut in 0..actual.block.stmts.len() {
            let mut changed = actual.block.clone();
            changed.stmts.remove(cut);
            assert!(!guarded(&changed));
        }
        let mut dropped = actual.block.clone();
        let syn::Stmt::Local(selected) = &mut dropped.stmts[2] else {
            panic!("actual kind");
        };
        let syn::Expr::Match(selected) = selected.init.as_mut().unwrap().expr.as_mut() else {
            panic!("actual retained attempt");
        };
        let syn::Expr::Block(human) = selected.arms[0].body.as_mut() else {
            panic!("actual human owner");
        };
        human.block.stmts.remove(1);
        assert!(!guarded(&dropped));
        let mut runtime = actual.block.clone();
        runtime.stmts[2] = syn::parse_quote!(let consumer = LeaseConsumer::Runtime;);
        assert!(!guarded(&runtime));
    }

    #[test]
    fn response_lease_origin_is_negative_only_and_cannot_ignore_an_actual_abort_or_other_sink() {
        // Only negative identity/latch DATA; no Owners, native role, Current,
        // context or response permission is supplied by this fixture.
        for foreign in [false, true] {
            let sink = Sink::new();
            let live = Rc::new(Cell::new(true));
            let actual = ConsumerLeaseOrigin {
                identity: sink.identity.clone(),
                refused: Rc::new(Cell::new(false)),
                live: Rc::downgrade(&live),
                consumer: LeaseConsumer::Runtime,
            };
            actual.check(&sink).unwrap();
            if foreign {
                let other = Sink::new();
                assert!(actual.check(&other).is_err());
                assert!(
                    other.is_open(),
                    "foreign negative view cannot burn another Sink"
                );
            } else {
                actual.refused.set(true);
            }
            assert!(actual.check(&sink).is_err());
            assert!(!sink.is_open());
            assert!(sink.request.finish().is_err());
        }
    }

    fn method(name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let methods = file
            .items
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item)
                    if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.segments.len() == 1 && path.path.segments[0].ident == "ResponseBorrow") =>
                {
                    Some(item)
                }
                _ => None,
            })
            .flat_map(|item| item.items)
            .filter_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), 1);
        methods.into_iter().next().unwrap()
    }

    #[test]
    fn actual_restored_response_borrow_requires_the_http_context_and_actual_lease_latch() {
        let actual = method("from_restored");
        let expected: syn::Block = syn::parse_quote!({
            let current = current.borrow_response(runtime)?;
            if refused.get() {
                current.refuse();
                anyhow::bail!("native response aborted");
            }
            Ok(Self {
                source: ResponseSource::Restored(current),
                refused,
                known: false,
            })
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        let syn::FnArg::Typed(current) = &actual.sig.inputs[0] else {
            panic!("actual concrete scope");
        };
        assert!(matches!(&*current.ty, syn::Type::Reference(reference)
            if matches!(&*reference.elem, syn::Type::Path(path)
                if path.path.segments.last().unwrap().ident == "RestoredServingScope")));
        for index in 0..2 {
            let mut bypass = actual.block.clone();
            bypass.stmts.remove(index);
            assert!(!guarded(&bypass));
        }
        assert!(matches!(actual.vis, syn::Visibility::Inherited));
    }

    #[test]
    fn one_actual_transport_loop_requires_first_io_and_guarded_completion_for_both_sources() {
        let actual = method("drive");
        let expected: syn::Block = syn::parse_quote!({
            ensure!(
                request.1 != Operation::Complete,
                "native response completed before first I/O"
            );
            self.check()?;
            self.arm()?;
            loop {
                if request.1 == Operation::Complete {
                    self.complete()?;
                    break Ok(request.0);
                }
                transport
                    .execute(request.0, request.1, || self.check())
                    .await?;
                request = transport.next().await?;
            }
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        for index in 0..3 {
            let mut bypass = actual.block.clone();
            bypass.stmts.remove(index);
            assert!(!guarded(&bypass));
        }
        let mut no_completion = actual.block.clone();
        let syn::Stmt::Expr(syn::Expr::Loop(actual_loop), _) = &mut no_completion.stmts[3] else {
            panic!("loop");
        };
        let syn::Stmt::Expr(syn::Expr::If(completed), _) = &mut actual_loop.body.stmts[0] else {
            panic!("completion");
        };
        completed.then_branch.stmts.remove(0);
        assert!(!guarded(&no_completion));
    }

    #[test]
    fn actual_restored_completion_checks_the_original_and_known_result_without_releasing_ownership()
    {
        let actual = method("complete");
        let expected_branch: syn::Expr = syn::parse_quote!({
            current.response_complete()?;
            current.finish_known()?;
            current.check()?;
        });
        let branch = |body: &syn::Block| {
            body.stmts.iter().find_map(|statement| {
                let syn::Stmt::Expr(syn::Expr::Match(selected), _) = statement else {
                    return None;
                };
                selected.arms.iter().find_map(|arm| {
                    let expected_pat: syn::Pat =
                        syn::parse_quote!(ResponseSource::Restored(current));
                    (arm.pat.to_token_stream().to_string()
                        == expected_pat.to_token_stream().to_string())
                    .then(|| arm.body.to_token_stream().to_string())
                })
            })
        };
        let expected = expected_branch.to_token_stream().to_string();
        assert!(branch(&actual.block).is_some_and(|actual| actual == expected));
        let mut early_finish = actual.block.clone();
        let syn::Stmt::Expr(syn::Expr::Match(selected), _) = &mut early_finish.stmts[1] else {
            panic!("source");
        };
        let arm = selected.arms.last_mut().unwrap();
        *arm.body = syn::parse_quote!({
            current.finish()?;
        });
        assert!(branch(&early_finish).is_some_and(|actual| actual != expected));
        // Native scope and HTTP request completion remain distinct consuming
        // operations owned outside this nonescaping transport borrow.
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
    fn actual_live_lease_binding_refuses_runtime_human_and_foreign_intent_swaps() -> Result<()> {
        let intent = FreshIntent::fixture_oauth(
            &crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "alice".into(),
            },
            "same-actual-original",
            &day2_capabilities::Digest::new(b"lease intent"),
            "https://security.example.com",
            5,
            50,
        )?;
        let foreign = FreshIntent::fixture_oauth(
            &crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "alice".into(),
            },
            "other-actual-original",
            &day2_capabilities::Digest::new(b"lease intent"),
            "https://security.example.com",
            5,
            50,
        )?;
        // Actual generic lease/liveness machinery with DATA-only material;
        // this supplies no native owner, Current or positive permission.
        for human in [false, true] {
            let Fixture { registry, .. } = fixture();
            let sink = Sink::new();
            let lease = Lease::acquire(registry, "calendar", &sink.identity, None)?;
            let origin = ConsumerLeaseOrigin {
                identity: lease.identity.clone(),
                refused: lease.refused.clone(),
                live: Rc::downgrade(&lease.live),
                consumer: if human {
                    LeaseConsumer::Human(intent.commitment()?)
                } else {
                    LeaseConsumer::Runtime
                },
            };
            if human {
                origin.require_human(&sink, &intent)?;
                assert!(origin.require_runtime(&sink).is_err());
            } else {
                origin.require_runtime(&sink)?;
                assert!(origin.require_human(&sink, &intent).is_err());
            }
            assert!(origin.refused.get() && !sink.is_open());
            assert!(origin.require_human(&sink, &intent).is_err());
            drop(lease);
        }
        let Fixture { registry, .. } = fixture();
        let sink = Sink::new();
        let lease = Lease::acquire(registry, "calendar", &sink.identity, None)?;
        let origin = ConsumerLeaseOrigin {
            identity: lease.identity.clone(),
            refused: lease.refused.clone(),
            live: Rc::downgrade(&lease.live),
            consumer: LeaseConsumer::Human(intent.commitment()?),
        };
        origin.require_human(&sink, &intent)?;
        assert!(origin.require_human(&sink, &foreign).is_err());
        assert!(origin.require_human(&sink, &intent).is_err());
        assert!(!sink.is_open());
        Ok(())
    }

    #[test]
    fn response_origin_observes_registry_clear_while_a_sql_unit_is_open() -> Result<()> {
        // The actual generic reservation/Drop machinery with DATA material,
        // plus real SQLite. This is a negative-latch control, not native SQL.
        let Fixture { registry, .. } = fixture();
        let sink = Sink::new();
        let lease = Lease::acquire(registry.clone(), "calendar", &sink.identity, None)?;
        let origin = ConsumerLeaseOrigin {
            identity: lease.identity.clone(),
            refused: lease.refused.clone(),
            live: Rc::downgrade(&lease.live),
            consumer: LeaseConsumer::Runtime,
        };
        origin.check(&sink)?;
        let mut db = rusqlite::Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE unchanged(value INTEGER)")?;
        let tx = db.transaction()?;
        registry.borrow_mut().clear();
        let called = Cell::new(false);
        let later = (|| -> Result<()> {
            origin.check(&sink)?;
            called.set(true);
            tx.execute("INSERT INTO unchanged VALUES(1)", [])?;
            Ok(())
        })();
        assert!(later.is_err());
        assert!(!called.get());
        tx.rollback()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM unchanged", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        drop(lease);
        Ok(())
    }

    #[test]
    fn returned_or_lost_response_lease_origin_cannot_validate_or_refuse_a_replacement() -> Result<()>
    {
        for known in [false, true] {
            let Fixture { registry, .. } = fixture();
            let sink = Sink::new();
            let mut lease = Lease::acquire(registry.clone(), "calendar", &sink.identity, None)?;
            let old = ConsumerLeaseOrigin {
                identity: lease.identity.clone(),
                refused: lease.refused.clone(),
                live: Rc::downgrade(&lease.live),
                consumer: LeaseConsumer::Runtime,
            };
            old.check(&sink)?;
            lease.known = known;
            drop(lease);
            assert!(old.live.upgrade().is_none());
            assert!(old.check(&sink).is_err());
            assert!(
                sink.is_open(),
                "stale view cannot poison a replacement Sink"
            );
            if known {
                let next = Lease::acquire(registry.clone(), "calendar", &sink.identity, None)?;
                let current = ConsumerLeaseOrigin {
                    identity: next.identity.clone(),
                    refused: next.refused.clone(),
                    live: Rc::downgrade(&next.live),
                    consumer: LeaseConsumer::Runtime,
                };
                current.check(&sink)?;
                assert!(old.check(&sink).is_err());
                assert!(!next.refused.get());
                current.check(&sink)?;
                drop(next);
            }
        }
        Ok(())
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
