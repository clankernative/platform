//! Actual finite App response ownership. Registry entries are moved, never
//! reconstructed from DATA. The pinned driver keeps lexical native borrows;
//! the registry contains only a negative busy/abort marker while it waits.

#[cfg(test)]
use super::fixtures;
use super::{
    AppStorage, CompletedResponse, Consumer, EnrolledClock, EnrolledClockSource,
    NativeConsumerContext, NativeRequestFinalContext, OWNERS, OriginalPhase, OwnerSource, Owners,
    PendingWriter, Phase, PhaseOriginal, RestoredHostRouting, RuntimeConsumer, Sink, SinkState,
};
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

impl<T> Drop for Registry<T> {
    fn drop(&mut self) {
        self.clear();
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
            if let Some(parent) = &reservation.parent_refusal {
                parent.refuse();
            }
        }
        self.reserved.clear();
        self.available.clear();
    }

    fn refuse_for(&self, identity: &ResponseIdentity) {
        for reservation in self.reserved.values() {
            if reservation.identity.same_http(identity) {
                reservation.refused.set(true);
                if let Some(parent) = &reservation.parent_refusal {
                    parent.refuse();
                }
            }
        }
    }
}

// Internal grouping of the same three negative routing roots, not a native
// owner, proof alias or source of positive authority. It has no methods/getters.
struct AbortRoots(
    Rc<Cell<bool>>,
    Weak<Cell<bool>>,
    Rc<super::RestoredAppRefusal>,
);

/// One request's actual early owner, shared only as executor-local routing.
/// Restored capture moves the existing registry value before native capture;
/// sharing this slot cannot create an owner, request, clock or permission.
#[derive(Clone)]
pub(super) struct RequestOwner {
    source: Rc<RefCell<RequestOwnerSource>>,
    refused: Rc<Cell<bool>>,
    // Direct negative roots remain callable while the slot or native parent
    // is borrowed. They are installed exactly once from the actual lease.
    abort: Rc<std::cell::OnceCell<AbortRoots>>,
}

enum RequestOwnerSource {
    Empty,
    Capturing,
    Initial,
    NonNative,
    #[cfg(test)]
    Model(Option<u64>),
    Restored(Box<Lease<Owners>>),
    Moved,
    Refused,
}

fn require_autonomous_selection(
    kind: NativeRole,
    actual: &AuthorityScope,
    requested: &AuthorityScope,
) -> Result<()> {
    ensure!(
        kind == NativeRole::AppHost && actual == requested,
        "native autonomous selection changed"
    );
    Ok(())
}

/// This fixed autonomous entry cannot use an HTTP routing object as its
/// missing restored supplier. Call before constructing a synthetic Sink.
pub(super) fn require_autonomous_source(scope: &AuthorityScope) -> Result<()> {
    OWNERS.with(|entries| {
        let mut entries = entries.try_borrow_mut()?;
        ensure!(
            !entries.reserved.contains_key(scope.app.as_str()),
            "native request owner busy"
        );
        let owner = entries
            .available
            .get_mut(scope.app.as_str())
            .context("native autonomous owner missing")?;
        require_autonomous_selection(owner.kind, owner.selection.scope(), scope)?;
        match &owner.source {
            OwnerSource::Initial(_) => Ok(()),
            OwnerSource::Restored { .. } => {
                owner.refuse();
                anyhow::bail!("restored autonomous request supplier missing");
            }
        }
    })
}

impl RequestOwner {
    pub(super) fn new() -> Self {
        Self {
            source: Rc::new(RefCell::new(RequestOwnerSource::Empty)),
            refused: Rc::new(Cell::new(false)),
            abort: Rc::new(std::cell::OnceCell::new()),
        }
    }

    pub(super) fn capture_app(&self, sink: &Sink, scope: &AuthorityScope) -> Result<()> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            {
                let mut source = self.source.try_borrow_mut()?;
                ensure!(
                    matches!(*source, RequestOwnerSource::Empty),
                    "native request owner already selected"
                );
                *source = RequestOwnerSource::Capturing;
            }
            let registry = OWNERS.with(Rc::clone);
            let restored = {
                let entries = registry.try_borrow()?;
                ensure!(
                    !entries.reserved.contains_key(scope.app.as_str()),
                    "native request owner busy"
                );
                let owner = entries
                    .available
                    .get(scope.app.as_str())
                    .context("native request App missing")?;
                ensure!(
                    owner.kind == NativeRole::AppHost && owner.selection.scope() == scope,
                    "native request App selection changed"
                );
                match &owner.source {
                    OwnerSource::Initial(_) => false,
                    OwnerSource::Restored { .. } => true,
                }
            };
            if !restored {
                sink.response_tickets.capture_app(scope, &sink.identity)?;
                sink.request.capture_app(scope)?;
                *self.source.try_borrow_mut()? = RequestOwnerSource::Initial;
                return Ok(());
            }
            // No wait, callback or native capture separates exclusion from
            // moving this exact value out of the same registry.
            let mut lease = Lease::acquire(registry, scope.app.as_str(), &sink.identity, None)?;
            let owner = lease
                .owners
                .as_mut()
                .context("native early owner missing")?;
            let OwnerSource::Restored { refusal, .. } = &owner.source else {
                anyhow::bail!("native restored owner changed");
            };
            ensure!(
                self.abort
                    .set(AbortRoots(
                        Rc::clone(&lease.refused),
                        Rc::downgrade(&lease.live),
                        Rc::clone(refusal)
                    ))
                    .is_ok(),
                "native request abort roots already selected"
            );
            sink.response_tickets
                .capture_app_owner(scope, &sink.identity, owner)?;
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                unreachable!("checked restored owner");
            };
            {
                let mut routing = routing.try_borrow_mut()?;
                let runtime = std::sync::Arc::clone(&routing.runtime);
                routing.capture_request(&runtime, sink)?;
            }
            ensure!(
                !self.refused.get() && !lease.refused.get() && sink.is_open(),
                "native request refused during capture"
            );
            *self.source.try_borrow_mut()? = RequestOwnerSource::Restored(Box::new(lease));
            Ok(())
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                    sink.abort();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn capture_non_native(&self, sink: &Sink) -> Result<()> {
        let captured = (|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            ensure!(
                matches!(*source, RequestOwnerSource::Empty),
                "native request owner already selected"
            );
            *source = RequestOwnerSource::Capturing;
            sink.request.capture_non_native()?;
            *source = RequestOwnerSource::NonNative;
            Ok(())
        })();
        if captured.is_err() {
            self.refuse();
            sink.abort();
        }
        captured
    }

    // Test transport classification retains its actual Model original; it
    // cannot supply an enrolled stage or make a native Runtime ordinary.
    #[cfg(test)]
    pub(super) fn capture_model(&self, sink: &Sink) -> Result<()> {
        let same = Rc::ptr_eq(&self.source, &sink.request_owner.source)
            && Rc::ptr_eq(&self.refused, &sink.request_owner.refused)
            && Rc::ptr_eq(&self.abort, &sink.request_owner.abort);
        if !same {
            self.refuse();
            anyhow::bail!("scripted request Sink changed");
        }
        let captured = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused",
            );
            let mut source = self.source.try_borrow_mut()?;
            ensure!(
                matches!(*source, RequestOwnerSource::Empty),
                "native request owner already selected",
            );
            *source = RequestOwnerSource::Capturing;
            let domain = crate::oauth::effects::current_domain();
            if let Some(domain) = domain {
                super::fixtures::require_model_domain(domain)?;
            }
            sink.request.capture_model()?;
            ensure!(
                domain == crate::oauth::effects::current_domain(),
                "scripted request domain changed",
            );
            if let Some(domain) = domain {
                super::fixtures::require_model_domain(domain)?;
            }
            *source = RequestOwnerSource::Model(domain);
            Ok(())
        }));
        match captured {
            Ok(captured) => {
                if captured.is_err() {
                    self.refuse();
                    sink.abort();
                }
                captured
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// Source selection DATA only; the accepting method below revalidates the
    /// same lease, Runtime, capture and actual native selection itself.
    pub(super) fn uses_restored(&self) -> Result<bool> {
        ensure!(!self.refused.get(), "native request owner refused");
        match &*self.source.try_borrow()? {
            RequestOwnerSource::Empty
            | RequestOwnerSource::Initial
            | RequestOwnerSource::NonNative => Ok(false),
            #[cfg(test)]
            RequestOwnerSource::Model(_) => Ok(false),
            RequestOwnerSource::Restored(_) => Ok(true),
            _ => anyhow::bail!("native request owner unavailable"),
        }
    }

    /// Capture only on the actual already-leased App. No registry lookup,
    /// synthetic human origin or Shell/Runtime conversion is possible here.
    pub(super) fn capture_human_clock(&self, sink: &Sink, app: &str) -> Result<EnrolledClock> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native restored human owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity),
                "native early human lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native early human owner missing")?;
            ensure!(
                owner.kind == NativeRole::AppHost && owner.selection.scope().app.as_str() == app,
                "native human App changed"
            );
            ensure!(owner.originals.len() < 1024, "native original capacity");
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native human parent changed");
            };
            let clock = {
                let mut actual = routing.try_borrow_mut()?;
                let runtime = std::sync::Arc::clone(&actual.runtime);
                let scope = actual.require_runtime(&runtime)?;
                ensure!(
                    owner.selection.scope() == &scope,
                    "native human full selection changed"
                );
                // Selection precedes debt; debt precedes every human capture.
                owner.response_rights.mark_unfenced()?;
                actual.capture_human_clock(&runtime, sink)?
            };
            Ok(EnrolledClock {
                clock,
                source: EnrolledClockSource::Restored(routing.clone()),
                selection: owner.selection.clone(),
                kind: NativeRole::AppHost,
            })
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                    sink.abort();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn sample_human_clock(
        &self,
        sink: &Sink,
        expected: &Role<RestoredHostRouting>,
        selection: &super::NativeSelection,
        clock: &mut crate::security_epoch::native_enrollment::EnrolledOriginalClock,
    ) -> Result<std::time::Duration> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native restored human owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity),
                "native early human lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native early human owner missing")?;
            ensure!(
                owner.kind == NativeRole::AppHost && &owner.selection == selection,
                "native human full selection changed"
            );
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native human parent changed");
            };
            ensure!(
                Rc::ptr_eq(&routing.slot, &expected.slot),
                "native human clock parent changed"
            );
            let mut actual = routing.try_borrow_mut()?;
            let runtime = std::sync::Arc::clone(&actual.runtime);
            actual.require_runtime(&runtime)?;
            actual.sample_human_clock(&runtime, sink, clock)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                    sink.abort();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn with_pending<T>(
        &self,
        sink: &Sink,
        app: &str,
        original: &mut super::Original<EnrolledClock>,
        operation: impl FnOnce(&mut PendingWriter<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native restored Pending owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity),
                "native Pending lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native Pending owner missing")?;
            let selection = owner.selection.clone();
            ensure!(
                owner.kind == NativeRole::AppHost
                    && selection.scope().app.as_str() == app
                    && original.clock.selection == selection,
                "native Pending full selection changed"
            );
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native Pending parent changed");
            };
            let EnrolledClockSource::Restored(expected) = &original.clock.source else {
                anyhow::bail!("native Pending clock source changed");
            };
            ensure!(
                Rc::ptr_eq(&routing.slot, &expected.slot),
                "native Pending clock parent changed"
            );
            let mut actual = routing.try_borrow_mut()?;
            let runtime = std::sync::Arc::clone(&actual.runtime);
            let scope = actual.require_runtime(&runtime)?;
            let context = NativeConsumerContext::captured(
                &runtime,
                original,
                sink,
                sink.request.consumer_origin(&scope, NativeRole::AppHost)?,
            )?;
            sink.request
                .with_restored_current(&scope, &mut actual.parent, context, |current| {
                    current.require_app_selection(&runtime, &selection.policy, &selection.store)?;
                    PendingWriter::from_restored(&runtime, current)?.run(operation)
                })
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                    sink.abort();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn bind_human(
        &self,
        sink: &Sink,
        intent: &FreshIntent,
        original: super::Original<EnrolledClock>,
    ) -> Result<()> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native restored binding owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity),
                "native human binding lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native binding owner missing")?;
            ensure!(
                owner.kind == NativeRole::AppHost
                    && owner.selection.scope().app.as_str() == intent.app()
                    && owner.selection == original.clock.selection,
                "native human binding selection changed"
            );
            ensure!(
                !owner.originals.contains_key(intent.attempt()) && owner.originals.len() < 1024,
                "native App original cannot be replaced"
            );
            let OwnerSource::Restored { routing, .. } = &owner.source else {
                anyhow::bail!("native binding parent changed");
            };
            let EnrolledClockSource::Restored(expected) = &original.clock.source else {
                anyhow::bail!("native binding clock source changed");
            };
            ensure!(
                Rc::ptr_eq(&routing.slot, &expected.slot),
                "native binding clock parent changed"
            );
            let mut stored = super::StoredOriginal::new(original, intent);
            super::enlist(NativeRole::AppHost, intent, &mut stored.response, None)?;
            owner.originals.insert(intent.attempt().into(), stored);
            Ok(())
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                    sink.abort();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn with_human_consumer<T>(
        &self,
        sink: &Sink,
        intent: &FreshIntent,
        phase: super::Phase,
        wall: i64,
        guard: &super::ConsumerGuard,
        operation: impl FnOnce(&mut Consumer<'_, '_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut setup = HumanSetup {
                owner: self,
                sink,
                delegated: false,
            };
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native restored human owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity),
                "native human lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native human owner missing")?;
            let selection = owner.selection.clone();
            ensure!(
                owner.kind == NativeRole::AppHost && selection.scope().app.as_str() == intent.app(),
                "native human selection changed"
            );
            let stored = owner
                .originals
                .get_mut(intent.attempt())
                .context("native original absent; rows cannot restore it")?;
            super::validate_enlist(NativeRole::AppHost, intent, &stored.response)?;
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native human parent changed");
            };
            let EnrolledClockSource::Restored(expected) = &stored.original.clock.source else {
                anyhow::bail!("native human clock source changed");
            };
            ensure!(
                Rc::ptr_eq(&routing.slot, &expected.slot)
                    && stored.original.clock.selection == selection,
                "native human clock parent changed"
            );
            let mut actual = routing.try_borrow_mut()?;
            let runtime = std::sync::Arc::clone(&actual.runtime);
            let scope = actual.require_runtime(&runtime)?;
            let mut original = OriginalPhase {
                original: super::PhaseOriginal::Native(&mut stored.original),
                intent,
                wall,
                phase,
            };
            let context = NativeConsumerContext::human(
                &runtime,
                &mut original,
                sink,
                sink.request.consumer_origin(&scope, NativeRole::AppHost)?,
            )?;
            // The real context/Current/Request own refusal and independent
            // posts. Preserve an actually checked, unarmed known exclusion;
            // a callback Err alone is not unknown native completion.
            setup.delegated = true;
            sink.request
                .with_restored_current(&scope, &mut actual.parent, context, |current| {
                    current.require_app_selection(&runtime, &selection.policy, &selection.store)?;
                    super::enlist(NativeRole::AppHost, intent, &mut stored.response, None)?;
                    Consumer::from_restored(&runtime, current, intent, phase, guard)?.run(operation)
                })
        }));
        match result {
            Ok(result) => result,
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn with_runtime_consumer<T>(
        &self,
        sink: &Sink,
        runtime: &crate::store::Runtime,
        phase: super::RuntimePhase,
        operation: impl FnOnce(&mut RuntimeConsumer<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native restored HTTP owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity),
                "native early lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native early owner missing")?;
            let selection = owner.selection.clone();
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native restored owner changed");
            };
            let mut routing = routing.try_borrow_mut()?;
            let scope = routing.require_runtime(runtime)?;
            ensure!(
                owner.kind == NativeRole::AppHost && selection.scope() == &scope,
                "native restored owner selection changed"
            );
            let context = NativeConsumerContext::runtime_http(
                runtime,
                phase,
                sink,
                sink.request.consumer_origin(&scope, NativeRole::AppHost)?,
            )?;
            sink.request
                .with_restored_current(&scope, &mut routing.parent, context, |current| {
                    current.require_app_selection(runtime, &selection.policy, &selection.store)?;
                    RuntimeConsumer::from_restored(runtime, phase, current)?.run(operation)
                })
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                    sink.abort();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn response_scope(
        &self,
        sink: &Sink,
        runtime: &crate::store::Runtime,
    ) -> Result<Option<AuthorityScope>> {
        let result = (|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let restored = {
                let source = self.source.try_borrow()?;
                match &*source {
                    RequestOwnerSource::Restored(_) => true,
                    RequestOwnerSource::Initial => {
                        ensure!(
                            runtime.uses_native_storage(),
                            "native captured Runtime cannot become ordinary"
                        );
                        false
                    }
                    RequestOwnerSource::NonNative => {
                        ensure!(
                            !runtime.uses_native_storage(),
                            "ordinary capture cannot become native"
                        );
                        return Ok(None);
                    }
                    #[cfg(test)]
                    RequestOwnerSource::Model(domain) => {
                        let domain = domain.context("scripted response fixture missing")?;
                        super::fixtures::require_model_domain(domain)?;
                        ensure!(
                            Some(domain) == crate::oauth::effects::current_domain()
                                && !runtime.uses_native_storage(),
                            "scripted response profile changed"
                        );
                        return Ok(None);
                    }
                    _ => anyhow::bail!("native response capture unavailable"),
                }
            };
            if restored {
                return self.runtime_scope(sink, runtime).map(Some);
            }
            super::runtime_response_scope(runtime)
        })();
        if result.is_err() {
            self.refuse();
            sink.abort();
        }
        result
    }

    /// Immutable response selection DATA on the same captured owner. The
    /// exact Runtime allocation is checked before returning even this DATA.
    /// No stage, native permission, storage handle or new owner is exposed.
    pub(super) fn runtime_scope(
        &self,
        sink: &Sink,
        runtime: &crate::store::Runtime,
    ) -> Result<AuthorityScope> {
        let result = (|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native restored response owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity),
                "native early lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native early owner missing")?;
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native restored owner changed");
            };
            let scope = routing.try_borrow_mut()?.require_runtime(runtime)?;
            ensure!(
                owner.kind == NativeRole::AppHost && owner.selection.scope() == &scope,
                "native restored response selection changed"
            );
            Ok(scope)
        })();
        if result.is_err() {
            self.refuse();
            sink.abort();
        }
        result
    }

    /// Classification only. This borrows the already moved actual owner;
    /// native selection and all Runtime/current checks remain mandatory in
    /// every accepting consumer and transport scope.
    pub(super) fn prepare_runtime(&self, sink: &Sink, scope: &AuthorityScope) -> Result<bool> {
        ensure!(
            !self.refused.get() && sink.is_open(),
            "native request owner refused"
        );
        let source = self.source.try_borrow()?;
        match &*source {
            RequestOwnerSource::Initial => Ok(false),
            RequestOwnerSource::Restored(lease) => {
                ensure!(
                    !lease.refused.get()
                        && lease.live.get()
                        && lease.identity.same_http(&sink.identity),
                    "native early lease changed"
                );
                let owner = lease
                    .owners
                    .as_ref()
                    .context("native early owner missing")?;
                ensure!(
                    owner.kind == NativeRole::AppHost
                        && owner.selection.scope() == scope
                        && matches!(&owner.source, OwnerSource::Restored { .. }),
                    "native early owner selection changed"
                );
                Ok(true)
            }
            _ => anyhow::bail!("native request owner unavailable"),
        }
    }

    /// Stage-free response classification against the same already captured
    /// human original. True is DATA only: the real restored response driver
    /// still acquires/checks its Current before any disclosure and settles the
    /// actual request after transport. Only captured Initial may use its
    /// existing registry participant; every other unavailable source refuses.
    fn prepare_finite_human(&self, sink: &Sink, intent: &FreshIntent) -> Result<bool> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ensure!(!self.refused.get() && sink.is_open(), "native request owner refused");
            let source = self.source.try_borrow()?;
            match &*source {
                RequestOwnerSource::Initial => Ok(false),
                RequestOwnerSource::Restored(lease) => {
                    require_finite_http_lease(lease, intent.app(), &sink.identity)?;
                    let owner = lease.owners.as_ref().context("native finite owner missing")?;
                    ensure!(
                        owner.kind == NativeRole::AppHost
                            && owner.selection.scope().app.as_str() == intent.app(),
                        "native finite owner selection changed"
                    );
                    let stored = owner.originals.get(intent.attempt())
                        .context("native finite original missing")?;
                    stored.response.require_bound(intent, &sink.identity)?;
                    let OwnerSource::Restored { routing, .. } = &owner.source else {
                        anyhow::bail!("native finite parent changed");
                    };
                    let EnrolledClockSource::Restored(expected) = &stored.original.clock.source else {
                        anyhow::bail!("native finite clock source changed");
                    };
                    ensure!(
                        owner.selection == stored.original.clock.selection
                            && Rc::ptr_eq(&routing.slot, &expected.slot),
                        "native finite clock parent changed"
                    );
                    sink.request.consumer_origin(owner.selection.scope(), NativeRole::AppHost)?
                        .require_request(&sink.request)?;
                    Ok(true)
                }
                _ => anyhow::bail!("native finite request owner unavailable"),
            }
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                    sink.abort();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        }
    }

    /// The same early lease is transferred once, never resolved again from
    /// app DATA. Busy/failed/moved sources cannot fall back to initial owners.
    fn take_response(
        &self,
        sink: &Sink,
        app: &str,
        intent: Option<&FreshIntent>,
        scope: Option<&AuthorityScope>,
    ) -> Result<Lease<Owners>> {
        let result = (|| {
            ensure!(
                !self.refused.get() && sink.is_open(),
                "native request owner refused"
            );
            let mut source = self.source.try_borrow_mut()?;
            let RequestOwnerSource::Restored(lease) = &mut *source else {
                anyhow::bail!("native captured response owner unavailable");
            };
            ensure!(
                !lease.refused.get()
                    && lease.live.get()
                    && lease.identity.same_http(&sink.identity)
                    && lease.key == app,
                "native early response lease changed"
            );
            let owners = lease
                .owners
                .as_ref()
                .context("native early owner missing")?;
            ensure!(
                owners.kind == NativeRole::AppHost
                    && matches!(&owners.source, OwnerSource::Restored { .. }),
                "native early response role changed"
            );
            if let Some(scope) = scope {
                ensure!(
                    owners.selection.scope() == scope,
                    "native response scope changed"
                );
            }
            if let Some(intent) = intent {
                owners
                    .originals
                    .get(intent.attempt())
                    .context("native response original missing")?
                    .response
                    .require_bound(intent, &sink.identity)?;
            }
            lease.attempt = intent.map(|intent| intent.attempt().to_owned());
            let RequestOwnerSource::Restored(lease) =
                std::mem::replace(&mut *source, RequestOwnerSource::Moved)
            else {
                unreachable!("checked actual early lease");
            };
            Ok(*lease)
        })();
        if result.is_err() {
            self.refuse();
            sink.abort();
        }
        result
    }

    pub(super) fn refuse(&self) {
        self.refused.set(true);
        if let Some(AbortRoots(lease, live, parent)) = self.abort.get() {
            lease.set(true);
            // A completed/retired lease may have returned the same whole
            // parent for another request. Old Sinks cannot burn that owner.
            if live.upgrade().is_some_and(|live| live.get()) {
                parent.refuse();
            }
        }
        // Immediate refusal above must not depend on reacquiring this slot.
        // Releasing the actual lease is cleanup, never positive settlement.
        if let Ok(mut source) = self.source.try_borrow_mut() {
            *source = RequestOwnerSource::Refused;
        }
    }
}

/// Negative-only setup cleanup. A successful native delegation takes over
/// disposal; this flag cannot supply a Current, original or settlement.
struct HumanSetup<'a> {
    owner: &'a RequestOwner,
    sink: &'a Sink,
    delegated: bool,
}

impl Drop for HumanSetup<'_> {
    fn drop(&mut self) {
        if !self.delegated {
            self.owner.refuse();
            self.sink.abort();
        }
    }
}

/// One genuine autonomous operation. Its nominal identity is not HTTP DATA,
/// and locator clones cannot outlive the actual attempt as authority.
pub(super) struct RuntimeRequest {
    identity: Rc<()>,
    runtime: std::sync::Arc<crate::store::Runtime>,
    scope: AuthorityScope,
    request: super::request::Request,
    lease: RefCell<Option<Lease<Owners>>>,
    abort: std::cell::OnceCell<AbortRoots>,
    refused: Cell<bool>,
    complete: Cell<bool>,
}

impl RuntimeRequest {
    fn capture(runtime: &crate::store::Runtime) -> Result<Rc<Self>> {
        super::require_new_runtime_frame()?;
        let registry = OWNERS.with(Rc::clone);
        let actual = {
            let mut entries = registry.try_borrow_mut()?;
            ensure!(
                !entries.reserved.contains_key(runtime.app()),
                "native operation owner busy"
            );
            let owner = entries
                .available
                .get_mut(runtime.app())
                .context("native autonomous owner missing")?;
            let scope = super::sql_runtime_scope(runtime)?;
            require_autonomous_selection(owner.kind, owner.selection.scope(), &scope)?;
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native restored autonomous source missing");
            };
            let routing = routing.try_borrow_mut()?;
            // Reject foreign input before owning/moving this parent. This is
            // pure object identity, not the refusing native routing operation.
            ensure!(
                std::ptr::eq(std::sync::Arc::as_ptr(&routing.runtime), runtime),
                "native autonomous Runtime changed"
            );
            std::sync::Arc::clone(&routing.runtime)
        };
        let frame = Rc::new(Self {
            identity: Rc::new(()),
            scope: super::sql_runtime_scope(runtime)?,
            runtime: actual,
            request: super::request::Request::new(),
            lease: RefCell::new(None),
            abort: std::cell::OnceCell::new(),
            refused: Cell::new(false),
            complete: Cell::new(false),
        });
        let mut lease = Lease::acquire_runtime(registry, runtime.app(), &frame.identity)?;
        ensure!(
            lease.identity.same_runtime(&frame.identity),
            "native Runtime frame identity changed"
        );
        let owner = lease
            .owners
            .as_mut()
            .context("native autonomous owner missing")?;
        let parent = owner
            .retained_parent_refusal()
            .context("native restored refusal missing")?;
        ensure!(
            frame
                .abort
                .set(AbortRoots(
                    Rc::clone(&lease.refused),
                    Rc::downgrade(&lease.live),
                    parent
                ))
                .is_ok(),
            "native Runtime roots already selected"
        );
        let OwnerSource::Restored { routing, .. } = &mut owner.source else {
            anyhow::bail!("native restored autonomous source changed");
        };
        {
            let mut routing = routing.try_borrow_mut()?;
            routing.require_runtime(runtime)?;
            frame
                .request
                .capture_restored_app(&frame.scope, &mut routing.parent)?;
        }
        *frame.lease.try_borrow_mut()? = Some(lease);
        Ok(frame)
    }

    pub(super) fn require_runtime(&self, runtime: &crate::store::Runtime) -> Result<()> {
        let selected = !self.refused.get()
            && !self.complete.get()
            && std::ptr::eq(std::sync::Arc::as_ptr(&self.runtime), runtime)
            && runtime.uses_native_storage()
            && self
                .abort
                .get()
                .is_some_and(|AbortRoots(refused, live, _)| {
                    !refused.get() && live.upgrade().is_some_and(|live| live.get())
                });
        if !selected {
            self.refuse();
            anyhow::bail!("native Runtime frame changed or closed");
        }
        Ok(())
    }

    pub(super) fn require_scope(&self, scope: &AuthorityScope) -> Result<()> {
        self.require_runtime(&self.runtime)?;
        if &self.scope != scope {
            self.refuse();
            anyhow::bail!("native Runtime frame scope changed");
        }
        Ok(())
    }

    pub(super) fn require_origin(
        &self,
        native: &super::request::ConsumerRequestOrigin,
    ) -> Result<()> {
        self.require_runtime(&self.runtime)?;
        if !native.same_request(&self.request) {
            self.refuse();
            anyhow::bail!("native Runtime request original changed");
        }
        Ok(())
    }

    pub(super) fn consumer_origin(
        &self,
        runtime: &crate::store::Runtime,
    ) -> Result<super::request::ConsumerRequestOrigin> {
        self.require_runtime(runtime)?;
        self.request
            .consumer_origin(&self.scope, NativeRole::AppHost)
    }

    pub(super) fn refuse(&self) {
        self.refused.set(true);
        if let Some(AbortRoots(refused, live, parent)) = self.abort.get() {
            refused.set(true);
            if live.upgrade().is_some_and(|live| live.get()) {
                parent.refuse();
            }
        }
        self.request.refuse();
        if let Ok(mut lease) = self.lease.try_borrow_mut() {
            drop(lease.take());
        }
    }

    pub(super) fn run<T>(
        runtime: &crate::store::Runtime,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let frame = Self::capture(runtime)?;
        Self::run_captured(frame, operation)
    }

    fn run_captured<T>(frame: Rc<Self>, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let value = super::with_runtime_frame(Rc::clone(&frame), operation)?;
            frame.finish()?;
            Ok(value)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    frame.refuse();
                }
                result
            }
            Err(payload) => {
                frame.refuse();
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(super) fn with_consumer<T>(
        &self,
        runtime: &crate::store::Runtime,
        phase: super::RuntimePhase,
        operation: impl FnOnce(&mut RuntimeConsumer<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.require_runtime(runtime)?;
            let mut held = self.lease.try_borrow_mut()?;
            let lease = held.as_mut().context("native Runtime owner consumed")?;
            ensure!(
                lease.identity.same_runtime(&self.identity),
                "native Runtime lease changed"
            );
            let owner = lease
                .owners
                .as_mut()
                .context("native Runtime owner missing")?;
            let selection = owner.selection.clone();
            let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                anyhow::bail!("native Runtime source changed");
            };
            let mut routing = routing.try_borrow_mut()?;
            routing.require_runtime(runtime)?;
            let context = NativeConsumerContext::runtime_operation(runtime, phase, self)?;
            self.request.with_restored_current(
                &self.scope,
                &mut routing.parent,
                context,
                |current| {
                    current.require_app_selection(runtime, &selection.policy, &selection.store)?;
                    RuntimeConsumer::from_restored(runtime, phase, current)?.run(operation)
                },
            )
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                }
                result
            }
            Err(payload) => {
                self.refuse();
                std::panic::resume_unwind(payload)
            }
        }
    }

    fn finish(&self) -> Result<()> {
        self.require_runtime(&self.runtime)?;
        let mut lease = self
            .lease
            .try_borrow_mut()?
            .take()
            .context("native Runtime owner consumed")?;
        ensure!(
            lease.identity.same_runtime(&self.identity),
            "native Runtime lease changed"
        );
        let owner = lease
            .owners
            .as_mut()
            .context("native Runtime owner missing")?;
        let OwnerSource::Restored { routing, .. } = &mut owner.source else {
            anyhow::bail!("native Runtime source changed");
        };
        {
            let mut routing = routing.try_borrow_mut()?;
            routing.require_runtime(&self.runtime)?;
            let request = self.request.take(&self.scope, NativeRole::AppHost)?;
            let context =
                NativeRequestFinalContext::runtime_operation(&self.runtime, self, &request)?;
            request.finish_restored(&mut routing.parent, context)?;
        }
        let refused = Rc::clone(&lease.refused);
        lease.known = true;
        drop(lease);
        ensure!(!refused.get(), "native Runtime owner return unknown");
        self.complete.set(true);
        Ok(())
    }
}

impl Drop for RuntimeRequest {
    fn drop(&mut self) {
        if !self.complete.get() {
            self.refuse();
        }
    }
}

impl<T: LeaseMaterial> Registry<T> {
    pub(super) fn retire_parent(&mut self, key: &str, parent: &Rc<super::RestoredAppRefusal>) {
        let same = self
            .available
            .get(key)
            .and_then(LeaseMaterial::retained_parent_refusal)
            .is_some_and(|actual| Rc::ptr_eq(&actual, parent));
        if same {
            self.available.remove(key);
        }
        if let Some(reservation) = self.reserved.get(key)
            && reservation
                .parent_refusal
                .as_ref()
                .is_some_and(|actual| Rc::ptr_eq(actual, parent))
        {
            reservation.refused.set(true);
            parent.refuse();
        }
        // Unknown live reservations remain present until their actual lease
        // drops. Cleanup never frees capacity or manufactures known completion.
    }
}

/// Nominal identity of the one shared lease core. Runtime work cannot mint
/// an HTTP response identity or a response completion witness.
#[derive(Clone)]
enum LeaseIdentity {
    Http(ResponseIdentity),
    Runtime(Rc<()>),
}

impl LeaseIdentity {
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Http(left), Self::Http(right)) => left.same(right),
            (Self::Runtime(left), Self::Runtime(right)) => Rc::ptr_eq(left, right),
            _ => false,
        }
    }

    fn same_http(&self, other: &ResponseIdentity) -> bool {
        matches!(self, Self::Http(actual) if actual.same(other))
    }

    fn same_runtime(&self, other: &Rc<()>) -> bool {
        matches!(self, Self::Runtime(actual) if Rc::ptr_eq(actual, other))
    }

    fn http(&self) -> Result<&ResponseIdentity> {
        match self {
            Self::Http(identity) => Ok(identity),
            Self::Runtime(_) => anyhow::bail!("runtime lease cannot become an HTTP response"),
        }
    }
}

struct Reservation {
    identity: LeaseIdentity,
    refused: Rc<Cell<bool>>,
    parent_refusal: Option<Rc<super::RestoredAppRefusal>>,
}

mod sealed {
    pub trait Material {}
}

pub(super) trait LeaseMaterial: sealed::Material {
    fn retained_parent_refusal(&self) -> Option<Rc<super::RestoredAppRefusal>>;
    fn refuse_lease(&mut self, attempt: Option<&str>);
}

impl sealed::Material for Owners {}
impl LeaseMaterial for Owners {
    fn retained_parent_refusal(&self) -> Option<Rc<super::RestoredAppRefusal>> {
        match &self.source {
            OwnerSource::Initial(_) => None,
            OwnerSource::Restored { refusal, .. } => Some(Rc::clone(refusal)),
        }
    }

    fn refuse_lease(&mut self, attempt: Option<&str>) {
        self.refuse();
        if let Some(stored) = attempt.and_then(|attempt| self.originals.get_mut(attempt)) {
            stored.original.refuse();
        }
    }
}

struct Lease<T: LeaseMaterial> {
    registry: Rc<RefCell<Registry<T>>>,
    key: String,
    identity: LeaseIdentity,
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
        ($type:ty, $bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <$type as Ambiguous<_>>::check;
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
    assert_not_impl!(RuntimeRequest, Clone);
    assert_not_impl!(RuntimeRequest, Copy);
    assert_not_impl!(RuntimeRequest, Default);
    assert_not_impl!(RuntimeRequest, std::fmt::Debug);
    assert_not_impl!(RuntimeRequest, Send);
    assert_not_impl!(RuntimeRequest, Sync);
    assert_not_impl!(RuntimeRequest, serde::Serialize);
    assert_not_impl!(RuntimeRequest, serde::Deserialize<'static>);
    assert_not_impl!(HumanSetup<'static>, Clone);
    assert_not_impl!(HumanSetup<'static>, Copy);
    assert_not_impl!(HumanSetup<'static>, Default);
    assert_not_impl!(HumanSetup<'static>, Send);
    assert_not_impl!(HumanSetup<'static>, Sync);
    assert_not_impl!(HumanSetup<'static>, serde::Serialize);
    assert_not_impl!(HumanSetup<'static>, serde::Deserialize<'static>);
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
    if sink.request_owner.prepare_finite_human(sink, &binding.intent)? {
        return Ok(());
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
        let OwnerSource::Initial(initial) = &mut owners.source else {
            anyhow::bail!("restored response requires its actual early owner lease");
        };
        let AppStorage::Participant(participant) = &mut initial.storage else {
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

// Pure checks of the actual retained lease, also exercised with inert DATA
// by portable tests. This never returns material, a stage or a native owner.
fn require_finite_http_lease<T: LeaseMaterial>(
    lease: &Lease<T>,
    app: &str,
    identity: &ResponseIdentity,
) -> Result<()> {
    ensure!(
        !lease.known && !lease.refused.get() && lease.live.get()
            && lease.key == app && lease.identity.same_http(identity)
            && lease.owners.is_some(),
        "native finite response lease changed"
    );
    Ok(())
}

impl<T: LeaseMaterial> Lease<T> {
    fn acquire(
        registry: Rc<RefCell<Registry<T>>>,
        key: &str,
        identity: &ResponseIdentity,
        attempt: Option<&str>,
    ) -> Result<Self> {
        Self::acquire_same(
            registry,
            key,
            &LeaseIdentity::Http(identity.clone()),
            attempt,
        )
    }

    fn acquire_runtime(
        registry: Rc<RefCell<Registry<T>>>,
        key: &str,
        frame: &Rc<()>,
    ) -> Result<Self> {
        Self::acquire_same(
            registry,
            key,
            &LeaseIdentity::Runtime(Rc::clone(frame)),
            None,
        )
    }

    fn acquire_same(
        registry: Rc<RefCell<Registry<T>>>,
        key: &str,
        identity: &LeaseIdentity,
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
            let parent_refusal = entries
                .available
                .get(key)
                .context("native response owner absent")?
                .retained_parent_refusal();
            entries.reserved.insert(
                lease.key.clone(),
                Reservation {
                    identity: identity.clone(),
                    refused: lease.refused.clone(),
                    parent_refusal,
                },
            );
            lease.owners = entries.available.remove(key);
        }
        Ok(lease)
    }
}

impl Lease<Owners> {
    pub(super) fn consumer_origin(&self) -> Result<ConsumerLeaseOrigin> {
        ensure!(
            self.owners.is_some() && !self.known && !self.refused.get() && self.live.get(),
            "native response lease unavailable"
        );
        let owners = self
            .owners
            .as_ref()
            .context("native response lease owner missing")?;
        let identity = match self.identity.http() {
            Ok(identity) => identity,
            Err(error) => {
                self.refused.set(true);
                if let Some(parent) = owners.retained_parent_refusal() {
                    parent.refuse();
                }
                return Err(error);
            }
        };
        let consumer = match &self.attempt {
            Some(attempt) => {
                let original = owners
                    .originals
                    .get(attempt)
                    .context("native response lease original missing")?;
                original
                    .response
                    .require_bound(&original.response.intent, identity)?;
                LeaseConsumer::Human(original.response.intent.commitment()?)
            }
            None => LeaseConsumer::Runtime,
        };
        Ok(ConsumerLeaseOrigin {
            identity: identity.clone(),
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
            let OwnerSource::Initial(initial) = &mut owner.source else {
                anyhow::bail!("restored response cannot acquire a later replacement lease");
            };
            let AppStorage::Participant(participant) = &mut initial.storage else {
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
            self.refused.set(true);
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

impl CompletedResponse {
    pub(super) fn require_lease(&self, sink: &Sink, lease: &ConsumerLeaseOrigin) -> Result<()> {
        if !Rc::ptr_eq(&self.refused, &lease.refused) {
            self.refused.set(true);
            anyhow::bail!("native completed response lease changed");
        }
        ensure!(
            !self.published && !self.refused.get(),
            "native completed response refused"
        );
        lease.check(sink)
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
    ) -> Result<CompletedResponse> {
        ensure!(
            request.1 != Operation::Complete,
            "native response completed before first I/O"
        );
        self.check()?;
        self.arm()?;
        loop {
            if request.1 == Operation::Complete {
                self.complete()?;
                break Ok(CompletedResponse {
                    sequence: request.0,
                    refused: self.refused.clone(),
                    published: false,
                });
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

/// One native response unit on the already captured request. The shared
/// ResponseBorrow loop is the only transport engine/CompletedResponse factory.
async fn drive_restored_unit<'request, 'original, T: hyper::rt::Write + Unpin>(
    request: &mut super::request::Lease,
    routing: &mut RestoredHostRouting,
    context: NativeConsumerContext<'request, 'original>,
    runtime: &crate::store::Runtime,
    transport: &mut Transport<T>,
    first: (u64, Operation),
    refused: Rc<Cell<bool>>,
) -> Result<CompletedResponse> {
    routing.require_runtime(runtime)?;
    let selection = routing.selection.clone();
    let mut current = request.begin_restored_current(&mut routing.parent, context)?;
    let requested = async {
        current.require_app_selection(runtime, &selection.policy, &selection.store)?;
        transport.scope_entered();
        let mut response = ResponseBorrow::from_restored(&mut current, runtime, refused)?;
        response.drive(transport, first).await
    }
    .await;
    // Native ACK/release/counter/original posts are evaluated even after the
    // transport returned an error; the first real error remains primary.
    let finished = current.finish();
    let completed = requested?;
    finished?;
    Ok(completed)
}

impl Sink {
    async fn drive_restored_response<T: hyper::rt::Write + Unpin>(
        &self,
        mut transport: Transport<T>,
        first: (u64, Operation),
        intent: Option<FreshIntent>,
        effects: crate::managed_credentials::effects::Captured,
        mut lease: Lease<Owners>,
    ) -> Result<()> {
        effects
            .run_async(async {
                let scope_origin = lease.consumer_origin()?;
                let final_origin = lease.consumer_origin()?;
                let refused = Rc::clone(&lease.refused);
                let owners = lease
                    .owners
                    .as_mut()
                    .context("native early response owner missing")?;
                let scope = owners.selection.scope().clone();
                let OwnerSource::Restored { routing, .. } = &mut owners.source else {
                    anyhow::bail!("native restored response cannot select initial owner");
                };
                let mut held = routing.take()?;
                let routing = held.owner();
                let runtime = std::sync::Arc::clone(&routing.runtime);
                routing.require_runtime(&runtime)?;
                ensure!(
                    owners.kind == NativeRole::AppHost && routing.selection == owners.selection,
                    "native restored response selection changed"
                );
                let mut request = self.request.take(&scope, NativeRole::AppHost)?;
                let (mut original, response_binding) = match &intent {
                    Some(intent) => {
                        let stored = owners
                            .originals
                            .get_mut(intent.attempt())
                            .context("native response original absent")?;
                        (
                            Some(OriginalPhase {
                                original: PhaseOriginal::Native(&mut stored.original),
                                intent,
                                wall: super::super::effects::wall_time()?,
                                phase: Phase::Response,
                            }),
                            Some(&mut stored.response),
                        )
                    }
                    None => (None, None),
                };
                let result = async {
                    transport.scope_attempt();
                    if let Some(original) = &mut original {
                        let context = NativeConsumerContext::human_response(
                            &runtime,
                            original,
                            self,
                            request.consumer_origin()?,
                            scope_origin,
                        )?;
                        drive_restored_unit(
                            &mut request,
                            routing,
                            context,
                            &runtime,
                            &mut transport,
                            first,
                            refused,
                        )
                        .await
                    } else {
                        let context = NativeConsumerContext::runtime_response(
                            &runtime,
                            self,
                            request.consumer_origin()?,
                            scope_origin,
                        )?;
                        drive_restored_unit(
                            &mut request,
                            routing,
                            context,
                            &runtime,
                            &mut transport,
                            first,
                            refused,
                        )
                        .await
                    }
                }
                .await;
                let mut completed = result?;
                ensure!(
                    self.is_open() && !lease.refused.get(),
                    "native response finalization aborted"
                );
                let terminal = self
                    .response_tickets
                    .prepare_native(&self.identity, &owners.response_rights)?;
                if let Some(binding) = response_binding {
                    binding.connection = None;
                }
                if let Some(original) = &mut original {
                    let context = NativeRequestFinalContext::human_response(
                        &runtime,
                        original,
                        self,
                        &request,
                        final_origin,
                        &completed,
                    )?;
                    request.finish_restored(&mut routing.parent, context)?;
                } else {
                    let context = NativeRequestFinalContext::runtime_response(
                        &runtime,
                        self,
                        &request,
                        final_origin,
                        &completed,
                    )?;
                    request.finish_restored(&mut routing.parent, context)?;
                }
                // Actual native request settlement precedes publication. No await or
                // fallible work follows these known/disposition transitions.
                transport.complete(completed.sequence)?;
                held.known = true;
                lease.known = true;
                self.state.set(SinkState::Complete);
                terminal.complete();
                completed.published = true;
                Ok(())
            })
            .await
    }

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
        if self.request_owner.uses_restored()? {
            let lease =
                self.request_owner
                    .take_response(self, app, intent.as_ref(), scope.as_ref())?;
            return self
                .drive_restored_response(transport, first, intent, effects, lease)
                .await;
        }
        let mut lease = Lease::take(self, app, intent.as_ref(), scope.as_ref())?;
        let refused = lease.refused.clone();
        let owners = lease.owners.as_mut().expect("actual leased owner");
        let scope = owners.selection.scope().clone();
        let policy = owners.selection.policy.clone();
        let store = owners.selection.store.clone();
        let OwnerSource::Initial(initial) = &mut owners.source else {
            owners.refuse();
            anyhow::bail!("restored response must move its same early owner lease");
        };
        let mut role = initial.role.take()?;
        let mut request_owner = self.request.take(&scope, NativeRole::AppHost)?;
        let result = effects
            .run_async(async {
                let role = role.owner();
                let AppStorage::Participant(participant) = &mut initial.storage else {
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
        let mut sequence = result?;
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
        transport.complete(sequence.sequence)?;
        role.known = true;
        lease.known = true;
        self.state.set(SinkState::Complete);
        terminal.complete();
        sequence.published = true;
        Ok(())
    }
}

/// Negative lease-view DATA for closed factory refusal tests only. No native
/// role, original, request capture, installed owner or Current is constructed.
#[cfg(test)]
pub(super) fn runtime_lease_for_factory_tests(
    sink: &Sink,
) -> (ConsumerLeaseOrigin, Rc<Cell<bool>>, Rc<Cell<bool>>) {
    let refused = Rc::new(Cell::new(false));
    let live = Rc::new(Cell::new(true));
    let lease = ConsumerLeaseOrigin {
        identity: sink.identity.clone(),
        refused: refused.clone(),
        live: Rc::downgrade(&live),
        consumer: LeaseConsumer::Runtime,
    };
    (lease, refused, live)
}

#[cfg(test)]
mod restored_response_source_tests {
    use super::*;
    use quote::ToTokens;

    #[test]
    fn completed_response_marker_is_bound_to_live_lease_and_unknown_drop_refuses_it() {
        for cut in 0..5 {
            let sink = Sink::new();
            let live = Rc::new(Cell::new(true));
            let refused = Rc::new(Cell::new(false));
            let lease = ConsumerLeaseOrigin {
                identity: sink.identity.clone(),
                refused: refused.clone(),
                live: Rc::downgrade(&live),
                consumer: LeaseConsumer::Runtime,
            };
            let mut completed = CompletedResponse {
                sequence: 7,
                refused: refused.clone(),
                published: false,
            };
            match cut {
                0 => {}
                1 => live.set(false),
                2 => refused.set(true),
                3 => completed.published = true,
                _ => {
                    completed.refused = Rc::new(Cell::new(false));
                }
            }
            assert_eq!(completed.require_lease(&sink, &lease).is_ok(), cut == 0);
            if cut == 4 {
                assert!(
                    sink.is_open(),
                    "foreign marker has no right to burn another Sink"
                );
            }
            drop(completed);
            if cut == 0 {
                assert!(refused.get(), "abandonment after I/O is still unknown");
            }
        }
    }

    #[test]
    fn actual_completed_response_producer_follows_real_complete_and_stays_armed_through_publication()
     {
        let drive = method("drive");
        let expected: syn::ReturnType = syn::parse_quote!(-> Result<CompletedResponse>);
        assert_eq!(
            drive.sig.output.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let source = drive.block.to_token_stream().to_string();
        let complete = "self . complete () ? ;";
        let construct = "CompletedResponse { sequence : request . 0 , refused : self . refused . clone () , published : false , }";
        assert_eq!(source.matches(complete).count(), 1);
        assert_eq!(source.matches(construct).count(), 1);
        assert!(source.find(complete) < source.find(construct));
        let actual = syn::parse_file(include_str!("response.rs")).unwrap();
        let mut producers = 0;
        for item in &actual.items {
            let syn::Item::Impl(item) = item else {
                continue;
            };
            for item in &item.items {
                let syn::ImplItem::Fn(item) = item else {
                    continue;
                };
                struct Producers(usize);
                impl<'ast> syn::visit::Visit<'ast> for Producers {
                    fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                        if value.path.is_ident("CompletedResponse") {
                            self.0 += 1;
                        }
                        syn::visit::visit_expr_struct(self, value);
                    }
                }
                let mut count = Producers(0);
                syn::visit::Visit::visit_block(&mut count, &item.block);
                producers += count.0;
            }
        }
        assert_eq!(
            producers, 1,
            "no scalar, DATA or alternate completion factory"
        );
        let delivered = actual
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("Sink")) {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "drive_response" => Some(item),
                    _ => None,
                })
            })
            .unwrap();
        let source = delivered.block.to_token_stream().to_string();
        let publication = "transport . complete (sequence . sequence) ?";
        let disarm = "sequence . published = true";
        assert_eq!(source.matches(publication).count(), 1);
        assert_eq!(source.matches(disarm).count(), 1);
        assert!(source.find(publication) < source.find(disarm));
    }

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
            let identity = match self.identity.http() {
                Ok(identity) => identity,
                Err(error) => {
                    self.refused.set(true);
                    if let Some(parent) = owners.retained_parent_refusal() {
                        parent.refuse();
                    }
                    return Err(error);
                }
            };
            let consumer = match &self.attempt {
                Some(attempt) => {
                    let original = owners
                        .originals
                        .get(attempt)
                        .context("native response lease original missing")?;
                    original
                        .response
                        .require_bound(&original.response.intent, identity)?;
                    LeaseConsumer::Human(original.response.intent.commitment()?)
                }
                None => LeaseConsumer::Runtime,
            };
            Ok(ConsumerLeaseOrigin {
                identity: identity.clone(),
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
        let consumer_index = actual.block.stmts.iter().position(|stmt| matches!(stmt,
            syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "consumer")
        )).expect("actual retained consumer selection");
        let mut dropped = actual.block.clone();
        let syn::Stmt::Local(selected) = &mut dropped.stmts[consumer_index] else {
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
        runtime.stmts[consumer_index] = syn::parse_quote!(let consumer = LeaseConsumer::Runtime;);
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
                    break Ok(CompletedResponse {
                        sequence: request.0,
                        refused: self.refused.clone(),
                        published: false,
                    });
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

    #[test]
    fn actual_busy_reservations_retain_and_refuse_the_same_parent_without_a_routing_borrow() {
        use quote::ToTokens;
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let method = |owner: &str, name: &str| {
            file.items.iter().find_map(|item| match item {
                syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().unwrap().ident == owner) => item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item.clone()), _ => None,
                }), _ => None,
            }).unwrap()
        };
        let projection = method("Owners", "retained_parent_refusal");
        let expected: syn::Block = syn::parse_quote!({
            match &self.source {
                OwnerSource::Initial(_) => None,
                OwnerSource::Restored { refusal, .. } => Some(Rc::clone(refusal)),
            }
        });
        assert_eq!(
            projection.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let acquire = method("Lease", "acquire_same");
        let syn::Stmt::Expr(syn::Expr::Block(actual), _) = &acquire.block.stmts[1] else {
            panic!("actual acquisition frame");
        };
        let expected: syn::Block = syn::parse_quote!({
            let mut entries = lease.registry.try_borrow_mut()?;
            ensure!(
                !entries.reserved.contains_key(key),
                "native response owner busy"
            );
            let parent_refusal = entries
                .available
                .get(key)
                .context("native response owner absent")?
                .retained_parent_refusal();
            entries.reserved.insert(
                lease.key.clone(),
                Reservation {
                    identity: identity.clone(),
                    refused: lease.refused.clone(),
                    parent_refusal,
                },
            );
            lease.owners = entries.available.remove(key);
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        for index in 0..actual.block.stmts.len() {
            let mut omitted = actual.block.clone();
            omitted.stmts.remove(index);
            assert!(!guarded(&omitted));
        }
        let mut late_exclusion = actual.block.clone();
        late_exclusion.stmts.swap(1, 2);
        assert!(!guarded(&late_exclusion));
        for (name, expected) in [
            (
                "drop",
                syn::parse_quote!({
                    self.clear();
                }),
            ),
            (
                "clear",
                syn::parse_quote!({
                    for reservation in self.reserved.values() {
                        reservation.refused.set(true);
                        if let Some(parent) = &reservation.parent_refusal {
                            parent.refuse();
                        }
                    }
                    self.reserved.clear();
                    self.available.clear();
                }),
            ),
            (
                "refuse_for",
                syn::parse_quote!({
                    for reservation in self.reserved.values() {
                        if reservation.identity.same_http(identity) {
                            reservation.refused.set(true);
                            if let Some(parent) = &reservation.parent_refusal {
                                parent.refuse();
                            }
                        }
                    }
                }),
            ),
        ] {
            let expected: syn::Block = expected;
            let actual = method("Registry", name);
            assert_eq!(
                actual.block.to_token_stream().to_string(),
                expected.to_token_stream().to_string()
            );
            let text = actual.block.to_token_stream().to_string();
            if name == "drop" {
                let empty: syn::Block = syn::parse_quote!({});
                assert_ne!(
                    empty.to_token_stream().to_string(),
                    expected.to_token_stream().to_string()
                );
                continue;
            }
            let call: syn::Expr = syn::parse_quote!(parent.refuse());
            let call = call.to_token_stream().to_string();
            assert_eq!(text.matches(&call).count(), 1);
            let missing: syn::Block =
                syn::parse_str(&text.replacen(&call, "unrelated ()", 1)).unwrap();
            assert_ne!(
                missing.to_token_stream().to_string(),
                expected.to_token_stream().to_string()
            );
        }
    }

    fn request_owner_method(name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let mut found = file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("RequestOwner")) { return None; }
            item.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
        });
        let result = found.next().unwrap();
        assert!(found.next().is_none());
        result
    }

    fn early_capture_is_guarded(body: &syn::Block) -> bool {
        use quote::ToTokens;
        let source = body.to_token_stream().to_string();
        let steps: [syn::Expr; 6] = [
            syn::parse_quote!(entries.reserved.contains_key(scope.app.as_str())),
            syn::parse_quote!(Lease::acquire(
                registry,
                scope.app.as_str(),
                &sink.identity,
                None
            )),
            syn::parse_quote!(self.abort.set(AbortRoots(
                Rc::clone(&lease.refused),
                Rc::downgrade(&lease.live),
                Rc::clone(refusal)
            ))),
            syn::parse_quote!(sink.response_tickets.capture_app_owner(
                scope,
                &sink.identity,
                owner
            )),
            syn::parse_quote!(routing.capture_request(&runtime, sink)),
            syn::parse_quote!(RequestOwnerSource::Restored(Box::new(lease))),
        ];
        let mut after = 0;
        for step in steps {
            let step = step.to_token_stream().to_string();
            if source.matches(&step).count() != 1 {
                return false;
            }
            let at = source.find(&step).unwrap();
            if at < after {
                return false;
            }
            after = at + step.len();
        }
        let runtime: syn::Expr = syn::parse_quote!(std::sync::Arc::clone(&routing.runtime));
        let native: syn::Expr = syn::parse_quote!(routing.capture_request(&runtime, sink));
        let initial: syn::Expr = syn::parse_quote!(sink.request.capture_app(scope));
        let last: syn::Expr = syn::parse_quote!(ensure!(
            !self.refused.get() && !lease.refused.get() && sink.is_open(),
            "native request refused during capture"
        ));
        let runtime = runtime.to_token_stream().to_string();
        let native = native.to_token_stream().to_string();
        let initial = initial.to_token_stream().to_string();
        let last = last.to_token_stream().to_string();
        source.matches(&runtime).count() == 1
            && source.matches(&initial).count() == 1
            && source.matches(&last).count() == 1
            && source.find(&runtime) < source.find(&native)
            && source.find(&native) < source.find(&last)
    }

    #[test]
    fn actual_early_capture_moves_the_owner_before_native_capture_and_registers_its_same_ledger() {
        use quote::ToTokens;
        let actual = request_owner_method("capture_app");
        assert!(early_capture_is_guarded(&actual.block));
        let source = actual.block.to_token_stream().to_string();
        for (from, to) in [
            (
                quote::quote!(Lease::acquire(
                    registry,
                    scope.app.as_str(),
                    &sink.identity,
                    None
                )),
                quote::quote!(replacement_lease()),
            ),
            (
                quote::quote!(self.abort.set(AbortRoots(
                    Rc::clone(&lease.refused),
                    Rc::downgrade(&lease.live),
                    Rc::clone(refusal)
                ))),
                quote::quote!(Ok(())),
            ),
            (
                quote::quote!(sink.response_tickets.capture_app_owner(
                    scope,
                    &sink.identity,
                    owner
                )),
                quote::quote!(sink.response_tickets.capture_app(scope, &sink.identity)),
            ),
            (
                quote::quote!(routing.capture_request(&runtime, sink)),
                quote::quote!(sink.request.capture_app(scope)),
            ),
            (
                quote::quote!(std::sync::Arc::clone(&routing.runtime)),
                quote::quote!(std::sync::Arc::clone(&other.runtime)),
            ),
        ] {
            let from = from.to_string();
            assert_eq!(source.matches(&from).count(), 1);
            let changed: syn::Block =
                syn::parse_str(&source.replacen(&from, &to.to_string(), 1)).unwrap();
            assert!(!early_capture_is_guarded(&changed));
        }
        let mut changed = actual.block.clone();
        // A separately appended replacement capture is also forbidden.
        changed
            .stmts
            .push(syn::parse_quote!(sink.request.capture_app(scope)?;));
        assert!(!early_capture_is_guarded(&changed));

        let file = syn::parse_file(include_str!("../native_management.rs")).unwrap();
        let sink_capture = file
            .items
            .iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("Sink")) {
                    return None;
                }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == "capture_app_request" => {
                        Some(item)
                    }
                    _ => None,
                })
            })
            .unwrap();
        let expected: syn::Block =
            syn::parse_quote!({ self.request_owner.capture_app(self, scope) });
        assert_eq!(
            sink_capture.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
    }

    fn runtime_port_is_guarded(body: &syn::Block) -> bool {
        use quote::ToTokens;
        let source = body.to_token_stream().to_string();
        let steps: [syn::Expr; 5] = [
            syn::parse_quote!(routing.require_runtime(runtime)),
            syn::parse_quote!(NativeConsumerContext::runtime_http(
                runtime,
                phase,
                sink,
                sink.request.consumer_origin(&scope, NativeRole::AppHost)?,
            )),
            syn::parse_quote!(current.require_app_selection(
                runtime,
                &selection.policy,
                &selection.store
            )),
            syn::parse_quote!(RuntimeConsumer::from_restored(runtime, phase, current)),
            syn::parse_quote!(
                RuntimeConsumer::from_restored(runtime, phase, current)?.run(operation)
            ),
        ];
        let mut after = 0;
        for step in steps {
            let step = step.to_token_stream().to_string();
            if source.matches(&step).count() != 1 {
                return false;
            }
            let at = source.find(&step).unwrap();
            if at < after {
                return false;
            }
            after = at;
        }
        let unit: syn::Expr = syn::parse_quote!(sink.request.with_restored_current(
            &scope,
            &mut routing.parent,
            context,
            |current| {
                current.require_app_selection(runtime, &selection.policy, &selection.store)?;
                RuntimeConsumer::from_restored(runtime, phase, current)?.run(operation)
            }
        ));
        let unit = unit.to_token_stream().to_string();
        source.matches(&unit).count() == 1
            && ![
                "capture_app",
                "capture_restored_app",
                "begin_current_request",
                "begin_current_stage",
                "startup",
            ]
            .iter()
            .any(|name| source.contains(name))
    }

    #[test]
    fn actual_restored_runtime_http_port_keeps_runtime_parent_original_and_postchecks_together() {
        use quote::ToTokens;
        let actual = request_owner_method("with_runtime_consumer");
        assert!(runtime_port_is_guarded(&actual.block));
        let source = actual.block.to_token_stream().to_string();
        for (from, to) in [
            (
                quote::quote!(routing.require_runtime(runtime)),
                quote::quote!(routing.require_runtime(other)),
            ),
            (
                quote::quote!(&mut routing.parent),
                quote::quote!(&mut other.parent),
            ),
            (
                quote::quote!(NativeConsumerContext::runtime_http(
                    runtime,
                    phase,
                    sink,
                    sink.request.consumer_origin(&scope, NativeRole::AppHost)?,
                )),
                quote::quote!(NativeConsumerContext::startup(runtime, &request)),
            ),
            (
                quote::quote!(current.require_app_selection(
                    runtime,
                    &selection.policy,
                    &selection.store
                )),
                quote::quote!(Ok(())),
            ),
            (
                quote::quote!(
                    RuntimeConsumer::from_restored(runtime, phase, current)?.run(operation)
                ),
                quote::quote!(operation(unchecked_current)),
            ),
        ] {
            let from = from.to_string();
            assert_eq!(source.matches(&from).count(), 1);
            let changed: syn::Block =
                syn::parse_str(&source.replacen(&from, &to.to_string(), 1)).unwrap();
            assert!(!runtime_port_is_guarded(&changed));
        }
        let mut recaptured = actual.block.clone();
        recaptured.stmts.push(
            syn::parse_quote!(sink.request.capture_restored_app(&scope, &mut routing.parent)?;),
        );
        assert!(!runtime_port_is_guarded(&recaptured));
    }

    #[test]
    fn actual_autonomous_driver_cannot_relabel_a_restored_capture_as_http() {
        use quote::ToTokens;
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let actual = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "require_autonomous_source" => Some(item),
                _ => None,
            })
            .unwrap();
        let refusal: syn::Expr = syn::parse_quote!(match &owner.source {
            OwnerSource::Initial(_) => Ok(()),
            OwnerSource::Restored { .. } => {
                owner.refuse();
                anyhow::bail!("restored autonomous request supplier missing");
            }
        });
        let source = actual.block.to_token_stream().to_string();
        let refusal = refusal.to_token_stream().to_string();
        assert_eq!(source.matches(&refusal).count(), 1);
        let selected: syn::Expr = syn::parse_quote!(require_autonomous_selection(
            owner.kind,
            owner.selection.scope(),
            scope
        ));
        let selected = selected.to_token_stream().to_string();
        let guarded = |body: &syn::Block| {
            let source = body.to_token_stream().to_string();
            source.matches(&selected).count() == 1
                && source.matches(&refusal).count() == 1
                && source.find(&selected) < source.find(&refusal)
        };
        assert!(guarded(&actual.block));
        let removed: syn::Block = syn::parse_str(&source.replacen(&selected, "Ok(())", 1)).unwrap();
        assert!(!guarded(&removed));
        // Keep the real source match, but move actual full selection after it.
        let late = source.replacen(&selected, "Ok(())", 1).replacen(
            &refusal,
            &format!("{{ let result = {refusal}; {selected}?; result }}"),
            1,
        );
        let late: syn::Block = syn::parse_str(&late).unwrap();
        assert!(!guarded(&late));
        let changed: syn::Block = syn::parse_str(&source.replacen(&refusal, "Ok(())", 1)).unwrap();
        assert!(!changed.to_token_stream().to_string().contains(&refusal));

        let file = syn::parse_file(include_str!("../native_management.rs")).unwrap();
        let driver = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "with_app_request" => Some(item),
                _ => None,
            })
            .unwrap();
        let source = driver.block.to_token_stream().to_string();
        let autonomous: syn::Expr = syn::parse_quote!(response::require_autonomous_source(scope));
        let autonomous = autonomous.to_token_stream().to_string();
        let sink: syn::Expr = syn::parse_quote!(Sink::new());
        let sink = sink.to_token_stream().to_string();
        assert_eq!(source.matches(&autonomous).count(), 1);
        assert_eq!(source.matches(&sink).count(), 1);
        assert!(source.find(&autonomous) < source.find(&sink));
        let runtime_driver = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "with_runtime_consumer" => Some(item),
                _ => None,
            })
            .unwrap();
        let early: syn::Stmt = syn::parse_quote!(match captured {
            Some(ActiveRequest::Runtime(frame)) => {
                return frame.with_consumer(runtime, phase, operation);
            }
            Some(ActiveRequest::Http(sink)) if sink.request_owner.uses_restored()? => {
                return sink
                    .request_owner
                    .with_runtime_consumer(&sink, runtime, phase, operation);
            }
            Some(ActiveRequest::Http(_)) | None => {}
        });
        let early = early.to_token_stream().to_string();
        let body = runtime_driver.block.to_token_stream().to_string();
        assert_eq!(body.matches(&early).count(), 1);
        let ordinary: syn::Expr = syn::parse_quote!(!runtime.uses_native_storage());
        assert!(body.find(&early) < body.find(&ordinary.to_token_stream().to_string()));
    }

    #[test]
    fn foreign_autonomous_scope_or_role_is_refused_before_the_parent_is_selected() {
        let scope = |installation: &str, environment: &str, app: &str| AuthorityScope {
            installation: installation.to_owned().try_into().unwrap(),
            environment: environment.to_owned().try_into().unwrap(),
            app: app.to_owned().try_into().unwrap(),
        };
        let actual = scope("instance", "production", "calendar");
        require_autonomous_selection(NativeRole::AppHost, &actual, &actual).unwrap();
        for foreign in [
            scope("other-instance", "production", "calendar"),
            scope("instance", "staging", "calendar"),
            scope("instance", "production", "other-app"),
        ] {
            assert!(require_autonomous_selection(NativeRole::AppHost, &actual, &foreign).is_err());
        }
        assert!(require_autonomous_selection(NativeRole::SecurityShell, &actual, &actual).is_err());
    }

    #[test]
    fn captured_response_scope_uses_the_same_sink_lease_and_actual_runtime_before_data() {
        use quote::ToTokens;
        let actual = request_owner_method("runtime_scope");
        let source = actual.block.to_token_stream().to_string();
        let pointer: syn::Expr =
            syn::parse_quote!(routing.try_borrow_mut()?.require_runtime(runtime));
        let pointer = pointer.to_token_stream().to_string();
        let selected: syn::Expr = syn::parse_quote!(ensure!(
            owner.kind == NativeRole::AppHost && owner.selection.scope() == &scope,
            "native restored response selection changed"
        ));
        let selected = selected.to_token_stream().to_string();
        let guarded = |body: &syn::Block| {
            let source = body.to_token_stream().to_string();
            source.matches(&pointer).count() == 1
                && source.matches(&selected).count() == 1
                && source.find(&pointer) < source.find(&selected)
        };
        assert!(guarded(&actual.block));
        let removed: syn::Block =
            syn::parse_str(&source.replacen(&pointer, "metadata_scope(runtime)", 1)).unwrap();
        assert!(!guarded(&removed));
        let foreign: syn::Block = syn::parse_str(&source.replacen(
            &pointer,
            "routing.try_borrow_mut()?.require_runtime(other)",
            1,
        ))
        .unwrap();
        assert!(!guarded(&foreign));
        let late = source
            .replacen(&pointer, "metadata_scope(runtime)", 1)
            .replacen(&selected, &format!("{{ {selected}; {pointer} }}"), 1);
        assert!(!guarded(&syn::parse_str(&late).unwrap()));

        let file = syn::parse_file(include_str!("../native_management.rs")).unwrap();
        let selected = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "captured_runtime_response_scope" => {
                    Some(item)
                }
                _ => None,
            })
            .unwrap();
        let expected: syn::Block =
            syn::parse_quote!({ sink.request_owner.response_scope(sink, runtime) });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&selected.block));
        let mut registry_fallback = selected.block.clone();
        registry_fallback.stmts[0] =
            syn::Stmt::Expr(syn::parse_quote!(runtime_response_scope(runtime)), None);
        assert!(!guarded(&registry_fallback));
    }

    #[test]
    fn actual_response_classification_selects_the_captured_source_before_ordinary_runtime() {
        use quote::ToTokens;
        let actual = request_owner_method("response_scope");
        let expected: syn::Block = syn::parse_quote!({
            let result = (|| {
                ensure!(
                    !self.refused.get() && sink.is_open(),
                    "native request owner refused"
                );
                let restored = {
                    let source = self.source.try_borrow()?;
                    match &*source {
                        RequestOwnerSource::Restored(_) => true,
                        RequestOwnerSource::Initial => {
                            ensure!(
                                runtime.uses_native_storage(),
                                "native captured Runtime cannot become ordinary"
                            );
                            false
                        }
                        RequestOwnerSource::NonNative => {
                            ensure!(
                                !runtime.uses_native_storage(),
                                "ordinary capture cannot become native"
                            );
                            return Ok(None);
                        }
                        #[cfg(test)]
                        RequestOwnerSource::Model(domain) => {
                            let domain = domain.context("scripted response fixture missing")?;
                            super::fixtures::require_model_domain(domain)?;
                            ensure!(
                                Some(domain) == crate::oauth::effects::current_domain()
                                    && !runtime.uses_native_storage(),
                                "scripted response profile changed"
                            );
                            return Ok(None);
                        }
                        _ => anyhow::bail!("native response capture unavailable"),
                    }
                };
                if restored {
                    return self.runtime_scope(sink, runtime).map(Some);
                }
                super::runtime_response_scope(runtime)
            })();
            if result.is_err() {
                self.refuse();
                sink.abort();
            }
            result
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        let mut downgrade = actual.block.clone();
        downgrade.stmts.insert(
            0,
            syn::parse_quote!(if !runtime.uses_native_storage() {
                return Ok(None);
            }),
        );
        assert!(!guarded(&downgrade));
        let text = actual.block.to_token_stream().to_string();
        let actual_route: syn::Expr =
            syn::parse_quote!(self.runtime_scope(sink, runtime).map(Some));
        let actual_route = actual_route.to_token_stream().to_string();
        assert_eq!(text.matches(&actual_route).count(), 1);
        let downgraded: syn::Block =
            syn::parse_str(&text.replacen(&actual_route, "Ok(None)", 1)).unwrap();
        assert!(!guarded(&downgraded));
        for from in [
            "super::fixtures::require_model_domain(domain)?",
            "Some(domain) == crate::oauth::effects::current_domain()",
            "!runtime.uses_native_storage()",
        ] {
            let selected: syn::Expr = syn::parse_str(from).unwrap();
            let selected = selected.to_token_stream().to_string();
            let index = text.rfind(&selected).unwrap();
            let mut changed = text.clone();
            let replacement = if from.ends_with('?') {
                "Ok(())?"
            } else {
                "true"
            };
            changed.replace_range(index..index + selected.len(), replacement);
            assert!(!guarded(&syn::parse_str(&changed).unwrap()), "{from}");
        }
    }

    #[test]
    fn ordinary_response_requires_actual_non_native_capture_and_never_initial_or_empty()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (runtime, _, _) = crate::oauth::admission::tests::management_fixture(directory.path())?;
        assert!(!runtime.uses_native_storage());
        let uncaptured = Sink::new();
        assert!(super::super::captured_runtime_response_scope(&runtime, &uncaptured).is_err());
        assert!(!uncaptured.is_open());
        let initial_only = Sink::new();
        *initial_only.request_owner.source.borrow_mut() = RequestOwnerSource::Initial;
        assert!(super::super::captured_runtime_response_scope(&runtime, &initial_only).is_err());
        assert!(!initial_only.is_open());
        let ordinary = Sink::new();
        ordinary.capture_non_native_request()?;
        assert!(super::super::captured_runtime_response_scope(&runtime, &ordinary)?.is_none());
        assert!(ordinary.is_open());
        Ok(())
    }

    #[test]
    fn model_response_requires_actual_capture_and_the_same_active_non_native_profile() -> Result<()>
    {
        use quote::ToTokens;
        let directory = tempfile::tempdir()?;
        let (runtime, _, _) = crate::oauth::admission::tests::management_fixture(directory.path())?;
        assert!(!runtime.uses_native_storage());
        let world = crate::oauth::simulation::World::new(917_328);
        let escaped = crate::oauth::effects::scope(world.clone(), || -> Result<_> {
            let empty = Sink::new();
            assert!(super::super::captured_runtime_response_scope(&runtime, &empty).is_err());
            let actual = Sink::new();
            actual.capture_model_request()?;
            assert!(super::super::captured_runtime_response_scope(&runtime, &actual)?.is_none());
            assert!(actual.is_open() && actual.request.model_origin()?.is_some());
            let duplicate = Sink::new();
            duplicate.capture_model_request()?;
            assert!(duplicate.capture_model_request().is_err() && !duplicate.is_open());
            let foreign_owner = Sink::new();
            let foreign_sink = Sink::new();
            assert!(
                foreign_owner
                    .request_owner
                    .capture_model(&foreign_sink)
                    .is_err()
            );
            assert!(foreign_sink.is_open() && !foreign_sink.request.has_started()?);
            assert!(foreign_owner.request_owner.refused.get());
            let changed = Sink::new();
            changed.capture_model_request()?;
            crate::oauth::effects::scope(crate::oauth::simulation::World::new(917_329), || {
                assert!(super::super::captured_runtime_response_scope(&runtime, &changed).is_err());
            });
            assert!(!changed.is_open());
            Ok(actual)
        })?;
        assert!(super::super::captured_runtime_response_scope(&runtime, &escaped).is_err());
        assert!(!escaped.is_open());
        let unscoped = Sink::new();
        unscoped.capture_model_request()?;
        assert!(super::super::captured_runtime_response_scope(&runtime, &unscoped).is_err());

        let actual = request_owner_method("capture_model");
        let same: syn::Expr = syn::parse_str(
            "Rc::ptr_eq(&self.source, &sink.request_owner.source) && Rc::ptr_eq(&self.refused, &sink.request_owner.refused) && Rc::ptr_eq(&self.abort, &sink.request_owner.abort)",
        )?;
        let same = same.to_token_stream().to_string();
        let call: syn::Expr = syn::parse_quote!(sink.request.capture_model()?);
        let call = call.to_token_stream().to_string();
        let publishing: syn::Expr = syn::parse_quote!(*source = RequestOwnerSource::Model(domain));
        let publishing = publishing.to_token_stream().to_string();
        let guarded = |body: &syn::Block| {
            let Some(syn::Stmt::Local(first)) = body.stmts.first() else {
                return false;
            };
            let text = body.to_token_stream().to_string();
            first
                .init
                .as_ref()
                .is_some_and(|init| init.expr.to_token_stream().to_string() == same)
                && text.matches(&call).count() == 1
                && text.matches(&publishing).count() == 1
                && text.find(&call) < text.find(&publishing)
                && text
                    .matches("super :: fixtures :: require_model_domain (domain) ?")
                    .count()
                    == 2
                && text.contains("std :: panic :: catch_unwind")
                && text.contains("std :: panic :: resume_unwind")
        };
        assert!(guarded(&actual.block));
        let text = actual.block.to_token_stream().to_string();
        assert!(!guarded(&syn::parse_str(
            &text.replacen(&call, "Ok(())?", 1)
        )?));
        assert!(!guarded(&syn::parse_str(&text.replacen(&same, "true", 1))?));
        let source = syn::parse_file(include_str!("../native_management.rs"))?;
        let methods = source.items.iter().filter_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            (item.trait_.is_none() && matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("Sink"))).then_some(item)
        }).flat_map(|item| &item.items).filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "capture_model_request" => Some(item),
            _ => None,
        }).collect::<Vec<_>>();
        assert_eq!(methods.len(), 1);
        let sink = methods[0];
        let expected: syn::Block = syn::parse_quote!({ self.request_owner.capture_model(self) });
        assert_eq!(
            sink.block.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        Ok(())
    }

    fn sink_method(name: &str) -> syn::ImplItemFn {
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let mut found = file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("Sink")) {
                return None;
            }
            item.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
        });
        let result = found.next().unwrap();
        assert!(found.next().is_none());
        result
    }

    #[test]
    fn actual_driver_takes_the_same_early_lease_once_and_never_falls_back_after_restored_failure() {
        use quote::ToTokens;
        let actual = sink_method("drive_response");
        let expected: syn::Stmt = syn::parse_quote!(if self.request_owner.uses_restored()? {
            let lease =
                self.request_owner
                    .take_response(self, app, intent.as_ref(), scope.as_ref())?;
            return self
                .drive_restored_response(transport, first, intent, effects, lease)
                .await;
        });
        let expected = expected.to_token_stream().to_string();
        let source = actual.block.to_token_stream().to_string();
        assert_eq!(source.matches(&expected).count(), 1);
        let fallback: syn::Expr =
            syn::parse_quote!(Lease::take(self, app, intent.as_ref(), scope.as_ref()));
        assert!(source.find(&expected) < source.find(&fallback.to_token_stream().to_string()));
        let bypass: syn::Stmt = syn::parse_quote!(if self.request_owner.uses_restored()? {
            let _ = self
                .request_owner
                .take_response(self, app, intent.as_ref(), scope.as_ref());
        });
        let changed = source.replacen(&expected, &bypass.to_token_stream().to_string(), 1);
        assert!(!changed.contains(&expected));
        let take = request_owner_method("take_response")
            .block
            .to_token_stream()
            .to_string();
        let moved: syn::Expr =
            syn::parse_quote!(std::mem::replace(&mut *source, RequestOwnerSource::Moved));
        let moved = moved.to_token_stream().to_string();
        assert_eq!(take.matches(&moved).count(), 1);
        assert!(
            !take.contains("acquire") && !take.contains("OWNERS") && !take.contains("capture_app")
        );
        let checked: syn::Expr = syn::parse_quote!(lease.identity.same_http(&sink.identity));
        assert!(take.find(&checked.to_token_stream().to_string()) < take.find(&moved));
        let substituted = take.replacen(
            &moved,
            "std::mem::replace(&mut *source, RequestOwnerSource::Initial)",
            1,
        );
        assert!(!substituted.contains(&moved));
    }

    #[test]
    fn actual_restored_unit_uses_one_shared_transport_engine_and_evaluates_posts_before_primary_error()
     {
        use quote::ToTokens;
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let actual = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "drive_restored_unit" => Some(item),
                _ => None,
            })
            .unwrap();
        let expected: syn::Block = syn::parse_quote!({
            routing.require_runtime(runtime)?;
            let selection = routing.selection.clone();
            let mut current = request.begin_restored_current(&mut routing.parent, context)?;
            let requested = async {
                current.require_app_selection(runtime, &selection.policy, &selection.store)?;
                transport.scope_entered();
                let mut response = ResponseBorrow::from_restored(&mut current, runtime, refused)?;
                response.drive(transport, first).await
            }
            .await;
            let finished = current.finish();
            let completed = requested?;
            finished?;
            Ok(completed)
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        for cut in [0, 2, 3, 4] {
            let mut missing = actual.block.clone();
            missing.stmts.remove(cut);
            assert!(!guarded(&missing));
        }
        let mut early = actual.block.clone();
        early.stmts.swap(4, 5);
        assert!(!guarded(&early));
        let mut suppressed = actual.block.clone();
        suppressed.stmts[4] = syn::parse_quote!(let finished = Ok(()););
        assert!(!guarded(&suppressed));
    }

    fn captured_driver_body(body: &syn::Block) -> Option<&syn::Block> {
        let [syn::Stmt::Expr(syn::Expr::Await(wait), _)] = body.stmts.as_slice() else {
            return None;
        };
        let syn::Expr::MethodCall(call) = &*wait.base else {
            return None;
        };
        if call.method != "run_async"
            || !matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("effects"))
            || call.args.len() != 1
        {
            return None;
        }
        let syn::Expr::Async(future) = &call.args[0] else {
            return None;
        };
        Some(&future.block)
    }

    #[test]
    fn actual_restored_clock_and_final_settlement_remain_inside_one_captured_effect_scope() {
        use quote::ToTokens;
        let actual = sink_method("drive_restored_response");
        let body = captured_driver_body(&actual.block).unwrap();
        let source = body.to_token_stream().to_string();
        assert_eq!(source.matches("wall_time").count(), 1);
        assert_eq!(source.matches("finish_restored").count(), 2);
        assert!(!source.contains("run_async"));
        let mut ambient = actual.block.clone();
        ambient.stmts.insert(
            0,
            syn::parse_quote!(let wall = super::super::effects::wall_time()?;),
        );
        assert!(captured_driver_body(&ambient).is_none());
        let mut uncaptured = actual.block.clone();
        let syn::Stmt::Expr(syn::Expr::Await(wait), _) = &mut uncaptured.stmts[0] else {
            panic!("actual captured future");
        };
        let syn::Expr::MethodCall(call) = &mut *wait.base else {
            panic!("actual captured wrapper");
        };
        call.method = syn::parse_quote!(unscoped);
        assert!(captured_driver_body(&uncaptured).is_none());
    }

    #[test]
    fn actual_restored_driver_binds_both_origins_and_final_context_before_known_publication() {
        use quote::ToTokens;
        let actual = sink_method("drive_restored_response");
        let body =
            captured_driver_body(&actual.block).expect("entire driver retains captured effects");
        let source = body.to_token_stream().to_string();
        let origin: syn::Expr = syn::parse_quote!(lease.consumer_origin());
        let origin = origin.to_token_stream().to_string();
        assert_eq!(source.matches(&origin).count(), 2);
        let owner: syn::Expr = syn::parse_quote!(lease.owners.as_mut());
        assert!(source.rfind(&origin) < source.find(&owner.to_token_stream().to_string()));
        for factory in ["human_response", "runtime_response"] {
            assert_eq!(
                source
                    .matches(&format!("NativeConsumerContext :: {factory}"))
                    .count(),
                1
            );
            assert_eq!(
                source
                    .matches(&format!("NativeRequestFinalContext :: {factory}"))
                    .count(),
                1
            );
        }
        let settled: syn::Expr =
            syn::parse_quote!(request.finish_restored(&mut routing.parent, context));
        let settled = settled.to_token_stream().to_string();
        assert_eq!(source.matches(&settled).count(), 2);
        let tail: syn::Block = syn::parse_quote!({
            transport.complete(completed.sequence)?;
            held.known = true;
            lease.known = true;
            self.state.set(SinkState::Complete);
            terminal.complete();
            completed.published = true;
            Ok(())
        });
        let guarded = |body: &syn::Block| {
            let source = body.to_token_stream().to_string();
            let actual_tail = syn::Block {
                brace_token: Default::default(),
                stmts: body
                    .stmts
                    .iter()
                    .rev()
                    .take(7)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect(),
            };
            source.matches(&settled).count() == 2
                && actual_tail.to_token_stream().to_string() == tail.to_token_stream().to_string()
        };
        assert!(guarded(body));
        let changed: syn::Block = syn::parse_str(&source.replacen(&settled, "Ok(())", 1)).unwrap();
        assert!(!guarded(&changed));
        for cut in [
            body.stmts.len() - 7,
            body.stmts.len() - 5,
            body.stmts.len() - 2,
        ] {
            let mut missing = body.clone();
            missing.stmts.remove(cut);
            assert!(!guarded(&missing));
        }
    }

    #[test]
    fn actual_early_abort_is_direct_and_stale_projection_cannot_refuse_a_returned_parent() {
        use quote::ToTokens;
        let actual = request_owner_method("refuse");
        let expected: syn::Block = syn::parse_quote!({
            self.refused.set(true);
            if let Some(AbortRoots(lease, live, parent)) = self.abort.get() {
                lease.set(true);
                if live.upgrade().is_some_and(|live| live.get()) {
                    parent.refuse();
                }
            }
            if let Ok(mut source) = self.source.try_borrow_mut() {
                *source = RequestOwnerSource::Refused;
            }
        });
        let guarded = |body: &syn::Block| {
            body.to_token_stream().to_string() == expected.to_token_stream().to_string()
        };
        assert!(guarded(&actual.block));
        let mut after_borrow = actual.block.clone();
        after_borrow.stmts.swap(1, 2);
        assert!(!guarded(&after_borrow));
        let mut unguarded = actual.block.clone();
        unguarded.stmts[1] = syn::parse_quote!(if let Some(AbortRoots(lease, live, parent)) =
            self.abort.get()
        {
            lease.set(true);
            parent.refuse();
        });
        assert!(!guarded(&unguarded));
        let mut missing = actual.block.clone();
        missing.stmts.remove(1);
        assert!(!guarded(&missing));

        // No native owner fixture: actual early-slot refusal remains sticky
        // even while a synchronous consumer holds that slot's RefCell loan.
        let owner = RequestOwner::new();
        let clone = owner.clone();
        let held = owner.source.borrow_mut();
        clone.refuse();
        assert!(owner.refused.get());
        drop(held);
        clone.refuse();
        assert!(matches!(
            *owner.source.borrow(),
            RequestOwnerSource::Refused
        ));
    }

    // Non-authority material exercises the SAME move/reservation/Drop code.
    // It has no conversion to Owners, a native stage, peer or serving phase.
    struct Material {
        parent: Option<Rc<super::super::RestoredAppRefusal>>,
        incarnation: u32,
        refused: Rc<Cell<bool>>,
        dropped: Rc<Cell<u32>>,
    }
    impl sealed::Material for Material {}
    impl LeaseMaterial for Material {
        fn retained_parent_refusal(&self) -> Option<Rc<super::super::RestoredAppRefusal>> {
            self.parent.as_ref().map(Rc::clone)
        }
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
                parent: None,
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
    fn replacing_or_dropping_the_actual_registry_value_refuses_an_outstanding_lease_immediately() {
        for cut in 0..3 {
            let Fixture {
                registry,
                refused,
                dropped,
            } = fixture();
            let lease =
                Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None)
                    .unwrap();
            assert!(!lease.refused.get());
            assert!(!refused.get());
            let replacement_refused = Rc::new(Cell::new(false));
            let replacement_dropped = Rc::new(Cell::new(0));
            let mut next = Registry::default();
            next.available.insert(
                "calendar".into(),
                Material {
                    parent: None,
                    incarnation: 2,
                    refused: Rc::clone(&replacement_refused),
                    dropped: Rc::clone(&replacement_dropped),
                },
            );
            if cut == 2 {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _old = std::mem::replace(&mut *registry.borrow_mut(), next);
                    std::panic::panic_any(7u8);
                }));
                assert_eq!(*result.unwrap_err().downcast::<u8>().unwrap(), 7);
            } else {
                let mut held = registry.borrow_mut();
                let old = if cut == 0 {
                    std::mem::replace(&mut *held, next)
                } else {
                    let old = std::mem::take(&mut *held);
                    *held = next;
                    old
                };
                drop(old);
                assert!(
                    registry.try_borrow_mut().is_err(),
                    "registry borrow stays held during actual value disposal"
                );
            }
            assert!(
                lease.refused.get(),
                "reservation is refused before the moved-out owner or lease drops"
            );
            assert!(
                !refused.get(),
                "model owner is still loaned out; this is the actual reservation latch"
            );
            assert_eq!(dropped.get(), 0);
            assert!(!replacement_refused.get());
            drop(lease);
            assert!(refused.get());
            assert_eq!(dropped.get(), 1);
            assert!(
                !replacement_refused.get(),
                "old lease cannot refuse replacement material"
            );
            assert_eq!(replacement_dropped.get(), 0);
            assert_eq!(registry.borrow().available["calendar"].incarnation, 2);
        }
    }

    fn early_negative_fixture(
        lease: &Lease<Material>,
        parent: Rc<super::super::RestoredAppRefusal>,
    ) -> RequestOwner {
        let owner = RequestOwner::new();
        *owner.source.borrow_mut() = RequestOwnerSource::Capturing;
        assert!(
            owner
                .abort
                .set(AbortRoots(
                    Rc::clone(&lease.refused),
                    Rc::downgrade(&lease.live),
                    parent
                ))
                .is_ok()
        );
        owner
    }

    #[test]
    fn active_early_abort_reaches_both_actual_negative_roots_while_the_slot_is_held() {
        use crate::security_epoch::native_enrollment::{
            negative_parent_refusal_roots, new_negative_parent_refusal_fixture,
        };
        let Fixture { registry, .. } = fixture();
        let lease =
            Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None).unwrap();
        let parent = Rc::new(new_negative_parent_refusal_fixture());
        let owner = early_negative_fixture(&lease, Rc::clone(&parent));
        let clone = owner.clone();
        let slot = owner.source.borrow_mut();
        let map = registry.borrow_mut();
        assert_eq!(negative_parent_refusal_roots(&parent), [false, false]);
        clone.refuse();
        assert!(lease.refused.get());
        assert!(owner.refused.get());
        assert_eq!(negative_parent_refusal_roots(&parent), [true, true]);
        clone.refuse();
        assert_eq!(negative_parent_refusal_roots(&parent), [true, true]);
        drop(map);
        drop(slot);
        drop(lease);
    }

    #[test]
    fn moved_request_abort_reaches_actual_roots_while_the_driver_suspends_without_slot_borrows() {
        use crate::security_epoch::native_enrollment::{
            negative_parent_refusal_roots, new_negative_parent_refusal_fixture,
        };
        let Fixture {
            registry, refused, ..
        } = fixture();
        let lease =
            Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None).unwrap();
        let parent = Rc::new(new_negative_parent_refusal_fixture());
        let owner = early_negative_fixture(&lease, Rc::clone(&parent));
        *owner.source.borrow_mut() = RequestOwnerSource::Moved;
        let role = Role::new(7u32);
        let route = role.clone();
        let mut driver = Box::pin(async move {
            let _lease = lease;
            let mut actual = route.take().unwrap();
            assert_eq!(*actual.owner(), 7);
            std::future::pending::<()>().await;
        });
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(driver.as_mut().poll(&mut cx).is_pending());
        assert!(owner.source.try_borrow_mut().is_ok());
        assert!(registry.try_borrow_mut().is_ok());
        assert!(role.slot.try_borrow_mut().is_ok());
        assert!(role.try_borrow_mut().is_err());
        let held = owner.source.borrow_mut();
        owner.refuse();
        assert_eq!(negative_parent_refusal_roots(&parent), [true, true]);
        drop(held);
        drop(driver);
        assert!(refused.get());
        assert!(owner.uses_restored().is_err());
        assert!(role.try_borrow_mut().is_err());
    }

    #[test]
    fn actual_registry_retirement_uses_parent_incarnation_and_keeps_unknown_reservations() {
        use crate::security_epoch::native_enrollment::{
            negative_parent_refusal_roots, new_negative_parent_refusal_fixture,
        };
        for busy in [false, true] {
            let Fixture {
                registry, dropped, ..
            } = fixture();
            let old = Rc::new(new_negative_parent_refusal_fixture());
            registry
                .borrow_mut()
                .available
                .get_mut("calendar")
                .unwrap()
                .parent = Some(Rc::clone(&old));
            let held = if busy {
                Some(
                    Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None)
                        .unwrap(),
                )
            } else {
                None
            };
            old.refuse();
            registry.borrow_mut().retire_parent("calendar", &old);
            assert_eq!(negative_parent_refusal_roots(&old), [true, true]);
            if let Some(held) = held {
                assert!(held.refused.get());
                assert!(registry.borrow().reserved.contains_key("calendar"));
                assert_eq!(dropped.get(), 0);
                drop(held);
            } else {
                assert!(registry.borrow().available.is_empty());
                assert_eq!(dropped.get(), 1);
            }
        }
        let Fixture { registry, .. } = fixture();
        let old = Rc::new(new_negative_parent_refusal_fixture());
        let next = Rc::new(new_negative_parent_refusal_fixture());
        registry
            .borrow_mut()
            .available
            .get_mut("calendar")
            .unwrap()
            .parent = Some(Rc::clone(&next));
        old.refuse();
        registry.borrow_mut().retire_parent("calendar", &old);
        assert!(registry.borrow().available.contains_key("calendar"));
        assert_eq!(negative_parent_refusal_roots(&next), [false, false]);
        let current =
            Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None).unwrap();
        registry.borrow_mut().retire_parent("calendar", &old);
        assert!(!current.refused.get());
        assert_eq!(negative_parent_refusal_roots(&next), [false, false]);
        drop(current);
    }

    #[test]
    fn restored_human_ports_keep_the_same_actual_clock_request_and_creator() {
        use quote::ToTokens;
        let ordered = |source: &str, expressions: Vec<proc_macro2::TokenStream>| {
            let mut end = 0;
            expressions.into_iter().all(|expression| {
                let expression = expression.to_string();
                if source.matches(&expression).count() != 1 {
                    return false;
                }
                let at = source.find(&expression).unwrap();
                if at < end {
                    return false;
                }
                end = at + expression.len();
                true
            })
        };
        let captured = request_owner_method("capture_human_clock");
        let captured = captured.block.to_token_stream().to_string();
        let steps = vec![
            quote::quote!(actual.require_runtime(&runtime)),
            quote::quote!(ensure!(
                owner.selection.scope() == &scope,
                "native human full selection changed"
            )),
            quote::quote!(owner.response_rights.mark_unfenced()),
            quote::quote!(actual.capture_human_clock(&runtime, sink)),
        ];
        assert!(ordered(&captured, steps.clone()));
        for expression in &steps {
            let changed = captured.replacen(&expression.to_string(), "unrelated()", 1);
            assert!(!ordered(&changed, steps.clone()));
        }
        for name in [
            "sample_human_clock",
            "with_pending",
            "bind_human",
            "with_human_consumer",
        ] {
            let source = request_owner_method(name)
                .block
                .to_token_stream()
                .to_string();
            let identity = quote::quote!(lease.identity.same_http(&sink.identity)).to_string();
            let same_parent = quote::quote!(Rc::ptr_eq(&routing.slot, &expected.slot)).to_string();
            assert_eq!(source.matches(&identity).count(), 1, "{name}");
            assert_eq!(source.matches(&same_parent).count(), 1, "{name}");
            assert!(source.find(&identity) < source.find(&same_parent));
            assert!(
                !source.contains("OWNERS")
                    && !source.contains("capture_restored_app")
                    && !source.contains("EnrolledProcessRoleOwner")
            );
        }
        let pending = request_owner_method("with_pending")
            .block
            .to_token_stream()
            .to_string();
        assert_eq!(
            pending.matches("NativeConsumerContext :: captured").count(),
            1
        );
        assert_eq!(pending.matches("PendingWriter :: from_restored").count(), 1);
        let bound = request_owner_method("bind_human")
            .block
            .to_token_stream()
            .to_string();
        let enlist = quote::quote!(super::enlist(
            NativeRole::AppHost,
            intent,
            &mut stored.response,
            None
        ))
        .to_string();
        let insert =
            quote::quote!(owner.originals.insert(intent.attempt().into(), stored)).to_string();
        assert!(bound.find(&enlist) < bound.find(&insert));
    }

    #[test]
    fn restored_human_delegation_preserves_known_exclusions_and_poisoned_setup_has_no_success_tail()
    {
        use quote::ToTokens;
        let actual = request_owner_method("with_human_consumer");
        let expected: syn::Expr = syn::parse_quote!(match result {
            Ok(result) => result,
            Err(payload) => {
                self.refuse();
                sink.abort();
                std::panic::resume_unwind(payload)
            }
        });
        let Some(syn::Stmt::Expr(tail, None)) = actual.block.stmts.last() else {
            panic!("actual human return");
        };
        assert_eq!(
            tail.to_token_stream().to_string(),
            expected.to_token_stream().to_string()
        );
        let source = actual.block.to_token_stream().to_string();
        let context = quote::quote!(NativeConsumerContext::human).to_string();
        let delegation = quote::quote!(sink.request.with_restored_current).to_string();
        let enabled = quote::quote!(setup.delegated = true).to_string();
        let consumer = quote::quote!(Consumer::from_restored).to_string();
        for step in [&context, &delegation, &enabled, &consumer] {
            assert_eq!(source.matches(step).count(), 1);
        }
        assert!(
            source.find(&context) < source.find(&enabled)
                && source.find(&enabled) < source.find(&delegation)
                && source.find(&delegation) < source.find(&consumer)
        );
        #[derive(Default)]
        struct Setups(Vec<syn::ExprStruct>);
        impl<'ast> syn::visit::Visit<'ast> for Setups {
            fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
                if value.path.is_ident("HumanSetup") {
                    self.0.push(value.clone());
                }
                syn::visit::visit_expr_struct(self, value);
            }
        }
        let mut setups = Setups::default();
        syn::visit::Visit::visit_block(&mut setups, &actual.block);
        let [cleanup] = setups.0.as_slice() else {
            panic!("one actual negative setup guard");
        };
        let expected_cleanup: syn::ExprStruct = syn::parse_quote!(HumanSetup {
            owner: self,
            sink,
            delegated: false
        });
        let fields = |value: &syn::ExprStruct| {
            value
                .fields
                .iter()
                .map(|field| field.to_token_stream().to_string())
                .collect::<Vec<_>>()
        };
        assert!(cleanup.attrs.is_empty() && cleanup.qself.is_none() && cleanup.rest.is_none());
        assert_eq!(fields(cleanup), fields(&expected_cleanup));
        let cleanup = cleanup.to_token_stream().to_string();
        let borrow = quote::quote!(self.source.try_borrow_mut()).to_string();
        assert_eq!(source.matches(&cleanup).count(), 1);
        assert!(source.find(&cleanup) < source.find(&borrow));
        assert!(
            !source.contains("NativeConsumerContext :: runtime")
                && !source.contains("begin_current_request")
        );
        let mut changed = actual.block.clone();
        *changed.stmts.last_mut().unwrap() = syn::Stmt::Expr(
            syn::parse_quote!(match result {
                Ok(result) => {
                    if result.is_err() {
                        self.refuse();
                    }
                    result
                }
                Err(payload) => std::panic::resume_unwind(payload),
            }),
            None,
        );
        assert_ne!(
            changed.stmts.last().unwrap().to_token_stream().to_string(),
            actual
                .block
                .stmts
                .last()
                .unwrap()
                .to_token_stream()
                .to_string()
        );
    }

    #[test]
    fn runtime_capture_checks_full_selection_before_moving_the_same_nominal_lease() {
        use quote::ToTokens;
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let method = |name: &str| {
            file.items.iter().find_map(|item| {
                let syn::Item::Impl(item) = item else { return None; };
                if !matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("RuntimeRequest")) { return None; }
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item), _ => None,
                })
            }).unwrap()
        };
        let capture = method("capture");
        let expected: syn::Block = syn::parse_quote!({
            super::require_new_runtime_frame()?;
            let registry = OWNERS.with(Rc::clone);
            let actual = {
                let mut entries = registry.try_borrow_mut()?;
                ensure!(
                    !entries.reserved.contains_key(runtime.app()),
                    "native operation owner busy"
                );
                let owner = entries
                    .available
                    .get_mut(runtime.app())
                    .context("native autonomous owner missing")?;
                let scope = super::sql_runtime_scope(runtime)?;
                require_autonomous_selection(owner.kind, owner.selection.scope(), &scope)?;
                let OwnerSource::Restored { routing, .. } = &mut owner.source else {
                    anyhow::bail!("native restored autonomous source missing");
                };
                let routing = routing.try_borrow_mut()?;
                ensure!(
                    std::ptr::eq(std::sync::Arc::as_ptr(&routing.runtime), runtime),
                    "native autonomous Runtime changed"
                );
                std::sync::Arc::clone(&routing.runtime)
            };
        });
        let guarded = |body: &syn::Block| {
            body.stmts
                .iter()
                .take(3)
                .map(|stmt| stmt.to_token_stream().to_string())
                .collect::<Vec<_>>()
                == expected
                    .stmts
                    .iter()
                    .map(|stmt| stmt.to_token_stream().to_string())
                    .collect::<Vec<_>>()
        };
        assert!(guarded(&capture.block));
        for index in 0..3 {
            let mut changed = capture.block.clone();
            changed.stmts.remove(index);
            assert!(!guarded(&changed));
        }
        let source = capture.block.to_token_stream().to_string();
        for (before, after) in [
            (
                quote::quote!(require_autonomous_selection(
                    owner.kind,
                    owner.selection.scope(),
                    &scope
                )),
                quote::quote!(Ok(())),
            ),
            (
                quote::quote!(std::ptr::eq(
                    std::sync::Arc::as_ptr(&routing.runtime),
                    runtime
                )),
                quote::quote!(true),
            ),
        ] {
            let before = before.to_string();
            assert_eq!(source.matches(&before).count(), 1);
            let changed: syn::Block =
                syn::parse_str(&source.replacen(&before, &after.to_string(), 1)).unwrap();
            assert!(!guarded(&changed));
        }
        let moved = quote::quote!(Lease::acquire_runtime(
            registry,
            runtime.app(),
            &frame.identity
        ))
        .to_string();
        let saved = quote::quote!(
            frame
                .request
                .capture_restored_app(&frame.scope, &mut routing.parent)
        )
        .to_string();
        assert_eq!(source.matches(&moved).count(), 1);
        assert_eq!(source.matches(&saved).count(), 1);
        assert!(source.find(&moved) < source.find(&saved));
        assert!(
            !source.contains("ResponseIdentity")
                && !source.contains("Sink :: new")
                && !source.contains("response_tickets")
        );
        let finished = method("finish").block.to_token_stream().to_string();
        let final_context = quote::quote!(NativeRequestFinalContext::runtime_operation(
            &self.runtime,
            self,
            &request
        ))
        .to_string();
        let native_finish =
            quote::quote!(request.finish_restored(&mut routing.parent, context)).to_string();
        let known = quote::quote!(lease.known = true).to_string();
        assert_eq!(finished.matches(&final_context).count(), 1);
        assert_eq!(finished.matches(&native_finish).count(), 1);
        assert!(
            finished.find(&final_context) < finished.find(&native_finish)
                && finished.find(&native_finish) < finished.find(&known)
        );
        assert!(!finished.contains("capture_restored_app") && !finished.contains("Sink :: new"));
    }

    #[test]
    fn human_setup_refuses_both_real_negative_roots_before_a_held_source_can_escape() -> Result<()>
    {
        use crate::security_epoch::native_enrollment::{
            negative_parent_refusal_roots, new_negative_parent_refusal_fixture,
        };
        let sink = Sink::new();
        let retained = sink.clone();
        let parent = Rc::new(new_negative_parent_refusal_fixture());
        let refused = Rc::new(Cell::new(false));
        let live = Rc::new(Cell::new(true));
        assert!(
            sink.request_owner
                .abort
                .set(AbortRoots(
                    Rc::clone(&refused),
                    Rc::downgrade(&live),
                    Rc::clone(&parent)
                ))
                .is_ok()
        );
        let held = retained.request_owner.source.borrow_mut();
        let intent = crate::oauth::fresh_auth::FreshIntent::fixture_oauth(
            &crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "alice".into(),
            },
            "human-held-setup",
            &day2_capabilities::Digest::new(b"same human setup"),
            "https://security.example.com",
            5,
            305,
        )?;
        let guard = super::super::ConsumerGuard {
            intent: intent.clone(),
            role: NativeRole::AppHost,
            armed: Cell::new(false),
            settled: false,
            local: std::marker::PhantomData,
        };
        let mut entered = false;
        let result = sink.request_owner.with_human_consumer(
            &sink,
            &intent,
            super::super::Phase::Pending,
            5,
            &guard,
            |_| {
                entered = true;
                Ok(())
            },
        );
        assert!(
            result
                .unwrap_err()
                .downcast_ref::<std::cell::BorrowMutError>()
                .is_some()
        );
        assert!(!entered);
        assert!(retained.request_owner.refused.get() && refused.get());
        assert!(!retained.is_open());
        assert_eq!(negative_parent_refusal_roots(&parent), [true, true]);
        drop(held);
        assert!(
            retained
                .request_owner
                .with_human_consumer(
                    &retained,
                    &intent,
                    super::super::Phase::Pending,
                    5,
                    &guard,
                    |_| {
                        entered = true;
                        Ok(())
                    }
                )
                .is_err()
        );
        assert!(!entered);
        Ok(())
    }

    #[test]
    fn nominal_runtime_lease_cannot_become_http_or_be_refused_by_a_foreign_http_identity() {
        let Fixture { registry, .. } = fixture();
        let actual = Rc::new(());
        let other = Rc::new(());
        let http = ResponseIdentity::new();
        let lease = Lease::acquire_runtime(registry.clone(), "calendar", &actual).unwrap();
        assert!(lease.identity.same_runtime(&actual));
        assert!(!lease.identity.same_runtime(&other));
        assert!(!lease.identity.same_http(&http));
        assert!(lease.identity.http().is_err());
        assert!(!lease.identity.same(&LeaseIdentity::Http(http.clone())));
        registry.borrow().refuse_for(&http);
        assert!(!lease.refused.get());
        assert!(Lease::acquire(registry.clone(), "calendar", &http, None).is_err());
        assert!(Lease::acquire_runtime(registry.clone(), "calendar", &other).is_err());
        assert!(!lease.refused.get());
        drop(lease);
    }

    #[test]
    fn runtime_attempt_refuses_on_error_or_unwind_even_when_locator_clones_and_slot_loans_survive()
    -> Result<()> {
        use crate::security_epoch::native_enrollment::{
            negative_parent_refusal_roots, new_negative_parent_refusal_fixture,
        };
        let directory = tempfile::tempdir()?;
        let (runtime, _, _) = crate::oauth::admission::tests::management_fixture(directory.path())?;
        let runtime = std::sync::Arc::new(runtime);
        for panic in [false, true] {
            let Fixture { registry, .. } = fixture();
            let identity = Rc::new(());
            let lease = Lease::acquire_runtime(registry, "calendar", &identity)?;
            let parent = Rc::new(new_negative_parent_refusal_fixture());
            // Negative-only frame: ordinary Runtime and NO actual Owners.
            // It cannot pass require_runtime, capture, native unit or finish.
            let frame = Rc::new(RuntimeRequest {
                identity,
                runtime: std::sync::Arc::clone(&runtime),
                scope: AuthorityScope {
                    installation: "fixture".to_owned().try_into()?,
                    environment: "test".to_owned().try_into()?,
                    app: "calendar".to_owned().try_into()?,
                },
                request: super::super::request::Request::new(),
                lease: RefCell::new(None),
                abort: std::cell::OnceCell::new(),
                refused: Cell::new(false),
                complete: Cell::new(false),
            });
            assert!(
                frame
                    .abort
                    .set(AbortRoots(
                        Rc::clone(&lease.refused),
                        Rc::downgrade(&lease.live),
                        Rc::clone(&parent)
                    ))
                    .is_ok()
            );
            let retained = Rc::clone(&frame);
            let held = retained.lease.borrow_mut();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                RuntimeRequest::run_captured(frame, || -> Result<()> {
                    if panic {
                        std::panic::panic_any(23u8);
                    }
                    anyhow::bail!("actual callback refusal")
                })
            }));
            if panic {
                assert_eq!(*result.unwrap_err().downcast::<u8>().unwrap(), 23);
            } else {
                assert_eq!(
                    result.unwrap().unwrap_err().to_string(),
                    "actual callback refusal"
                );
            }
            assert!(retained.refused.get());
            assert!(lease.refused.get());
            assert_eq!(negative_parent_refusal_roots(&parent), [true, true]);
            assert!(super::super::require_new_runtime_frame().is_ok());
            drop(held);
            drop(lease);
        }
        Ok(())
    }

    #[test]
    fn old_early_abort_after_known_return_cannot_refuse_the_reused_parent_or_next_lease() {
        use crate::security_epoch::native_enrollment::{
            negative_parent_refusal_roots, new_negative_parent_refusal_fixture,
        };
        let Fixture {
            registry, refused, ..
        } = fixture();
        let mut lease =
            Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None).unwrap();
        let parent = Rc::new(new_negative_parent_refusal_fixture());
        let old = early_negative_fixture(&lease, Rc::clone(&parent));
        let retired_live = Rc::clone(&lease.live);
        lease.known = true; // Generic material bookkeeping, not native settlement.
        drop(lease);
        assert!(!retired_live.get());
        assert!(old.abort.get().unwrap().1.upgrade().is_some());
        assert_eq!(negative_parent_refusal_roots(&parent), [false, false]);
        assert!(!refused.get());
        let next =
            Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None).unwrap();
        let fresh = early_negative_fixture(&next, Rc::clone(&parent));
        let held = old.source.borrow_mut();
        old.refuse();
        old.refuse();
        assert!(!next.refused.get());
        assert_eq!(negative_parent_refusal_roots(&parent), [false, false]);
        drop(held);
        fresh.refuse();
        assert!(next.refused.get());
        assert_eq!(negative_parent_refusal_roots(&parent), [true, true]);
        drop(next);
        assert!(refused.get());
    }

    #[test]
    fn registry_value_drop_invokes_the_actual_negative_projection_before_loaned_material_drops() {
        use crate::security_epoch::native_enrollment::{
            negative_parent_refusal_roots, new_negative_parent_refusal_fixture,
        };
        let Fixture {
            registry, dropped, ..
        } = fixture();
        let lease =
            Lease::acquire(registry.clone(), "calendar", &ResponseIdentity::new(), None).unwrap();
        // Populate only the negative projection in the actual generic core.
        // No accepted App, native owner, Current or positive loan is built.
        let parent = Rc::new(new_negative_parent_refusal_fixture());
        registry
            .borrow_mut()
            .reserved
            .get_mut("calendar")
            .unwrap()
            .parent_refusal = Some(Rc::clone(&parent));
        let mut held = registry.borrow_mut();
        let old = std::mem::take(&mut *held);
        drop(old);
        assert!(lease.refused.get());
        assert_eq!(negative_parent_refusal_roots(&parent), [true, true]);
        assert_eq!(dropped.get(), 0);
        drop(held);
        drop(lease);
        assert_eq!(dropped.get(), 1);
    }

    #[test]
    fn finite_human_classification_keeps_the_actual_early_lease_when_registry_is_empty() -> Result<()> {
        let intent = FreshIntent::fixture_oauth(
            &crate::iap::Verified { email: "alice@example.com".into(), subject: "alice".into() },
            "finite-human-original", &day2_capabilities::Digest::new(b"finite-human"),
            "https://security.example.com", 5, 50,
        )?;
        // The actual reservation/identity/liveness predicate with inert DATA
        // only. No native owner, participant or successful Current is forged.
        let Fixture { registry, .. } = fixture();
        let material = registry.borrow_mut().remove("calendar").unwrap();
        registry.borrow_mut().insert(intent.app().into(), material);
        let sink = Sink::new();
        let lease = Lease::acquire(registry.clone(), intent.app(), &sink.identity, None)?;
        assert!(registry.borrow().available.is_empty());
        assert!(registry.borrow().reserved.contains_key(intent.app()));
        require_finite_http_lease(&lease, intent.app(), &sink.identity)?;
        let binding = super::super::ResponseBinding {
            intent: intent.clone(), connection: Some(sink.identity.clone()),
        };
        binding.require_bound(&intent, &sink.identity)?;
        let foreign = Sink::new();
        assert!(require_finite_http_lease(&lease, intent.app(), &foreign.identity).is_err());
        assert!(require_finite_http_lease(&lease, "another-app", &sink.identity).is_err());
        assert!(binding.require_bound(&intent, &foreign.identity).is_err());
        // Foreign classification DATA does not mutate the rightful lease.
        require_finite_http_lease(&lease, intent.app(), &sink.identity)?;
        assert!(!lease.refused.get());
        registry.borrow_mut().clear();
        assert!(require_finite_http_lease(&lease, intent.app(), &sink.identity).is_err());
        for cut in 0..6 {
            let Fixture { registry, .. } = fixture();
            let sink = Sink::new();
            let mut lease = Lease::acquire(registry, "calendar", &sink.identity, None)?;
            match cut {
                0 => lease.known = true,
                1 => lease.refused.set(true),
                2 => lease.live.set(false),
                3 => { drop(lease.owners.take()); }
                4 => lease.identity = LeaseIdentity::Runtime(Rc::new(())),
                _ => lease.identity = LeaseIdentity::Http(Sink::new().identity.clone()),
            }
            assert!(require_finite_http_lease(&lease, "calendar", &sink.identity).is_err(), "cut {cut}");
        }
        Ok(())
    }

    #[test]
    fn actual_finite_human_dispatch_precedes_registry_and_cannot_fall_back_after_restored_failure() {
        use quote::ToTokens;
        fn dispatch(body: &syn::Block) -> bool {
            let expected: syn::Stmt = syn::parse_quote! {
                if sink.request_owner.prepare_finite_human(sink, &binding.intent)? {
                    return Ok(());
                }
            };
            let found = body.stmts.iter().enumerate().filter_map(|(i, item)|
                (item.to_token_stream().to_string() == expected.to_token_stream().to_string()).then_some(i)
            ).collect::<Vec<_>>();
            found.len() == 1 && found[0] + 2 == body.stmts.len()
                && matches!(body.stmts.last(), Some(syn::Stmt::Expr(syn::Expr::MethodCall(call), None))
                    if call.method == "with" && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("OWNERS")))
        }
        let file = syn::parse_file(include_str!("response.rs")).unwrap();
        let actual = file.items.iter().find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "require_finite_binding" => Some(item), _ => None,
        }).unwrap();
        assert!(dispatch(&actual.block));
        let index = actual.block.stmts.len() - 2;
        let mut deleted = actual.block.clone();
        deleted.stmts.remove(index);
        assert!(!dispatch(&deleted), "the previous registry-only path must fail");
        let mut late = actual.block.clone();
        late.stmts.swap(index, index + 1);
        assert!(!dispatch(&late));
        let mut bypass = actual.block.clone();
        bypass.stmts[index] = syn::parse_quote! {
            if sink.request_owner.prepare_finite_human(sink, &binding.intent).unwrap_or(false) {
                return Ok(());
            }
        };
        assert!(!dispatch(&bypass));
        let mut reclassified = actual.block.clone();
        reclassified.stmts[index] = syn::parse_quote! { if false { return Ok(()); } };
        assert!(!dispatch(&reclassified));
    }

    #[test]
    fn actual_restored_finite_preflight_keeps_closed_source_clock_and_capture_checks() {
        use quote::ToTokens;
        use syn::{parse::Parser, visit_mut::VisitMut};
        // Compare parsed expressions while ignoring optional call-list trailing
        // punctuation only. Tuple arity, argument order and every expression
        // node remain part of the guard.
        fn same(left: &syn::Stmt, right: &syn::Stmt) -> bool {
            struct Calls;
            impl VisitMut for Calls {
                fn visit_expr_call_mut(&mut self, item: &mut syn::ExprCall) {
                    item.args = item.args.iter().cloned().collect();
                    syn::visit_mut::visit_expr_call_mut(self, item);
                }
                fn visit_expr_method_call_mut(&mut self, item: &mut syn::ExprMethodCall) {
                    item.args = item.args.iter().cloned().collect();
                    syn::visit_mut::visit_expr_method_call_mut(self, item);
                }
            }
            let (mut left, mut right) = (left.clone(), right.clone());
            Calls.visit_stmt_mut(&mut left);
            Calls.visit_stmt_mut(&mut right);
            left.to_token_stream().to_string() == right.to_token_stream().to_string()
        }
        fn ensured(statement: &syn::Stmt, predicate: syn::Expr, message: &str) -> bool {
            let mac = match statement {
                syn::Stmt::Macro(item) => &item.mac,
                syn::Stmt::Expr(syn::Expr::Macro(item), _) => &item.mac,
                _ => return false,
            };
            if !mac.path.is_ident("ensure") { return false; }
            let Ok(args) = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated.parse2(mac.tokens.clone()) else { return false; };
            args.len() == 2 && args[0].to_token_stream().to_string() == predicate.to_token_stream().to_string()
                && matches!(&args[1], syn::Expr::Lit(item) if matches!(&item.lit, syn::Lit::Str(value) if value.value() == message))
        }
        fn restored(body: &syn::Block) -> bool {
            if body.stmts.len() != 10 { return false; }
            let expected: [(usize, syn::Stmt); 8] = [
                (0, syn::parse_quote!(require_finite_http_lease(lease, intent.app(), &sink.identity)?;)),
                (1, syn::parse_quote!(let owner = lease.owners.as_ref().context("native finite owner missing")?;)),
                (3, syn::parse_quote!(let stored = owner.originals.get(intent.attempt()).context("native finite original missing")?;)),
                (4, syn::parse_quote!(stored.response.require_bound(intent, &sink.identity)?;)),
                (5, syn::parse_quote!(let OwnerSource::Restored { routing, .. } = &owner.source else { anyhow::bail!("native finite parent changed"); };)),
                (6, syn::parse_quote!(let EnrolledClockSource::Restored(expected) = &stored.original.clock.source else { anyhow::bail!("native finite clock source changed"); };)),
                (8, syn::parse_quote!(sink.request.consumer_origin(owner.selection.scope(), NativeRole::AppHost)?.require_request(&sink.request)?;)),
                (9, syn::Stmt::Expr(syn::parse_quote!(Ok(true)), None)),
            ];
            expected.iter().all(|(index, expected)| same(&body.stmts[*index], expected))
                && ensured(&body.stmts[2], syn::parse_quote!(owner.kind == NativeRole::AppHost && owner.selection.scope().app.as_str() == intent.app()), "native finite owner selection changed")
                && ensured(&body.stmts[7], syn::parse_quote!(owner.selection == stored.original.clock.selection && Rc::ptr_eq(&routing.slot, &expected.slot)), "native finite clock parent changed")
        }
        let actual = request_owner_method("prepare_finite_human");
        let [syn::Stmt::Local(result), _] = actual.block.stmts.as_slice() else { panic!("actual guarded preflight"); };
        assert!(matches!(&result.pat, syn::Pat::Ident(id) if id.ident == "result"));
        let syn::Expr::Call(catch) = &*result.init.as_ref().unwrap().expr else { panic!("actual catch"); };
        assert_eq!(catch.func.to_token_stream().to_string(), "std :: panic :: catch_unwind");
        assert_eq!(catch.args.len(), 1);
        let syn::Expr::Call(safe) = &catch.args[0] else { panic!("actual unwind-safe wrapper"); };
        assert_eq!(safe.func.to_token_stream().to_string(), "std :: panic :: AssertUnwindSafe");
        assert_eq!(safe.args.len(), 1);
        let syn::Expr::Closure(closed) = &safe.args[0] else { panic!("actual synchronous operation"); };
        assert!(closed.inputs.is_empty() && closed.asyncness.is_none() && closed.capture.is_none());
        let syn::Expr::Block(closed) = &*closed.body else { panic!("actual operation block"); };
        let [entry, source, syn::Stmt::Expr(syn::Expr::Match(selected), None)] = closed.block.stmts.as_slice() else { panic!("entry check then same source and fixed dispatch only"); };
        assert!(ensured(entry, syn::parse_quote!(!self.refused.get() && sink.is_open()), "native request owner refused"));
        assert!(same(source, &syn::parse_quote!(let source = self.source.try_borrow()?;)));
        assert_eq!(selected.expr.to_token_stream().to_string(), "& * source");
        let initial: syn::Expr = syn::parse_quote!(Ok(false));
        let refused: syn::Expr = syn::parse_quote!(anyhow::bail!("native finite request owner unavailable"));
        assert_eq!(selected.arms.len(), 3);
        assert!(selected.arms.iter().all(|arm| arm.guard.is_none()));
        assert_eq!(selected.arms[0].pat.to_token_stream().to_string(), "RequestOwnerSource :: Initial");
        assert_eq!(selected.arms[0].body.to_token_stream().to_string(), initial.to_token_stream().to_string());
        assert_eq!(selected.arms[1].pat.to_token_stream().to_string(), "RequestOwnerSource :: Restored (lease)");
        assert!(matches!(selected.arms[2].pat, syn::Pat::Wild(_)));
        assert_eq!(selected.arms[2].body.to_token_stream().to_string(), refused.to_token_stream().to_string());
        let syn::Expr::Block(actual_restored) = &*selected.arms[1].body else { panic!("actual restored preflight"); };
        assert!(restored(&actual_restored.block));
        for index in 0..actual_restored.block.stmts.len() {
            let mut deleted = actual_restored.block.clone();
            deleted.stmts.remove(index);
            assert!(!restored(&deleted));
        }
        for (index, replacement) in [
            (0, syn::parse_quote!(require_finite_http_lease(lease, intent.app(), &other.identity)?;)),
            (4, syn::parse_quote!(stored.response.require_bound(other, &sink.identity)?;)),
            (6, syn::parse_quote!(let EnrolledClockSource::Initial(expected) = &stored.original.clock.source else { anyhow::bail!("native finite clock source changed"); };)),
            (7, syn::parse_quote!(ensure!(owner.selection == stored.original.clock.selection, "native finite clock parent changed");)),
            (8, syn::parse_quote!(sink.request.consumer_origin(owner.selection.scope(), NativeRole::AppHost)?.require_request(&other.request)?;)),
        ] {
            let mut changed = actual_restored.block.clone();
            changed.stmts[index] = replacement;
            assert!(!restored(&changed));
        }
        let wrapper: syn::Stmt = syn::parse_quote! {
            match result {
                Ok(result) => { if result.is_err() { self.refuse(); sink.abort(); } result }
                Err(payload) => { self.refuse(); sink.abort(); std::panic::resume_unwind(payload) }
            }
        };
        assert!(same(actual.block.stmts.last().unwrap(), &wrapper));
        let body = actual.block.to_token_stream().to_string();
        for forbidden in ["OWNERS", "begin_current", "NativeAcquisition", "prepare_runtime", "unwrap_or"] {
            assert!(!body.contains(forbidden), "{forbidden}");
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
                identity: lease.identity.http().unwrap().clone(),
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
            identity: lease.identity.http().unwrap().clone(),
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
            identity: lease.identity.http().unwrap().clone(),
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
                identity: lease.identity.http().unwrap().clone(),
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
                    identity: next.identity.http().unwrap().clone(),
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
                parent: None,
                incarnation: 1,
                refused: Rc::new(Cell::new(false)),
                dropped: dropped.clone(),
            });
            let mut held = role.take().unwrap();
            held.known = true;
            if replacement {
                *role.slot.borrow_mut() = RoleSlot {
                    owner: Some(Material {
                        parent: None,
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
            parent: None,
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
    fn known_return_collision_refuses_its_own_latch_and_preserves_the_replacement() {
        let Fixture {
            registry, refused, ..
        } = fixture();
        let identity = Rc::new(());
        let mut lease = Lease::acquire_runtime(registry.clone(), "calendar", &identity).unwrap();
        let outcome = Rc::clone(&lease.refused);
        let replacement = Rc::new(Cell::new(false));
        registry.borrow_mut().available.insert(
            "calendar".into(),
            Material {
                parent: None,
                incarnation: 2,
                refused: Rc::clone(&replacement),
                dropped: Rc::new(Cell::new(0)),
            },
        );
        lease.known = true;
        drop(lease);
        assert!(
            outcome.get(),
            "a refused native owner return cannot report a known action"
        );
        assert!(refused.get());
        assert!(!replacement.get());
        assert_eq!(registry.borrow()["calendar"].incarnation, 2);
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
                    parent: None,
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
                identity: LeaseIdentity::Http(identity.clone()),
                refused: marker.clone(),
                parent_refusal: None,
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
