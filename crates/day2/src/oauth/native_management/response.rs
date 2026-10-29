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
                        let mut request = first;
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
