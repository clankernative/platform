//! Same-stage read material retained independently of a long mutable stage
//! borrow. Every use reborrows the SAME actual enrollment and original clock.
//! No parsed identity, renewed role, token alone or mutable caller callback can
//! construct this owner. Its short I/O borrow remains read-only.

use super::{AuthenticatedReads, ReadScope};
use crate::security_epoch::{
    controller::preparation_timing::{Operation, Timings},
    credential_material::CredentialMaterial,
    firestore::{Budget, EpochObservation, EpochReply, Port, Sample},
    native_clock::NativeAcquisition,
    native_enrollment::{EnrolledRoleStage, SameEnrolledOwner},
    native_identity::NativeProcessObservation,
    transport::{NativeHttp, Route},
};
use anyhow::{Result, ensure};
use day2_capabilities::{
    Digest,
    security_epoch::{
        EpochStore,
        bootstrap::{InitialBootstrapPolicy, NativeRole},
    },
};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::Duration,
};

// The fixed writer is a lexical child so it can consume this material while
// every field stays private. No credential/HTTP getter or raw-parts factory.
mod provider;
mod writer;
pub(in crate::security_epoch) use provider::StorageMetadataRead;
pub(in crate::security_epoch) use writer::ControllerBorrow;
pub(crate) use writer::ControllerPort;

pub(crate) struct RetainedEpochReads {
    scope: ReadScope,
    owner: SameEnrolledOwner,
    policy: InitialBootstrapPolicy,
    purpose: NativeRole,
    store: EpochStore,
    http: NativeHttp,
    credential: CredentialMaterial,
    source: CredentialMaterial,
    kubernetes: CredentialMaterial,
    acquisition: NativeAcquisition,
    process: NativeProcessObservation,
    selection: Digest,
    valid: bool,
    timings: Timings,
}

// One actual authenticated owner, with two closed same-thread facades. There
// is no phase backedge, raw-material getter, Clone or scalar constructor.
struct ControllerReadState {
    material: RefCell<RetainedEpochReads>,
    gate: Rc<SharedUseGate>,
}

// DATA-only single-thread use gate, not a role or permission constructor.
// An exclusive use spends availability. Only its actual non-Clone token can
// complete it. Broader continuation guards also refuse on error or unwind;
// neither kind grants authority or performs I/O during Drop.
struct SharedUseGate {
    valid: Cell<bool>,
    available: Cell<bool>,
}

pub(in crate::security_epoch) struct RefusalGuard {
    gate: Rc<SharedUseGate>,
    exclusive: bool,
    completed: bool,
}

impl SharedUseGate {
    fn new() -> Self {
        Self {
            valid: Cell::new(true),
            available: Cell::new(true),
        }
    }

    fn enter(self: &Rc<Self>) -> Result<RefusalGuard> {
        if !self.valid.get() || !self.available.replace(false) {
            self.valid.set(false);
            anyhow::bail!("epoch_shared_authentication_refused");
        }
        Ok(RefusalGuard {
            gate: Rc::clone(self),
            exclusive: true,
            completed: false,
        })
    }

    fn guard(self: &Rc<Self>) -> Result<RefusalGuard> {
        if !self.valid.get() || !self.available.get() {
            self.refuse();
            anyhow::bail!("epoch_shared_authentication_refused");
        }
        Ok(RefusalGuard {
            gate: Rc::clone(self),
            exclusive: false,
            completed: false,
        })
    }

    fn refuse(&self) {
        self.valid.set(false);
        self.available.set(false);
    }
}

impl RefusalGuard {
    pub(in crate::security_epoch) fn complete(mut self) -> Result<()> {
        ensure!(
            self.gate.valid.get() && self.gate.available.get() != self.exclusive,
            "epoch_shared_authentication_refused"
        );
        if self.exclusive {
            self.gate.available.set(true);
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for RefusalGuard {
    fn drop(&mut self) {
        // Refusal only: no I/O, grant, clock sampling or successful completion.
        if !self.completed {
            self.gate.refuse();
        }
    }
}

pub(crate) struct ControllerEpochReads {
    state: Rc<ControllerReadState>,
}

pub(crate) struct ProviderEpochReads {
    state: Rc<ControllerReadState>,
}

// Production compiler controls, not cfg(test) owners or native proof fixtures.
const _: () = {
    macro_rules! assert_not_impl {
        ($type:ty, $trait:path) => {{
            trait AmbiguousIfImpl<A> {
                fn check() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            impl<T: ?Sized + $trait> AmbiguousIfImpl<u8> for T {}
            let _ = <$type as AmbiguousIfImpl<_>>::check;
        }};
    }
    macro_rules! assert_local_material {
        ($type:ty) => {
            assert_not_impl!($type, Clone);
            assert_not_impl!($type, Copy);
            assert_not_impl!($type, Default);
            assert_not_impl!($type, serde::Serialize);
            assert_not_impl!($type, serde::Deserialize<'static>);
            assert_not_impl!($type, std::fmt::Debug);
            assert_not_impl!($type, Send);
            assert_not_impl!($type, Sync);
        };
    }
    assert_local_material!(ControllerEpochReads);
    assert_local_material!(ProviderEpochReads);
    assert_local_material!(RefusalGuard);
};

impl ControllerReadState {
    fn refuse(&self) {
        // Refusal remains sticky even if an internal borrow is unavailable.
        self.gate.refuse();
        if let Ok(mut material) = self.material.try_borrow_mut() {
            material.refuse();
        }
    }
}

impl ControllerEpochReads {
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.state.refuse();
    }

    /// Closed authentication observation against an actual owning stage. Only
    /// this facade borrows its own hidden material; callers cannot substitute
    /// another material object or obtain the stage, credentials or a proof.
    pub(in crate::security_epoch) fn check_stage(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<()> {
        let result = (|| {
            let borrow = self.state.gate.enter()?;
            let mut material = self.state.material.try_borrow_mut()?;
            ensure!(
                material.scope == ReadScope::StorageBootstrap,
                "epoch_bootstrap_read_purpose_changed"
            );
            material.check_bootstrap(stage, policy, store)?;
            drop(material);
            borrow.complete()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

impl AuthenticatedReads<'_, '_> {
    pub(in crate::security_epoch) fn retain_storage_bootstrap(self) -> Result<RetainedEpochReads> {
        self.retain_scoped(ReadScope::StorageBootstrap)
    }

    pub(in crate::security_epoch) fn retain_storage_metadata_observation(
        self,
    ) -> Result<RetainedEpochReads> {
        self.retain_scoped(ReadScope::StorageMetadataObservation)
    }

    fn retain_scoped(mut self, expected: ReadScope) -> Result<RetainedEpochReads> {
        if self.scope != expected {
            self.acquisition.refuse();
            anyhow::bail!("epoch_native_retained_purpose_changed");
        }
        self.sample()?;
        let owner = self.stage.capture_same_owner()?;
        self.sample()?;
        let Self {
            scope,
            stage,
            policy,
            purpose,
            store,
            http,
            credential,
            source,
            kubernetes,
            acquisition,
            process,
            selection,
            ..
        } = self;
        ensure!(
            scope != ReadScope::Current,
            "epoch_retained_current_factory_removed"
        );
        let acquisition = stage
            .storage()?
            .complete_storage_authentication(acquisition, store.max_lease_seconds)?;
        Ok(RetainedEpochReads {
            scope,
            owner,
            policy,
            purpose,
            store,
            http,
            credential,
            source,
            kubernetes,
            acquisition,
            process,
            selection,
            valid: true,
            timings: Timings::disabled(),
        })
    }
}

impl RetainedEpochReads {
    /// Consume the genuine full authentication exactly once. Both facades
    /// spend the SAME original Current interval; only a later actual file/peer
    /// phase can install the fixed writer. No credential or clock is exported.
    pub(in crate::security_epoch) fn into_controller(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        timings: Timings,
    ) -> Result<(ControllerEpochReads, ProviderEpochReads)> {
        stage.require_purpose(
            crate::security_epoch::native_enrollment::StagePurpose::StorageBootstrap,
        )?;
        if self.scope != ReadScope::StorageBootstrap {
            self.refuse();
            anyhow::bail!("epoch_bootstrap_read_purpose_changed");
        }
        self.check_bootstrap(stage, policy, store)?;
        self.timings = timings;
        let state = Rc::new(ControllerReadState {
            material: RefCell::new(self),
            gate: Rc::new(SharedUseGate::new()),
        });
        Ok((
            ControllerEpochReads {
                state: Rc::clone(&state),
            },
            ProviderEpochReads { state },
        ))
    }

    /// The operator-only observation returns only the closed metadata facade;
    /// no Controller facade, file, peer, counter or writer is constructed.
    pub(in crate::security_epoch) fn into_provider_observation(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        timings: Timings,
    ) -> Result<ProviderEpochReads> {
        stage.require_purpose(
            crate::security_epoch::native_enrollment::StagePurpose::StorageMetadataObservation,
        )?;
        if self.scope != ReadScope::StorageMetadataObservation {
            self.refuse();
            anyhow::bail!("epoch_metadata_read_purpose_changed");
        }
        self.check_bootstrap(stage, policy, store)?;
        self.timings = timings;
        Ok(ProviderEpochReads {
            state: Rc::new(ControllerReadState {
                material: RefCell::new(self),
                gate: Rc::new(SharedUseGate::new()),
            }),
        })
    }

    /// The fixed writer must consume the SAME original read material after
    /// the actual current file/peer join, never a later stage of the same owner.
    fn check_bootstrap(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<()> {
        let result = (|| {
            stage.check_selection(policy, store, NativeRole::EpochController)?;
            ensure!(
                self.purpose == NativeRole::EpochController
                    && self.scope != ReadScope::Current
                    && self.policy == *policy
                    && self.store == *store
                    && self.selection == Digest::of(store)?,
                "epoch_bootstrap_read_selection_changed"
            );
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.sample(stage).map(|_| ())
    }

    fn sample(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<Sample> {
        let timings = self.timings.clone();
        let result = timings.measure(Operation::AuthenticationCheck, || {
            ensure!(self.valid, "epoch_retained_read_refused");
            // This child samples THIS actual stage's original domain; it
            // neither begins a new interval nor renews our retained owner.
            let same_stage = match self.scope {
                ReadScope::Current => {
                    anyhow::bail!("epoch_retained_current_factory_removed")
                }
                ReadScope::StorageBootstrap | ReadScope::StorageMetadataObservation => {
                    self.owner.check(stage)?;
                    stage.check_selection(&self.policy, &self.store, self.purpose)?;
                    self.scope.require(stage)?;
                    self.scope.io(stage, self.store.max_lease_seconds)?
                }
            };
            self.scope.join(&mut self.acquisition, same_stage)?;
            self.process.check(&mut self.acquisition)?;
            self.acquisition.sample()?;
            self.owner.check(stage)?;
            // Charge the final stage check too; its parent interval may be
            // wider than this retained view or the caller's context budget.
            self.acquisition.sample()
        });
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// The bootstrap counter and slot are one coherent read-only snapshot.
    /// Keep the SAME actual stage before and after its read and rollback.
    pub(in crate::security_epoch) fn read_bootstrap_snapshot(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        selection: &EpochStore,
        core: &crate::security_epoch::control_slot::LogicalCore,
    ) -> Result<(
        EpochObservation,
        crate::security_epoch::control_slot_io::SlotObservation,
    )> {
        let result = (|| {
            ensure!(
                self.scope == ReadScope::StorageBootstrap,
                "epoch_bootstrap_read_purpose_changed"
            );
            ensure!(
                self.selection == Digest::of(selection)?,
                "epoch_retained_read_selection_changed"
            );
            self.check(stage)?;
            let budget = self.acquisition.budget()?;
            let pair = crate::security_epoch::control_slot_io::read_with_counter(
                selection,
                core,
                &mut CurrentReadPort { owner: self, stage },
                budget,
            )?;
            self.check(stage)?;
            Ok(pair)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.valid = false;
        self.acquisition.refuse();
    }

    fn post(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        let result = (|| {
            ensure!(
                self.scope != ReadScope::StorageMetadataObservation,
                "epoch_metadata_only_read_refused"
            );
            self.check(stage)?;
            ensure!(
                max_bytes == 65536 && body.len() <= 65536,
                "epoch_retained_read_budget"
            );
            let route = if url.ends_with("/documents:batchGet") {
                Route::EpochRead
            } else if url.ends_with("/documents:rollback") {
                Route::EpochRollback
            } else {
                anyhow::bail!("epoch_retained_read_write_or_route_refused")
            };
            ensure!(
                self.http.matches(&route, url)?,
                "epoch_retained_read_recipient_changed"
            );
            let authorization = self.credential.authorization()?;
            let timeout = budget
                .remaining_native(&mut self.acquisition)?
                .min(Duration::from_secs(5));
            let bytes = self.http.request_with_ceiling(
                route,
                &authorization,
                Some(body),
                &mut self.acquisition,
                timeout,
            )?;
            self.check(stage)?;
            budget.remaining_native(&mut self.acquisition)?;
            Ok(EpochReply {
                status: 200,
                body: bytes,
            })
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

struct CurrentReadPort<'io, 'stage, 'role> {
    owner: &'io mut RetainedEpochReads,
    stage: &'stage mut EnrolledRoleStage<'role>,
}

impl Port for CurrentReadPort<'_, '_, '_> {
    fn sample(&mut self) -> Result<Sample> {
        self.owner.sample(self.stage)
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        // Ordinary reads retain their previous full pre/post observations.
        let result = (|| {
            budget.remaining(self)?;
            self.owner.post(self.stage, url, body, budget, max_bytes)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn refuse(&mut self) {
        self.owner.refuse();
    }
}

#[cfg(test)]
mod shared_gate_tests {
    // DATA-only synchronization controls. No fake role, process, credential,
    // file phase, authenticated owner or positive native proof is constructed.
    use super::SharedUseGate;
    use std::{
        cell::RefCell,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
    };

    #[test]
    fn successful_borrow_releases_only_availability_and_refusal_never_revives() {
        let gate = Rc::new(SharedUseGate::new());
        let continuation = gate.guard().unwrap();
        gate.enter().unwrap().complete().unwrap();
        continuation.complete().unwrap();
        gate.enter().unwrap().complete().unwrap();
        gate.refuse();
        assert!(gate.enter().is_err());
        assert!(gate.guard().is_err());
        assert_eq!(Rc::strong_count(&gate), 1);
        assert!(Rc::try_unwrap(gate).is_ok());
    }

    #[test]
    fn reentry_and_refcell_borrow_failure_poison_every_facade() {
        for reentry in [false, true] {
            let gate = Rc::new(SharedUseGate::new());
            let sibling = Rc::clone(&gate);
            let material = RefCell::new(());
            let held = material.borrow();
            let guard = gate.enter().unwrap();
            if reentry {
                assert!(sibling.enter().is_err());
                assert!(guard.complete().is_err());
            } else {
                assert!(material.try_borrow_mut().is_err());
                drop(guard);
            }
            drop(held);
            assert!(gate.enter().is_err());
            assert!(sibling.guard().is_err());
        }
    }

    #[test]
    fn failed_semantic_continuation_poisoning_survives_successful_transport_use() {
        let gate = Rc::new(SharedUseGate::new());
        let semantic = gate.guard().unwrap();
        gate.enter().unwrap().complete().unwrap();
        // For example, a later profile/JSON/attachment check fails. Completion
        // of the preceding I/O cannot complete that enclosing obligation.
        drop(semantic);
        assert!(gate.enter().is_err());
    }

    #[test]
    fn unwind_closes_exclusive_and_nonexclusive_continuations() {
        for exclusive in [false, true] {
            let gate = Rc::new(SharedUseGate::new());
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let _guard = if exclusive {
                        gate.enter().unwrap()
                    } else {
                        gate.guard().unwrap()
                    };
                    panic!("interrupted native use");
                }))
                .is_err()
            );
            assert!(gate.enter().is_err());
            assert!(gate.guard().is_err());
        }
    }
}
