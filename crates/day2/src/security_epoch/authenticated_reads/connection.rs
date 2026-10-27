//! Retain actual counter authentication in its admitted connection. Each
//! request borrows that owner with its own existing original interval; no
//! admission clock, historical counter or parsed identity becomes permission.

use super::{AuthenticatedReads, ReadScope};
use crate::security_epoch::{
    controller::evidence::{PreparationFailure, PreparationStep},
    credential_material::CounterMaterial,
    firestore::{self, Budget, EpochObservation, EpochReply, Names, Port, Sample},
    native_clock::NativeAcquisition,
    native_enrollment::{
        EnrolledRoleStage, IdleCredentialAdmission, IdleCredentialPublication, SameEnrolledOwner,
    },
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
use std::{cell::Cell, rc::Rc, time::Duration};

// This state belongs only to the genuine activated storage owner. Failed or
// interrupted cold admission cannot return to Vacant or silently reauthenticate.
pub(in crate::security_epoch) struct CounterConnectionSlot {
    state: CounterConnectionState,
}

enum CounterConnectionState {
    Vacant,
    Admitted(Box<CounterConnection>),
    Refused,
}

pub(in crate::security_epoch) struct CounterConnection {
    owner: SameEnrolledOwner,
    policy: InitialBootstrapPolicy,
    purpose: NativeRole,
    store: EpochStore,
    selection: Digest,
    http: NativeHttp,
    credential: CounterMaterial,
    readmission_hint: bool,
    valid: Rc<Cell<bool>>,
}

pub(in crate::security_epoch) struct CounterRequest<'connection> {
    connection: &'connection mut CounterConnection,
    request: CounterUseGuard,
}

/// Prepared material is not eligible for a request. The actual exclusion
/// capability stays with the caller across its physical postchecks, then must
/// be consumed by publish on this same original. Any earlier exit is terminal.
pub(in crate::security_epoch) struct CounterReadmission<'connection> {
    slot: &'connection mut CounterConnectionSlot,
    connection: Option<Box<CounterConnection>>,
    replacement: Option<CounterMaterial>,
    completion: CounterReadmissionCompletion,
}

// Keep cancellation refusal owned and nongeneric independently of the slot
// borrow. The slot was already closed before this guard is constructed.
struct CounterReadmissionCompletion {
    acquisition: Option<NativeAcquisition>,
    valid: Rc<Cell<bool>>,
    completed: bool,
}

// Own the actual request acquisition independently of the lexical connection
// borrow. Unfinished Drop refuses both its real original and connection gate.
struct CounterUseGuard {
    acquisition: NativeAcquisition,
    valid: Rc<Cell<bool>>,
    completed: bool,
}

impl AuthenticatedReads<'_, '_> {
    fn into_counter_connection(mut self) -> Result<CounterConnection> {
        ensure!(
            self.scope == ReadScope::Current,
            "epoch_counter_connection_purpose"
        );
        self.sample()?;
        let mut owner = self.stage.capture_same_owner()?;
        let selected = super::reader_selection(&self.policy, self.purpose)?;
        let mut credential = self.credential.admit_counter(
            &selected.workload.google_service_account,
            &mut self.acquisition,
        )?;
        credential.check(&mut self.acquisition, self.store.max_lease_seconds)?;
        owner.meet_current_read_view(self.stage, &mut self.acquisition)?;
        // The full caller still owns the same actual role/process and its
        // admission interval. Do not publish on a tokeninfo-only success.
        self.process.check(&mut self.acquisition)?;
        self.scope
            .check_selection(self.stage, &self.policy, &self.store, self.purpose)?;
        credential.check(&mut self.acquisition, self.store.max_lease_seconds)?;
        owner.meet_current_read_view(self.stage, &mut self.acquisition)?;
        self.acquisition.remaining()?;
        Ok(CounterConnection {
            owner,
            policy: self.policy,
            purpose: self.purpose,
            store: self.store,
            selection: self.selection,
            http: self.http,
            credential,
            readmission_hint: true,
            valid: Rc::new(Cell::new(true)),
        })
        // The short-lived source/Kubernetes projections and old admission
        // acquisition/process observation are dropped, not kept as warm grants.
    }
}

impl CounterConnectionSlot {
    pub(in crate::security_epoch) fn new() -> Self {
        Self {
            state: CounterConnectionState::Vacant,
        }
    }

    /// One-shot scheduling DATA. Taking a later request cannot move or reset
    /// this hint, and a missing/refused connection is never treated as idle.
    pub(in crate::security_epoch) fn take_readmission_delay(&mut self) -> Result<Option<Duration>> {
        let CounterConnectionState::Admitted(connection) = &mut self.state else {
            anyhow::bail!("epoch_counter_connection_refused");
        };
        ensure!(connection.valid.get(), "epoch_counter_connection_refused");
        if !connection.readmission_hint {
            return Ok(None);
        }
        // Fresh dispatch DATA from BOOTTIME. Use the fixed material deadline,
        // not an old relative duration that late startup could reschedule.
        let now = crate::security_epoch::native_clock::boottime()?;
        connection.readmission_hint = false;
        Ok(Some(connection.credential.readmission_delay(now)))
    }

    /// A full provider admission on the SAME healthy, genuinely idle native
    /// owner. This is never called from request/failure/expiry fallback.
    pub(in crate::security_epoch) fn prepare_readmission<'connection>(
        &'connection mut self,
        mut idle: IdleCredentialAdmission<'_, '_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        purpose: NativeRole,
    ) -> Result<CounterReadmission<'connection>> {
        let state = std::mem::replace(&mut self.state, CounterConnectionState::Refused);
        let CounterConnectionState::Admitted(connection) = state else {
            anyhow::bail!("epoch_counter_readmission_connection_refused");
        };
        let valid = Rc::clone(&connection.valid);
        let mut pending = CounterReadmission {
            slot: self,
            connection: Some(connection),
            replacement: None,
            completion: CounterReadmissionCompletion {
                acquisition: None,
                valid,
                completed: false,
            },
        };
        let stage = idle.stage()?;
        pending.completion.acquisition =
            Some(stage.narrow_io_acquisition(store.max_lease_seconds)?);
        {
            let connection = pending.connection.as_mut().unwrap();
            let acquisition = pending.completion.acquisition.as_mut().unwrap();
            ensure!(
                connection.valid.get()
                    && connection.policy == *policy
                    && connection.store == *store
                    && connection.purpose == purpose
                    && connection.selection == Digest::of(store)?,
                "epoch_counter_readmission_selection_changed"
            );
            connection.owner.check(stage)?;
            stage.check_current_selection(policy, store, purpose)?;
            // OLD expiry narrows the actual new admission original BEFORE
            // any full provider authentication. It can only become shorter.
            connection
                .credential
                .check(acquisition, store.max_lease_seconds)?;
            connection
                .owner
                .meet_current_read_view(stage, acquisition)?;
            acquisition.remaining()?;
        }
        let mut replacement = AuthenticatedReads::acquire(policy, store, purpose, idle.stage()?)?
            .into_counter_connection()?;
        ensure!(
            replacement.policy == *policy
                && replacement.store == *store
                && replacement.purpose == purpose
                && replacement.selection == Digest::of(store)?,
            "epoch_counter_readmission_recipient_changed"
        );
        replacement.owner.check(idle.stage()?)?;
        // Retain the admitted connection's actual transport/owner. The full
        // authentication's temporary clients/projections drop while its
        // original/exclusion are still live, BEFORE the final postchecks.
        let CounterConnection {
            owner,
            policy: checked_policy,
            purpose: _,
            store: checked_store,
            selection,
            http,
            credential,
            readmission_hint: _,
            valid,
        } = replacement;
        drop((owner, checked_policy, checked_store, selection, http, valid));
        pending.replacement = Some(credential);
        {
            let stage = idle.stage()?;
            let connection = pending.connection.as_mut().unwrap();
            let acquisition = pending.completion.acquisition.as_mut().unwrap();
            let actual = stage.narrow_io_acquisition(store.max_lease_seconds)?;
            acquisition.join_current_view(actual)?;
            connection
                .credential
                .check(acquisition, store.max_lease_seconds)?;
            pending
                .replacement
                .as_mut()
                .unwrap()
                .check(acquisition, store.max_lease_seconds)?;
            connection
                .owner
                .meet_current_read_view(stage, acquisition)?;
            connection.owner.check(stage)?;
            acquisition.remaining()?;
        }
        // Only the temporary borrow is completed. The caller's owned
        // publication capability STILL excludes all request construction.
        idle.finish_known()?;
        Ok(pending)
    }

    /// Cold setup only, before this participant enters its request loop. A
    /// missing, failed or expired connection is never admitted by `request`.
    pub(in crate::security_epoch) fn admit(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        purpose: NativeRole,
    ) -> Result<()> {
        // Close the slot before the first fallible stage operation, including
        // early refusal or unwind before an admission acquisition exists.
        let was_vacant = matches!(&self.state, CounterConnectionState::Vacant);
        self.state = CounterConnectionState::Refused;
        let mut original = stage.narrow_io_acquisition(store.max_lease_seconds)?;
        if !was_vacant {
            original.refuse();
            anyhow::bail!("epoch_counter_connection_admission_already_attempted");
        }
        let result = (|| {
            let connection = AuthenticatedReads::acquire(policy, store, purpose, stage)
                .map_err(|error| {
                    PreparationFailure::at(PreparationStep::CounterProviderAcquire, error)
                })?
                .into_counter_connection()
                .map_err(|error| PreparationFailure::at(PreparationStep::CounterMaterial, error))?;
            stage
                .check_current_selection(policy, store, purpose)
                .map_err(|error| {
                    PreparationFailure::at(PreparationStep::CounterStagePostcheck, error)
                })?;
            original.remaining().map_err(|error| {
                PreparationFailure::at(PreparationStep::CounterOriginalPostcheck, error)
            })?;
            Ok(connection)
        })();
        match result {
            Ok(connection) => {
                self.state = CounterConnectionState::Admitted(Box::new(connection));
                Ok(())
            }
            Err(error) => {
                original.refuse();
                Err(error)
            }
        }
    }

    pub(in crate::security_epoch) fn request<'connection>(
        &'connection mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
        purpose: NativeRole,
    ) -> Result<CounterRequest<'connection>> {
        let mut acquisition = stage.narrow_io_acquisition(store.max_lease_seconds)?;
        if !matches!(&self.state, CounterConnectionState::Admitted(_)) {
            self.refuse();
            acquisition.refuse();
            anyhow::bail!("epoch_counter_connection_refused");
        }
        let CounterConnectionState::Admitted(connection) = &mut self.state else {
            acquisition.refuse();
            anyhow::bail!("epoch_counter_connection_refused");
        };
        let checked = (|| {
            ensure!(
                connection.valid.get()
                    && connection.policy == *policy
                    && connection.store == *store
                    && connection.purpose == purpose
                    && connection.selection == Digest::of(store)?,
                "epoch_counter_connection_selection_changed"
            );
            // Join the actual live admitted process/task/clock anchors before
            // using a token deadline across distinct request domains.
            connection.owner.check(stage)?;
            stage.check_current_selection(policy, store, purpose)?;
            connection
                .credential
                .check(&mut acquisition, store.max_lease_seconds)?;
            connection
                .owner
                .meet_current_read_view(stage, &mut acquisition)?;
            connection.owner.check(stage)?;
            acquisition.remaining()?;
            Ok(())
        })();
        match checked {
            Ok(()) => {
                let request = CounterUseGuard {
                    acquisition,
                    valid: Rc::clone(&connection.valid),
                    completed: false,
                };
                Ok(CounterRequest {
                    connection,
                    request,
                })
            }
            Err(error) => {
                connection.valid.set(false);
                acquisition.refuse();
                Err(error)
            }
        }
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.state = CounterConnectionState::Refused;
    }
}

impl CounterReadmission<'_> {
    /// Call only after the same actual physical phase's final checked close.
    /// A different original's publication capability cannot settle this one.
    pub(in crate::security_epoch) fn publish(
        mut self,
        mut publication: IdleCredentialPublication,
    ) -> Result<()> {
        let acquisition = self
            .completion
            .acquisition
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("epoch_counter_readmission_original_missing"))?;
        publication.check_acquisition(acquisition)?;
        let connection = self
            .connection
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("epoch_counter_readmission_owner_missing"))?;
        ensure!(
            connection.valid.get(),
            "epoch_counter_readmission_connection_refused"
        );
        connection
            .credential
            .check(acquisition, connection.store.max_lease_seconds)?;
        let replacement = self
            .replacement
            .take()
            .ok_or_else(|| anyhow::anyhow!("epoch_counter_readmission_material_missing"))?;
        // Install into the still-INELIGIBLE owned box. Old secret zeroization
        // and every fallible postcheck precede publication into the slot.
        let previous = std::mem::replace(&mut connection.credential, replacement);
        drop(previous);
        connection
            .credential
            .check(acquisition, connection.store.max_lease_seconds)?;
        publication.check_acquisition(acquisition)?;
        acquisition.remaining()?;
        connection.readmission_hint = true;
        let connection = self.connection.take().unwrap();
        self.slot.state = CounterConnectionState::Admitted(connection);
        // Infallible completion releases actual exclusion only AFTER install.
        // Until this function returns, the Rust slot borrow also stays held.
        publication.finish_published();
        self.completion.completed = true;
        Ok(())
    }
}

impl Drop for CounterReadmissionCompletion {
    fn drop(&mut self) {
        if !self.completed {
            self.valid.set(false);
            if let Some(acquisition) = &mut self.acquisition {
                acquisition.refuse();
            }
        }
    }
}

impl CounterRequest<'_> {
    fn sample(&mut self, stage: &mut EnrolledRoleStage<'_>) -> Result<Sample> {
        let result = (|| {
            ensure!(
                self.connection.valid.get() && !self.request.completed,
                "epoch_counter_request_refused"
            );
            self.connection.owner.check(stage)?;
            stage.check_current_selection(
                &self.connection.policy,
                &self.connection.store,
                self.connection.purpose,
            )?;
            let actual = stage.narrow_io_acquisition(self.connection.store.max_lease_seconds)?;
            self.request.acquisition.join_current_view(actual)?;
            self.connection.credential.check(
                &mut self.request.acquisition,
                self.connection.store.max_lease_seconds,
            )?;
            self.connection
                .owner
                .meet_current_read_view(stage, &mut self.request.acquisition)?;
            self.request.acquisition.sample()?;
            self.connection.owner.check(stage)?;
            self.request.acquisition.sample()
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

    pub(in crate::security_epoch) fn read(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        selection: &EpochStore,
        names: &Names,
    ) -> Result<EpochObservation> {
        let result = (|| {
            ensure!(
                self.connection.selection == Digest::of(selection)?
                    && names.matches_selection(selection),
                "epoch_counter_request_selection_changed"
            );
            self.check(stage)?;
            let budget = self.request.acquisition.budget()?;
            let observed = firestore::read_with_budget(
                &mut CounterReadPort {
                    request: self,
                    stage,
                },
                names,
                budget,
            )?;
            self.check(stage)?;
            Ok(observed)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn check_observation(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        observation: &mut EpochObservation,
    ) -> Result<()> {
        let result = (|| {
            self.check(stage)?;
            let selection = self.connection.store.clone();
            observation.remaining(
                &selection,
                &mut CounterReadPort {
                    request: self,
                    stage,
                },
            )?;
            self.check(stage)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(in crate::security_epoch) fn finish(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        self.request.completed = true;
        Ok(())
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.request.refuse();
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
            self.check(stage)?;
            ensure!(
                max_bytes == 65_536 && body.len() <= 65_536,
                "epoch_counter_request_budget"
            );
            let route = counter_read_route(url)?;
            ensure!(
                self.connection.http.matches(&route, url)?,
                "epoch_counter_request_recipient_changed"
            );
            let authorization = self.connection.credential.authorization(
                &mut self.request.acquisition,
                self.connection.store.max_lease_seconds,
            )?;
            let timeout = budget
                .remaining_native(&mut self.request.acquisition)?
                .min(Duration::from_secs(5));
            let bytes = self.connection.http.request_with_ceiling(
                route,
                &authorization,
                Some(body),
                &mut self.request.acquisition,
                timeout,
            )?;
            self.check(stage)?;
            budget.remaining_native(&mut self.request.acquisition)?;
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

impl CounterUseGuard {
    fn refuse(&mut self) {
        self.valid.set(false);
        self.acquisition.refuse();
    }
}

impl Drop for CounterUseGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.refuse();
        }
    }
}

// Route selection alone grants nothing: the caller must also match the exact
// provider/database URL owned by the genuinely admitted connection.
fn counter_read_route(url: &str) -> Result<Route<'static>> {
    if url.ends_with("/documents:batchGet") {
        Ok(Route::EpochRead)
    } else if url.ends_with("/documents:rollback") {
        Ok(Route::EpochRollback)
    } else {
        anyhow::bail!("epoch_counter_request_write_or_route_refused")
    }
}

struct CounterReadPort<'io, 'connection, 'stage, 'role> {
    request: &'io mut CounterRequest<'connection>,
    stage: &'stage mut EnrolledRoleStage<'role>,
}

// These owners cannot be reconstructed, copied, serialized, formatted or moved
// to another executor. CounterRequest additionally borrows its actual owner.
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
    macro_rules! local_owner {
        ($type:ty) => {
            assert_not_impl!($type, Clone);
            assert_not_impl!($type, Copy);
            assert_not_impl!($type, Default);
            assert_not_impl!($type, std::fmt::Debug);
            assert_not_impl!($type, serde::Serialize);
            assert_not_impl!($type, serde::Deserialize<'static>);
            assert_not_impl!($type, Send);
            assert_not_impl!($type, Sync);
        };
    }
    local_owner!(CounterConnectionSlot);
    local_owner!(CounterConnection);
    local_owner!(CounterRequest<'static>);
    local_owner!(CounterReadmission<'static>);
    local_owner!(CounterReadmissionCompletion);
    local_owner!(CounterUseGuard);
};

impl Port for CounterReadPort<'_, '_, '_, '_> {
    fn sample(&mut self) -> Result<Sample> {
        self.request.sample(self.stage)
    }

    fn post(
        &mut self,
        url: &str,
        body: &[u8],
        budget: &mut Budget,
        max_bytes: usize,
    ) -> Result<EpochReply> {
        let result = (|| {
            budget.remaining(self)?;
            self.request.post(self.stage, url, body, budget, max_bytes)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn refuse(&mut self) {
        self.request.refuse();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CounterConnectionSlot, CounterConnectionState, CounterReadmission,
        CounterReadmissionCompletion, CounterUseGuard, Route, counter_read_route,
    };
    use crate::security_epoch::native_clock::NativeAcquisition;
    use day2_capabilities::Digest;
    use std::{cell::Cell, rc::Rc, time::Duration};
    use syn::parse::Parser;
    use syn::visit::Visit;

    #[test]
    fn unpublished_replacement_drop_and_unwind_keep_slot_and_original_refused() {
        // Terminal lower state/clock control only. No actual enrolled owner,
        // credential admission, publication capability or connection is forged.
        for has_original in [false, true] {
            for unwind in [false, true] {
                let mut original = NativeAcquisition::fixture(
                    Digest::new(b"unfinished-counter-readmission"),
                    std::process::id(),
                    Duration::from_secs(10),
                    Duration::from_secs(5),
                );
                let valid = Rc::new(Cell::new(true));
                let mut slot = CounterConnectionSlot {
                    state: CounterConnectionState::Refused,
                };
                let pending = CounterReadmission {
                    slot: &mut slot,
                    connection: None,
                    replacement: None,
                    completion: CounterReadmissionCompletion {
                        acquisition: has_original
                            .then(|| original.narrow(5, Duration::from_secs(15)).unwrap()),
                        valid: Rc::clone(&valid),
                        completed: false,
                    },
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _pending = pending;
                    if unwind {
                        panic!("controlled unpublished replacement cancellation");
                    }
                }));
                assert_eq!(result.is_err(), unwind);
                assert!(!valid.get());
                assert!(matches!(slot.state, CounterConnectionState::Refused));
                assert_eq!(original.sample().is_err(), has_original);
            }
        }
    }

    #[test]
    fn counter_request_drop_and_unwind_refuse_the_same_actual_clock_and_gate() {
        // A lower clock/refusal adapter fixture only. No enrolled connection,
        // counter observation, file, peer or serving owner is constructed.
        for unwind in [false, true] {
            let mut original = NativeAcquisition::fixture(
                Digest::new(b"counter-request-original"),
                std::process::id(),
                Duration::from_secs(10),
                Duration::from_secs(5),
            );
            let valid = Rc::new(Cell::new(true));
            let guard = CounterUseGuard {
                acquisition: original.narrow(5, Duration::from_secs(15)).unwrap(),
                valid: Rc::clone(&valid),
                completed: false,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _actual = guard;
                if unwind {
                    panic!("controlled counter cancellation");
                }
            }));
            assert_eq!(result.is_err(), unwind);
            assert!(!valid.get());
            assert!(original.sample().is_err());
        }
    }

    #[test]
    fn retained_counter_transport_has_no_commit_or_generic_provider_route() {
        for (suffix, rollback) in [("batchGet", false), ("rollback", true)] {
            let route = counter_read_route(&format!(
                "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:{suffix}"
            ))
            .unwrap();
            assert!(matches!(route, Route::EpochRollback) == rollback);
            assert!(matches!(route, Route::EpochRead) != rollback);
        }
        for denied in [
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:commit",
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:beginTransaction",
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:batchWrite",
            "https://firestore.googleapis.com/v1/projects/p/databases/d/documents:batchGet?replacement=true",
            "https://example.com/metadata",
        ] {
            assert!(counter_read_route(denied).is_err());
        }
    }

    fn method_calls(source: &str, owner: &str, method: &str) -> Vec<String> {
        #[derive(Default)]
        struct Calls(Vec<String>);
        impl<'ast> Visit<'ast> for Calls {
            fn visit_local(&mut self, local: &'ast syn::Local) {
                if matches!(&local.pat, syn::Pat::TupleStruct(pattern)
                    if pattern.path.segments.iter().map(|s|s.ident.to_string()).collect::<Vec<_>>() == ["CounterConnectionState", "Admitted"])
                    && local.init.as_ref().is_some_and(|init| matches!(&*init.expr,
                        syn::Expr::Reference(reference) if matches!(&*reference.expr,
                            syn::Expr::Field(field) if field.member==syn::Member::Named(syn::Ident::new("state",proc_macro2::Span::call_site()))
                                && matches!(&*field.base,syn::Expr::Path(path) if path.path.is_ident("self")))))
                {
                    self.0.push("gate:Admitted".to_owned());
                }
                syn::visit::visit_local(self, local);
            }
            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                if mac.path.is_ident("matches")
                    && mac.tokens.to_string().replace(' ', "")
                        == "&self.state,CounterConnectionState::Vacant"
                {
                    self.0.push("gate:Vacant".to_owned());
                }
                if mac.path.is_ident("ensure") {
                    let arguments =
                        syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                            .parse2(mac.tokens.clone())
                            .unwrap();
                    // Parse only this actual guard's expression. It is a
                    // finite restoration check, not a macro/type resolver.
                    if let Some(condition) = arguments.first() {
                        let mut guard = Calls::default();
                        guard.visit_expr(condition);
                        self.0.extend(guard.0);
                    }
                }
                syn::visit::visit_macro(self, mac);
            }
            fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
                if matches!(&*expression.left,syn::Expr::Field(field)
                    if field.member==syn::Member::Named(syn::Ident::new("state",proc_macro2::Span::call_site()))
                        && matches!(&*field.base,syn::Expr::Path(path) if path.path.is_ident("self")))
                    && matches!(&*expression.right,syn::Expr::Path(path) if path.path.segments.iter().map(|s|s.ident.to_string()).collect::<Vec<_>>()==["CounterConnectionState","Refused"])
                {
                    self.0.push("gate:Refused".to_owned());
                }
                syn::visit::visit_expr_assign(self, expression);
            }
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    self.0.push(
                        path.path
                            .segments
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::"),
                    );
                }
                syn::visit::visit_expr_call(self, call);
            }
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.0.push(call.method.to_string());
                syn::visit::visit_expr_method_call(self, call);
            }
        }
        let parsed = syn::parse_file(source).unwrap();
        let function = parsed.items.iter().find_map(|item| match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|s|s.ident==owner)) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident==method => Some(function),
                _=>None,
            }),
            _=>None,
        }).unwrap();
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        calls.0
    }

    fn idle_wrapper_keeps_terminal_validity_monotonic(source: &str, owner: &str) -> bool {
        fn is_self(expression: &syn::Expr) -> bool {
            matches!(expression, syn::Expr::Path(path) if path.path.is_ident("self"))
        }
        let parsed = syn::parse_file(source).unwrap();
        let body = parsed.items.iter().find_map(|item| {
            let syn::Item::Impl(implementation) = item else { return None; };
            if !matches!(&*implementation.self_ty, syn::Type::Path(path) if path.path.is_ident(owner)) { return None; }
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == "readmit_counter_idle" => Some(&function.block),
                _ => None,
            })
        }).unwrap();
        #[derive(Default)]
        struct Audit {
            invalid: bool,
            opening_guards: usize,
        }
        impl<'ast> Visit<'ast> for Audit {
            fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
                if is_self(&field.base)
                    && matches!(&field.member, syn::Member::Named(name) if name == "valid")
                {
                    self.invalid = true;
                }
                syn::visit::visit_expr_field(self, field);
            }
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if is_self(&call.receiver) && call.method != "refuse" {
                    self.invalid = true;
                }
                syn::visit::visit_expr_method_call(self, call);
            }
            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                // Inspect the actual macro input, rather than trusting its
                // name: a block/helper/setter inside ensure! must not reopen
                // terminal validity while escaping this syntax visitor.
                let arguments =
                    syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                        .parse2(mac.tokens.clone());
                let valid = arguments.is_ok_and(|arguments| {
                    arguments.len() == 2
                        && matches!(&arguments[0], syn::Expr::Field(field)
                            if is_self(&field.base)
                            && matches!(&field.member, syn::Member::Named(name) if name == "valid"))
                        && matches!(&arguments[1], syn::Expr::Lit(literal)
                            if matches!(&literal.lit, syn::Lit::Str(value)
                                if ["active_app_storage_refused", "active_controller_storage_refused"].contains(&value.value().as_str())))
                });
                if !mac.path.is_ident("ensure") || !valid {
                    self.invalid = true;
                }
                self.opening_guards += 1;
            }
        }
        let mut audit = Audit::default();
        audit.visit_block(body);
        let terminal = body.stmts.iter().any(|statement| {
            let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else { return false; };
            matches!(&*branch.cond, syn::Expr::MethodCall(call)
                if call.method == "is_err" && call.args.is_empty()
                && matches!(&*call.receiver,syn::Expr::Path(path) if path.path.is_ident("result")))
                && matches!(branch.then_branch.stmts.first(),Some(syn::Stmt::Expr(syn::Expr::MethodCall(call),Some(_)))
                    if is_self(&call.receiver) && call.method == "refuse" && call.args.is_empty())
                && branch.else_branch.is_none()
        });
        !audit.invalid && audit.opening_guards == 1 && terminal
    }

    #[test]
    fn idle_material_replacement_never_reopens_terminal_app_or_controller_validity() {
        // Real-wrapper restoration control only; no native permission, owner
        // or successful material publication is manufactured by this test.
        for (source, owner) in [
            (
                include_str!("../bootstrap.rs"),
                "ActiveAppStorageContinuity",
            ),
            (
                include_str!("../bootstrap/controller_serving.rs"),
                "ActiveControllerStorageContinuity",
            ),
        ] {
            assert!(idle_wrapper_keeps_terminal_validity_monotonic(
                source, owner
            ));
            let (prefix, body) = source.split_once("fn readmit_counter_idle(").unwrap();
            for changed in [
                body.replacen("let result =", "self.valid = false; let result =", 1),
                body.replacen(
                    "if result.is_err()",
                    "if result.is_ok() { self.valid = true; } if result.is_err()",
                    1,
                ),
                body.replacen("self.refuse();", "if false { self.refuse(); }", 1),
                body.replacen("self.refuse();", "self.restore_valid();", 1),
                body.replacen("self.valid,", "{ self.valid = true; true },", 1),
                body.replacen("self.valid,", "{ self.restore_valid(); true },", 1),
                body.replacen("self.valid,", "true,", 1),
            ] {
                assert_ne!(body, changed);
                assert!(!idle_wrapper_keeps_terminal_validity_monotonic(
                    &format!("{prefix}fn readmit_counter_idle({changed}"),
                    owner
                ));
            }
        }
    }

    fn selected_body(source: &str, owner: &str, method: &str) -> syn::Block {
        syn::parse_file(source)
            .unwrap()
            .items
            .into_iter()
            .find_map(|item| {
                let syn::Item::Impl(item) = item else {
                    return None;
                };
                if !matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|name| name.ident == owner))
                {
                    return None;
                }
                item.items.into_iter().find_map(|item| match item {
                    syn::ImplItem::Fn(function) if function.sig.ident == method => {
                        Some(function.block)
                    }
                    _ => None,
                })
            })
            .unwrap()
    }

    fn expression_path(expression: &syn::Expr) -> String {
        match expression {
            syn::Expr::Path(path) => path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
            syn::Expr::Field(field) => format!(
                "{}.{}",
                expression_path(&field.base),
                match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(_) => return String::new(),
                }
            ),
            _ => String::new(),
        }
    }

    fn direct_checked(
        statement: &syn::Stmt,
        receiver: &str,
        method: &str,
        arguments: &[&str],
    ) -> bool {
        let syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_)) = statement else {
            return false;
        };
        let syn::Expr::MethodCall(call) = &*attempt.expr else {
            return false;
        };
        expression_path(&call.receiver) == receiver
            && call.method == method
            && call.args.iter().map(expression_path).collect::<Vec<_>>() == arguments
    }

    fn local_value<'a>(statement: &'a syn::Stmt, name: &str) -> Option<&'a syn::Expr> {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        if !matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == name) {
            return None;
        }
        Some(&*local.init.as_ref()?.expr)
    }

    fn idle_prepare_keeps_old_cap_before_full_authentication(source: &str) -> bool {
        let body = selected_body(source, "CounterConnectionSlot", "prepare_readmission");
        let Some(index) = body
            .stmts
            .iter()
            .position(|statement| local_value(statement, "replacement").is_some())
        else {
            return false;
        };
        let Some(syn::Stmt::Expr(syn::Expr::Block(before), _)) =
            index.checked_sub(1).and_then(|index| body.stmts.get(index))
        else {
            return false;
        };
        let statements = &before.block.stmts;
        let Some(tail) = statements
            .len()
            .checked_sub(3)
            .map(|index| &statements[index..])
        else {
            return false;
        };
        if !direct_checked(
            &tail[0],
            "connection.credential",
            "check",
            &["acquisition", "store.max_lease_seconds"],
        ) || !direct_checked(
            &tail[1],
            "connection.owner",
            "meet_current_read_view",
            &["stage", "acquisition"],
        ) || !direct_checked(&tail[2], "acquisition", "remaining", &[])
        {
            return false;
        }
        let Some(syn::Expr::Try(attempt)) = local_value(&body.stmts[index], "replacement") else {
            return false;
        };
        let syn::Expr::MethodCall(into) = &*attempt.expr else {
            return false;
        };
        let syn::Expr::Try(acquire) = &*into.receiver else {
            return false;
        };
        let syn::Expr::Call(acquire) = &*acquire.expr else {
            return false;
        };
        into.method == "into_counter_connection"
            && into.args.is_empty()
            && expression_path(&acquire.func) == "AuthenticatedReads::acquire"
            && acquire.args.len() == 4
            && acquire
                .args
                .iter()
                .take(3)
                .map(expression_path)
                .collect::<Vec<_>>()
                == ["policy", "store", "purpose"]
            && matches!(&acquire.args[3], syn::Expr::Try(stage)
                if matches!(&*stage.expr,syn::Expr::MethodCall(call)
                    if expression_path(&call.receiver)=="idle" && call.method=="stage" && call.args.is_empty()))
    }

    fn idle_publication_keeps_final_caps_before_atomic_install(source: &str) -> bool {
        let body = selected_body(source, "CounterReadmission", "publish");
        let positions = |receiver, method, args: &[&str]| {
            body.stmts
                .iter()
                .enumerate()
                .filter_map(|(index, statement)| {
                    direct_checked(statement, receiver, method, args).then_some(index)
                })
                .collect::<Vec<_>>()
        };
        let publications = positions("publication", "check_acquisition", &["acquisition"]);
        let credentials = positions(
            "connection.credential",
            "check",
            &["acquisition", "connection.store.max_lease_seconds"],
        );
        let remaining = positions("acquisition", "remaining", &[]);
        if publications.len() != 2 || credentials.len() != 2 || remaining.len() != 1 {
            return false;
        }
        let Some(replace) = body.stmts.iter().position(|statement| matches!(local_value(statement,"previous"),Some(syn::Expr::Call(call))
            if expression_path(&call.func)=="std::mem::replace" && call.args.len()==2
                && matches!(&call.args[0],syn::Expr::Reference(reference)
                    if reference.mutability.is_some() && expression_path(&reference.expr)=="connection.credential")
                && expression_path(&call.args[1])=="replacement")) else { return false; };
        let Some(drop_old) = body.stmts.iter().position(|statement| matches!(statement,syn::Stmt::Expr(syn::Expr::Call(call),Some(_))
            if expression_path(&call.func)=="drop" && call.args.len()==1 && expression_path(&call.args[0])=="previous")) else { return false; };
        let Some(install) = body.stmts.iter().position(|statement| matches!(statement,syn::Stmt::Expr(syn::Expr::Assign(assign),Some(_))
            if expression_path(&assign.left)=="self.slot.state"
                && matches!(&*assign.right,syn::Expr::Call(call) if expression_path(&call.func)=="CounterConnectionState::Admitted"
                    && call.args.len()==1 && expression_path(&call.args[0])=="connection"))) else { return false; };
        let Some(finish) = body.stmts.iter().position(|statement| matches!(statement,syn::Stmt::Expr(syn::Expr::MethodCall(call),Some(_))
            if expression_path(&call.receiver)=="publication" && call.method=="finish_published" && call.args.is_empty())) else { return false; };
        let order = [
            publications[0],
            credentials[0],
            replace,
            drop_old,
            credentials[1],
            publications[1],
            remaining[0],
            install,
            finish,
        ];
        order.windows(2).all(|pair| pair[0] < pair[1])
    }

    fn controller_idle_keeps_physical_close_before_publication(source: &str) -> bool {
        let body = selected_body(
            source,
            "ActiveControllerStorageContinuity",
            "readmit_counter_idle",
        );
        let Some(syn::Expr::Call(invoked)) = body
            .stmts
            .iter()
            .find_map(|statement| local_value(statement, "result"))
        else {
            return false;
        };
        let syn::Expr::Paren(wrapper) = &*invoked.func else {
            return false;
        };
        let syn::Expr::Closure(closure) = &*wrapper.expr else {
            return false;
        };
        let syn::Expr::Block(closure) = &*closure.body else {
            return false;
        };
        let statements = &closure.block.stmts;
        let Some(tail) = statements
            .len()
            .checked_sub(3)
            .map(|index| &statements[index..])
        else {
            return false;
        };
        matches!(local_value(&tail[0],"pending"),Some(syn::Expr::Try(attempt))
            if matches!(&*attempt.expr,syn::Expr::MethodCall(call)
                if expression_path(&call.receiver)=="self.counter" && call.method=="prepare_readmission"))
            && direct_checked(&tail[1], "physical", "finish_controller_known", &[])
            && matches!(&tail[2],syn::Stmt::Expr(syn::Expr::MethodCall(call),None)
                if expression_path(&call.receiver)=="pending" && call.method=="publish"
                    && call.args.len()==1 && expression_path(&call.args[0])=="publication")
    }

    #[test]
    fn idle_replacement_restoration_controls_pin_actual_caps_and_publication_order() {
        // Finite production-boundary restoration controls, not a positive
        // native-owner simulation or an assertion that network I/O succeeds.
        let source = include_str!("connection.rs");
        assert!(idle_prepare_keeps_old_cap_before_full_authentication(
            source
        ));
        assert!(idle_publication_keeps_final_caps_before_atomic_install(
            source
        ));
        let (prefix, prepare) = source.split_once("fn prepare_readmission<").unwrap();
        let old_cap = "connection\n                .credential\n                .check(acquisition, store.max_lease_seconds)?;";
        for changed in [
            prepare.replacen(old_cap, "", 1),
            prepare.replacen(old_cap, &format!("if false {{ {old_cap} }}"), 1),
            prepare.replacen(old_cap, &old_cap.replace("connection", "foreign"), 1),
        ] {
            assert_ne!(prepare, changed);
            assert!(!idle_prepare_keeps_old_cap_before_full_authentication(
                &format!("{prefix}fn prepare_readmission<{changed}")
            ));
        }
        let (prefix, publish) = source.split_once("fn publish(").unwrap();
        let check = "publication.check_acquisition(acquisition)?;";
        let first_end = publish.find(check).unwrap() + check.len();
        let (first, later) = publish.split_at(first_end);
        for changed in [
            publish.replacen("publication.check_acquisition(acquisition)?;", "", 2),
            format!("{first}{}", later.replacen(check, "", 1)),
            publish.replacen("acquisition.remaining()?;", "", 1),
            publish.replacen("drop(previous);", "", 1),
            publish.replacen(
                "publication.check_acquisition(acquisition)?;",
                "publication.check_acquisition(foreign)?;",
                1,
            ),
            publish.replacen(
                "let previous =",
                "self.slot.state = CounterConnectionState::Admitted(connection); let previous =",
                1,
            ),
        ] {
            assert_ne!(publish, changed);
            assert!(!idle_publication_keeps_final_caps_before_atomic_install(
                &format!("{prefix}fn publish({changed}")
            ));
        }
        let source = include_str!("../bootstrap/controller_serving.rs");
        assert!(controller_idle_keeps_physical_close_before_publication(
            source
        ));
        let changed = source.replacen(
            "physical.finish_controller_known()?;\n            pending.publish(publication)",
            "pending.publish(publication)?;\n            physical.finish_controller_known()",
            1,
        );
        assert_ne!(source, changed);
        assert!(!controller_idle_keeps_physical_close_before_publication(
            &changed
        ));
    }

    fn cold_counter_entry_shape(source: &str) -> bool {
        fn path(value: &syn::Expr, name: &str) -> bool {
            matches!(value,syn::Expr::Path(p) if p.path.is_ident(name))
        }
        fn field(value: &syn::Expr, owner: &str, name: &str) -> bool {
            matches!(value,syn::Expr::Field(f) if path(&f.base,owner)
                && matches!(&f.member,syn::Member::Named(actual) if actual==name))
        }
        fn local<'a>(statement: &'a syn::Stmt, name: &str) -> Option<&'a syn::Expr> {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            if !matches!(&local.pat,syn::Pat::Ident(p) if p.ident==name) {
                return None;
            }
            local.init.as_ref().map(|init| &*init.expr)
        }
        fn narrow(value: &syn::Expr) -> bool {
            matches!(value,syn::Expr::MethodCall(call) if call.method=="narrow_io_acquisition"
                && path(&call.receiver,"stage") && call.args.len()==1
                && field(&call.args[0],"store","max_lease_seconds"))
        }
        let parsed = syn::parse_file(source).unwrap();
        let name = "admit";
        let Some(body) = parsed.items.iter().find_map(|item| {
            let syn::Item::Impl(item) = item else { return None; };
            if !matches!(&*item.self_ty,syn::Type::Path(p) if p.path.is_ident("CounterConnectionSlot")) { return None; }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(f) if f.sig.ident==name => Some(&f.block),
                _ => None,
            })
        }) else { return false; };
        body.stmts.len() >= 4
            && matches!(local(&body.stmts[0],"was_vacant"),Some(syn::Expr::Macro(m))
                if m.mac.path.is_ident("matches")
                && m.mac.tokens.to_string().replace(' ',"")=="&self.state,CounterConnectionState::Vacant")
            && matches!(&body.stmts[1],syn::Stmt::Expr(syn::Expr::Assign(a),Some(_))
                if field(&a.left,"self","state") && matches!(&*a.right,syn::Expr::Path(p)
                    if p.path.segments.iter().map(|s|s.ident.to_string()).collect::<Vec<_>>()==["CounterConnectionState","Refused"]))
            && matches!(local(&body.stmts[2],"original"),Some(syn::Expr::Try(t)) if narrow(&t.expr))
            && matches!(&body.stmts[3],syn::Stmt::Expr(syn::Expr::If(i),_)
                if matches!(&*i.cond,syn::Expr::Unary(u) if matches!(u.op,syn::UnOp::Not(_)) && path(&u.expr,"was_vacant"))
                && i.then_branch.stmts.len()==2
                && matches!(&i.then_branch.stmts[0],syn::Stmt::Expr(syn::Expr::MethodCall(c),Some(_))
                    if c.method=="refuse" && c.args.is_empty() && path(&c.receiver,"original"))
                && matches!(&i.then_branch.stmts[1],syn::Stmt::Macro(m)
                    if m.semi_token.is_some()
                    && m.mac.path.segments.iter().map(|s|s.ident.to_string()).collect::<Vec<_>>()==["anyhow","bail"]
                    && syn::parse2::<syn::LitStr>(m.mac.tokens.clone()).is_ok_and(|s|s.value()=="epoch_counter_connection_admission_already_attempted")))
    }

    fn cold_publication_keeps_token_cap_through_final_postchecks(source: &str) -> bool {
        let calls = method_calls(source, "AuthenticatedReads", "into_counter_connection");
        let Some(start) = calls.iter().position(|call| call == "admit_counter") else {
            return false;
        };
        calls.get(start + 1..start + 8).is_some_and(|calls| {
            calls
                == [
                    "check",
                    "meet_current_read_view",
                    "check",
                    "check_selection",
                    "check",
                    "meet_current_read_view",
                    "remaining",
                ]
        })
    }

    #[test]
    fn cold_token_cap_covers_postchecks_before_connection_publication() {
        // The native owner remains nonconstructible. These finite controls
        // bind the real cold factory to its lower material/clock tests.
        let source = include_str!("connection.rs");
        assert!(cold_publication_keeps_token_cap_through_final_postchecks(
            source
        ));
        let (prefix, body) = source.split_once("fn into_counter_connection(").unwrap();
        for removed in [
            "credential.check(&mut self.acquisition, self.store.max_lease_seconds)?;",
            "owner.meet_current_read_view(self.stage, &mut self.acquisition)?;",
            "self.acquisition.remaining()?;",
        ] {
            let changed = body.replacen(removed, "", 1);
            assert_ne!(body, changed);
            assert!(!cold_publication_keeps_token_cap_through_final_postchecks(
                &format!("{prefix}fn into_counter_connection({changed}")
            ));
        }
    }

    #[test]
    fn cold_counter_admission_is_terminal_before_first_fallible_stage() {
        // Finite controls on the real native callers; no native stage or
        // admitted counter connection can be manufactured by this DATA test.
        let source = include_str!("connection.rs");
        assert!(cold_counter_entry_shape(source));
    }

    #[test]
    fn cold_counter_admission_guard_rejects_retryable_early_failure_paths() {
        let source = include_str!("connection.rs");
        let (prefix, body) = source
            .split_once("pub(in crate::security_epoch) fn admit(")
            .unwrap();
        for (before, after) in [
            (
                "self.state = CounterConnectionState::Refused;",
                "if false { self.state = CounterConnectionState::Refused; }",
            ),
            (
                "let was_vacant = matches!(&self.state, CounterConnectionState::Vacant);",
                "let was_vacant = true;",
            ),
            ("original.refuse();", ""),
            (
                "anyhow::bail!(\"epoch_counter_connection_admission_already_attempted\");",
                "let _ = anyhow::anyhow!(\"epoch_counter_connection_admission_already_attempted\");",
            ),
            (
                "anyhow::bail!(\"epoch_counter_connection_admission_already_attempted\");",
                "if false { anyhow::bail!(\"epoch_counter_connection_admission_already_attempted\"); }",
            ),
            (
                "original.refuse();\n            anyhow::bail!(\"epoch_counter_connection_admission_already_attempted\");",
                "",
            ),
        ] {
            let changed = body.replacen(before, after, 1);
            assert_ne!(body, changed);
            assert!(!cold_counter_entry_shape(&format!(
                "{prefix}pub(in crate::security_epoch) fn admit({changed}"
            ),));
        }
        let closed = "self.state = CounterConnectionState::Refused;";
        let narrow = "let mut original = stage.narrow_io_acquisition(store.max_lease_seconds)?;";
        let reordered =
            body.replacen(closed, "", 1)
                .replacen(narrow, &format!("{narrow} {closed}"), 1);
        assert_ne!(body, reordered);
        assert!(!cold_counter_entry_shape(&format!(
            "{prefix}pub(in crate::security_epoch) fn admit({reordered}"
        ),));
    }

    fn current_read_cap_shape(source: &str, request: bool) -> bool {
        fn path(expression: &syn::Expr, names: &[&str]) -> bool {
            match (expression, names.split_last()) {
                (syn::Expr::Path(path), Some((name, []))) => path.path.is_ident(name),
                (syn::Expr::Field(field), Some((name, parent))) => {
                    matches!(&field.member, syn::Member::Named(actual) if actual == name)
                        && path(&field.base, parent)
                }
                _ => false,
            }
        }
        fn actual_mut(expression: &syn::Expr, names: &[&str]) -> bool {
            matches!(expression, syn::Expr::Reference(reference)
                if reference.mutability.is_some() && path(&reference.expr, names))
        }
        fn direct_call(statement: &syn::Stmt) -> Option<&syn::ExprMethodCall> {
            match statement {
                syn::Stmt::Expr(syn::Expr::Try(attempt), Some(_)) => match &*attempt.expr {
                    syn::Expr::MethodCall(call) => Some(call),
                    _ => None,
                },
                _ => None,
            }
        }
        let parsed = syn::parse_file(source).unwrap();
        let (owner, method, binding) = if request {
            ("CounterConnectionSlot", "request", "checked")
        } else {
            ("CounterRequest", "sample", "result")
        };
        let body = parsed.items.iter().find_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            if !matches!(&*implementation.self_ty, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|name| name.ident == owner))
            {
                return None;
            }
            implementation.items.iter().find_map(|item| {
                let syn::ImplItem::Fn(function) = item else {
                    return None;
                };
                if function.sig.ident != method {
                    return None;
                }
                function.block.stmts.iter().find_map(|statement| {
                    let syn::Stmt::Local(local) = statement else {
                        return None;
                    };
                    if !matches!(&local.pat, syn::Pat::Ident(name) if name.ident == binding) {
                        return None;
                    }
                    let syn::Expr::Call(call) = &*local.init.as_ref()?.expr else {
                        return None;
                    };
                    let syn::Expr::Paren(parenthesized) = &*call.func else {
                        return None;
                    };
                    let syn::Expr::Closure(closure) = &*parenthesized.expr else {
                        return None;
                    };
                    let syn::Expr::Block(body) = &*closure.body else {
                        return None;
                    };
                    Some(&body.block)
                })
            })
        });
        let Some(body) = body else {
            return false;
        };
        let (credential, owner, acquisition, lease): (&[&str], &[&str], &[&str], &[&str]) =
            if request {
                (
                    &["connection", "credential"],
                    &["connection", "owner"],
                    &["acquisition"],
                    &["store", "max_lease_seconds"],
                )
            } else {
                (
                    &["self", "connection", "credential"],
                    &["self", "connection", "owner"],
                    &["self", "request", "acquisition"],
                    &["self", "connection", "store", "max_lease_seconds"],
                )
            };
        body.stmts
            .windows(4)
            .enumerate()
            .any(|(index, statements)| {
                let Some(check) = direct_call(&statements[0]) else {
                    return false;
                };
                let Some(meet) = direct_call(&statements[1]) else {
                    return false;
                };
                let Some(post) = direct_call(&statements[2]) else {
                    return false;
                };
                let Some(final_check) = direct_call(&statements[3]) else {
                    return false;
                };
                let joined = request
                    || index
                        .checked_sub(1)
                        .and_then(|index| direct_call(&body.stmts[index]))
                        .is_some_and(|call| {
                            call.method == "join_current_view"
                                && path(&call.receiver, acquisition)
                                && call.args.len() == 1
                                && path(&call.args[0], &["actual"])
                        });
                // The request checks its owner then remaining interval; sample
                // charges an observation, checks its owner, then returns a final
                // observation. No I/O, conditional or ignored result may intervene.
                let postchecks = if request {
                    post.method == "check"
                        && path(&post.receiver, owner)
                        && post.args.len() == 1
                        && path(&post.args[0], &["stage"])
                        && final_check.method == "remaining"
                        && path(&final_check.receiver, acquisition)
                        && final_check.args.is_empty()
                } else {
                    post.method == "sample"
                        && path(&post.receiver, acquisition)
                        && post.args.is_empty()
                        && final_check.method == "check"
                        && path(&final_check.receiver, owner)
                        && final_check.args.len() == 1
                        && path(&final_check.args[0], &["stage"])
                };
                joined
                    && postchecks
                    && check.method == "check"
                    && path(&check.receiver, credential)
                    && check.args.len() == 2
                    && actual_mut(&check.args[0], acquisition)
                    && path(&check.args[1], lease)
                    && meet.method == "meet_current_read_view"
                    && path(&meet.receiver, owner)
                    && meet.args.len() == 2
                    && path(&meet.args[0], &["stage"])
                    && actual_mut(&meet.args[1], acquisition)
            })
    }

    #[test]
    fn actual_counter_requests_propagate_narrowed_caps_before_release_postchecks() {
        // Pin the surviving native consumer rather than the deleted retained
        // Current factory. These finite AST controls manufacture no authority.
        let source = include_str!("connection.rs");
        for (request, receiver, acquisition) in [
            (true, "connection\n                .owner", "acquisition"),
            (
                false,
                "self.connection\n                .owner",
                "self.request.acquisition",
            ),
        ] {
            assert!(current_read_cap_shape(source, request));
            let actual = format!(
                "{receiver}\n                .meet_current_read_view(stage, &mut {acquisition})?;"
            );
            assert_eq!(source.matches(&actual).count(), 1);
            let credential = if request {
                "connection\n                .credential\n                .check(&mut acquisition, store.max_lease_seconds)?;"
            } else {
                "self.connection.credential.check(\n                &mut self.request.acquisition,\n                self.connection.store.max_lease_seconds,\n            )?;"
            };
            for replacement in [
                String::new(),
                actual.replace("?;", ";"),
                format!("let _ = {}", actual.replace("?;", ";")),
                format!("if false {{ {actual} }}"),
                actual.replace(receiver, "foreign.owner"),
                actual.replace("(stage,", "(unrelated_stage,"),
                actual.replace(&format!("&mut {acquisition}"), "&mut unrelated"),
            ] {
                let changed = source.replacen(&actual, &replacement, 1);
                assert_ne!(source, changed);
                assert!(!current_read_cap_shape(&changed, request));
            }
            let without_meet = source.replacen(&actual, "", 1);
            let reordered = without_meet.replacen(credential, &format!("{actual} {credential}"), 1);
            assert_ne!(source, reordered);
            assert!(!current_read_cap_shape(&reordered, request));
        }
    }

    fn retained_request_shape(source: &str) -> bool {
        let request = method_calls(source, "CounterConnectionSlot", "request");
        let cold = method_calls(source, "CounterConnectionSlot", "admit");
        let sample = method_calls(source, "CounterRequest", "sample");
        let admission = method_calls(source, "AuthenticatedReads", "into_counter_connection");
        cold.iter()
            .filter(|call| call.as_str() == "AuthenticatedReads::acquire")
            .count()
            == 1
            && cold
                .iter()
                .filter(|call| call.as_str() == "into_counter_connection")
                .count()
                == 1
            && request.iter().all(|call| {
                call != "AuthenticatedReads::acquire"
                    && call != "into_counter_connection"
                    && call != "admit"
            })
            && request.iter().any(|call| call == "check_current_selection")
            && request.iter().any(|call| call == "meet_current_read_view")
            && request.iter().any(|call| call == "gate:Admitted")
            && sample
                .iter()
                .filter(|call| call.as_str() == "check")
                .count()
                == 3
            && sample.iter().any(|call| call == "check_current_selection")
            && sample.iter().any(|call| call == "meet_current_read_view")
            && sample.iter().any(|call| call == "join_current_view")
            && sample
                .iter()
                .all(|call| !call.contains("acquire") && call != "read" && call != "request")
            && admission.iter().any(|call| call == "capture_same_owner")
            && admission.iter().any(|call| call == "admit_counter")
            && admission.iter().any(|call| call == "check_selection")
            && cold.iter().any(|call| call == "gate:Vacant")
            && cold.iter().any(|call| call == "gate:Refused")
            && cold.iter().position(|call| call == "gate:Refused")
                < cold
                    .iter()
                    .position(|call| call == "AuthenticatedReads::acquire")
    }

    #[test]
    fn retained_counter_requests_keep_the_actual_owner_and_cannot_enter_cold_admission() {
        // Finite source restoration controls, not a fake positive native owner
        // or a claim of general Rust control-flow/type-resolution soundness.
        let source = include_str!("connection.rs");
        assert!(retained_request_shape(source));
        // Maintenance now has a different same-original join and an Admitted
        // hint read. Mutate the actual selected request methods, not the first
        // similarly spelled operation anywhere in the source file.
        let sample_marker = "impl CounterRequest<'_> {";
        let request_marker = "pub(in crate::security_epoch) fn request<'connection>(";
        let (before_sample, sample) = source.split_once(sample_marker).unwrap();
        let (before_request, request) = source.split_once(request_marker).unwrap();
        for (index, changed) in [
            source.replacen("self.connection.owner.check(stage)?;", "", 1),
            source.replace("stage.check_current_selection(", "stage.check_selection("),
            source.replace(".meet_current_read_view(", ".unchecked_current_read_view("),
            format!(
                "{before_sample}{sample_marker}{}",
                sample.replacen(".join_current_view(", ".join_storage_bootstrap_view(", 1)
            ),
            source.replacen("self.stage.capture_same_owner()?", "unavailable_owner()", 1),
            source.replacen(".admit_counter(", ".unqualified_counter(", 1),
            source.replacen(
                "let was_vacant = matches!(&self.state, CounterConnectionState::Vacant);",
                "let was_vacant = true;",
                1,
            ),
            format!(
                "{before_request}{request_marker}{}",
                request.replacen(
                    "CounterConnectionState::Admitted(connection) = &mut self.state",
                    "CounterConnectionState::Admitted(connection) = available_elsewhere()",
                    1,
                )
            ),
            source.replacen(
                "let checked = (|| {",
                "let checked = (|| { self.admit(stage, policy, store, purpose)?;",
                1,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            assert_ne!(changed, source);
            assert!(
                !retained_request_shape(&changed),
                "request restoration mutant {index}"
            );
        }
    }

    #[test]
    fn serving_constructor_completes_counter_admission_before_publishing_the_app() {
        // This pins the actual production constructor, not a synthetic owner.
        // It complements the Linux admission/handle controls; it is not a
        // general control-flow or native deployment qualification claim.
        let source = include_str!("../serving.rs");
        let ordered = |source: &str| {
            let calls = method_calls(source, "ServingParticipant", "app");
            calls
                .iter()
                .filter(|call| call.as_str() == "admit_counter")
                .count()
                == 1
                && calls.iter().position(|call| call == "admit_counter")
                    < calls.iter().position(|call| call == "Box::new")
        };
        assert!(ordered(source));
        let missing = source.replacen("app.admit_counter(stage)?;", "", 1);
        assert_ne!(source, missing);
        assert!(!ordered(&missing));
    }

    #[test]
    fn cold_counter_admission_joins_the_actual_app_file_and_peer() {
        let source = include_str!("../storage_authority/initial.rs");
        let joined = |source: &str| {
            let calls = method_calls(
                source,
                "AppInitialStorageContinuity",
                "check_counter_admission",
            );
            calls
                .iter()
                .filter(|call| call.as_str() == "check_current")
                .count()
                == 2
                && calls
                    .iter()
                    .filter(|call| call.as_str() == "check_retained_identity")
                    .count()
                    == 1
        };
        assert!(joined(source));
        for changed in [
            source.replacen("self.peer.check_retained_identity(stage)?;", "", 1),
            source.replacen("self.file.check_current(stage)?;", "", 1),
        ] {
            assert_ne!(source, changed);
            assert!(!joined(&changed));
        }
    }

    #[test]
    fn counter_send_keeps_exact_recipient_expiry_timeout_and_postchecks() {
        let source = include_str!("connection.rs");
        let guarded = |source: &str| {
            let calls = method_calls(source, "CounterRequest", "post");
            let at = |name| calls.iter().position(|call| call == name);
            calls.iter().filter(|call| call.as_str() == "check").count() == 2
                && at("matches").is_some()
                && at("matches") < at("authorization")
                && at("authorization") < at("request_with_ceiling")
                && at("remaining_native") < at("request_with_ceiling")
                && calls
                    .iter()
                    .filter(|call| call.as_str() == "request_with_ceiling")
                    .count()
                    == 1
                && calls.iter().rposition(|call| call == "check") > at("request_with_ceiling")
                && calls.iter().rposition(|call| call == "remaining_native")
                    > at("request_with_ceiling")
                && calls
                    .iter()
                    .filter(|call| call.as_str() == "remaining_native")
                    .count()
                    == 2
        };
        assert!(
            guarded(source),
            "actual calls: {:?}",
            method_calls(source, "CounterRequest", "post")
        );
        for changed in [
            source.replacen("self.connection.http.matches(&route, url)?", "true", 1),
            source.replacen(
                "let authorization = self.connection.credential.authorization(",
                "let authorization = self.connection.credential.unchecked_authorization(",
                1,
            ),
            source.replacen(
                "self.check(stage)?;\n            budget.remaining_native",
                "budget.remaining_native",
                1,
            ),
        ] {
            assert_ne!(source, changed);
            assert!(!guarded(&changed));
        }
    }
}
