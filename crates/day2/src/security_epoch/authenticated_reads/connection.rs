//! Retain actual counter authentication in its admitted connection. Each
//! request borrows that owner with its own existing original interval; no
//! admission clock, historical counter or parsed identity becomes permission.

use super::{AuthenticatedReads, ReadScope};
use crate::security_epoch::{
    credential_material::CounterMaterial,
    firestore::{self, Budget, EpochObservation, EpochReply, Names, Port, Sample},
    native_clock::{NativeAcquisition, NativeOriginalRefusal},
    native_enrollment::{EnrolledRoleStage, SameEnrolledOwner},
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
    valid: Rc<Cell<bool>>,
}

pub(in crate::security_epoch) struct CounterRequest<'connection> {
    connection: &'connection mut CounterConnection,
    request: CounterUseGuard,
}

/// Negative continuation of the ACTUAL finished restored read. It owns the
/// same before-I/O acquisition and observation, never a Connection borrow,
/// copied deadline or replacement read. Only finish_restored constructs it.
/// There is no Current, credential, transport, stage or snapshot getter.
pub(in crate::security_epoch) struct CompletedRestoredCounterRead {
    request: CounterUseGuard,
    observation: RestoredEpochObservation,
    selection: Digest,
    reader: Digest,
    original: NativeOriginalRefusal,
    state: CompletedReadState,
}

#[derive(PartialEq, Eq)]
enum CompletedReadState {
    PendingFinal,
    Checking,
    FinalChecked,
    Released,
    Refused,
}

impl CompletedReadState {
    fn refuse(&mut self) {
        *self = Self::Refused;
    }

    fn begin_final(&mut self) -> Result<()> {
        if *self != Self::PendingFinal {
            self.refuse();
            anyhow::bail!("epoch_completed_counter_final_spent");
        }
        *self = Self::Checking;
        Ok(())
    }

    fn finish_final(&mut self) -> Result<()> {
        if *self != Self::Checking {
            self.refuse();
            anyhow::bail!("epoch_completed_counter_final_refused");
        }
        *self = Self::FinalChecked;
        Ok(())
    }

    fn require_release(&mut self) -> Result<()> {
        if *self != Self::FinalChecked {
            self.refuse();
            anyhow::bail!("epoch_completed_counter_final_required");
        }
        Ok(())
    }

    fn release(&mut self) -> Result<()> {
        self.require_release()?;
        *self = Self::Released;
        Ok(())
    }
}

impl CompletedRestoredCounterRead {
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.state.refuse();
        self.request.refuse();
        self.observation.refuse();
    }

    fn remaining_original(&mut self) -> Result<()> {
        let result = self.observation.remaining_completed_original(
            &self.selection,
            &self.reader,
            &mut self.request.acquisition,
        );
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

impl Drop for CompletedRestoredCounterRead {
    fn drop(&mut self) {
        if self.state != CompletedReadState::Released {
            self.refuse();
        }
    }
}

struct CompletedCounterCheck<'slot, 'tail, 'stage, 'role> {
    slot: &'slot mut CounterConnectionSlot,
    tail: &'tail mut CompletedRestoredCounterRead,
    stage: &'stage mut EnrolledRoleStage<'role>,
    done: bool,
}

impl Drop for CompletedCounterCheck<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.stage.refuse_serving();
            self.tail.refuse();
            self.slot.refuse();
        }
    }
}

// Comparison/refusal of actual connection roots only. This pure leaf supplies
// no slot, native request or completion tail and has no public constructor.
fn require_completed_connection(
    completed: bool,
    retained: &Rc<Cell<bool>>,
    actual: &Rc<Cell<bool>>,
    expected_selection: &Digest,
    actual_selection: &Digest,
) -> Result<()> {
    let matches = completed
        && retained.get()
        && actual.get()
        && Rc::ptr_eq(retained, actual)
        && expected_selection == actual_selection;
    if !matches {
        retained.set(false);
        actual.set(false);
    }
    ensure!(
        matches,
        "epoch_completed_counter_connection_changed_or_refused"
    );
    Ok(())
}

/// A restored ten-record observation retains the actual request's BEFORE-IO
/// budget. Its commitment is comparison DATA; neither parsed bytes nor that
/// digest can construct a Current, native role, physical owner or new clock.
pub(in crate::security_epoch) struct RestoredEpochObservation {
    selection: Digest,
    reader: Digest,
    snapshot: Digest,
    budget: Budget,
    valid: bool,
    local: std::marker::PhantomData<Rc<()>>,
}

impl RestoredEpochObservation {
    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.valid = false;
    }

    pub(in crate::security_epoch) fn snapshot_data(&self) -> &Digest {
        &self.snapshot
    }

    fn remaining_completed_original(
        &mut self,
        selection: &Digest,
        reader: &Digest,
        original: &mut NativeAcquisition,
    ) -> Result<()> {
        let result: Result<()> = (|| {
            self.require_binding(selection, reader)?;
            self.budget.remaining_native(original)?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn remaining(
        &mut self,
        selection: &EpochStore,
        names: &firestore::RestoreWriterPeerRead,
        port: &mut impl Port,
    ) -> Result<()> {
        let result =
            (|| self.remaining_bound(&Digest::of(selection)?, &names.binding_data()?, port))();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn remaining_bound(
        &mut self,
        selection: &Digest,
        reader: &Digest,
        port: &mut impl Port,
    ) -> Result<()> {
        let result = (|| {
            self.require_binding(selection, reader)?;
            self.budget.remaining(port)?;
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn require_binding(&mut self, selection: &Digest, reader: &Digest) -> Result<()> {
        let result = (|| {
            ensure!(self.valid, "restored_epoch_observation_refused");
            ensure!(
                self.selection == *selection && self.reader == *reader,
                "restored_epoch_observation_binding_changed"
            );
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
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
        let owner = self.stage.capture_same_owner()?;
        let selected = super::reader_selection(&self.policy, self.purpose)?;
        let credential = self.credential.admit_counter(
            &selected.workload.google_service_account,
            &mut self.acquisition,
        )?;
        // The full caller still owns the same actual role/process and its
        // admission interval. Do not publish on a tokeninfo-only success.
        self.process.check(&mut self.acquisition)?;
        self.scope
            .check_selection(self.stage, &self.policy, &self.store, self.purpose)?;
        Ok(CounterConnection {
            owner,
            policy: self.policy,
            purpose: self.purpose,
            store: self.store,
            selection: self.selection,
            http: self.http,
            credential,
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
            let connection = AuthenticatedReads::acquire(policy, store, purpose, stage)?
                .into_counter_connection()?;
            stage.check_current_selection(policy, store, purpose)?;
            original.remaining()?;
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

    /// Fixed restored Controller entry. Only the actual never-attempted slot
    /// may authenticate; every warm request borrows its same admitted owner.
    /// Refused or uncertain admission is terminal, never another cold attempt.
    pub(in crate::security_epoch) fn restored_controller_request<'connection>(
        &'connection mut self,
        stage: &mut EnrolledRoleStage<'_>,
        policy: &InitialBootstrapPolicy,
        store: &EpochStore,
    ) -> Result<CounterRequest<'connection>> {
        if matches!(&self.state, CounterConnectionState::Vacant) {
            self.admit(stage, policy, store, NativeRole::EpochController)?;
        }
        self.request(stage, policy, store, NativeRole::EpochController)
    }

    pub(in crate::security_epoch) fn refuse(&mut self) {
        self.state = CounterConnectionState::Refused;
    }

    /// Final read-only post AFTER native peer return, without re-opening a
    /// counter request or replacing its old observation. This returns no grant.
    pub(in crate::security_epoch) fn check_completed_restored(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        tail: &mut CompletedRestoredCounterRead,
    ) -> Result<()> {
        let mut attempt = CompletedCounterCheck {
            slot: self,
            tail,
            stage,
            done: false,
        };
        let requested: Result<()> = (|| {
            attempt.tail.state.begin_final()?;
            attempt
                .slot
                .completed_current(attempt.stage, attempt.tail)?;
            attempt.tail.remaining_original()
        })();
        // Both posts execute even after a binding/budget/native failure. A
        // fresh sample cannot repair the old observation's high-water/expiry.
        let checked = attempt.slot.completed_current(attempt.stage, attempt.tail);
        let budget_post = attempt.tail.remaining_original();
        requested?;
        checked?;
        budget_post?;
        attempt.tail.state.finish_final()?;
        attempt.done = true;
        Ok(())
    }

    /// Consume the negative duty only AFTER the sole genuine lexical driver
    /// has received actual native completion for this same snapshot. This is
    /// pure identity/refusal validation: no clock, I/O, reauthentication, slot
    /// promotion or permission is produced. Source controls at that driver
    /// must bind this consuming call after the actual native Result succeeds.
    pub(in crate::security_epoch) fn release_completed_restored(
        &mut self,
        mut tail: CompletedRestoredCounterRead,
        snapshot: &Digest,
    ) -> Result<()> {
        let requested: Result<()> = (|| {
            tail.state.require_release()?;
            let CounterConnectionState::Admitted(connection) = &self.state else {
                anyhow::bail!("epoch_completed_counter_slot_refused");
            };
            require_completed_connection(
                tail.request.completed,
                &tail.request.valid,
                &connection.valid,
                &tail.selection,
                &connection.selection,
            )?;
            tail.original
                .require_same(&tail.request.acquisition.retained_refusal())?;
            ensure!(
                connection.purpose == NativeRole::EpochController
                    && tail.observation.snapshot == *snapshot,
                "epoch_completed_counter_snapshot_changed"
            );
            tail.observation
                .require_binding(&tail.selection, &tail.reader)?;
            tail.state.release()?;
            Ok(())
        })();
        if requested.is_err() {
            tail.refuse();
            self.refuse();
        }
        requested
    }

    fn completed_current(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        tail: &mut CompletedRestoredCounterRead,
    ) -> Result<()> {
        let CounterConnectionState::Admitted(connection) = &mut self.state else {
            anyhow::bail!("epoch_completed_counter_slot_refused");
        };
        require_completed_connection(
            tail.request.completed,
            &tail.request.valid,
            &connection.valid,
            &tail.selection,
            &connection.selection,
        )?;
        ensure!(
            connection.purpose == NativeRole::EpochController
                && connection.selection == Digest::of(&connection.store)?,
            "epoch_completed_counter_selection_changed"
        );
        tail.original
            .require_same(&tail.request.acquisition.retained_refusal())?;
        connection.owner.check(stage)?;
        stage.check_current_selection(&connection.policy, &connection.store, connection.purpose)?;
        // Bind to the SAME actual saved original before using the retained
        // credential ceiling, then meet its shorter bound back into that stage.
        connection
            .owner
            .meet_current_read_view(stage, &mut tail.request.acquisition)?;
        connection.credential.check(
            &mut tail.request.acquisition,
            connection.store.max_lease_seconds,
        )?;
        connection
            .owner
            .meet_current_read_view(stage, &mut tail.request.acquisition)?;
        connection.owner.check(stage)?;
        tail.request.acquisition.remaining()?;
        Ok(())
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

    /// Read the complete restored-writer lineage on this actual admitted
    /// connection and original. No initial bootstrap request or observation is
    /// manufactured. The independent post runs even on transport/codec error.
    pub(in crate::security_epoch) fn read_restored(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        selection: &EpochStore,
        names: &firestore::RestoreWriterPeerRead,
    ) -> Result<RestoredEpochObservation> {
        let requested: Result<RestoredEpochObservation> = (|| {
            ensure!(
                self.connection.store == *selection && names.matches_selection_data(selection),
                "epoch_counter_restored_selection_changed"
            );
            self.check(stage)?;
            let mut budget = self.request.acquisition.budget()?;
            let mut port = CounterReadPort {
                request: self,
                stage,
            };
            let bytes = budget.call(
                &mut port,
                &names.endpoint_data(),
                &names.strong_body_data()?,
            )?;
            let snapshot = names.response_commitment_data(&bytes)?;
            budget.remaining_decoding(&mut port)?;
            Ok(RestoredEpochObservation {
                selection: Digest::of(selection)?,
                reader: names.binding_data()?,
                snapshot,
                budget,
                valid: true,
                local: std::marker::PhantomData,
            })
        })();
        let checked = self.check(stage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let observed = requested?;
        checked?;
        Ok(observed)
    }

    /// The caller checks its OLD observation before replacing it with a fresh
    /// read. A fresh response can never repair this original or refusal latch.
    pub(in crate::security_epoch) fn check_restored_observation(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        names: &firestore::RestoreWriterPeerRead,
        observation: &mut RestoredEpochObservation,
    ) -> Result<()> {
        let requested = (|| {
            self.check(stage)?;
            let selection = self.connection.store.clone();
            observation.remaining(
                &selection,
                names,
                &mut CounterReadPort {
                    request: self,
                    stage,
                },
            )
        })();
        let checked = self.check(stage);
        if requested.is_err() || checked.is_err() {
            observation.refuse();
            self.refuse();
        }
        requested?;
        checked
    }

    /// One fixed read-only confirmation on THIS retained request and original.
    /// It supplies no write port or owner reconstructed from reservation DATA.
    pub(in crate::security_epoch) fn confirm_restore_reservation(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        selection: &EpochStore,
        names: &firestore::RestoreConfirmationNames,
    ) -> Result<crate::security_epoch::kernel::Snapshot> {
        let requested = (|| {
            ensure!(
                self.connection.store == *selection && names.matches_selection(selection),
                "epoch_counter_restore_selection_changed"
            );
            self.check(stage)?;
            let mut budget = self.request.acquisition.budget()?;
            let mut port = CounterReadPort {
                request: self,
                stage,
            };
            let bytes = budget.call(&mut port, &names.endpoint(), &names.body()?)?;
            let observed = names.confirm(&bytes)?;
            budget.remaining_decoding(&mut port)?;
            Ok(observed.snapshot)
        })();
        // Evaluate the real postcheck even if the read, decoding or equality
        // check failed. Preserve that first failure and permanently refuse.
        let checked = self.check(stage);
        if requested.is_err() || checked.is_err() {
            self.refuse();
        }
        let snapshot = requested?;
        checked?;
        Ok(snapshot)
    }

    pub(in crate::security_epoch) fn finish(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<()> {
        self.check(stage)?;
        self.request.completed = true;
        Ok(())
    }

    /// End the real counter borrow BEFORE peer release while retaining its
    /// actual original and OLD ten-record budget for the later final post.
    /// Moving the whole guard avoids a self-reference to the admitted slot.
    pub(in crate::security_epoch) fn finish_restored(
        mut self,
        stage: &mut EnrolledRoleStage<'_>,
        names: &firestore::RestoreWriterPeerRead,
        mut observation: RestoredEpochObservation,
    ) -> Result<CompletedRestoredCounterRead> {
        let requested: Result<(Digest, Digest, NativeOriginalRefusal)> = (|| {
            ensure!(
                self.connection.purpose == NativeRole::EpochController,
                "epoch_completed_counter_controller_required"
            );
            self.check_restored_observation(stage, names, &mut observation)?;
            let selection = self.connection.selection.clone();
            let reader = names.binding_data()?;
            let original = self.request.acquisition.retained_refusal();
            self.finish(stage)?;
            Ok((selection, reader, original))
        })();
        if requested.is_err() {
            observation.refuse();
            self.refuse();
        }
        let (selection, reader, original) = requested?;
        // No fallible operation, clock, I/O or callback after finish and before
        // moving this exact guard; no scalar reconstructs its acquisition.
        Ok(CompletedRestoredCounterRead {
            request: self.request,
            observation,
            selection,
            reader,
            original,
            state: CompletedReadState::PendingFinal,
        })
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
    local_owner!(CounterUseGuard);
    local_owner!(RestoredEpochObservation);
    local_owner!(CompletedRestoredCounterRead);
    local_owner!(CompletedCounterCheck<'static, 'static, 'static, 'static>);
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
    use super::{CounterUseGuard, Route, counter_read_route};
    use crate::security_epoch::native_clock::NativeAcquisition;
    use day2_capabilities::Digest;
    use std::{cell::Cell, rc::Rc, time::Duration};
    use syn::parse::Parser;
    use syn::visit::Visit;

    // Clock/binding adapter tests only: these construct no native role,
    // enrolled CounterConnection, real read receipt, physical owner or Current.
    struct ObservationClock {
        domain: Digest,
        now: Duration,
    }

    impl crate::security_epoch::firestore::Port for ObservationClock {
        fn sample(&mut self) -> anyhow::Result<crate::security_epoch::firestore::Sample> {
            Ok(crate::security_epoch::firestore::Sample {
                domain: self.domain.clone(),
                elapsed: self.now,
            })
        }

        fn post(
            &mut self,
            _: &str,
            _: &[u8],
            _: &mut crate::security_epoch::firestore::Budget,
            _: usize,
        ) -> anyhow::Result<crate::security_epoch::firestore::EpochReply> {
            anyhow::bail!("observation_clock_has_no_transport")
        }

        fn refuse(&mut self) {}
    }

    fn observation_clock_fixture() -> (super::RestoredEpochObservation, ObservationClock) {
        use crate::security_epoch::firestore::{Budget, Sample};
        let domain = Digest::new(b"actual-lower-original");
        let budget = Budget::from_native_origin(
            Sample {
                domain: domain.clone(),
                elapsed: Duration::from_secs(10),
            },
            Duration::from_secs(10),
            Duration::from_secs(15),
        )
        .unwrap();
        (
            super::RestoredEpochObservation {
                selection: Digest::new(b"selected-store"),
                reader: Digest::new(b"complete-restored-reader"),
                snapshot: Digest::new(b"complete-ten-record-commitment"),
                budget,
                valid: true,
                local: std::marker::PhantomData,
            },
            ObservationClock {
                domain,
                now: Duration::from_secs(10),
            },
        )
    }

    #[test]
    fn restored_observation_keeps_before_io_origin_and_permanent_clock_refusal() {
        let (mut observed, mut port) = observation_clock_fixture();
        let selection = observed.selection.clone();
        let reader = observed.reader.clone();
        port.now = Duration::from_secs(14); // Delivery consumed four seconds.
        observed
            .remaining_bound(&selection, &reader, &mut port)
            .unwrap();
        assert_eq!(
            observed.snapshot_data(),
            &Digest::new(b"complete-ten-record-commitment")
        );
        port.now = Duration::from_secs(15); // Equality is refusal, not a new lease.
        assert!(
            observed
                .remaining_bound(&selection, &reader, &mut port)
                .is_err()
        );
        port.now = Duration::from_secs(14);
        assert!(
            observed
                .remaining_bound(&selection, &reader, &mut port)
                .is_err()
        );
    }

    #[test]
    fn restored_observation_replay_matches_independent_binding_clock_model() {
        // Independent model retains its own scalar original/deadline/highwater
        // and latch. It never reads the production Budget or validity fields.
        for seed in 0..32_u64 {
            let (mut observed, mut port) = observation_clock_fixture();
            let selection = Digest::new(b"selected-store");
            let reader = Digest::new(b"complete-restored-reader");
            let mut valid = true;
            let mut highwater = 10_u64;
            for step in 0..12_u64 {
                let event = (seed.wrapping_mul(7) + step.wrapping_mul(11)) % 9;
                let time = match event {
                    0 => 9,
                    1 => 15,
                    2 => 16,
                    _ => 10 + step % 5,
                };
                let selected = if event == 3 {
                    Digest::new(b"foreign-store")
                } else {
                    selection.clone()
                };
                let names = if event == 4 {
                    Digest::new(b"same-selectors-different-activation")
                } else {
                    reader.clone()
                };
                let domain = if event == 5 {
                    Digest::new(b"foreign-original")
                } else {
                    Digest::new(b"actual-lower-original")
                };
                let expected = valid
                    && event != 3
                    && event != 4
                    && event != 5
                    && time >= highwater
                    && time < 15;
                if expected {
                    highwater = time;
                } else {
                    valid = false;
                }
                port.now = Duration::from_secs(time);
                port.domain = domain;
                let actual = observed
                    .remaining_bound(&selected, &names, &mut port)
                    .is_ok();
                assert_eq!(actual, expected, "seed={seed}, step={step}, event={event}");
            }
        }
    }

    #[test]
    fn completed_connection_comparison_twice_replays_independent_negative_root_histories() {
        // Pure comparison/latch leaf only. No admitted connection, genuine
        // completion tail, enrolled role, physical owner or Current exists.
        for seed in 0..32_u64 {
            let mut replays = Vec::new();
            for _ in 0..2 {
                let roots = [Rc::new(Cell::new(true)), Rc::new(Cell::new(true))];
                let selection = Digest::new(b"actual-completed-selection");
                let mut model = [true, true];
                let mut trace = Vec::new();
                for step in 0..12_u64 {
                    let event = (seed.wrapping_mul(5) + step.wrapping_mul(11)) % 7;
                    let selected = usize::from(event == 2);
                    let completed = event != 0;
                    let selected_digest = if event == 1 {
                        Digest::new(b"foreign-selection")
                    } else {
                        selection.clone()
                    };
                    if event == 3 {
                        roots[0].set(false);
                        model[0] = false;
                    }
                    if event == 4 {
                        roots[selected].set(false);
                        model[selected] = false;
                    }
                    let expected =
                        completed && model[0] && model[selected] && selected == 0 && event != 1;
                    if !expected {
                        model[0] = false;
                        model[selected] = false;
                    }
                    let actual = super::require_completed_connection(
                        completed,
                        &roots[0],
                        &roots[selected],
                        &selection,
                        &selected_digest,
                    )
                    .is_ok();
                    assert_eq!(actual, expected, "seed={seed}, step={step}, event={event}");
                    assert_eq!([roots[0].get(), roots[1].get()], model);
                    trace.push((actual, [roots[0].get(), roots[1].get()]));
                }
                replays.push(trace);
            }
            assert_eq!(replays[0], replays[1]);
        }
    }

    #[test]
    fn completed_observation_retains_its_old_budget_despite_replacement_clock_attempts() {
        // Real lower native-clock/Budget adapters, not a completed owner or
        // stage. Fresh fixture clocks deliberately cannot renew the OLD read.
        for seed in 0..32_u64 {
            let mut replays = Vec::new();
            for _ in 0..2 {
                let (mut observed, _) = observation_clock_fixture();
                let selected = Digest::new(b"selected-store");
                let reader = Digest::new(b"complete-restored-reader");
                let mut valid = true;
                let mut latest = 10_u64;
                let mut trace = Vec::new();
                for step in 0..12_u64 {
                    let event = (seed.wrapping_mul(7) + step.wrapping_mul(11)) % 9;
                    let now = match event {
                        0 => 9,
                        1 => 15,
                        2 => 16,
                        _ => 10 + step % 5,
                    };
                    let selection = if event == 3 {
                        Digest::new(b"foreign-store")
                    } else {
                        selected.clone()
                    };
                    let names = if event == 4 {
                        Digest::new(b"foreign-reader")
                    } else {
                        reader.clone()
                    };
                    let domain = if event == 5 {
                        Digest::new(b"foreign-original")
                    } else {
                        Digest::new(b"actual-lower-original")
                    };
                    // A new test clock would otherwise have its own five
                    // seconds from now. Only the retained observation's old
                    // domain/high-water/15s deadline is the model's oracle.
                    let mut clock = NativeAcquisition::fixture(
                        domain,
                        std::process::id(),
                        Duration::from_secs(now),
                        Duration::from_secs(5),
                    );
                    if event == 6 {
                        clock.refuse();
                    }
                    let expected = valid
                        && event != 3
                        && event != 4
                        && event != 5
                        && event != 6
                        && now >= latest
                        && now < 15;
                    if expected {
                        latest = now;
                    } else {
                        valid = false;
                    }
                    let actual = observed
                        .remaining_completed_original(&selection, &names, &mut clock)
                        .is_ok();
                    assert_eq!(actual, expected, "seed={seed}, step={step}, event={event}");
                    trace.push(actual);
                }
                replays.push(trace);
            }
            assert_eq!(replays[0], replays[1]);
        }
    }

    #[test]
    fn completed_read_lifecycle_twice_replays_an_independent_one_way_model() {
        use super::CompletedReadState as State;
        for seed in 0..32_u64 {
            let mut replays = Vec::new();
            for _ in 0..2 {
                let mut state = State::PendingFinal;
                let mut model = 0_u8; // pending, checking, checked, released, refused
                let mut trace = Vec::new();
                for step in 0..12_u64 {
                    let action = if seed % 2 == 0 && step < 3 {
                        step
                    } else {
                        (seed * 3 + step * 7) % 5
                    };
                    let expected = match action {
                        0 if model == 0 => {
                            model = 1;
                            true
                        }
                        1 if model == 1 => {
                            model = 2;
                            true
                        }
                        2 if model == 2 => {
                            model = 3;
                            true
                        }
                        3 if model == 2 => true,
                        4 => {
                            model = 4;
                            true
                        }
                        _ => {
                            model = 4;
                            false
                        }
                    };
                    let actual = match action {
                        0 => state.begin_final().is_ok(),
                        1 => state.finish_final().is_ok(),
                        2 => state.release().is_ok(),
                        3 => state.require_release().is_ok(),
                        _ => {
                            state.refuse();
                            true
                        }
                    };
                    assert_eq!(
                        actual, expected,
                        "seed={seed}, step={step}, action={action}"
                    );
                    let observed = match state {
                        State::PendingFinal => 0,
                        State::Checking => 1,
                        State::FinalChecked => 2,
                        State::Released => 3,
                        State::Refused => 4,
                    };
                    assert_eq!(observed, model);
                    trace.push((actual, observed));
                }
                replays.push(trace);
            }
            assert_eq!(replays[0], replays[1]);
        }
    }

    // Finite source comparison for these closed bodies, not a macro resolver.
    // Preserve tuple grouping/commas; ignore only formatter-optional commas in
    // call/macro/struct lists and punctuation's token-string spacing.
    fn completed_tokens(stream: proc_macro2::TokenStream) -> String {
        fn normalize_punctuation(tokens: Vec<proc_macro2::TokenTree>) -> proc_macro2::TokenStream {
            use proc_macro2::{Punct, Spacing, TokenTree};
            // Preserve actual compound operators. Only an operator's boundary
            // spacing may differ between source macro tokens and typed syn:
            // `==&value` is `==` then `&`, but `&&` is NEVER two references.
            const OPERATORS: &[&str] = &[
                "<<=", ">>=", "...", "..=", "::", "->", "=>", "==", "!=", ">=", "<=", "&&", "||",
                "<<", ">>", "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "..",
            ];
            let mut output = Vec::new();
            let mut index = 0;
            while index < tokens.len() {
                let TokenTree::Punct(first) = &tokens[index] else {
                    output.push(tokens[index].clone());
                    index += 1;
                    continue;
                };
                let mut end = index + 1;
                let mut previous = first;
                while previous.spacing() == Spacing::Joint {
                    let Some(TokenTree::Punct(next)) = tokens.get(end) else {
                        break;
                    };
                    previous = next;
                    end += 1;
                }
                let mut at = index;
                while at < end {
                    let available: String = tokens[at..end]
                        .iter()
                        .map(|token| {
                            let TokenTree::Punct(p) = token else {
                                unreachable!();
                            };
                            p.as_char()
                        })
                        .collect();
                    let length = OPERATORS
                        .iter()
                        .find(|op| available.starts_with(**op))
                        .map_or(1, |op| op.len());
                    for offset in 0..length {
                        let TokenTree::Punct(p) = &tokens[at + offset] else {
                            unreachable!();
                        };
                        let spacing = if offset + 1 < length {
                            Spacing::Joint
                        } else if at + offset + 1 == end {
                            p.spacing()
                        } else {
                            Spacing::Alone
                        };
                        output.push(TokenTree::Punct(Punct::new(p.as_char(), spacing)));
                    }
                    at += length;
                }
                index = end;
            }
            output.into_iter().collect()
        }
        fn normalize(stream: proc_macro2::TokenStream) -> proc_macro2::TokenStream {
            use proc_macro2::{Delimiter, Group, TokenTree};
            let mut output = Vec::new();
            for token in stream {
                match token {
                    TokenTree::Group(group) => {
                        let optional = matches!(output.last(),Some(TokenTree::Ident(name))
                            if !["let","return","if","else","while","for","match"].contains(&name.to_string().as_str()))
                            || matches!(output.last(),Some(TokenTree::Punct(p)) if matches!(p.as_char(),'!'|'>'));
                        let mut inner: Vec<_> = normalize(group.stream()).into_iter().collect();
                        if optional
                            && matches!(
                                group.delimiter(),
                                Delimiter::Parenthesis | Delimiter::Brace
                            )
                            && matches!(inner.last(),Some(TokenTree::Punct(p)) if p.as_char()==',')
                        {
                            inner.pop();
                        }
                        output.push(TokenTree::Group(Group::new(
                            group.delimiter(),
                            inner.into_iter().collect(),
                        )));
                    }
                    other => output.push(other),
                }
            }
            normalize_punctuation(output)
        }
        normalize(stream).to_string()
    }

    fn completed_body(owner: &str, name: &str) -> syn::Block {
        let file = syn::parse_file(include_str!("connection.rs")).unwrap();
        let mut bodies=file.items.into_iter().filter_map(|item| {
            let syn::Item::Impl(item)=item else {return None;};
            if !matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.len()==1 && path.path.segments[0].ident==owner) {return None;}
            item.items.into_iter().find_map(|item|match item {
                syn::ImplItem::Fn(method) if method.sig.ident==name=>Some(method.block),_=>None,
            })
        });
        let result = bodies.next().expect("actual unique closed method");
        assert!(bodies.next().is_none());
        result
    }

    fn same_completed_body(actual: &syn::Block, expected: &str) -> bool {
        use quote::ToTokens as _;
        let expected: syn::Block = syn::parse_str(expected).unwrap();
        completed_tokens(actual.to_token_stream()) == completed_tokens(expected.to_token_stream())
    }

    #[test]
    fn completed_body_comparison_keeps_tuple_arguments_and_arity() {
        let normal = |s: &str| completed_tokens(s.parse().unwrap());
        assert_eq!(normal("call(stage,)"), normal("call(stage)"));
        assert_ne!(normal("(stage,)"), normal("(stage)"));
        assert_ne!(normal("let (stage,)=value;"), normal("let (stage)=value;"));
        assert_ne!(normal("return (stage,);"), normal("return (stage);"));
        assert_ne!(normal("call(stage,reader)"), normal("call((stage,reader))"));
        assert_ne!(normal("call(actual)"), normal("call(foreign)"));
        assert_ne!(normal("a && b"), normal("a & &b"));
        assert_ne!(normal("a || b"), normal("a | |x| b"));
        assert_eq!(
            normal("ensure!(actual==&value)"),
            normal("ensure!(actual == &value)")
        );
    }

    #[test]
    fn restored_counter_factory_authenticates_only_the_real_never_attempted_slot() {
        let actual = completed_body("CounterConnectionSlot", "restored_controller_request");
        let expected = r#"{
            if matches!(&self.state,CounterConnectionState::Vacant) {
                self.admit(stage,policy,store,NativeRole::EpochController)?;
            }
            self.request(stage,policy,store,NativeRole::EpochController)
        }"#;
        assert!(same_completed_body(&actual, expected));
        use quote::ToTokens as _;
        let rendered = actual.to_token_stream().to_string();
        for (from, to) in [
            (
                "CounterConnectionState :: Vacant",
                "CounterConnectionState::Refused",
            ),
            (
                "self . admit (stage , policy , store , NativeRole :: EpochController)",
                "unrelated()",
            ),
            (
                "self . request (stage , policy , store , NativeRole :: EpochController)",
                "Ok(forged)",
            ),
        ] {
            assert_eq!(rendered.matches(from).count(), 1);
            let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(
                !same_completed_body(&changed, expected),
                "fixed cold/warm cut {from}"
            );
        }
        let changed: syn::Block = syn::parse_quote!({
            if !matches!(&self.state, CounterConnectionState::Admitted(_)) {
                self.admit(stage, policy, store, NativeRole::EpochController)?;
            }
            self.request(stage, policy, store, NativeRole::EpochController)
        });
        assert!(
            !same_completed_body(&changed, expected),
            "no failed-admission fallback"
        );
    }

    #[test]
    fn actual_restored_finish_moves_the_same_guard_and_old_observation_without_a_new_clock() {
        let actual = completed_body("CounterRequest", "finish_restored");
        let expected = r#"{
            let requested:Result<(Digest,Digest,NativeOriginalRefusal)>=(|| {
                ensure!(self.connection.purpose==NativeRole::EpochController,"epoch_completed_counter_controller_required");
                self.check_restored_observation(stage,names,&mut observation)?;
                let selection=self.connection.selection.clone();
                let reader=names.binding_data()?;
                let original=self.request.acquisition.retained_refusal();
                self.finish(stage)?;
                Ok((selection,reader,original))
            })();
            if requested.is_err() {observation.refuse();self.refuse();}
            let (selection,reader,original)=requested?;
            Ok(CompletedRestoredCounterRead {request:self.request,observation,selection,reader,original,state:CompletedReadState::PendingFinal})
        }"#;
        assert!(same_completed_body(&actual, expected));
        use quote::ToTokens as _;
        let rendered = actual.to_token_stream().to_string();
        for (from, to) in [
            (
                "self . check_restored_observation (stage , names , & mut observation)",
                "self.check(stage)",
            ),
            ("self . finish (stage)", "unrelated()"),
            ("request : self . request", "request:forged"),
            (
                "CompletedReadState :: PendingFinal",
                "CompletedReadState::Released",
            ),
            ("observation . refuse () ; self . refuse ()", "unrelated()"),
        ] {
            assert_eq!(rendered.matches(from).count(), 1);
            let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(
                !same_completed_body(&changed, expected),
                "closed finish cut {from}"
            );
        }
    }

    #[test]
    fn actual_completed_post_arms_before_work_keeps_both_independent_posts_and_error_priority() {
        let actual = completed_body("CounterConnectionSlot", "check_completed_restored");
        let expected = r#"{
            let mut attempt=CompletedCounterCheck {slot:self,tail,stage,done:false};
            let requested:Result<()>=(|| {
                attempt.tail.state.begin_final()?;
                attempt.slot.completed_current(attempt.stage,attempt.tail)?;
                attempt.tail.remaining_original()
            })();
            let checked=attempt.slot.completed_current(attempt.stage,attempt.tail);
            let budget_post=attempt.tail.remaining_original();
            requested?;
            checked?;
            budget_post?;
            attempt.tail.state.finish_final()?;
            attempt.done=true;
            Ok(())
        }"#;
        assert!(same_completed_body(&actual, expected));
        for cut in 0..actual.stmts.len() - 1 {
            let mut omitted = actual.clone();
            omitted.stmts.remove(cut);
            assert!(!same_completed_body(&omitted, expected), "post cut {cut}");
        }
        let mut conditional = actual.clone();
        conditional.stmts[2] = syn::parse_quote!(let checked=if requested.is_ok() {attempt.slot.completed_current(attempt.stage,attempt.tail)} else {Ok(())};);
        assert!(!same_completed_body(&conditional, expected));
        let mut priority = actual.clone();
        priority.stmts.swap(4, 5);
        assert!(!same_completed_body(&priority, expected));
        let mut premature = actual.clone();
        premature.stmts.swap(7, 4);
        assert!(!same_completed_body(&premature, expected));
    }

    #[test]
    fn actual_completed_owner_guard_meets_only_the_old_acquisition_and_rechecks_credential_ceiling()
    {
        let actual = completed_body("CounterConnectionSlot", "completed_current");
        let expected = r#"{
            let CounterConnectionState::Admitted(connection)=&mut self.state else {anyhow::bail!("epoch_completed_counter_slot_refused");};
            require_completed_connection(tail.request.completed,&tail.request.valid,&connection.valid,&tail.selection,&connection.selection)?;
            ensure!(connection.purpose==NativeRole::EpochController && connection.selection==Digest::of(&connection.store)?,"epoch_completed_counter_selection_changed");
            tail.original.require_same(&tail.request.acquisition.retained_refusal())?;
            connection.owner.check(stage)?;
            stage.check_current_selection(&connection.policy,&connection.store,connection.purpose)?;
            connection.owner.meet_current_read_view(stage,&mut tail.request.acquisition)?;
            connection.credential.check(&mut tail.request.acquisition,connection.store.max_lease_seconds)?;
            connection.owner.meet_current_read_view(stage,&mut tail.request.acquisition)?;
            connection.owner.check(stage)?;
            tail.request.acquisition.remaining()?;
            Ok(())
        }"#;
        assert!(same_completed_body(&actual, expected));
        for cut in 0..actual.stmts.len() - 1 {
            let mut omitted = actual.clone();
            omitted.stmts.remove(cut);
            assert!(
                !same_completed_body(&omitted, expected),
                "old-acquisition cut {cut}"
            );
        }
        let mut wrong_stage = actual.clone();
        wrong_stage.stmts[6] = syn::parse_quote!(connection.owner.meet_current_read_view(foreign,&mut tail.request.acquisition)?;);
        assert!(!same_completed_body(&wrong_stage, expected));
        let mut swapped = actual.clone();
        swapped.stmts.swap(7, 8);
        assert!(!same_completed_body(&swapped, expected));
        let calls = method_calls(
            include_str!("connection.rs"),
            "CounterConnectionSlot",
            "completed_current",
        );
        for denied in [
            "request",
            "read",
            "read_restored",
            "admit",
            "acquire",
            "narrow_io_acquisition",
            "begin",
            "budget",
            "post",
            "authorization",
        ] {
            assert!(
                !calls.iter().any(|call| call == denied),
                "no new authority: {denied}"
            );
        }
    }

    #[test]
    fn actual_completed_disposal_consumes_only_final_checked_same_snapshot_without_any_clock() {
        let actual = completed_body("CounterConnectionSlot", "release_completed_restored");
        let expected = r#"{
            let requested:Result<()>=(|| {
                tail.state.require_release()?;
                let CounterConnectionState::Admitted(connection)=&self.state else {anyhow::bail!("epoch_completed_counter_slot_refused");};
                require_completed_connection(tail.request.completed,&tail.request.valid,&connection.valid,&tail.selection,&connection.selection)?;
                tail.original.require_same(&tail.request.acquisition.retained_refusal())?;
                ensure!(connection.purpose==NativeRole::EpochController && tail.observation.snapshot==*snapshot,"epoch_completed_counter_snapshot_changed");
                tail.observation.require_binding(&tail.selection,&tail.reader)?;
                tail.state.release()?;
                Ok(())
            })();
            if requested.is_err() {tail.refuse();self.refuse();}
            requested
        }"#;
        assert!(same_completed_body(&actual, expected));
        use quote::ToTokens as _;
        let rendered = actual.to_token_stream().to_string();
        for (from, to) in [
            ("tail . state . require_release ()", "unrelated()"),
            ("tail . observation . snapshot == * snapshot", "true"),
            (
                "tail . observation . require_binding (& tail . selection , & tail . reader)",
                "unrelated()",
            ),
            ("tail . state . release ()", "unrelated()"),
            ("tail . refuse () ; self . refuse ()", "unrelated()"),
        ] {
            assert_eq!(rendered.matches(from).count(), 1);
            let changed: syn::Block = syn::parse_str(&rendered.replacen(from, to, 1)).unwrap();
            assert!(
                !same_completed_body(&changed, expected),
                "disposal cut {from}"
            );
        }
        let calls = method_calls(
            include_str!("connection.rs"),
            "CounterConnectionSlot",
            "release_completed_restored",
        );
        for denied in [
            "sample",
            "check",
            "remaining",
            "remaining_native",
            "begin",
            "request",
            "admit",
            "read",
            "read_restored",
            "post",
            "authorization",
        ] {
            assert!(
                !calls.iter().any(|call| call == denied),
                "disposal is negative only: {denied}"
            );
        }
    }

    #[test]
    fn actual_completed_token_and_check_scope_keep_drop_refusal_until_consuming_release() {
        let actual = completed_body("CompletedRestoredCounterRead", "drop");
        assert!(same_completed_body(
            &actual,
            "{if self.state != CompletedReadState::Released {self.refuse();}}"
        ));
        let mut lost = actual.clone();
        lost.stmts.clear();
        assert!(!same_completed_body(
            &lost,
            "{if self.state != CompletedReadState::Released {self.refuse();}}"
        ));
        let actual = completed_body("CompletedCounterCheck", "drop");
        let expected =
            "{if !self.done {self.stage.refuse_serving();self.tail.refuse();self.slot.refuse();}}";
        assert!(same_completed_body(&actual, expected));
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = &actual.stmts[0] else {
            panic!("actual armed drop");
        };
        for cut in 0..3 {
            let mut changed = actual.clone();
            let syn::Stmt::Expr(syn::Expr::If(changed_branch), _) = &mut changed.stmts[0] else {
                unreachable!();
            };
            changed_branch.then_branch.stmts.remove(cut);
            assert!(!same_completed_body(&changed, expected));
        }
        assert_eq!(branch.then_branch.stmts.len(), 3);
    }

    fn completed_factories(source: &str) -> Vec<(Option<String>, Option<String>)> {
        #[derive(Default)]
        struct Factories {
            owner: Option<String>,
            method: Option<String>,
            found: Vec<(Option<String>, Option<String>)>,
        }
        impl<'ast> Visit<'ast> for Factories {
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                if item.attrs.iter().any(|a|matches!(&a.meta,syn::Meta::List(meta) if meta.path.is_ident("cfg") && meta.tokens.to_string()=="test")) {return;}
                syn::visit::visit_item_mod(self, item);
            }
            fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
                let old = self.owner.clone();
                self.owner = match &*item.self_ty {
                    syn::Type::Path(path) if path.path.segments.len() == 1 => {
                        Some(path.path.segments[0].ident.to_string())
                    }
                    _ => None,
                };
                syn::visit::visit_item_impl(self, item);
                self.owner = old;
            }
            fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
                let old = self.method.replace(item.sig.ident.to_string());
                syn::visit::visit_impl_item_fn(self, item);
                self.method = old;
            }
            fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
                if item.path.segments.last().is_some_and(|part| {
                    part.ident == "CompletedRestoredCounterRead"
                        || part.ident == "Self"
                            && self.owner.as_deref() == Some("CompletedRestoredCounterRead")
                }) {
                    self.found.push((self.owner.clone(), self.method.clone()));
                }
                syn::visit::visit_expr_struct(self, item);
            }
        }
        let mut found = Factories::default();
        found.visit_file(&syn::parse_file(source).unwrap());
        found.found
    }

    #[test]
    fn completed_tail_has_only_the_actual_consuming_finish_factory_and_no_part_adoption() {
        let source = include_str!("connection.rs");
        let expected = vec![(
            Some("CounterRequest".to_owned()),
            Some("finish_restored".to_owned()),
        )];
        assert_eq!(completed_factories(source), expected);
        for counterfeit in [
            "fn counterfeit(request:Untrusted,observation:Untrusted,selection:Untrusted,reader:Untrusted)->Untrusted {CompletedRestoredCounterRead {request,observation,selection,reader,state:CompletedReadState::PendingFinal}}",
            "impl CompletedRestoredCounterRead {fn counterfeit(request:Untrusted,observation:Untrusted,selection:Untrusted,reader:Untrusted)->Self {Self {request,observation,selection,reader,state:CompletedReadState::PendingFinal}}}",
        ] {
            assert_ne!(
                completed_factories(&format!("{source}\n{counterfeit}")),
                expected
            );
        }
    }

    fn restored_read_post_order(source: &str) -> bool {
        fn is_error_call(value: &syn::Expr, name: &str) -> bool {
            matches!(value,syn::Expr::MethodCall(c) if c.method=="is_err" && c.args.is_empty()
                && matches!(&*c.receiver,syn::Expr::Path(p) if p.path.is_ident(name)))
        }
        let file = syn::parse_file(source).unwrap();
        let function = file.items.iter().find_map(|item| match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty,syn::Type::Path(p) if p.path.segments.last().is_some_and(|s|s.ident=="CounterRequest")) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident=="read_restored" => Some(method), _=>None,
            }), _=>None,
        }).unwrap();
        let statements = &function.block.stmts;
        matches!(statements.first(),Some(syn::Stmt::Local(local))
            if matches!(&local.pat,syn::Pat::Type(typed)
                if matches!(&*typed.pat,syn::Pat::Ident(p) if p.ident=="requested")))
            && matches!(statements.get(1),Some(syn::Stmt::Local(local)) if matches!(&local.pat,syn::Pat::Ident(p) if p.ident=="checked") && local.init.as_ref().is_some_and(|i|matches!(&*i.expr,syn::Expr::MethodCall(c) if c.method=="check")))
            && matches!(statements.get(2),Some(syn::Stmt::Expr(syn::Expr::If(branch),_))
                if matches!(&*branch.cond,syn::Expr::Binary(e) if matches!(e.op,syn::BinOp::Or(_))
                    && is_error_call(&e.left,"requested") && is_error_call(&e.right,"checked"))
                && branch.else_branch.is_none() && branch.then_branch.stmts.len()==1
                && matches!(branch.then_branch.stmts.first(),Some(syn::Stmt::Expr(syn::Expr::MethodCall(c),Some(_)))
                    if c.method=="refuse" && c.args.is_empty() && matches!(&*c.receiver,syn::Expr::Path(p) if p.path.is_ident("self"))))
            && matches!(statements.get(3),Some(syn::Stmt::Local(local)) if matches!(&local.pat,syn::Pat::Ident(p) if p.ident=="observed") && local.init.as_ref().is_some_and(|i|matches!(&*i.expr,syn::Expr::Try(t) if matches!(&*t.expr,syn::Expr::Path(p) if p.path.is_ident("requested")))))
            && matches!(statements.get(4),Some(syn::Stmt::Expr(syn::Expr::Try(t),Some(_))) if matches!(&*t.expr,syn::Expr::Path(p) if p.path.is_ident("checked")))
    }

    #[test]
    fn actual_restored_reader_captures_original_before_io_and_posts_even_after_error() {
        let source = include_str!("connection.rs");
        let calls = method_calls(source, "CounterRequest", "read_restored");
        for required in [
            "budget",
            "call",
            "response_commitment_data",
            "remaining_decoding",
            "binding_data",
        ] {
            assert_eq!(
                calls.iter().filter(|call| *call == required).count(),
                1,
                "{required}"
            );
        }
        assert_eq!(calls.iter().filter(|call| *call == "check").count(), 2);
        for denied in ["begin", "acquire", "finish", "read", "commit", "rollback"] {
            assert!(!calls.iter().any(|call| call == denied), "{denied}");
        }
        let position = |name: &str| calls.iter().position(|call| call == name).unwrap();
        assert!(position("budget") < position("call"));
        assert!(position("call") < position("response_commitment_data"));
        assert!(position("response_commitment_data") < position("remaining_decoding"));
        assert!(restored_read_post_order(source));
        // Exact production target, not a copy of the helper or a fixture string.
        let prefix = source
            .split_once("    pub(in crate::security_epoch) fn read_restored(")
            .unwrap()
            .0;
        let body = &source[prefix.len()..];
        let marker = "let checked = self.check(stage);";
        let changed = body.replacen(marker, "", 1);
        assert_ne!(body, changed);
        assert!(!restored_read_post_order(&format!("{prefix}{changed}")));
        let marker = "self.refuse();";
        let changed = body.replacen(marker, "", 1);
        assert_ne!(body, changed);
        assert!(!restored_read_post_order(&format!("{prefix}{changed}")));
        let marker = "let observed = requested?;";
        let changed = body.replacen(marker, "return requested;", 1);
        assert_ne!(body, changed);
        assert!(!restored_read_post_order(&format!("{prefix}{changed}")));
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

    #[test]
    fn restore_confirmation_keeps_the_actual_read_request_and_unconditional_postcheck() {
        let source = include_str!("connection.rs");
        let name = "confirm_restore_reservation";
        let calls = method_calls(source, "CounterRequest", name);
        assert_eq!(calls.iter().filter(|call| *call == "budget").count(), 1);
        assert_eq!(calls.iter().filter(|call| *call == "call").count(), 1);
        assert_eq!(calls.iter().filter(|call| *call == "confirm").count(), 1);
        assert_eq!(calls.iter().filter(|call| *call == "check").count(), 2);
        for denied in [
            "request",
            "acquire",
            "begin",
            "finish",
            "commit_and_readback",
            "post",
        ] {
            assert!(!calls.iter().any(|call| call == denied));
        }
        // The actual source keeps both Results alive until the permanent
        // refusal decision; `requested?` must not bypass the real postcheck.
        let parsed = syn::parse_file(source).unwrap();
        let method = parsed.items.iter().find_map(|item| match item {
            syn::Item::Impl(item) if matches!(&*item.self_ty,syn::Type::Path(p) if p.path.segments.last().is_some_and(|s|s.ident=="CounterRequest")) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident==name => Some(method),
                _=>None,
            }),
            _=>None,
        }).unwrap();
        fn checked_before_try(body: &syn::Block) -> bool {
            let statements = &body.stmts;
            matches!(statements.get(1), Some(syn::Stmt::Local(local))
                if matches!(&local.pat,syn::Pat::Ident(p) if p.ident=="checked")
                && local.init.as_ref().is_some_and(|i|matches!(&*i.expr,syn::Expr::MethodCall(call) if call.method=="check")))
                && matches!(
                    statements.get(2),
                    Some(syn::Stmt::Expr(syn::Expr::If(_), _))
                )
                && matches!(statements.get(3), Some(syn::Stmt::Local(local))
                    if local.init.as_ref().is_some_and(|i|matches!(&*i.expr,syn::Expr::Try(_))))
        }
        assert!(checked_before_try(&method.block));
        let mut reordered = method.block.clone();
        reordered.stmts.swap(1, 3);
        assert!(!checked_before_try(&reordered));
        let mut missing = method.block.clone();
        missing.stmts.remove(1);
        assert!(!checked_before_try(&missing));
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
        for changed in [
            source.replacen("self.connection.owner.check(stage)?;", "", 1),
            source.replace("stage.check_current_selection(", "stage.check_selection("),
            source.replace(".meet_current_read_view(", ".unchecked_current_read_view("),
            source.replacen(".join_current_view(", ".join_storage_bootstrap_view(", 1),
            source.replacen("self.stage.capture_same_owner()?", "unavailable_owner()", 1),
            source.replacen(".admit_counter(", ".unqualified_counter(", 1),
            source.replacen(
                "let was_vacant = matches!(&self.state, CounterConnectionState::Vacant);",
                "let was_vacant = true;",
                1,
            ),
            source.replacen(
                "CounterConnectionState::Admitted(connection) = &mut self.state",
                "CounterConnectionState::Admitted(connection) = available_elsewhere()",
                1,
            ),
            source.replacen(
                "let checked = (|| {",
                "let checked = (|| { self.admit(stage, policy, store, purpose)?;",
                1,
            ),
        ] {
            assert_ne!(changed, source);
            assert!(!retained_request_shape(&changed));
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
