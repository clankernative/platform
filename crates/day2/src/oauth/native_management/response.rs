//! Actual finite App response ownership. Registry entries are moved, never
//! reconstructed from DATA. The pinned driver keeps lexical native borrows;
//! the registry contains only a negative busy/abort marker while it waits.

#[cfg(test)]
use super::fixtures;
use super::{
    AppStorage, OWNERS, OriginalPhase, Owners, Phase, PhaseOriginal, RuntimeConsumer, Sink,
    SinkState,
};
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
    request_data:
        &'scope Option<crate::security_epoch::native_enrollment::EnrolledRequestDiagnosticData>,
}

/// Historical completion correlation only. No label can construct an owner.
#[derive(Clone, serde::Serialize)]
pub(in crate::oauth) struct QueryCorrelationData {
    invocation: String,
    native: Option<crate::security_epoch::native_enrollment::EnrolledRequestDiagnosticData>,
}

impl QueryCorrelationData {
    #[cfg(test)]
    pub(in crate::oauth) fn maximal_fixture() -> Self {
        Self { invocation: "q".repeat(128), native: Some(crate::security_epoch::native_enrollment::EnrolledRequestDiagnosticData::maximal_fixture()) }
    }
}

struct CorrelationState {
    attempted: bool,
    bound: Option<(ResponseIdentity, QueryCorrelationData)>,
}

pub(super) struct QueryCorrelation {
    state: RefCell<CorrelationState>,
    lost: Cell<bool>,
}

impl QueryCorrelation {
    pub(super) fn new() -> Self {
        Self {
            state: RefCell::new(CorrelationState {
                attempted: false,
                bound: None,
            }),
            lost: Cell::new(false),
        }
    }

    fn bind(
        &self,
        creator: &ResponseIdentity,
        expected: &ResponseIdentity,
        data: QueryCorrelationData,
    ) {
        let Ok(mut state) = self.state.try_borrow_mut() else {
            self.lost.set(true);
            return;
        };
        let bounded = serde_json::to_vec(&data)
            .ok()
            .is_some_and(|bytes| bytes.len() <= 1024);
        let valid = bounded
            && !state.attempted
            && creator.same(expected)
            && !data.invocation.is_empty()
            && data.invocation.len() <= 128
            && data
                .invocation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b));
        state.attempted = true;
        if !valid {
            self.lost.set(true);
            state.bound = None;
            return;
        }
        state.bound = Some((creator.clone(), data));
    }

    pub(super) fn data(&self, creator: &ResponseIdentity) -> Option<QueryCorrelationData> {
        if self.lost.get() {
            return None;
        }
        let state = self.state.try_borrow().ok()?;
        state
            .bound
            .as_ref()
            .filter(|(bound, _)| bound.same(creator))
            .map(|(_, data)| data.clone())
    }
}

impl Sink {
    fn bind_query_correlation(&self, parent: &QueryParent<'_, '_>) {
        let Some(accepted) = parent.accepted.as_ref() else {
            self.query_correlation.lost.set(true);
            return;
        };
        self.query_correlation.bind(
            parent.sql.identity,
            &self.identity,
            QueryCorrelationData {
                invocation: accepted.context.invocation_id.clone(),
                native: parent.sql.request_data.clone(),
            },
        );
    }

    pub(in crate::oauth) fn query_correlation_data(&self) -> Option<QueryCorrelationData> {
        self.query_correlation.data(&self.identity)
    }
}

/// Closed owner of a checked declared API query. Only the actual response
/// future constructs this value, while holding its real Current and request.
pub(crate) struct QueryParent<'scope, 'role> {
    sql: HostSql<'scope, 'role>,
    operation: String,
    accepted: Option<Box<crate::protocol::Request>>,
    observations: Vec<ConnectionObservation>,
}

pub(crate) struct HostRequestOwner<'scope, 'role> {
    source: HostRequestSource<'scope, 'role>,
}

enum HostRequestSource<'scope, 'role> {
    Metadata(HostSql<'scope, 'role>),
    Query(QueryParent<'scope, 'role>),
}

impl<'scope, 'role> HostRequestOwner<'scope, 'role> {
    pub(crate) fn read<T>(
        &mut self,
        operation: impl for<'db> FnOnce(&'db rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        match &mut self.source {
            HostRequestSource::Metadata(sql) => sql.read(operation),
            HostRequestSource::Query(parent) => parent.read(operation),
        }
    }

    pub(crate) fn write<T>(
        &mut self,
        operation: impl for<'db> FnOnce(
            &'db rusqlite::Transaction<'_>,
        ) -> Result<crate::store::SqlDecision<T>>,
    ) -> Result<T> {
        match &mut self.source {
            HostRequestSource::Metadata(sql) => sql.write(operation),
            HostRequestSource::Query(parent) => parent.write(operation),
        }
    }

    pub(crate) fn query(&mut self) -> Result<&mut QueryParent<'scope, 'role>> {
        match &mut self.source {
            HostRequestSource::Query(parent) => Ok(parent),
            HostRequestSource::Metadata(_) => anyhow::bail!("metadata response has no query owner"),
        }
    }
}

/// Short lexical loan, not a new participant, role, clock or purpose. The
/// accepted invocation is DATA bound to this real query parent's creator.
pub(super) struct QueryLoan<'scope, 'role> {
    sql: HostSql<'scope, 'role>,
    accepted: &'scope crate::protocol::Request,
    observations: &'scope mut Vec<ConnectionObservation>,
}

/// Allowlisted observation DATA only. No value here is consumed as authority.
#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ConnectionObservation {
    connection: String,
    observed_at: i64,
    token_version: String,
    token_expires_at: i64,
    refresh_threshold_at: i64,
    outcome: super::super::effects::RefreshObservation,
}

fn observe_material(
    observations: &mut Vec<ConnectionObservation>,
    connection: &str,
    observed_at: i64,
    token_version: i64,
    token_expires_at: i64,
    refresh_threshold_at: i64,
    outcome: super::super::effects::RefreshObservation,
) -> Result<()> {
    super::super::connect::identifier(connection)?;
    ensure!(
        (0..=253_402_300_799).contains(&observed_at)
            && (0..=253_402_300_799).contains(&token_expires_at)
            && (0..=253_402_300_799).contains(&refresh_threshold_at),
        "query observation time refused"
    );
    ensure!(
        observations.len() < 8
            && token_version > 0
            && observed_at >= 0
            && token_expires_at > observed_at
            && refresh_threshold_at >= 0
            && refresh_threshold_at <= token_expires_at,
        "query observation bounds refused"
    );
    observations.push(ConnectionObservation {
        connection: connection.into(),
        observed_at,
        token_version: token_version.to_string(),
        token_expires_at,
        refresh_threshold_at,
        outcome,
    });
    Ok(())
}

fn observation_header(
    observations: &[ConnectionObservation],
) -> Result<Option<axum::http::HeaderValue>> {
    if observations.is_empty() {
        return Ok(None);
    }
    #[derive(serde::Serialize)]
    struct Header<'a> {
        version: u8,
        connections: &'a [ConnectionObservation],
    }
    let bytes = serde_json::to_vec(&Header {
        version: 1,
        connections: observations,
    })?;
    ensure!(bytes.len() <= 4096, "query observation bytes exceeded");
    Ok(Some(axum::http::HeaderValue::from_bytes(&bytes)?))
}

impl QueryLoan<'_, '_> {
    pub(super) fn observe_material(
        &mut self,
        connection: &str,
        version: i64,
        expires_at: i64,
        observed_at: i64,
        threshold_at: i64,
        outcome: super::super::effects::RefreshObservation,
    ) -> Result<()> {
        self.sql.check_sql()?;
        observe_material(
            self.observations,
            connection,
            observed_at,
            version,
            expires_at,
            threshold_at,
            outcome,
        )?;
        self.sql.check_sql()
    }

    pub(super) fn prepare_sql(&mut self, runtime: &crate::store::Runtime) -> Result<()> {
        self.sql.prepare_sql(runtime)
    }
    pub(super) fn check(&mut self) -> Result<()> {
        self.sql.check_sql()
    }
    pub(super) fn refuse(&mut self) {
        self.sql.refuse();
    }
    pub(super) fn reobserve_outside_sql(&mut self) -> Result<()> {
        self.sql.reobserve_outside_sql()
    }
    pub(super) fn read<T>(
        &mut self,
        operation: impl for<'db> FnOnce(&'db rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        self.sql.read(operation)
    }
    pub(super) fn write<T>(
        &mut self,
        operation: impl for<'db> FnOnce(
            &'db rusqlite::Transaction<'_>,
        ) -> Result<crate::store::SqlDecision<T>>,
    ) -> Result<T> {
        self.sql.write(operation)
    }

    pub(super) fn require_request(&self, request: &crate::protocol::Request) -> Result<()> {
        require_same_query(self.accepted, request)
    }
}

// Private lifetime plumbing behind the concrete Calendar instruction entry.
// No operation factory or app-supplied callback is exposed by this helper.
fn checked_query_loan<C, T>(
    current: C,
    mut check: impl FnMut(&mut C) -> Result<()>,
    refuse: impl FnMut(&mut C),
    operation: impl FnOnce(&mut C) -> Result<T>,
) -> Result<T> {
    struct Borrow<C, F: FnMut(&mut C)> {
        current: C,
        refuse: F,
        known: bool,
    }
    impl<C, F: FnMut(&mut C)> Drop for Borrow<C, F> {
        fn drop(&mut self) {
            if !self.known {
                (self.refuse)(&mut self.current);
            }
        }
    }
    let mut borrowed = Borrow {
        current,
        refuse,
        known: false,
    };
    check(&mut borrowed.current)?;
    let result = operation(&mut borrowed.current);
    let checked = check(&mut borrowed.current);
    match (result, checked) {
        (Err(primary), _) => Err(primary),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => {
            borrowed.known = true;
            Ok(value)
        }
    }
}

fn require_same_query(
    accepted: &crate::protocol::Request,
    request: &crate::protocol::Request,
) -> Result<()> {
    ensure!(
        request.operation == accepted.operation
            && request.input == accepted.input
            && request.context == accepted.context,
        "native query invocation changed"
    );
    Ok(())
}

fn accepted_query_in(
    runtime: &crate::store::Runtime,
    db: &rusqlite::Connection,
    operation: &str,
    actor: &str,
    id: &str,
    input: &serde_json::Value,
) -> Result<crate::protocol::Request> {
    runtime.check_binding(db)?;
    ensure!(
        runtime.artifact().route(operation)?.kind == "query",
        "native query kind changed"
    );
    let (stored_operation, stored_actor, stored_input, artifact): (String, String, String, String) =
        db.query_row(
            "SELECT operation,actor,input,artifact FROM day2_invocations WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    ensure!(
        stored_operation == operation
            && stored_actor == actor
            && serde_json::from_str::<serde_json::Value>(&stored_input)? == *input
            && artifact == runtime.artifact().id(),
        "native query acceptance binding changed"
    );
    crate::authority_state::require_invocation_in(db, runtime, id, operation, actor)?;
    Ok(crate::protocol::Request {
        operation: stored_operation,
        input: stored_input,
        context: crate::store::invocation_context(db, id)?,
        observations: Vec::new(),
    })
}

impl QueryParent<'_, '_> {
    pub(crate) fn require_runtime(&mut self, runtime: &crate::store::Runtime) -> Result<()> {
        self.sql.prepare_sql(runtime)
    }

    pub(crate) fn refuse(&mut self) {
        self.sql.refuse();
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        self.sql.check_sql()
    }

    pub(crate) fn observation_header(&mut self) -> Result<Option<axum::http::HeaderValue>> {
        self.check()?;
        observation_header(&self.observations)
    }

    pub(crate) fn read<T>(
        &mut self,
        operation: impl for<'db> FnOnce(&'db rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        self.sql.read(operation)
    }

    pub(crate) fn write<T>(
        &mut self,
        operation: impl for<'db> FnOnce(
            &'db rusqlite::Transaction<'_>,
        ) -> Result<crate::store::SqlDecision<T>>,
    ) -> Result<T> {
        self.sql.write(operation)
    }

    pub(crate) fn bind_accepted(
        &mut self,
        operation: &str,
        actor: &str,
        id: &str,
        input: &serde_json::Value,
    ) -> Result<()> {
        ensure!(
            self.accepted.is_none() && operation == self.operation,
            "native query acceptance changed"
        );
        let runtime = self.sql.runtime;
        let accepted = self
            .sql
            .read(|db| accepted_query_in(runtime, db, operation, actor, id, input))?;
        self.accepted = Some(Box::new(accepted));
        self.check()?;
        self.sql.sink.bind_query_correlation(self);
        Ok(())
    }

    pub(crate) fn connection(
        &mut self,
        request: &crate::protocol::Request,
        instruction: &crate::protocol::Instruction,
    ) -> Result<String> {
        let result = self.connection_inner(request, instruction);
        if result.is_err() {
            self.sql.refuse();
        }
        result
    }

    fn connection_inner(
        &mut self,
        request: &crate::protocol::Request,
        instruction: &crate::protocol::Instruction,
    ) -> Result<String> {
        // Closed operation selection happens before borrowing the actual parent.
        let phase = super::super::usage::instruction_phase(instruction)?;
        let accepted = self
            .accepted
            .as_ref()
            .context("native query not accepted")?;
        let runtime = self.sql.runtime;
        let loan = QueryLoan {
            sql: self.sql.reborrow(),
            accepted,
            observations: &mut self.observations,
        };
        loan.require_request(request)?;
        let current = RuntimeConsumer {
            source: super::RuntimeSource::HostResponse(loan),
            runtime: Some(runtime),
            phase: Some(phase),
        };
        checked_query_loan(
            current,
            RuntimeConsumer::check,
            RuntimeConsumer::refuse,
            |current| super::super::usage::execute_current(runtime, request, instruction, current),
        )
    }
}

impl<'scope, 'role> HostSql<'scope, 'role> {
    fn reborrow(&mut self) -> HostSql<'_, 'role> {
        HostSql {
            runtime: self.runtime,
            stage: self.stage,
            current: self.current,
            policy: self.policy,
            store: self.store,
            scope: self.scope,
            sink: self.sink,
            identity: self.identity,
            refused: self.refused.clone(),
            request_data: self.request_data,
        }
    }
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

    pub(super) fn reobserve_outside_sql(&mut self) -> Result<()> {
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
        let request_data = request_owner.historical_diagnostic_data();
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
                                    let sql = HostSql {
                                        runtime: host.prepared_host_runtime(),
                                        stage: guard.stage,
                                        current: guard.current,
                                        policy: guard.policy,
                                        store: guard.store,
                                        scope: &scope,
                                        sink: self,
                                        identity: &self.identity,
                                        refused: guard.refused.clone(),
                                        request_data: &request_data,
                                    };
                                    let mut owner = HostRequestOwner {
                                        source: match host.selected_query_operation(&request)? {
                                            Some(operation) => {
                                                HostRequestSource::Query(QueryParent {
                                                    sql,
                                                    operation,
                                                    accepted: None,
                                                    observations: Vec::new(),
                                                })
                                            }
                                            None => HostRequestSource::Metadata(sql),
                                        },
                                    };
                                    host.execute_host_request(*request, &mut owner)?
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
            if call.method == "execute"
                && match &*call.receiver {
                    syn::Expr::Path(path) => {
                        path.path.is_ident("self") || path.path.is_ident("runtime")
                    }
                    syn::Expr::Field(field) => {
                        matches!(&field.member, syn::Member::Named(name) if name == "runtime")
                    }
                    _ => false,
                }
            {
                self.ordered.push("runtime::execute".into());
            }
            self.ordered.push(call.method.to_string());
            visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Paren(paren) = &*call.func
                && let syn::Expr::Field(field) = &*paren.expr
                && matches!(&field.member, syn::Member::Named(name) if name == "refuse")
            {
                self.ordered.push("refuse".into());
            }

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
            for name in ["HostSql", "QueryParent"] {
                if value.path.is_ident(name) {
                    self.ordered.push(name.into());
                }
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

    pub(super) fn one_method(source: &str, owner: &str, name: &str) -> Option<Vec<String>> {
        let mut methods = methods(source, owner, name);
        (methods.len() == 1).then(|| methods.remove(0))
    }

    pub(super) fn free_calls(source: &str, name: &str) -> Option<Vec<String>> {
        let file = syn::parse_file(source).ok()?;
        let mut functions = file.items.into_iter().filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        });
        let function = functions.next()?;
        if functions.next().is_some() {
            return None;
        }
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        Some(calls.ordered)
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

#[cfg(test)]
mod query_tests {
    use super::*;
    use crate::store::{ActingAs, ExecutionSql, Runtime};
    use serde_json::json;

    fn accepted_fixture() -> Result<(tempfile::TempDir, Runtime, crate::iap::Verified)> {
        let directory = tempfile::tempdir()?;
        let runtime = crate::oauth::admission::host_request_test_runtime(directory.path())?;
        let human = crate::iap::Verified {
            email: "alice@example.com".into(),
            subject: "query-signed-alice".into(),
        };
        let (verifier, assertion) = crate::iap::tests::signed_human(&human, 100);
        let verified = verifier.verify(&assertion, 100)?;
        runtime.sql_write(|tx| crate::iap::bind_subject(tx, &verified, 100))?;
        runtime.accept_on_behalf_of_verified_using(
            crate::store::InvocationInput {
                operation: "read",
                id: "query-accepted",
                input: &json!({}),
                at: 100,
            },
            ActingAs {
                authenticated: &verified.email,
                actor: &verified.email,
                trigger: crate::audit::Trigger::Request,
            },
            Some(&verified),
            &mut ExecutionSql::current(&runtime),
        )?;
        Ok((directory, runtime, verified))
    }

    #[test]
    fn accepted_query_binding_reads_actual_sqlite_and_preserves_signed_origin() -> Result<()> {
        let (_directory, runtime, human) = accepted_fixture()?;
        let request = runtime.sql_read(|db| {
            accepted_query_in(
                &runtime,
                db,
                "read",
                &human.email,
                "query-accepted",
                &json!({}),
            )
        })?;
        assert_eq!(request.context.invocation_id, "query-accepted");
        assert_eq!(request.context.actor, human.email);
        runtime.sql_read(|db| {
            let (kind, principal, subject): (String, String, String) = db.query_row(
                "SELECT kind,principal,subject FROM day2_invocation_origins WHERE invocation=?1",
                ["query-accepted"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(
                (kind, principal, subject),
                ("iap".into(), human.email.clone(), human.subject.clone())
            );
            for (operation, actor, id, input) in [
                ("other", human.email.as_str(), "query-accepted", json!({})),
                ("read", "bob@example.com", "query-accepted", json!({})),
                ("read", human.email.as_str(), "other", json!({})),
                (
                    "read",
                    human.email.as_str(),
                    "query-accepted",
                    json!({"foreign":1}),
                ),
            ] {
                assert!(accepted_query_in(&runtime, db, operation, actor, id, &input).is_err());
            }
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn borrowed_query_rejects_changed_operation_input_actor_or_invocation_before_use() -> Result<()>
    {
        let (_directory, runtime, human) = accepted_fixture()?;
        let request = runtime.sql_read(|db| {
            accepted_query_in(
                &runtime,
                db,
                "read",
                &human.email,
                "query-accepted",
                &json!({}),
            )
        })?;
        require_same_query(&request, &request)?;
        for index in 0..4 {
            let mut changed = request.clone();
            match index {
                0 => changed.operation = "foreign".into(),
                1 => changed.input = "{\"foreign\":1}".into(),
                2 => changed.context.actor = "bob@example.com".into(),
                _ => changed.context.invocation_id = "foreign".into(),
            }
            assert!(require_same_query(&request, &changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn distinct_runtime_with_identical_bindings_refuses_before_shared_engine_work() -> Result<()> {
        let (_directory, runtime, _) = accepted_fixture()?;
        let other = runtime.clone();
        assert_eq!(runtime.scope(), other.scope());
        assert_eq!(runtime.artifact().id(), other.artifact().id());
        assert_eq!(runtime.db(), other.db());
        let mut sql = ExecutionSql::current(&runtime);
        for error in [
            other
                .execute_using("query-accepted", crate::store::Fault::None, &mut sql)
                .unwrap_err(),
            other
                .prepare_credential_keys_using("query-accepted", &mut sql)
                .err()
                .unwrap(),
            crate::preparation::prepare_using(&other, "query-accepted", &mut sql).unwrap_err(),
            crate::execution::advance_for_query_or_command(
                &other,
                "query-accepted",
                crate::store::Fault::None,
                &mut sql,
            )
            .unwrap_err(),
        ] {
            assert_eq!(
                error.to_string(),
                "query execution Runtime identity changed"
            );
        }
        let status: String = runtime.sql_read(|db| {
            Ok(db.query_row(
                "SELECT status FROM day2_invocations WHERE id='query-accepted'",
                [],
                |row| row.get(0),
            )?)
        })?;
        assert_eq!(status, "pending");
        sql.require_runtime(&runtime)?;
        Ok(())
    }

    #[test]
    fn query_engine_refuses_command_continuation_or_effect_rows_without_driving_them() -> Result<()>
    {
        let (_directory, runtime, _) = accepted_fixture()?;
        let mut sql = ExecutionSql::current(&runtime);
        assert!(!crate::execution::advance_for_query_or_command(
            &runtime,
            "query-accepted",
            crate::store::Fault::None,
            &mut sql
        )?);
        runtime.sql_write(|tx| {
            tx.execute("INSERT INTO day2_external_effects(invocation,ordinal,identity,instruction) VALUES(?1,0,'foreign-effect','{}')", ["query-accepted"])?;
            Ok(())
        })?;
        let error = crate::execution::advance_for_query_or_command(
            &runtime,
            "query-accepted",
            crate::store::Fault::None,
            &mut sql,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "query_command_effect_refused");
        runtime.sql_write(|tx| {
            tx.execute(
                "DELETE FROM day2_external_effects WHERE invocation=?1",
                ["query-accepted"],
            )?;
            tx.execute(
                "INSERT INTO day2_execution(invocation,phase,trace) VALUES(?1,'effects','{}')",
                ["query-accepted"],
            )?;
            Ok(())
        })?;
        let error = crate::execution::advance_for_query_or_command(
            &runtime,
            "query-accepted",
            crate::store::Fault::None,
            &mut sql,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "query_command_continuation_refused");
        Ok(())
    }
    #[test]
    fn seeded_query_loans_keep_original_deadline_epoch_sticky_refusal_and_primary_error() {
        struct Model<'a> {
            now: u64,
            epoch: u64,
            refused: &'a std::cell::Cell<bool>,
        }
        impl Model<'_> {
            fn check_query(&mut self) -> Result<()> {
                ensure!(
                    !self.refused.get() && self.now < 5 && self.epoch == 1,
                    "model parent refused"
                );
                Ok(())
            }
            fn refuse_query(&mut self) {
                self.refused.set(true);
            }
        }
        // Seed selects only replayable scheduling DATA. The independent oracle
        // is the original strict deadline/epoch/refusal rule, not helper output.
        for seed in 0u64..64 {
            for action in 0..5 {
                let refused = std::cell::Cell::new(false);
                let entered = std::cell::Cell::new(false);
                let now = seed % 7;
                let result = checked_query_loan(
                    Model {
                        now,
                        epoch: 1,
                        refused: &refused,
                    },
                    Model::check_query,
                    Model::refuse_query,
                    |model| {
                        entered.set(true);
                        match action {
                            0 => {}
                            1 => model.refused.set(true), // subordinate refuses then returns Ok
                            2 => model.now = 5,           // equality at the ORIGINAL deadline
                            3 => model.epoch = 2,
                            _ => {
                                model.now = 5;
                                anyhow::bail!("primary provider error");
                            }
                        }
                        Ok(())
                    },
                );
                let expected = now < 5 && action == 0;
                assert_eq!(result.is_ok(), expected, "seed={seed},action={action}");
                assert_eq!(entered.get(), now < 5);
                assert_eq!(refused.get(), !expected);
                if now < 5 && action == 4 {
                    assert_eq!(result.unwrap_err().to_string(), "primary provider error");
                }
            }
        }
        let refused = std::cell::Cell::new(false);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _: Result<()> = checked_query_loan(
                    Model {
                        now: 0,
                        epoch: 1,
                        refused: &refused,
                    },
                    Model::check_query,
                    Model::refuse_query,
                    |_| {
                        panic!("scheduled query cancellation");
                    },
                );
            }))
            .is_err()
        );
        assert!(refused.get());
    }

    fn query_owner_wiring(source: &str) -> bool {
        use super::host_source_tests::{free_calls, one_method};
        let Some(owner) = one_method(source, "Sink", "drive_response_owner") else {
            return false;
        };
        let at = |name: &str| owner.iter().position(|call| call == name);
        if !matches!((at("arm"),at("selected_query_operation"),at("QueryParent"),at("execute_host_request")),
            (Some(arm),Some(select),Some(parent),Some(execute)) if arm < select && select < parent && parent < execute)
        {
            return false;
        }
        let Some(connection) = one_method(source, "QueryParent", "connection_inner") else {
            return false;
        };
        if ![
            "super::super::usage::instruction_phase",
            "require_request",
            "checked_query_loan",
            "super::super::usage::execute_current",
        ]
        .iter()
        .all(|name| connection.iter().any(|call| call == name))
        {
            return false;
        }
        if connection.iter().any(|call| {
            ["run", "arm", "finish_known", "with_runtime_consumer"].contains(&call.as_str())
        }) {
            return false;
        }
        let Some(borrow) = free_calls(source, "checked_query_loan") else {
            return false;
        };
        let checks: Vec<_> = borrow
            .iter()
            .enumerate()
            .filter_map(|(i, call)| (call == "check").then_some(i))
            .collect();
        matches!((checks.as_slice(), borrow.iter().position(|call| call == "operation")), ([before,after],Some(operation)) if *before < operation && operation < *after)
            && borrow.iter().any(|call| call == "refuse")
    }

    #[test]
    fn production_query_owner_mutations_cannot_upgrade_metadata_reenter_supplier_or_drop_postcheck()
    {
        let source = include_str!("response.rs");
        assert!(query_owner_wiring(source));
        for (from, to) in [
            (
                "host.selected_query_operation(&request)",
                "host.metadata_query_upgrade(&request)",
            ),
            ("QueryParent {", "MetadataUpgrade {"),
            (
                "loan.require_request(request)?",
                "loan.ignore_request(request)?",
            ),
            (
                "super::super::usage::execute_current(runtime, request, instruction, current)",
                "super::super::usage::execute(runtime, request, instruction)",
            ),
            (
                "let checked = check(&mut borrowed.current);",
                "let checked = Ok(());",
            ),
            (
                "(self.refuse)(&mut self.current);",
                "ignore_refusal(&mut self.current);",
            ),
        ] {
            assert!(
                source.contains(from),
                "production mutant target must exist: {from}"
            );
            assert!(
                !query_owner_wiring(&source.replace(from, to)),
                "must reject: {from}"
            );
        }
    }

    fn shared_sql_only(store: &str, preparation: &str, api: &str) -> bool {
        use super::host_source_tests::{free_calls, one_method};
        let targets = [
            one_method(store, "Runtime", "accept_with_caller_using"),
            one_method(store, "Runtime", "execute_using"),
            one_method(store, "Runtime", "execute_inner_using"),
            free_calls(preparation, "prepare_using"),
            one_method(api, "RequestContext", "dispatch_query"),
            one_method(api, "RequestContext", "dispatch_operation"),
        ];
        for index in [0, 1, 3] {
            let calls = &targets[index];
            // Native poison must be observed before audit/observation cleanup.
            if calls
                .as_ref()
                .is_none_or(|calls| !calls.iter().any(|name| name == "check_cleanup"))
            {
                return false;
            }
        }
        let Some(dispatch) = &targets[5] else {
            return false;
        };
        if !matches!((dispatch.iter().position(|name| name == "accept_on_behalf_of_verified_using"),
            dispatch.iter().position(|name| name == "bind_query"),
            dispatch.iter().position(|name| name == "execute_using")),
            (Some(accept),Some(bind),Some(execute)) if accept < bind && bind < execute)
        {
            return false;
        }
        targets.into_iter().all(|calls| {
            calls.is_some_and(|calls| {
                !calls.iter().any(|name| {
                    [
                        "sql_read",
                        "sql_write",
                        "sql_decide",
                        "runtime::execute",
                        "crate::store::ExecutionSql::current",
                        "ExecutionSql::current",
                        "accept_on_behalf_of_verified",
                        "crate::oauth::usage::execute",
                    ]
                    .contains(&name.as_str())
                })
            })
        })
    }

    fn begins_with_runtime_identity(source: &str, name: &str, argument: &str) -> bool {
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut bodies = Vec::new();
        for item in &file.items {
            match item {
                syn::Item::Fn(function) if function.sig.ident == name => {
                    bodies.push(function.block.as_ref())
                }
                syn::Item::Impl(item) => {
                    for member in &item.items {
                        if let syn::ImplItem::Fn(function) = member
                            && function.sig.ident == name
                        {
                            bodies.push(&function.block);
                        }
                    }
                }
                _ => {}
            }
        }
        if bodies.len() != 1 {
            return false;
        }
        let Some(syn::Stmt::Expr(syn::Expr::Try(checked), Some(_))) = bodies[0].stmts.first()
        else {
            return false;
        };
        let syn::Expr::MethodCall(call) = &*checked.expr else {
            return false;
        };
        call.method == "require_runtime"
            && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("sql"))
            && call.args.len() == 1
            && matches!(call.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident(argument))
    }

    #[test]
    fn shared_engine_runtime_identity_checks_cannot_move_after_work_or_be_removed() {
        for (source, name, argument) in [
            (
                include_str!("../../store.rs"),
                "accept_on_behalf_of_verified_using",
                "self",
            ),
            (
                include_str!("../../store.rs"),
                "accept_with_caller_using",
                "self",
            ),
            (include_str!("../../store.rs"), "execute_using", "self"),
            (
                include_str!("../../store.rs"),
                "execute_inner_using",
                "self",
            ),
            (
                include_str!("../../audit.rs"),
                "audit_admission_rejection_using",
                "self",
            ),
            (
                include_str!("../../audit.rs"),
                "audit_execution_interruption_using",
                "self",
            ),
            (
                include_str!("../../managed_credentials/issuance.rs"),
                "prepare_credential_keys_using",
                "self",
            ),
            (
                include_str!("../../preparation.rs"),
                "prepare_using",
                "runtime",
            ),
            (
                include_str!("../../execution.rs"),
                "advance_for_query_or_command",
                "runtime",
            ),
        ] {
            assert!(
                begins_with_runtime_identity(source, name, argument),
                "{name}"
            );
            let start = source.find(&format!("fn {name}(")).unwrap();
            let call = format!("sql.require_runtime({argument})?;");
            let mut removed = source[..start].to_owned();
            removed.push_str(&source[start..].replacen(&call, "", 1));
            assert!(
                !begins_with_runtime_identity(&removed, name, argument),
                "removed {name}"
            );
            let mut late = source[..start].to_owned();
            late.push_str(&source[start..].replacen(
                &call,
                &format!("sql.read(|_| Ok(()))?; {call}"),
                1,
            ));
            assert!(
                !begins_with_runtime_identity(&late, name, argument),
                "late {name}"
            );
        }
    }

    #[test]
    fn production_query_engine_mutations_cannot_restore_hidden_sql_or_provider_factories() {
        let store = include_str!("../../store.rs");
        let preparation = include_str!("../../preparation.rs");
        let api = include_str!("../../web_api.rs");
        assert!(shared_sql_only(store, preparation, api));
        assert!(!shared_sql_only(
            &store.replace("sql.read(", "self.sql_read("),
            preparation,
            api
        ));
        assert!(!shared_sql_only(
            store,
            &preparation.replace(
                "sql.connection(&request, &instruction)",
                "crate::oauth::usage::execute(runtime, &request, &instruction)"
            ),
            api
        ));
        assert!(!shared_sql_only(
            &store.replace("sql.check_cleanup()", "fresh_cleanup_owner()"),
            preparation,
            api
        ));
        assert!(!shared_sql_only(
            store,
            &preparation.replace("sql.check_cleanup()", "fresh_cleanup_owner()"),
            api
        ));
        assert!(!shared_sql_only(
            store,
            preparation,
            &api.replace(
                "crate::store::ExecutionSql::host(self.runtime, parent)?",
                "crate::store::ExecutionSql::current(self.runtime)"
            )
        ));
        assert!(!shared_sql_only(
            store,
            preparation,
            &api.replace(
                "self.runtime.execute_using(&invocation, Fault::None, sql)",
                "self.runtime.execute(&invocation, Fault::None)"
            )
        ));
    }
    #[test]
    fn refresh_observation_header_is_closed_bounded_and_contains_no_provider_material() -> Result<()>
    {
        use crate::oauth::effects::RefreshObservation::{MaterialCurrent, ReplacementCommitted};
        let mut records = Vec::new();
        assert!(observation_header(&records)?.is_none());
        observe_material(&mut records, "calendar", 900, 1, 1000, 940, MaterialCurrent)?;
        observe_material(
            &mut records,
            "calendar",
            950,
            2,
            4600,
            4540,
            ReplacementCommitted,
        )?;
        let header = observation_header(&records)?.unwrap();
        let value: serde_json::Value = serde_json::from_str(header.to_str()?)?;
        assert_eq!(value["version"], 1);
        assert_eq!(value["connections"][0]["token_expires_at"], 1000);
        assert_eq!(value["connections"][1]["outcome"], "replacement_committed");
        let expected: std::collections::BTreeSet<_> = [
            "connection",
            "observed_at",
            "token_version",
            "token_expires_at",
            "refresh_threshold_at",
            "outcome",
        ]
        .into_iter()
        .collect();
        for record in value["connections"].as_array().unwrap() {
            assert_eq!(
                record
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>(),
                expected
            );
        }
        for (version, expires, threshold) in [
            (0, 1000, 940),
            (1, 900, 840),
            (1, 1000, 1001),
            (1, i64::MAX, 940),
        ] {
            assert!(
                observe_material(
                    &mut records,
                    "calendar",
                    900,
                    version,
                    expires,
                    threshold,
                    MaterialCurrent
                )
                .is_err()
            );
        }
        assert_eq!(
            records.len(),
            2,
            "refused metadata is never partially appended"
        );
        while records.len() < 8 {
            observe_material(&mut records, "calendar", 900, 1, 1000, 940, MaterialCurrent)?;
        }
        assert!(
            observe_material(&mut records, "calendar", 900, 1, 1000, 940, MaterialCurrent).is_err()
        );
        assert_eq!(records.len(), 8);
        assert!(observation_header(&records)?.unwrap().as_bytes().len() <= 4096);
        Ok(())
    }

    fn refresh_publication_observation(source: &str) -> bool {
        use syn::visit::{self, Visit};
        struct Publication {
            found: usize,
            positive: bool,
        }
        impl<'ast> Visit<'ast> for Publication {
            fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
                if matches!(&*expression.expr, syn::Expr::Path(path) if path.path.is_ident("publication"))
                {
                    self.found += 1;
                    for arm in &expression.arms {
                        let good = matches!(&arm.pat, syn::Pat::TupleStruct(pattern)
                            if pattern.path.is_ident("Ok") && pattern.elems.len()==1
                            && matches!(&pattern.elems[0],syn::Pat::Lit(syn::ExprLit { lit: syn::Lit::Bool(value), .. }) if value.value));
                        struct Notes(usize);
                        impl<'ast> Visit<'ast> for Notes {
                            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                                if call.method == "observe_refresh_material" {
                                    self.0 += 1;
                                }
                                visit::visit_expr_method_call(self, call);
                            }
                        }
                        let mut notes = Notes(0);
                        notes.visit_expr(&arm.body);
                        if notes.0 != 0 {
                            self.positive = good && notes.0 == 1;
                        }
                    }
                }
                visit::visit_expr_match(self, expression);
            }
        }
        let Ok(file) = syn::parse_file(source) else {
            return false;
        };
        let mut check = Publication {
            found: 0,
            positive: false,
        };
        check.visit_file(&file);
        check.found == 1 && check.positive
    }

    #[test]
    fn refresh_committed_observation_cannot_move_to_a_refused_publication_arm() {
        let source = include_str!("../refresh.rs");
        assert!(refresh_publication_observation(source));
        let mutated = source.replace("Ok(true) => {", "Ok(false) => {");
        assert!(!refresh_publication_observation(&mutated));
    }
    #[test]
    fn query_completion_correlation_is_creator_bound_one_shot_and_missing_on_loss() {
        let creator = ResponseIdentity::new();
        let other = ResponseIdentity::new();
        let correlation = QueryCorrelation::new();
        assert!(correlation.data(&creator).is_none());
        correlation.bind(&creator, &creator, QueryCorrelationData::maximal_fixture());
        assert!(correlation.data(&creator).is_some());
        assert!(correlation.data(&other).is_none());
        correlation.bind(&creator, &creator, QueryCorrelationData::maximal_fixture());
        assert!(correlation.data(&creator).is_none());
        let foreign = QueryCorrelation::new();
        foreign.bind(&other, &creator, QueryCorrelationData::maximal_fixture());
        assert!(foreign.data(&creator).is_none());
        let overflow = QueryCorrelation::new();
        let mut invalid = QueryCorrelationData::maximal_fixture();
        invalid.invocation.push('q');
        overflow.bind(&creator, &creator, invalid);
        assert!(overflow.data(&creator).is_none());
        let busy = QueryCorrelation::new();
        let held = busy.state.borrow_mut();
        busy.bind(&creator, &creator, QueryCorrelationData::maximal_fixture());
        drop(held);
        assert!(busy.data(&creator).is_none());
    }
}
