//! Owner-executor composition. Routing IDs, View and SQLite records remain
//! DATA; only this executor's live registry can resolve an original. No lookup
//! restores it after restart or transfers it to a different thread.

use super::{
    fresh_auth::FreshIntent,
    native_original::{Clock, Original},
};
use crate::security_epoch::native_enrollment::{
    EnrolledOriginalClock, EnrolledProcessRoleOwner, EnrolledRoleStage, NativeRole,
};
use anyhow::{Context, Result, ensure};
use day2_capabilities::security_epoch::AuthorityScope;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

type Role = Rc<RefCell<EnrolledProcessRoleOwner>>;
struct EnrolledClock {
    clock: EnrolledOriginalClock,
    role: Role,
}
impl Clock for EnrolledClock {
    fn origin(&self) -> Duration {
        self.clock.origin()
    }
    fn sample(&mut self) -> Result<Duration> {
        let mut role = self
            .role
            .try_borrow_mut()
            .context("native role already borrowed")?;
        let mut stage = role.begin_current_stage()?;
        self.clock.sample(&mut stage)
    }
}

struct Owners {
    role: Role,
    kind: NativeRole,
    originals: BTreeMap<String, Original<EnrolledClock>>,
}

thread_local! {
    static OWNERS: RefCell<BTreeMap<String, Owners>> = const { RefCell::new(BTreeMap::new()) };
    static ACTIVE_SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

/// Install only on the final HTTP executor; enrollment is the real selected
/// native exchange. No role, origin, FD or clock comes from the HTTP request.
pub(super) fn install(scopes: &[AuthorityScope], kind: NativeRole) -> Result<()> {
    ensure!(
        !scopes.is_empty() && scopes.len() <= 128,
        "native enrollment scope capacity"
    );
    let mut selected = BTreeMap::new();
    for scope in scopes {
        let role = EnrolledProcessRoleOwner::enroll_current_thread(scope, kind)?;
        ensure!(
            selected
                .insert(
                    scope.app.as_str().into(),
                    Owners {
                        role: Rc::new(RefCell::new(role)),
                        kind,
                        originals: BTreeMap::new()
                    }
                )
                .is_none(),
            "native executor scope repeated"
        );
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        ensure!(owners.is_empty(), "native executor already enrolled");
        *owners = selected;
        Ok(())
    })
}

pub(super) fn clear() {
    OWNERS.with(|owners| owners.borrow_mut().clear());
}

#[cfg(test)]
pub(super) fn simulation_installed() -> bool {
    fixtures::active()
}

pub(crate) fn selected_scopes(
    instance: &crate::artifact::Instance,
    only_app: Option<&str>,
) -> Result<Vec<AuthorityScope>> {
    let mut scopes = Vec::new();
    for (app, binding) in &instance.apps {
        if binding.oauth_connections.is_empty() || only_app.is_some_and(|selected| selected != app)
        {
            continue;
        }
        let scope = AuthorityScope {
            installation: instance.installation.clone().try_into()?,
            environment: instance.environment.clone().try_into()?,
            app: app.clone().try_into()?,
        };
        ensure!(
            instance
                .control
                .as_ref()
                .context("native enrollment control missing")?
                .security_epochs
                .values()
                .filter(|epoch| epoch.scope == scope)
                .count()
                == 1,
            "native enrollment scope selection ambiguous"
        );
        scopes.push(scope);
    }
    ensure!(
        scopes.len() <= 128,
        "native enrollment scope selection missing"
    );
    Ok(scopes)
}

/// Not a Send handle. Capture is the FIRST operation in Manager::capture.
pub(crate) struct AppCreator<'a> {
    original: CapturedOriginal,
    app: String,
    start: &'a super::management::app::CaptureStart,
}

enum CapturedOriginal {
    Native(Original<EnrolledClock>),
    #[cfg(test)]
    Simulated(Original<fixtures::SimulationClock>),
}

fn capture(owners: &mut Owners, expected: NativeRole) -> Result<Original<EnrolledClock>> {
    ensure!(owners.kind == expected, "native original role changed");
    let clock = owners
        .role
        .try_borrow_mut()?
        .capture_original_clock(expected)?;
    Original::capture(EnrolledClock {
        clock,
        role: owners.role.clone(),
    })
}

pub(super) fn capture_app<'a>(
    start: &'a super::management::app::CaptureStart,
    app: &str,
) -> Result<AppCreator<'a>> {
    #[cfg(test)]
    if let Some(captured) = fixtures::capture_app(start, app)? {
        return Ok(captured);
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners.get_mut(app).context("native App executor missing")?;
        ensure!(owners.originals.len() < 1024, "native original capacity");
        Ok(AppCreator {
            original: CapturedOriginal::Native(capture(owners, NativeRole::AppHost)?),
            app: app.into(),
            start,
        })
    })
}

impl AppCreator<'_> {
    /// Called once AFTER the actual Pending transaction commits.
    pub(super) fn bind(
        self,
        committed: super::management::app::CommittedCapture<'_>,
        wall: i64,
    ) -> Result<()> {
        ensure!(
            std::ptr::eq(self.start, committed.start()),
            "native App creator changed before commit"
        );
        let intent = committed.intent();
        ensure!(
            self.app == intent.app(),
            "native App original target changed"
        );
        #[cfg(not(test))]
        let CapturedOriginal::Native(mut original) = self.original;
        #[cfg(test)]
        let mut original = match self.original {
            CapturedOriginal::Native(original) => original,
            #[cfg(test)]
            CapturedOriginal::Simulated(mut original) => {
                original.bind(intent, wall)?;
                return fixtures::bind_app(intent, original);
            }
        };
        let current_wall = super::effects::wall_time()?;
        ensure!(
            current_wall >= wall,
            "native original wall clock moved backwards"
        );
        original.bind(intent, current_wall)?;
        OWNERS.with(|owners| {
            let mut owners = owners.try_borrow_mut()?;
            let owners = owners
                .get_mut(intent.app())
                .context("native App executor lost")?;
            ensure!(
                owners.kind == NativeRole::AppHost
                    && !owners.originals.contains_key(intent.attempt()),
                "native App original cannot be replaced"
            );
            owners.originals.insert(intent.attempt().into(), original);
            enlist(NativeRole::AppHost, intent)?;
            Ok(())
        })
    }
}

/// Called at first Begins::reserve, before naming entropy or Claim. Reopening
/// can only check the SAME original; lost replies cannot create a replacement.
pub(super) fn reserve_shell(intent: &FreshIntent, wall: i64) -> Result<()> {
    #[cfg(test)]
    if fixtures::reserve_shell(intent, wall)? {
        return Ok(());
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners
            .get_mut(intent.app())
            .context("native Shell executor missing")?;
        ensure!(
            owners.kind == NativeRole::SecurityShell,
            "native Shell role changed"
        );
        if let Some(original) = owners.originals.get_mut(intent.attempt()) {
            original.check(intent, wall)?;
            return enlist(NativeRole::SecurityShell, intent);
        }
        ensure!(owners.originals.len() < 1024, "native original capacity");
        let mut original = capture(owners, NativeRole::SecurityShell)?;
        let current_wall = super::effects::wall_time()?;
        ensure!(
            current_wall >= wall,
            "native original wall clock moved backwards"
        );
        original.bind(intent, current_wall)?;
        owners.originals.insert(intent.attempt().into(), original);
        enlist(NativeRole::SecurityShell, intent)?;
        Ok(())
    })
}

/// These select consumers, never grants. Each invocation borrows the live
/// original and a newly acquired <=5s enrolled role stage on this executor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Pending,
    Claim,
    Publication,
    Callback,
    StartCommit,
    DispatchCommit,
    ProviderSend,
    FinishCommit,
    DisconnectCommit,
    Session,
    Signature,
    Verification,
    Response,
    ShellFlow,
}

pub(crate) struct RoleStage<'a> {
    source: RoleSource<'a>,
}

enum RoleSource<'a> {
    Native(Box<EnrolledRoleStage<'a>>),
    #[cfg(test)]
    Simulated(fixtures::SimulationStage),
}

// A closed borrow of the existing stage, never a new acquisition or owner.
// The scripted variant cannot be converted to the native variant.
enum BorrowedRoleStage<'stage, 'role> {
    Native(&'stage mut EnrolledRoleStage<'role>),
    #[cfg(test)]
    Simulated(&'stage mut fixtures::SimulationStage),
}

impl BorrowedRoleStage<'_, '_> {
    fn check(&mut self) -> Result<()> {
        match self {
            Self::Native(stage) => stage.check(),
            #[cfg(test)]
            Self::Simulated(stage) => stage.check(),
        }
    }
}

impl<'role> RoleStage<'role> {
    fn borrowed(&mut self) -> BorrowedRoleStage<'_, 'role> {
        match &mut self.source {
            RoleSource::Native(stage) => BorrowedRoleStage::Native(stage),
            #[cfg(test)]
            RoleSource::Simulated(stage) => BorrowedRoleStage::Simulated(stage),
        }
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        match &mut self.source {
            RoleSource::Native(stage) => stage.check(),
            #[cfg(test)]
            RoleSource::Simulated(stage) => stage.check(),
        }
    }

    pub(crate) fn check_for(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
        match &mut self.source {
            RoleSource::Native(stage) => stage.check_for(scope, role),
            #[cfg(test)]
            RoleSource::Simulated(stage) => stage.check_for(scope, role),
        }
    }

    /// S3 may borrow the real stage for native authenticated reads. A scripted
    /// role never constructs or substitutes a native enrolled stage.
    pub(crate) fn with_native<T>(
        &mut self,
        use_native: impl FnOnce(&mut EnrolledRoleStage<'_>) -> Result<T>,
    ) -> Result<T> {
        match &mut self.source {
            RoleSource::Native(stage) => {
                stage.check()?;
                use_native(stage)
            }
            #[cfg(test)]
            RoleSource::Simulated(_) => {
                anyhow::bail!("real native enrolled stage unavailable in simulation")
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RuntimePhase {
    InitialStorage,
    Read,
    Refresh,
}

/// Autonomous read/refresh has a current role phase, never a human original.
/// The callback retains the actual native borrow through read/admission/result.
pub(crate) fn with_current_app_role<T>(
    scope: &AuthorityScope,
    phase: RuntimePhase,
    use_current: impl FnOnce(&mut RoleStage<'_>) -> Result<T>,
) -> Result<T> {
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::with_app_role(scope, phase, use_current);
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners
            .get_mut(scope.app.as_str())
            .context("native App role executor missing")?;
        ensure!(
            owners.kind == NativeRole::AppHost,
            "autonomous runtime requires App owner"
        );
        let mut role = owners.role.try_borrow_mut()?;
        let mut stage = RoleStage {
            source: RoleSource::Native(Box::new(role.begin_current_stage()?)),
        };
        stage.check_for(scope, NativeRole::AppHost)?;
        let _ = phase;
        use_current(&mut stage)
    })
}

pub(crate) struct OriginalPhase<'a> {
    original: PhaseOriginal<'a>,
    intent: &'a FreshIntent,
    wall: i64,
    phase: Phase,
}

enum PhaseOriginal<'a> {
    Native(&'a mut Original<EnrolledClock>),
    #[cfg(test)]
    Simulated(&'a mut Original<fixtures::SimulationClock>),
}

/* The two borrows remain inside the callback; neither is a response DTO. */
impl OriginalPhase<'_> {
    fn refuse(&mut self) {
        match &mut self.original {
            PhaseOriginal::Native(original) => original.refuse(),
            #[cfg(test)]
            PhaseOriginal::Simulated(original) => original.refuse(),
        }
    }

    pub(crate) fn require_signature(
        &mut self,
        role: &mut RoleStage<'_>,
        expected: &FreshIntent,
    ) -> Result<()> {
        ensure!(
            self.phase == Phase::Signature && self.intent == expected,
            "native signature phase required"
        );
        self.check(role)
    }

    pub(crate) fn check(&mut self, stage: &mut RoleStage<'_>) -> Result<()> {
        self.check_at(stage.borrowed(), self.wall)
    }

    /// Check the SAME retained original against a native stage already held by
    /// the consumer. `entry_wall` is only a floor: obtain current wall time and
    /// sample the original enrolled clock through this exact stage. No new
    /// acquisition, clock, owner, continuation or operation permission is made.
    pub(crate) fn check_with_native(
        &mut self,
        stage: &mut EnrolledRoleStage<'_>,
        entry_wall: i64,
    ) -> Result<()> {
        self.check_at(BorrowedRoleStage::Native(stage), entry_wall)
    }

    fn check_at(&mut self, mut stage: BorrowedRoleStage<'_, '_>, entry_wall: i64) -> Result<()> {
        let result = (|| {
            let wall = super::effects::wall_time()?;
            ensure!(
                wall >= self.wall && wall >= entry_wall,
                "native original wall clock moved backwards"
            );
            self.wall = wall;
            stage.check()?;
            match (&mut self.original, stage) {
                (PhaseOriginal::Native(original), BorrowedRoleStage::Native(stage)) => {
                    let now = original.clock.clock.sample(stage);
                    original.check_sample(self.intent, self.wall, now)
                }
                #[cfg(test)]
                (PhaseOriginal::Simulated(original), BorrowedRoleStage::Simulated(_)) => {
                    original.check(self.intent, self.wall)
                }
                #[cfg(test)]
                _ => anyhow::bail!("native original role supplier changed"),
            }
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

/// A borrow through an actual consumer operation, including its commit/result.
/// Dropping an armed borrow (error, panic or ambiguous result) closes the retained
/// original permanently. SQL readback, elapsed time and a later request cannot
/// turn an unknown result into a new permission. This supplies original/role
/// settlement, not the missing S3 current-serving/storage producer.
pub(crate) struct Consumer<'a, 'role, 'original> {
    role: &'a mut RoleStage<'role>,
    original: &'a mut OriginalPhase<'original>,
    settled: bool,
}

impl Consumer<'_, '_, '_> {
    pub(crate) fn check(&mut self) -> Result<()> {
        self.original.check(self.role)
    }

    pub(crate) fn require_signature(&mut self, expected: &FreshIntent) -> Result<()> {
        self.original.require_signature(self.role, expected)
    }

    /// Hold the same borrow before COMMIT, through the actual SQLite result,
    /// and afterwards. An error (even after a possibly successful commit) never
    /// returns a dispatch permit or rearms the original.
    pub(crate) fn commit(&mut self, tx: rusqlite::Transaction<'_>) -> Result<()> {
        let result = (|| {
            self.check()?;
            tx.commit()?;
            self.check()
        })();
        if result.is_err() {
            self.original.refuse();
        }
        result
    }
}

impl Drop for Consumer<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.settled {
            self.original.refuse();
        }
    }
}

pub(crate) fn with_consumer<T>(
    intent: &FreshIntent,
    phase: Phase,
    wall: i64,
    operation: impl FnOnce(&mut Consumer<'_, '_, '_>) -> Result<T>,
) -> Result<T> {
    with_current_original(intent, phase, wall, |role, original| {
        let mut consumer = Consumer {
            role,
            original,
            settled: false,
        };
        consumer.check()?;
        let output = operation(&mut consumer)?;
        consumer.check()?;
        consumer.settled = true;
        Ok(output)
    })
}

/// This callback cannot escape the local borrow or return a transferable
/// permit. S3 performs its known commit/result inside it and rechecks both
/// borrowed stages at the actual cutoff. Unknown results remain owned by S3.
pub(crate) fn with_current_original<T>(
    intent: &FreshIntent,
    phase: Phase,
    wall: i64,
    use_current: impl FnOnce(&mut RoleStage<'_>, &mut OriginalPhase<'_>) -> Result<T>,
) -> Result<T> {
    with_current_for_role(intent, phase, wall, None, use_current)
}

fn with_current_for_role<T>(
    intent: &FreshIntent,
    phase: Phase,
    wall: i64,
    expected: Option<NativeRole>,
    use_current: impl FnOnce(&mut RoleStage<'_>, &mut OriginalPhase<'_>) -> Result<T>,
) -> Result<T> {
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::with_current(intent, phase, wall, expected, use_current);
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners
            .get_mut(intent.app())
            .context("native original executor missing")?;
        ensure!(
            expected.is_none_or(|expected| expected == owners.kind),
            "native response role changed"
        );
        match phase {
            Phase::StartCommit
            | Phase::DispatchCommit
            | Phase::ProviderSend
            | Phase::FinishCommit
            | Phase::DisconnectCommit
            | Phase::Verification => ensure!(
                owners.kind == NativeRole::AppHost,
                "native phase requires App owner"
            ),
            Phase::Session | Phase::Signature | Phase::ShellFlow => ensure!(
                owners.kind == NativeRole::SecurityShell,
                "native phase requires Shell owner"
            ),
            _ => {}
        }
        let original = owners
            .originals
            .get_mut(intent.attempt())
            .context("native original absent; rows cannot restore it")?;
        let role = original.clock.role.clone();
        let mut role = role.try_borrow_mut()?;
        let mut stage = RoleStage {
            source: RoleSource::Native(Box::new(role.begin_current_stage()?)),
        };
        let mut original = OriginalPhase {
            original: PhaseOriginal::Native(original),
            intent,
            wall,
            phase,
        };
        original.check(&mut stage)?;
        enlist(owners.kind, intent)?;
        use_current(&mut stage, &mut original)
    })
}

/// A connection-local list of DATA indexes, never a transferable permit. The
/// actual socket resolves them back to the retained executor owners on every
/// write/flush/shutdown. Disconnect drops this list, not the originals.
#[derive(Clone)]
pub(super) struct Sink {
    bindings: Rc<RefCell<BTreeMap<(NativeRole, String), SinkBinding>>>,
    refused: Rc<std::cell::Cell<bool>>,
}

pub(super) fn current_sink() -> Result<Sink> {
    ACTIVE_SINK.with(|slot| {
        slot.try_borrow()?
            .clone()
            .context("native response scope missing")
    })
}

#[derive(Clone)]
struct SinkBinding {
    intent: FreshIntent,
    effects: crate::managed_credentials::effects::Captured,
}

impl Sink {
    pub(super) fn new() -> Self {
        Self {
            bindings: Rc::new(RefCell::new(BTreeMap::new())),
            refused: Rc::new(std::cell::Cell::new(false)),
        }
    }

    /// A synchronous fixture RPC still has its own response scope. It must not
    /// enter another executor while the actual owner is already being polled.
    #[cfg(test)]
    pub(super) fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
        struct Restore(Option<Sink>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE_SINK.with(|slot| slot.replace(self.0.take()));
            }
        }
        let _restore = Restore(ACTIVE_SINK.with(|slot| slot.replace(Some(self.clone()))));
        operation()
    }

    pub(super) fn with_current<T>(&self, operation: impl FnOnce() -> T) -> Result<T> {
        ensure!(
            !self.refused.get(),
            "native response outcome unknown or excluded"
        );
        let intents: Vec<_> = self
            .bindings
            .try_borrow()?
            .iter()
            .map(|((role, _), binding)| (*role, binding.clone()))
            .collect();
        match intents.as_slice() {
            [] => Ok(operation()),
            [(role, binding)] => binding.effects.clone().run(|| {
                with_current_for_role(
                    &binding.intent,
                    Phase::Response,
                    super::effects::wall_time()?,
                    Some(*role),
                    |stage, original| {
                        let mut consumer = Consumer {
                            role: stage,
                            original,
                            settled: false,
                        };
                        consumer.check()?;
                        let output = operation();
                        consumer.check()?;
                        consumer.settled = true;
                        Ok(output)
                    },
                )
            }),
            _ => anyhow::bail!("native response must have exactly one original"),
        }
    }

    /// Retain uncertainty in each ORIGINAL owner, independently for App and
    /// Shell. Neither a handler/RPC success nor a later socket can erase it.
    pub(super) fn abort(&self) {
        self.refused.set(true);
        let Ok(bindings) = self.bindings.try_borrow() else {
            return;
        };
        for ((role, _), binding) in bindings.iter() {
            // Terminal exclusion is not a new action. It must not depend on
            // acquiring a still-current stage or a successful clock read.
            let _ = binding.effects.clone().run(|| refuse_original(&binding.intent, *role));
        }
    }

    pub(super) fn poll_io<T>(
        &self,
        operation: impl FnOnce() -> Poll<std::io::Result<T>>,
    ) -> Poll<std::io::Result<T>> {
        match self.with_current(operation) {
            Ok(Poll::Ready(Err(error))) => {
                self.abort();
                Poll::Ready(Err(error))
            }
            Ok(output) => output,
            Err(_) => {
                self.abort();
                Poll::Ready(Err(std::io::Error::other(
                    "native response authority or delivery unavailable",
                )))
            }
        }
    }

    pub(super) fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> {
        struct Scoped<F> {
            sink: Sink,
            future: Pin<Box<F>>,
        }
        impl<F: Future> Future for Scoped<F> {
            type Output = F::Output;
            fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
                struct Restore(Option<Sink>);
                impl Drop for Restore {
                    fn drop(&mut self) {
                        ACTIVE_SINK.with(|slot| slot.replace(self.0.take()));
                    }
                }
                let _restore =
                    Restore(ACTIVE_SINK.with(|slot| slot.replace(Some(self.sink.clone()))));
                self.future.as_mut().poll(cx)
            }
        }
        Scoped {
            sink: self.clone(),
            future: Box::pin(future),
        }
    }
}

fn refuse_original(intent: &FreshIntent, kind: NativeRole) -> Result<()> {
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::refuse_original(intent, kind);
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners.get_mut(intent.app()).context("native original executor missing")?;
        ensure!(owners.kind == kind, "native terminal owner changed");
        owners.originals.get_mut(intent.attempt()).context("native terminal original missing")?.refuse();
        Ok(())
    })
}

fn enlist(role: NativeRole, intent: &FreshIntent) -> Result<()> {
    ACTIVE_SINK.with(|slot| {
        if let Some(sink) = slot.try_borrow()?.as_ref() {
            ensure!(!sink.refused.get(), "native response sink refused");
            let mut indexes = sink.bindings.try_borrow_mut()?;
            let key = (role, intent.attempt().into());
            ensure!(
                indexes.is_empty() || indexes.contains_key(&key),
                "native response scope capacity"
            );
            if let Some(existing) = indexes.get(&key) {
                ensure!(
                    existing.intent == *intent,
                    "native response original changed"
                );
            } else {
                indexes.insert(
                    key,
                    SinkBinding {
                        intent: intent.clone(),
                        effects: crate::managed_credentials::effects::capture(),
                    },
                );
            }
        }
        Ok(())
    })
}

pub(super) fn check(intent: &FreshIntent, phase: Phase, wall: i64) -> Result<()> {
    with_current_original(intent, phase, wall, |stage, original| original.check(stage))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original_intent(attempt: &str, deadline: i64) -> Result<FreshIntent> {
        FreshIntent::fixture_oauth(
            &crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "alice".into(),
            },
            attempt,
            &day2_capabilities::Digest::new(b"same-stage original"),
            "https://security.example.com",
            5,
            deadline,
        )
    }

    #[test]
    fn consumer_retains_known_commit_and_excludes_expiry_before_commit() -> Result<()> {
        for elapsed in [0, 5] {
            let world = super::super::simulation::World::new(400 + elapsed);
            super::super::effects::scope(world.clone(), || -> Result<()> {
                let intent = original_intent("consumer-known-commit", 305)?;
                reserve_shell(&intent, 5)?;
                let mut db = rusqlite::Connection::open_in_memory()?;
                db.execute_batch("CREATE TABLE receipt(value INTEGER NOT NULL)")?;
                let result = with_consumer(&intent, Phase::Session, 5, |current| {
                    let tx = db.transaction()?;
                    tx.execute("INSERT INTO receipt VALUES(1)", [])?;
                    world.advance(elapsed);
                    current.commit(tx)
                });
                assert_eq!(result.is_ok(), elapsed == 0);
                assert_eq!(
                    db.query_row("SELECT count(*) FROM receipt", [], |row| row
                        .get::<_, i64>(0))?,
                    i64::from(elapsed == 0)
                );
                assert_eq!(
                    with_consumer(&intent, Phase::Session, 5, |_| Ok(())).is_ok(),
                    elapsed == 0
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn consumer_sqlite_commit_failure_and_lost_reply_never_rearm() -> Result<()> {
        for (seed, lost_reply) in [(410, false), (411, true)] {
            let world = super::super::simulation::World::new(seed);
            super::super::effects::scope(world, || -> Result<()> {
                let intent = original_intent("consumer-unknown-commit", 305)?;
                reserve_shell(&intent, 5)?;
                let mut db = rusqlite::Connection::open_in_memory()?;
                db.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE receipt(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)")?;
                if lost_reply {
                    db.execute("INSERT INTO parent VALUES(1)", [])?;
                }
                let result = with_consumer(&intent, Phase::Session, 5, |current| -> Result<()> {
                    let tx = db.transaction()?;
                    tx.execute("INSERT INTO receipt VALUES(1)", [])?;
                    if !lost_reply {
                        assert!(current.commit(tx).is_err());
                        // Even swallowing a native commit error cannot make
                        // the outer operation or a later phase succeed.
                        return Ok(());
                    }
                    current.commit(tx)?;
                    anyhow::bail!("controlled reply loss AFTER actual commit")
                });
                assert!(result.is_err());
                assert_eq!(
                    db.query_row("SELECT count(*) FROM receipt", [], |row| row
                        .get::<_, i64>(0))?,
                    i64::from(lost_reply)
                );
                let mut entered = false;
                assert!(
                    with_consumer(&intent, Phase::Session, 5, |_| {
                        entered = true;
                        Ok(())
                    })
                    .is_err()
                );
                assert!(!entered);
                assert!(reserve_shell(&intent, 5).is_err());
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn consumer_expiry_after_commit_and_unwind_preserve_refused_original() -> Result<()> {
        for panic in [false, true] {
            let world = super::super::simulation::World::new(if panic { 421 } else { 420 });
            super::super::effects::scope(world.clone(), || -> Result<()> {
                let intent = original_intent("consumer-postcommit-cutoff", 305)?;
                reserve_shell(&intent, 5)?;
                let mut db = rusqlite::Connection::open_in_memory()?;
                db.execute_batch("CREATE TABLE receipt(value INTEGER)")?;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    with_consumer(&intent, Phase::Session, 5, |current| {
                        let tx = db.transaction()?;
                        tx.execute("INSERT INTO receipt VALUES(1)", [])?;
                        current.commit(tx)?;
                        if panic {
                            panic!("controlled cancellation after known SQL commit");
                        }
                        world.advance(5);
                        Ok(())
                    })
                }));
                if panic {
                    assert!(result.is_err());
                } else {
                    assert!(result.unwrap().is_err());
                }
                assert_eq!(
                    db.query_row("SELECT count(*) FROM receipt", [], |row| row
                        .get::<_, i64>(0))?,
                    1
                );
                assert!(with_consumer(&intent, Phase::Session, 5, |_| Ok(())).is_err());
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn consumer_socket_pending_and_partial_write_do_not_settle_a_failed_delivery() -> Result<()> {
        let world = super::super::simulation::World::new(430);
        super::super::effects::scope(world, || -> Result<()> {
            let intent = original_intent("consumer-body-unknown", 305)?;
            let sink = Sink::new();
            sink.run(|| reserve_shell(&intent, 5))?;
            assert!(sink.poll_io::<usize>(|| Poll::Pending).is_pending());
            assert!(matches!(
                sink.poll_io(|| Poll::Ready(Ok(3))),
                Poll::Ready(Ok(3))
            ));
            assert!(matches!(
                sink.poll_io::<usize>(|| Poll::Ready(Err(std::io::Error::other(
                    "controlled disconnect"
                )))),
                Poll::Ready(Err(_))
            ));
            let mut retried = false;
            assert!(matches!(
                sink.poll_io(|| {
                    retried = true;
                    Poll::Ready(Ok(2))
                }),
                Poll::Ready(Err(_))
            ));
            assert!(!retried);
            // A different response/socket cannot erase the same owner's unknown
            // disposition. App and Shell registries remain independent.
            assert!(with_consumer(&intent, Phase::Session, 5, |_| Ok(())).is_err());
            Ok(())
        })
    }

    #[test]
    fn borrowed_stage_wall_floor_cannot_replace_current_time_or_clear_refusal() -> Result<()> {
        let world = super::super::simulation::World::new(90);
        super::super::effects::scope(world.clone(), || -> Result<()> {
            let intent = original_intent("borrowed-wall-floor", 305)?;
            reserve_shell(&intent, 5)?;
            with_current_original(&intent, Phase::ShellFlow, 5, |role, original| {
                original.check_at(role.borrowed(), 0)?;
                assert_eq!(original.wall, 5);
                // A supplied future floor is not a replacement clock sample.
                assert!(original.check_at(role.borrowed(), 7).is_err());
                world.advance(2);
                // Current time now meets both floors and this stage is still
                // under five seconds; the failed original remains refused.
                role.check()?;
                assert!(original.check(role).is_err());
                Ok(())
            })?;
            let mut entered = false;
            assert!(
                with_current_original(&intent, Phase::ShellFlow, 7, |_, _| {
                    entered = true;
                    Ok(())
                })
                .is_err()
            );
            assert!(!entered);
            Ok(())
        })
    }

    #[test]
    fn borrowed_stage_stale_entry_cannot_hide_stage_or_original_expiry() -> Result<()> {
        for (seed, elapsed, deadline) in [(91, 5, 305), (92, 2, 7)] {
            let world = super::super::simulation::World::new(seed);
            super::super::effects::scope(world.clone(), || -> Result<()> {
                let intent = original_intent("borrowed-expiry", deadline)?;
                reserve_shell(&intent, 5)?;
                with_current_original(&intent, Phase::ShellFlow, 5, |role, original| {
                    world.advance(elapsed);
                    assert!(original.check_at(role.borrowed(), 5).is_err());
                    assert!(original.check(role).is_err());
                    Ok(())
                })?;
                assert!(
                    with_current_original(&intent, Phase::ShellFlow, 5, |_, _| Ok(())).is_err()
                );
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn scripted_original_cannot_enter_the_native_stage_consumer() -> Result<()> {
        let world = super::super::simulation::World::new(93);
        super::super::effects::scope(world, || -> Result<()> {
            let intent = original_intent("native-borrow-required", 305)?;
            reserve_shell(&intent, 5)?;
            with_current_original(&intent, Phase::ShellFlow, 5, |role, original| {
                let mut entered = false;
                assert!(
                    role.with_native(|native| {
                        entered = true;
                        original.check_with_native(native, 5)
                    })
                    .is_err()
                );
                assert!(!entered);
                original.check(role)
            })
        })
    }

    #[test]
    fn signature_borrow_cannot_substitute_another_phase_or_original() -> Result<()> {
        let world = super::super::simulation::World::new(89);
        super::super::effects::scope(world, || -> Result<()> {
            let identity = crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "alice".into(),
            };
            let intent = FreshIntent::fixture_oauth(
                &identity,
                "original",
                &day2_capabilities::Digest::new(b"challenge"),
                "https://security.example.com",
                5,
                305,
            )?;
            let changed = FreshIntent::fixture_oauth(
                &identity,
                "original",
                &day2_capabilities::Digest::new(b"different challenge"),
                "https://security.example.com",
                5,
                305,
            )?;
            reserve_shell(&intent, 5)?;
            with_current_original(&intent, Phase::ShellFlow, 5, |role, original| {
                assert!(original.require_signature(role, &intent).is_err());
                Ok(())
            })?;
            with_current_original(&intent, Phase::Signature, 5, |role, original| {
                assert!(original.require_signature(role, &changed).is_err());
                original.require_signature(role, &intent)
            })
        })
    }

    #[test]
    fn autonomous_role_is_scope_bound_and_cannot_supply_a_native_stage() -> Result<()> {
        let scope = AuthorityScope {
            installation: "testco".to_owned().try_into()?,
            environment: "test".to_owned().try_into()?,
            app: "calendar".to_owned().try_into()?,
        };
        assert!(with_current_app_role(&scope, RuntimePhase::Read, |_| Ok(())).is_err());
        let world = super::super::simulation::World::new(88);
        super::super::effects::scope(world.clone(), || -> Result<()> {
            assert!(with_current_app_role(&scope, RuntimePhase::Read, |_| Ok(())).is_err());
            fixtures::select_app_scope(&scope)?;
            with_current_app_role(&scope, RuntimePhase::InitialStorage, |stage| {
                stage.check_for(&scope, NativeRole::AppHost)?;
                assert!(stage.with_native(|_| Ok(())).is_err());
                Ok(())
            })?;
            with_current_app_role(&scope, RuntimePhase::Read, |stage| {
                stage.check_for(&scope, NativeRole::AppHost)?;
                assert!(stage.with_native(|_| Ok(())).is_err());
                let mut wrong = scope.clone();
                wrong.environment = "different".to_owned().try_into()?;
                assert!(stage.check_for(&wrong, NativeRole::AppHost).is_err());
                Ok(())
            })?;
            let failed: Result<()> =
                with_current_app_role(&scope, RuntimePhase::Refresh, |stage| {
                    world.advance(5);
                    stage.check()
                });
            assert!(failed.is_err());
            assert!(with_current_app_role(&scope, RuntimePhase::Read, |_| Ok(())).is_err());
            Ok(())
        })
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;
    use crate::oauth::effects::Hooks;
    use std::cell::Cell;

    thread_local! {
        static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
        // Scope switches/polls do not recreate a simulated process. Retained
        // entries use weak suppliers, are pruned when a world ends, and cannot
        // move across OS threads. Explicit restart discards native ownership.
        static RETAINED: RefCell<BTreeMap<u64, Fixture>> = const { RefCell::new(BTreeMap::new()) };
    }
    struct Fixture {
        hooks: std::sync::Weak<dyn Hooks>,
        domain: u64,
        originals: BTreeMap<(NativeRole, String), Original<SimulationClock>>,
        scopes: BTreeMap<String, AuthorityScope>,
        roles: BTreeMap<(NativeRole, String), Rc<Cell<bool>>>,
    }
    pub(super) struct SimulationClock {
        hooks: std::sync::Weak<dyn Hooks>,
        origin: Duration,
        latest: Duration,
        owner_refused: Rc<Cell<bool>>,
    }
    pub(crate) struct SimulationStage {
        hooks: std::sync::Arc<dyn Hooks>,
        origin: Duration,
        latest: Duration,
        thread: std::thread::ThreadId,
        refused: bool,
        role: NativeRole,
        scope: Option<AuthorityScope>,
        owner_refused: Rc<Cell<bool>>,
    }
    impl SimulationStage {
        pub(super) fn check_for(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
            self.check()?;
            ensure!(
                self.scope.as_ref() == Some(scope) && self.role == role,
                "simulated native role selection changed"
            );
            Ok(())
        }
        pub(super) fn check(&mut self) -> Result<()> {
            let result = (|| {
                let now = self.hooks.monotonic();
                ensure!(
                    !self.refused
                        && !self.owner_refused.get()
                        && super::super::effects::current_domain() == Some(self.hooks.domain())
                        && self.thread == std::thread::current().id()
                        && now >= self.origin
                        && now >= self.latest
                        && now - self.origin < Duration::from_secs(5),
                    "simulated native stage expired or executor changed"
                );
                self.latest = now;
                Ok(())
            })();
            if result.is_err() {
                self.refused = true;
                self.owner_refused.set(true);
            }
            result
        }
    }
    impl Clock for SimulationClock {
        fn origin(&self) -> Duration {
            self.origin
        }
        fn sample(&mut self) -> Result<Duration> {
            let Some(hooks) = self.hooks.upgrade() else {
                self.owner_refused.set(true);
                anyhow::bail!("native simulation supplier ended");
            };
            if self.owner_refused.get()
                || super::super::effects::current_domain() != Some(hooks.domain())
            {
                self.owner_refused.set(true);
                anyhow::bail!("native simulation role or clock domain refused");
            }
            let now = hooks.monotonic();
            if now < self.origin || now < self.latest {
                self.owner_refused.set(true);
                anyhow::bail!("native simulation clock moved backwards");
            }
            self.latest = now;
            Ok(now)
        }
    }
    fn capture(
        fixture: &mut Fixture,
        role: NativeRole,
        app: &str,
    ) -> Result<Original<SimulationClock>> {
        let hooks = fixture
            .hooks
            .upgrade()
            .context("native simulation supplier ended")?;
        let origin = hooks.monotonic();
        let owner_refused = fixture
            .roles
            .entry((role, app.into()))
            .or_insert_with(|| Rc::new(Cell::new(false)))
            .clone();
        let mut clock = SimulationClock {
            hooks: std::sync::Arc::downgrade(&hooks),
            origin,
            latest: origin,
            owner_refused,
        };
        clock.sample()?;
        Original::capture(clock)
    }
    pub(crate) struct Guard {
        previous: Option<Fixture>,
        changed: bool,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if self.changed {
                let current = FIXTURE.with(|slot| slot.replace(self.previous.take()));
                if let Some(current) = current {
                    RETAINED.with(|retained| retained.borrow_mut().insert(current.domain, current));
                }
            }
        }
    }
    /// Explicit simulator supplier, scoped with the existing complete ambient
    /// effect fixture. It never constructs a real enrolled stage or removes a
    /// production proof refusal. Only test binaries contain this supplier.
    pub(crate) fn scope(hooks: std::sync::Arc<dyn Hooks>) -> Guard {
        FIXTURE.with(|slot| {
            let Ok(mut slot) = slot.try_borrow_mut() else {
                // A changed nested simulator domain cannot replace borrowed
                // originals. Current-domain checks below refuse that use.
                return Guard {
                    previous: None,
                    changed: false,
                };
            };
            if slot
                .as_ref()
                .is_some_and(|fixture| fixture.domain == hooks.domain())
            {
                return Guard {
                    previous: None,
                    changed: false,
                };
            }
            let retained = RETAINED.with(|retained| {
                let mut retained = retained.borrow_mut();
                retained.retain(|_, fixture| fixture.hooks.strong_count() != 0);
                retained.remove(&hooks.domain())
            });
            Guard {
                previous: slot.replace(retained.unwrap_or_else(|| Fixture {
                    domain: hooks.domain(),
                    hooks: std::sync::Arc::downgrade(&hooks),
                    originals: BTreeMap::new(),
                    scopes: BTreeMap::new(),
                    roles: BTreeMap::new(),
                })),
                changed: true,
            }
        })
    }
    pub(super) fn capture_app<'a>(
        start: &'a super::super::management::app::CaptureStart,
        app: &str,
    ) -> Result<Option<AppCreator<'a>>> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let Some(fixture) = slot.as_mut() else {
                return Ok(None);
            };
            ensure!(
                fixture.originals.len() < 1024,
                "fixture native original capacity"
            );
            Ok(Some(AppCreator {
                original: CapturedOriginal::Simulated(capture(fixture, NativeRole::AppHost, app)?),
                app: app.into(),
                start,
            }))
        })
    }
    pub(super) fn bind_app(
        intent: &FreshIntent,
        original: Original<SimulationClock>,
    ) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let fixture = slot.as_mut().context("fixture executor missing")?;
            ensure!(
                fixture
                    .originals
                    .insert((NativeRole::AppHost, intent.attempt().into()), original)
                    .is_none(),
                "fixture original replaced"
            );
            enlist(NativeRole::AppHost, intent)
        })
    }
    pub(super) fn reserve_shell(intent: &FreshIntent, wall: i64) -> Result<bool> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let Some(fixture) = slot.as_mut() else {
                return Ok(false);
            };
            let key = (NativeRole::SecurityShell, intent.attempt().into());
            if let Some(original) = fixture.originals.get_mut(&key) {
                original.check(intent, wall)?;
            } else {
                ensure!(
                    fixture.originals.len() < 1024,
                    "fixture native original capacity"
                );
                let mut original = capture(fixture, NativeRole::SecurityShell, intent.app())?;
                original.bind(intent, wall)?;
                fixture.originals.insert(key, original);
            }
            enlist(NativeRole::SecurityShell, intent)?;
            Ok(true)
        })
    }
    pub(super) fn active() -> bool {
        FIXTURE.with(|slot| slot.try_borrow().map_or(true, |fixture| fixture.is_some()))
    }

    pub(super) fn refuse_original(intent: &FreshIntent, kind: NativeRole) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            slot.as_mut().context("fixture executor missing")?.originals
                .get_mut(&(kind, intent.attempt().into())).context("fixture original missing")?.refuse();
            Ok(())
        })
    }

    pub(crate) fn restart(domain: u64) {
        FIXTURE.with(|slot| {
            assert!(
                slot.borrow()
                    .as_ref()
                    .is_none_or(|fixture| fixture.domain != domain),
                "cannot restart a borrowed fixture executor"
            )
        });
        RETAINED.with(|retained| retained.borrow_mut().remove(&domain));
    }

    pub(crate) fn select_app_scope(scope: &AuthorityScope) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let fixture = slot
                .as_mut()
                .context("native simulation supplier missing")?;
            if let Some(selected) = fixture.scopes.get(scope.app.as_str()) {
                ensure!(selected == scope, "native simulation scope cannot change");
            } else {
                fixture
                    .scopes
                    .insert(scope.app.as_str().into(), scope.clone());
            }
            fixture
                .roles
                .entry((NativeRole::AppHost, scope.app.as_str().into()))
                .or_insert_with(|| Rc::new(Cell::new(false)));
            Ok(())
        })
    }

    pub(super) fn with_app_role<T>(
        scope: &AuthorityScope,
        _phase: RuntimePhase,
        use_current: impl FnOnce(&mut RoleStage<'_>) -> Result<T>,
    ) -> Result<T> {
        FIXTURE.with(|slot| {
            let slot = slot.try_borrow()?;
            let fixture = slot
                .as_ref()
                .context("native simulation supplier missing")?;
            ensure!(
                fixture.scopes.get(scope.app.as_str()) == Some(scope),
                "native simulation App scope missing"
            );
            let hooks = fixture
                .hooks
                .upgrade()
                .context("native simulation supplier ended")?;
            let origin = hooks.monotonic();
            let mut stage = RoleStage {
                source: RoleSource::Simulated(SimulationStage {
                    hooks,
                    origin,
                    latest: origin,
                    thread: std::thread::current().id(),
                    refused: false,
                    role: NativeRole::AppHost,
                    scope: Some(scope.clone()),
                    owner_refused: fixture
                        .roles
                        .get(&(NativeRole::AppHost, scope.app.as_str().into()))
                        .context("native simulation role missing")?
                        .clone(),
                }),
            };
            stage.check_for(scope, NativeRole::AppHost)?;
            use_current(&mut stage)
        })
    }

    pub(super) fn with_current<T>(
        intent: &FreshIntent,
        phase: Phase,
        wall: i64,
        expected: Option<NativeRole>,
        use_current: impl FnOnce(&mut RoleStage<'_>, &mut OriginalPhase<'_>) -> Result<T>,
    ) -> Result<T> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let fixture = slot
                .as_mut()
                .context("native simulation supplier missing")?;
            let kind = expected.unwrap_or_else(|| match phase {
                Phase::ShellFlow | Phase::Session | Phase::Signature => NativeRole::SecurityShell,
                Phase::Response => {
                    if fixture
                        .originals
                        .contains_key(&(NativeRole::AppHost, intent.attempt().into()))
                    {
                        NativeRole::AppHost
                    } else {
                        NativeRole::SecurityShell
                    }
                }
                _ => NativeRole::AppHost,
            });
            let owner_refused = fixture
                .originals
                .get(&(kind, intent.attempt().into()))
                .context("fixture original absent; SQL cannot restore it")?
                .clock
                .owner_refused
                .clone();
            let hooks = fixture
                .hooks
                .upgrade()
                .context("native simulation supplier ended")?;
            let origin = hooks.monotonic();
            let mut stage = RoleStage {
                source: RoleSource::Simulated(SimulationStage {
                    hooks,
                    origin,
                    latest: origin,
                    thread: std::thread::current().id(),
                    refused: false,
                    role: kind,
                    scope: fixture.scopes.get(intent.app()).cloned(),
                    owner_refused,
                }),
            };
            let original = fixture
                .originals
                .get_mut(&(kind, intent.attempt().into()))
                .context("fixture original absent; SQL cannot restore it")?;
            let mut original = OriginalPhase {
                original: PhaseOriginal::Simulated(original),
                intent,
                wall,
                phase,
            };
            original.check(&mut stage)?;
            enlist(kind, intent)?;
            use_current(&mut stage, &mut original)
        })
    }
}
