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

pub(super) fn selected_scopes(
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
pub(crate) struct AppCreator {
    original: CapturedOriginal,
    app: String,
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

pub(super) fn capture_app(app: &str) -> Result<AppCreator> {
    #[cfg(test)]
    if let Some(captured) = fixtures::capture_app(app)? {
        return Ok(captured);
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners.get_mut(app).context("native App executor missing")?;
        ensure!(owners.originals.len() < 1024, "native original capacity");
        Ok(AppCreator {
            original: CapturedOriginal::Native(capture(owners, NativeRole::AppHost)?),
            app: app.into(),
        })
    })
}

impl AppCreator {
    /// Called once AFTER the actual Pending transaction commits.
    pub(super) fn bind(self, intent: &FreshIntent, wall: i64) -> Result<()> {
        ensure!(
            self.app == intent.app(),
            "native App original target changed"
        );
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
#[derive(Clone, Copy)]
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
    Response,
    ShellFlow,
}

pub(crate) struct RoleStage<'a> {
    source: RoleSource<'a>,
}

enum RoleSource<'a> {
    Native(EnrolledRoleStage<'a>),
    #[cfg(test)]
    Simulated(fixtures::SimulationStage),
}

impl RoleStage<'_> {
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
            source: RoleSource::Native(role.begin_current_stage()?),
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
}

enum PhaseOriginal<'a> {
    Native(&'a mut Original<EnrolledClock>),
    #[cfg(test)]
    Simulated(&'a mut Original<fixtures::SimulationClock>),
}

/* The two borrows remain inside the callback; neither is a response DTO. */
impl OriginalPhase<'_> {
    pub(crate) fn check(&mut self, stage: &mut RoleStage<'_>) -> Result<()> {
        let result = (|| {
            let wall = super::effects::wall_time()?;
            ensure!(
                wall >= self.wall,
                "native original wall clock moved backwards"
            );
            self.wall = wall;
            stage.check()?;
            match (&mut self.original, &mut stage.source) {
                (PhaseOriginal::Native(original), RoleSource::Native(stage)) => {
                    let now = original.clock.clock.sample(stage);
                    original.check_sample(self.intent, self.wall, now)
                }
                #[cfg(test)]
                (PhaseOriginal::Simulated(original), RoleSource::Simulated(_)) => {
                    original.check(self.intent, self.wall)
                }
                #[cfg(test)]
                _ => anyhow::bail!("native original role supplier changed"),
            }
        })();
        if result.is_err() {
            match &mut self.original {
                PhaseOriginal::Native(original) => original.refuse(),
                #[cfg(test)]
                PhaseOriginal::Simulated(original) => original.refuse(),
            }
        }
        result
    }
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
            | Phase::DisconnectCommit => ensure!(
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
            source: RoleSource::Native(role.begin_current_stage()?),
        };
        let mut original = OriginalPhase {
            original: PhaseOriginal::Native(original),
            intent,
            wall,
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
pub(super) struct Sink(Rc<RefCell<BTreeMap<(NativeRole, String), SinkBinding>>>);

#[derive(Clone)]
struct SinkBinding {
    intent: FreshIntent,
    effects: crate::managed_credentials::effects::Captured,
}

impl Sink {
    pub(super) fn new() -> Self {
        Self(Rc::new(RefCell::new(BTreeMap::new())))
    }

    pub(super) fn check(&self) -> Result<()> {
        let intents: Vec<_> = self
            .0
            .try_borrow()?
            .iter()
            .map(|((role, _), binding)| (*role, binding.clone()))
            .collect();
        for (role, binding) in intents {
            binding.effects.run(|| {
                with_current_for_role(
                    &binding.intent,
                    Phase::Response,
                    super::effects::wall_time()?,
                    Some(role),
                    |stage, original| original.check(stage),
                )
            })?;
        }
        Ok(())
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

fn enlist(role: NativeRole, intent: &FreshIntent) -> Result<()> {
    ACTIVE_SINK.with(|slot| {
        if let Some(sink) = slot.try_borrow()?.as_ref() {
            let mut indexes = sink.0.try_borrow_mut()?;
            let key = (role, intent.attempt().into());
            ensure!(
                indexes.len() < 4 || indexes.contains_key(&key),
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
pub(crate) mod fixtures {
    use super::*;
    use crate::oauth::effects::Hooks;

    thread_local! {
        static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
        // Distinct inner effect tracks survive across requests ONLY for the
        // lifetime of the fixed executor thread. A scope switch is not a
        // process restart and cannot discard its original owners.
        static RETAINED: RefCell<BTreeMap<u64, Fixture>> = const { RefCell::new(BTreeMap::new()) };
    }
    struct Fixture {
        hooks: std::sync::Arc<dyn Hooks>,
        originals: BTreeMap<(NativeRole, String), Original<SimulationClock>>,
        scopes: BTreeMap<String, AuthorityScope>,
    }
    pub(super) struct SimulationClock {
        hooks: std::sync::Arc<dyn Hooks>,
        origin: Duration,
    }
    pub(crate) struct SimulationStage {
        hooks: std::sync::Arc<dyn Hooks>,
        origin: Duration,
        latest: Duration,
        thread: std::thread::ThreadId,
        refused: bool,
        role: NativeRole,
        scope: Option<AuthorityScope>,
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
            }
            result
        }
    }
    impl Clock for SimulationClock {
        fn origin(&self) -> Duration {
            self.origin
        }
        fn sample(&mut self) -> Result<Duration> {
            ensure!(
                super::super::effects::current_domain() == Some(self.hooks.domain()),
                "native simulation clock domain changed"
            );
            Ok(self.hooks.monotonic())
        }
    }
    fn capture(fixture: &Fixture) -> Result<Original<SimulationClock>> {
        let origin = fixture.hooks.monotonic();
        Original::capture(SimulationClock {
            hooks: fixture.hooks.clone(),
            origin,
        })
    }
    pub(crate) struct Guard {
        previous: Option<Fixture>,
        changed: bool,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if self.changed {
                let current = FIXTURE.with(|slot| slot.replace(self.previous.take()));
                if super::super::native_http::owns_thread() {
                    if let Some(current) = current {
                        RETAINED.with(|retained| {
                            retained
                                .borrow_mut()
                                .insert(current.hooks.domain(), current)
                        });
                    }
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
                .is_some_and(|fixture| fixture.hooks.domain() == hooks.domain())
            {
                return Guard {
                    previous: None,
                    changed: false,
                };
            }
            let retained = RETAINED.with(|retained| retained.borrow_mut().remove(&hooks.domain()));
            Guard {
                previous: slot.replace(retained.unwrap_or_else(|| Fixture {
                    hooks,
                    originals: BTreeMap::new(),
                    scopes: BTreeMap::new(),
                })),
                changed: true,
            }
        })
    }
    pub(super) fn capture_app(app: &str) -> Result<Option<AppCreator>> {
        FIXTURE.with(|slot| {
            let slot = slot.borrow();
            let Some(fixture) = slot.as_ref() else {
                return Ok(None);
            };
            ensure!(
                fixture.originals.len() < 1024,
                "fixture native original capacity"
            );
            Ok(Some(AppCreator {
                original: CapturedOriginal::Simulated(capture(fixture)?),
                app: app.into(),
            }))
        })
    }
    pub(super) fn bind_app(
        intent: &FreshIntent,
        original: Original<SimulationClock>,
    ) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.borrow_mut();
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
            let mut slot = slot.borrow_mut();
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
                let mut original = capture(fixture)?;
                original.bind(intent, wall)?;
                fixture.originals.insert(key, original);
            }
            enlist(NativeRole::SecurityShell, intent)?;
            Ok(true)
        })
    }
    pub(super) fn active() -> bool {
        FIXTURE.with(|slot| slot.borrow().is_some())
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
            let origin = fixture.hooks.monotonic();
            let mut stage = RoleStage {
                source: RoleSource::Simulated(SimulationStage {
                    hooks: fixture.hooks.clone(),
                    origin,
                    latest: origin,
                    thread: std::thread::current().id(),
                    refused: false,
                    role: NativeRole::AppHost,
                    scope: Some(scope.clone()),
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
            let mut slot = slot.borrow_mut();
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
            let mut stage = RoleStage {
                source: RoleSource::Simulated(SimulationStage {
                    hooks: fixture.hooks.clone(),
                    origin: fixture.hooks.monotonic(),
                    latest: fixture.hooks.monotonic(),
                    thread: std::thread::current().id(),
                    refused: false,
                    role: kind,
                    scope: fixture.scopes.get(intent.app()).cloned(),
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
            };
            original.check(&mut stage)?;
            enlist(kind, intent)?;
            use_current(&mut stage, &mut original)
        })
    }
}
