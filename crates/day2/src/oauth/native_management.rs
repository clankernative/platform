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
use crate::security_epoch::serving::{
    CurrentServingPhase, ResponseIdentity, ServingParticipant, ServingUse,
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

mod response;

type Role = response::Role<EnrolledProcessRoleOwner>;

/// Checked desired selection DATA. This cannot enroll, open storage, create a
/// serving participant or replace any missing native supplier.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NativeSelection {
    policy: day2_capabilities::security_epoch::bootstrap::InitialBootstrapPolicy,
    store: day2_capabilities::security_epoch::EpochStore,
}

impl NativeSelection {
    pub(crate) fn scope(&self) -> &AuthorityScope {
        &self.policy.scope
    }
}

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
    selection: NativeSelection,
    originals: BTreeMap<String, StoredOriginal<EnrolledClock>>,
    storage: AppStorage,
}

struct StoredOriginal<C: Clock> {
    original: Original<C>,
    response: ResponseBinding,
}

impl<C: Clock> StoredOriginal<C> {
    fn new(original: Original<C>, intent: &FreshIntent) -> Self {
        Self {
            original,
            response: ResponseBinding {
                intent: intent.clone(),
                connection: None,
            },
        }
    }
}

// Connection matching DATA only. Current authority always comes from the
// original, enrolled role and genuine serving participant, never this record.
struct ResponseBinding {
    intent: FreshIntent,
    connection: Option<ResponseIdentity>,
}

impl ResponseBinding {
    fn require(&self, intent: &FreshIntent, identity: &ResponseIdentity) -> Result<()> {
        ensure!(self.intent == *intent, "native response original changed");
        ensure!(
            self.connection
                .as_ref()
                .is_none_or(|current| current.same(identity)),
            "native original belongs to another response"
        );
        Ok(())
    }

    fn require_bound(&self, intent: &FreshIntent, identity: &ResponseIdentity) -> Result<()> {
        self.require(intent, identity)?;
        ensure!(
            self.connection.is_some(),
            "native response original not bound"
        );
        Ok(())
    }
}

// Neither absence nor a refusal is a storage witness. Live variants consume
// the actual App first holder on THIS executor. Refused variants retain that
// same owner but cannot enter another bootstrap or consumer callback.
enum AppStorage {
    Connected(Box<crate::security_epoch::native_enrollment::InitialHolderConnection>),
    ShellConnected(Box<crate::security_epoch::native_enrollment::ShellServingConnection>),
    Refused,
    Bootstrapping(Box<crate::security_epoch::AppStorageBootstrap>),
    Participant(Box<ServingParticipant>),
    RefusedBootstrap(Box<crate::security_epoch::AppStorageBootstrap>),
    RefusedParticipant(Box<ServingParticipant>),
}

impl AppStorage {
    fn refuse(&mut self) {
        *self = match std::mem::replace(self, Self::Refused) {
            Self::Bootstrapping(mut storage) | Self::RefusedBootstrap(mut storage) => {
                storage.refuse();
                Self::RefusedBootstrap(storage)
            }
            Self::Participant(mut storage) | Self::RefusedParticipant(mut storage) => {
                storage.refuse();
                Self::RefusedParticipant(storage)
            }
            Self::Connected(_) | Self::ShellConnected(_) | Self::Refused => Self::Refused,
        };
    }
}

thread_local! {
    static OWNERS: Rc<RefCell<response::Registry<Owners>>> = Rc::new(RefCell::new(response::Registry::default()));
    static ACTIVE_SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

/// Install only on the final HTTP executor; each explicitly selected scope
/// requires the real native exchange. Empty selection installs no owner and
/// cannot capture/consume an original. Errors never become empty selection.
/// No role, origin, FD or clock comes from the HTTP request.
pub(super) fn install(selections: &[NativeSelection], kind: NativeRole) -> Result<()> {
    ensure!(
        response::is_empty(),
        "native executor has a retained response"
    );
    ensure!(selections.len() <= 128, "native enrollment scope capacity");
    let mut selected = BTreeMap::new();
    for selection in selections {
        let mut role = EnrolledProcessRoleOwner::enroll_current_thread(selection.scope(), kind)?;
        let storage = {
            let mut stage = role.begin_current_stage()?;
            stage.check_selection(&selection.policy, &selection.store, kind)?;
            let storage = match kind {
                NativeRole::AppHost => AppStorage::Connected(Box::new(
                    crate::security_epoch::native_enrollment::InitialHolderConnection::connect(
                        &mut stage,
                    )?,
                )),
                NativeRole::SecurityShell => {
                    let connection =
                        crate::security_epoch::native_enrollment::ShellServingConnection::connect(
                            &mut stage,
                        )?;
                    stage.check_selection(&selection.policy, &selection.store, kind)?;
                    AppStorage::ShellConnected(Box::new(connection))
                }
                NativeRole::EpochController => {
                    anyhow::bail!("native HTTP controller role refused")
                }
            };
            crate::security_epoch::serving::record_executor_enrollment(
                &mut stage,
                &selection.policy,
                &selection.store,
                kind,
            )?;
            storage
        };
        let storage = match storage {
            AppStorage::ShellConnected(mut connection) => {
                connection.wait_ready()?;
                let mut stage = role.begin_current_stage()?;
                stage.check_selection(&selection.policy, &selection.store, kind)?;
                let peer = connection.receive(&mut stage)?;
                stage.check_selection(&selection.policy, &selection.store, kind)?;
                AppStorage::Participant(Box::new(ServingParticipant::shell(peer)))
            }
            storage => storage,
        };
        ensure!(
            selected
                .insert(
                    selection.scope().app.as_str().into(),
                    Owners {
                        role: Role::new(role),
                        kind,
                        selection: selection.clone(),
                        originals: BTreeMap::new(),
                        storage,
                    }
                )
                .is_none(),
            "native executor scope repeated"
        );
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        ensure!(owners.is_empty(), "native executor already enrolled");
        owners.extend(selected);
        Ok(())
    })
}

pub(super) fn clear() {
    OWNERS.with(|owners| owners.borrow_mut().clear());
}

/// Called on the final enrolled App executor, before any Runtime or serving
/// database open. Selection and metadata are DATA; the real channel, first
/// holder and original file are supplied only by the native S1/S3 exchange.
pub(crate) fn prepare_initial_app_storage(
    metadata: &crate::store::InitialStoreMetadata,
    instance: &crate::artifact::Instance,
) -> Result<()> {
    use crate::security_epoch::{
        AppInitialStorageContinuity, AppPreparedFile, AppStorageBootstrap,
        native_enrollment::AuthenticatedInitialHolderOffer,
    };
    let control = instance
        .control
        .as_ref()
        .context("native App control missing")?;
    let policy = instance
        .native_bootstrap_for(metadata.app())?
        .context("native App bootstrap missing")?;
    let store = control
        .security_epochs
        .get(&policy.epoch_store.id)
        .context("native App epoch selection missing")?;
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners
            .get_mut(metadata.app())
            .context("native App executor missing")?;
        ensure!(
            owners.kind == NativeRole::AppHost,
            "native initial storage requires App owner"
        );
        ensure!(
            owners.selection.policy == *policy && owners.selection.store == *store,
            "native App selected policy changed"
        );
        // Consume the completed connector before waiting or acquiring a new
        // stage. A failed/unknown attempt cannot reconnect or adopt from DATA.
        let AppStorage::Connected(mut connection) =
            std::mem::replace(&mut owners.storage, AppStorage::Refused)
        else {
            anyhow::bail!("native App storage attempt already spent");
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            {
                connection.wait_ready()?;
                let mut role = owners.role.try_borrow_mut()?;
                let mut stage = role.begin_initial_first_holder_stage()?;
                stage.check_selection(policy, store, NativeRole::AppHost)?;
                let mut offer = AuthenticatedInitialHolderOffer::receive(*connection, &mut stage)?;
                let file = AppPreparedFile::observe_existing(
                    &mut stage, metadata, policy, store, &mut offer,
                )?;
                let holder = offer.finish(file)?;
                let storage = AppInitialStorageContinuity::retain(holder)?;
                owners.storage = AppStorage::Bootstrapping(Box::new(AppStorageBootstrap::retain(
                    storage, policy, store,
                )?));
                stage.check_selection(policy, store, NativeRole::AppHost)?;
            }
            // S3 owns the fixed Reserve/Dispatch/Settle pair. Each of its six
            // steps receives its storage-bootstrap stage from this SAME
            // enrollment and trusted local Bootstrapping state. Ordinary
            // serving never selects this purpose. A failed or incomplete step
            // cannot restart this once-only startup attempt.
            for _ in 0..6 {
                let AppStorage::Bootstrapping(storage) = &mut owners.storage else {
                    anyhow::bail!("native App bootstrap owner unavailable")
                };
                storage.prepare_current()?;
                let mut role = owners.role.try_borrow_mut()?;
                let mut stage = role.begin_storage_bootstrap_stage()?;
                stage.check_selection(policy, store, NativeRole::AppHost)?;
                storage.advance(&mut stage)?;
                stage.check_selection(policy, store, NativeRole::AppHost)?;
            }
            let storage = std::mem::replace(&mut owners.storage, AppStorage::Refused);
            let AppStorage::Bootstrapping(storage) = storage else {
                owners.storage = storage;
                anyhow::bail!("native App bootstrap owner unavailable")
            };
            match storage.into_active() {
                Ok(storage) => {
                    owners.storage =
                        AppStorage::Participant(Box::new(ServingParticipant::app(storage)));
                    Ok(())
                }
                Err(storage) => {
                    owners.storage = AppStorage::Bootstrapping(storage);
                    anyhow::bail!("native App activation incomplete")
                }
            }
        }));
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                owners.storage.refuse();
                Err(error)
            }
            Err(panic) => {
                owners.storage.refuse();
                std::panic::resume_unwind(panic)
            }
        }
    })
}

/// Lend the original activated App file/peer and a fresh stage from the SAME
/// executor. This is still not current serving authority: S3's consuming
/// Runtime/serving constructor must check the actual owner inside the callback.
/// No lookup can construct a holder or return its ownership.
fn with_app_participant<T>(
    scope: &AuthorityScope,
    operation: impl FnOnce(&mut ServingParticipant, &mut EnrolledRoleStage<'_>) -> Result<T>,
) -> Result<T> {
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners
            .get_mut(scope.app.as_str())
            .context("native App executor missing")?;
        ensure!(
            owners.kind == NativeRole::AppHost,
            "native storage requires App owner"
        );
        let AppStorage::Participant(storage) = &mut owners.storage else {
            anyhow::bail!("native active App holder unavailable")
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            storage.prepare_current()?;
            let mut role = owners.role.try_borrow_mut()?;
            let mut stage = role.begin_current_stage()?;
            stage.check_for(scope, NativeRole::AppHost)?;
            stage.check_selection(
                &owners.selection.policy,
                &owners.selection.store,
                owners.kind,
            )?;
            let value = operation(storage, &mut stage)?;
            stage.check_selection(
                &owners.selection.policy,
                &owners.selection.store,
                owners.kind,
            )?;
            stage.check_for(scope, NativeRole::AppHost)?;
            Ok(value)
        }));
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                owners.storage.refuse();
                Err(error)
            }
            Err(panic) => {
                owners.storage.refuse();
                std::panic::resume_unwind(panic)
            }
        }
    })
}

pub(crate) fn load_initial_app_runtime(
    scope: &AuthorityScope,
    metadata: crate::store::InitialStoreMetadata,
) -> Result<crate::store::Runtime> {
    with_app_participant(scope, |participant, stage| {
        crate::security_epoch::serving::load_native_runtime(participant, stage, metadata)
    })
}

// Retained selection DATA only. Resolve it before any SQL, clock or current
// acquisition so an unknown/foreign caller cannot touch the rightful original.
fn selected_pending_intent(
    intent: &FreshIntent,
    app: &str,
    attempt: &str,
    identity: &crate::iap::Verified,
) -> Result<FreshIntent> {
    ensure!(
        intent.app() == app && intent.attempt() == attempt,
        "native Pending original selection changed"
    );
    intent.require_identity(identity)?;
    intent.require_oauth_management()?;
    Ok(intent.clone())
}

pub(super) fn pending_intent(
    app: &str,
    attempt: &str,
    identity: &crate::iap::Verified,
) -> Result<FreshIntent> {
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::pending_intent(app, attempt, identity);
    }
    OWNERS.with(|owners| {
        let owners = owners.try_borrow()?;
        let owner = owners.get(app).context("native App executor missing")?;
        ensure!(
            owner.kind == NativeRole::AppHost,
            "native Pending requires App owner"
        );
        let original = owner
            .originals
            .get(attempt)
            .context("native Pending original absent; rows cannot restore it")?;
        selected_pending_intent(&original.response.intent, app, attempt, identity)
    })
}

#[cfg(test)]
pub(super) fn simulation_installed() -> bool {
    fixtures::active()
}

pub(crate) fn selected_scopes(
    instance: &crate::artifact::Instance,
    only_app: Option<&str>,
) -> Result<Vec<AuthorityScope>> {
    Ok(selected_profiles(instance, only_app)?
        .into_iter()
        .map(|selection| selection.policy.scope)
        .collect())
}

pub(crate) fn selected_profiles(
    instance: &crate::artifact::Instance,
    only_app: Option<&str>,
) -> Result<Vec<NativeSelection>> {
    let mut scopes = Vec::new();
    for (app, binding) in &instance.apps {
        if binding.oauth_connections.is_empty() || only_app.is_some_and(|selected| selected != app)
        {
            continue;
        }
        let Some(policy) = instance.native_bootstrap_for(app)? else {
            // A configured OAuth integration/epoch is metadata, not selection
            // of the native owner profile. HTTP may serve prerequisites, but
            // the empty native registry cannot capture or consume an original.
            continue;
        };
        let store = instance
            .control
            .as_ref()
            .context("native bootstrap control missing")?
            .security_epochs
            .get(&policy.epoch_store.id)
            .context("native bootstrap epoch missing")?;
        scopes.push(NativeSelection {
            policy: policy.clone(),
            store: store.clone(),
        });
    }
    ensure!(scopes.len() <= 128, "native enrollment scope capacity");
    Ok(scopes)
}

/// Not a Send handle. Capture is the FIRST operation in Manager::capture.
pub(crate) struct AppCreator<'a> {
    original: CapturedOriginal,
    app: String,
    start: &'a super::management::app::CaptureStart,
    pending: PendingCaptureState,
}

#[derive(PartialEq, Eq)]
enum PendingCaptureState {
    Captured,
    Attempted,
    Committed,
}

enum CapturedOriginal {
    Native(Original<EnrolledClock>),
    #[cfg(test)]
    Simulated(Original<fixtures::SimulationClock>),
}

/// Borrow of the original creator and its current storage scope before an
/// immutable Pending exists. It cannot sign, authenticate or bind an intent.
pub(crate) struct PendingWriter<'a, 'role> {
    source: PendingSource<'a, 'role>,
    committed: bool,
}

enum PendingSource<'a, 'role> {
    Native {
        original: &'a mut Original<EnrolledClock>,
        current: &'a mut dyn CurrentServingPhase,
        stage: &'a mut EnrolledRoleStage<'role>,
    },
    #[cfg(test)]
    Simulated {
        original: &'a mut Original<fixtures::SimulationClock>,
        stage: fixtures::SimulationStage,
    },
}

impl PendingWriter<'_, '_> {
    pub(super) fn check(&mut self) -> Result<()> {
        match &mut self.source {
            PendingSource::Native {
                original,
                current,
                stage,
            } => {
                current.check(stage)?;
                let sample = original.clock.clock.sample(stage);
                original.check_capture_sample(sample)
            }
            #[cfg(test)]
            PendingSource::Simulated { original, stage } => {
                stage.check()?;
                let sample = original.clock.sample();
                original.check_capture_sample(sample)
            }
        }
    }

    pub(super) fn commit(&mut self, tx: rusqlite::Transaction<'_>) -> Result<()> {
        let result = (|| {
            ensure!(!self.committed, "native Pending commit already attempted");
            self.check()?;
            self.committed = true;
            tx.commit()?;
            self.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn run<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check()?;
            match &mut self.source {
                PendingSource::Native { current, stage, .. } => current.arm(stage)?,
                #[cfg(test)]
                PendingSource::Simulated { .. } => {}
            }
            let value = operation(self)?;
            ensure!(self.committed, "native Pending commit missing");
            self.check()?;
            match &mut self.source {
                PendingSource::Native { current, stage, .. } => current.finish_known(stage)?,
                #[cfg(test)]
                PendingSource::Simulated { .. } => {}
            }
            self.check()?;
            Ok(value)
        }));
        match result {
            Ok(result) => {
                if result.is_err() {
                    self.refuse();
                }
                result
            }
            Err(panic) => {
                self.refuse();
                std::panic::resume_unwind(panic)
            }
        }
    }

    fn refuse(&mut self) {
        match &mut self.source {
            PendingSource::Native {
                original, current, ..
            } => {
                original.refuse();
                current.refuse();
            }
            #[cfg(test)]
            PendingSource::Simulated { original, .. } => original.refuse(),
        }
    }
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
            pending: PendingCaptureState::Captured,
        })
    })
}

impl AppCreator<'_> {
    /// The fixed Pending creation stays under the actual App participant and
    /// SAME enrolled stage. Capture precedes every DB/entropy operation; only
    /// the successful committed result can subsequently bind this original.
    pub(super) fn with_pending<T>(
        &mut self,
        operation: impl FnOnce(&mut PendingWriter<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            self.pending == PendingCaptureState::Captured,
            "native Pending capture already attempted"
        );
        self.pending = PendingCaptureState::Attempted;
        let result = match &mut self.original {
            CapturedOriginal::Native(original) => OWNERS.with(|owners| {
                let mut owners = owners.try_borrow_mut()?;
                let owners = owners
                    .get_mut(&self.app)
                    .context("native Pending executor missing")?;
                ensure!(
                    owners.kind == NativeRole::AppHost,
                    "native Pending requires App owner"
                );
                let AppStorage::Participant(participant) = &mut owners.storage else {
                    anyhow::bail!("native Pending participant unavailable")
                };
                participant.prepare_current()?;
                let mut role = owners.role.try_borrow_mut()?;
                let mut stage = role.begin_current_stage()?;
                stage.check_selection(
                    &owners.selection.policy,
                    &owners.selection.store,
                    owners.kind,
                )?;
                crate::security_epoch::serving::with_current_runtime_serving(
                    participant,
                    &mut stage,
                    crate::security_epoch::serving::RuntimeServingUse::PendingCapture,
                    |current, same| {
                        let value = PendingWriter {
                            source: PendingSource::Native {
                                original,
                                current,
                                stage: same,
                            },
                            committed: false,
                        }
                        .run(operation)?;
                        same.check_selection(
                            &owners.selection.policy,
                            &owners.selection.store,
                            owners.kind,
                        )?;
                        Ok(value)
                    },
                )
            }),
            #[cfg(test)]
            CapturedOriginal::Simulated(original) => fixtures::with_pending(original, operation),
        };
        if result.is_ok() {
            self.pending = PendingCaptureState::Committed;
        }
        result
    }

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
        ensure!(
            self.pending == PendingCaptureState::Committed,
            "native Pending commit not settled"
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
            owners.originals.insert(
                intent.attempt().into(),
                StoredOriginal::new(original, intent),
            );
            enlist(
                NativeRole::AppHost,
                intent,
                &mut owners.originals.get_mut(intent.attempt()).unwrap().response,
                Some(&mut owners.storage),
            )?;
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
            validate_enlist(NativeRole::SecurityShell, intent, &original.response)?;
            original.original.check(intent, wall)?;
            enlist(
                NativeRole::SecurityShell,
                intent,
                &mut original.response,
                Some(&mut owners.storage),
            )?;
            return Ok(());
        }
        ensure!(owners.originals.len() < 1024, "native original capacity");
        let mut original = capture(owners, NativeRole::SecurityShell)?;
        let current_wall = super::effects::wall_time()?;
        ensure!(
            current_wall >= wall,
            "native original wall clock moved backwards"
        );
        original.bind(intent, current_wall)?;
        owners.originals.insert(
            intent.attempt().into(),
            StoredOriginal::new(original, intent),
        );
        enlist(
            NativeRole::SecurityShell,
            intent,
            &mut owners.originals.get_mut(intent.attempt()).unwrap().response,
            Some(&mut owners.storage),
        )?;
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
    ShellAuthentication,
    Verification,
    Response,
    ResponseComplete,
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
            Self::Native(stage) => stage.require_current_role(),
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
            RoleSource::Native(stage) => stage.require_current_role(),
            #[cfg(test)]
            RoleSource::Simulated(stage) => stage.check(),
        }
    }

    pub(crate) fn check_for(&mut self, scope: &AuthorityScope, role: NativeRole) -> Result<()> {
        match &mut self.source {
            RoleSource::Native(stage) => {
                stage.require_current_role()?;
                stage.check_for(scope, role)
            }
            #[cfg(test)]
            RoleSource::Simulated(stage) => stage.check_for(scope, role),
        }
    }

    /// S3 may borrow the real stage for native authenticated reads. A scripted
    /// role never constructs or substitutes a native enrolled stage. A storage
    /// bootstrap or metadata-observation stage cannot become ordinary serving
    /// authority, even if its remaining interval is shorter than five seconds.
    pub(crate) fn with_native<T>(
        &mut self,
        use_native: impl FnOnce(&mut EnrolledRoleStage<'_>) -> Result<T>,
    ) -> Result<T> {
        match &mut self.source {
            RoleSource::Native(stage) => {
                stage.require_current_role()?;
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
    Registration,
    Read,
    Refresh,
}

/// Autonomous operation borrow. It has no human original, signature factory or
/// conversion into Consumer. Native construction always borrows the real App
/// participant and SAME stage; ordinary/test Runtime data cannot supply those.
pub(crate) struct RuntimeConsumer<'a, 'role> {
    source: RuntimeSource<'a, 'role>,
    runtime: Option<&'a crate::store::Runtime>,
}

enum RuntimeSource<'a, 'role> {
    Native {
        current: &'a mut dyn CurrentServingPhase,
        stage: &'a mut EnrolledRoleStage<'role>,
    },
    Ordinary,
    #[cfg(test)]
    Simulated(&'a mut RoleStage<'role>),
}

impl RuntimeConsumer<'_, '_> {
    pub(super) fn require_runtime(&self, runtime: &crate::store::Runtime) -> Result<()> {
        ensure!(
            self.runtime
                .is_some_and(|selected| std::ptr::eq(selected, runtime)),
            "native runtime consumer selection changed"
        );
        Ok(())
    }
    pub(super) fn check(&mut self) -> Result<()> {
        match &mut self.source {
            RuntimeSource::Native { current, stage } => current.check(stage),
            RuntimeSource::Ordinary => Ok(()),
            #[cfg(test)]
            RuntimeSource::Simulated(stage) => stage.check(),
        }
    }

    /// This does not mint a dispatch or publication permit. Existing durable
    /// CAS/selection/slot checks still own each transaction's actual authority.
    pub(super) fn commit(&mut self, tx: rusqlite::Transaction<'_>) -> Result<()> {
        let result = (|| {
            self.check()?;
            tx.commit()?;
            self.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(super) fn commit_write(
        &mut self,
        tx: crate::write_queue::WriteTransaction<'_>,
    ) -> Result<()> {
        let result = (|| {
            self.check()?;
            tx.commit()?;
            self.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(super) fn send<T>(&mut self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let result = (|| {
            self.check()?;
            let value = operation()?;
            self.check()?;
            Ok(value)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(super) fn refuse(&mut self) {
        #[cfg(test)]
        if let RuntimeSource::Simulated(stage) = &mut self.source
            && let RoleSource::Simulated(stage) = &mut stage.source
        {
            stage.refuse();
        }
        if let RuntimeSource::Native { current, .. } = &mut self.source {
            current.refuse();
        }
    }

    fn run<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.check()?;
        if let RuntimeSource::Native { current, stage } = &mut self.source {
            // SQLite open/recovery is an attempted effect too. No native file
            // access occurs before this real scope is armed.
            current.arm(stage)?;
        }
        let result = (|| {
            let value = operation(self)?;
            self.check()?;
            if let RuntimeSource::Native { current, stage } = &mut self.source {
                current.finish_known(stage)?;
            }
            self.check()?;
            Ok(value)
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }
}

pub(super) fn with_runtime_consumer<T>(
    runtime: &crate::store::Runtime,
    phase: RuntimePhase,
    operation: impl FnOnce(&mut RuntimeConsumer<'_, '_>) -> Result<T>,
) -> Result<T> {
    let purpose = match phase {
        RuntimePhase::Registration => {
            crate::security_epoch::serving::RuntimeServingUse::Registration
        }
        RuntimePhase::Read => crate::security_epoch::serving::RuntimeServingUse::Read,
        RuntimePhase::Refresh => crate::security_epoch::serving::RuntimeServingUse::Refresh,
        RuntimePhase::InitialStorage => {
            anyhow::bail!("native initial admission requires its dedicated factory")
        }
    };
    if !runtime.uses_native_storage() {
        #[cfg(test)]
        if let Some(scope) = fixtures::runtime_scope(runtime)? {
            return fixtures::with_app_role(&scope, phase, |stage| {
                RuntimeConsumer {
                    source: RuntimeSource::Simulated(stage),
                    runtime: Some(runtime),
                }
                .run(operation)
            });
        }
        return RuntimeConsumer {
            source: RuntimeSource::Ordinary,
            runtime: Some(runtime),
        }
        .run(operation);
    }
    let scope = OWNERS.with(|owners| {
        let owners = owners.try_borrow()?;
        Ok::<_, anyhow::Error>(
            owners
                .get(runtime.app())
                .context("native runtime executor missing")?
                .selection
                .scope()
                .clone(),
        )
    })?;
    with_app_participant(&scope, |participant, stage| {
        crate::security_epoch::serving::with_current_runtime_serving(
            participant,
            stage,
            purpose,
            |current, same| {
                RuntimeConsumer {
                    source: RuntimeSource::Native {
                        current,
                        stage: same,
                    },
                    runtime: Some(runtime),
                }
                .run(operation)
            },
        )
    })
}

/// Immutable Runtime/registry selection DATA, not current permission. A native
/// Runtime cannot downgrade to an unowned response when its supplier is absent.
pub(crate) fn runtime_response_scope(
    runtime: &crate::store::Runtime,
) -> Result<Option<AuthorityScope>> {
    if !runtime.uses_native_storage() {
        return Ok(None);
    }
    OWNERS.with(|owners| {
        let owners = owners.try_borrow()?;
        let owner = owners
            .get(runtime.app())
            .context("native runtime response executor missing")?;
        ensure!(
            owner.kind == NativeRole::AppHost,
            "native runtime response requires App owner"
        );
        Ok(Some(owner.selection.scope().clone()))
    })
}

fn with_runtime_response<T>(
    scope: &AuthorityScope,
    identity: &ResponseIdentity,
    complete: bool,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owner = owners
            .get_mut(scope.app.as_str())
            .context("native runtime response executor missing")?;
        ensure!(
            owner.kind == NativeRole::AppHost,
            "native runtime response requires App owner"
        );
        let AppStorage::Participant(participant) = &mut owner.storage else {
            anyhow::bail!("native runtime response participant unavailable")
        };
        // Pure exact-holder exclusion BEFORE touching the winner's role/clock.
        crate::security_epoch::serving::require_runtime_response(participant, scope, identity)?;
        participant.prepare_current()?;
        let mut role = owner.role.try_borrow_mut()?;
        let mut stage = role.begin_current_stage()?;
        stage.check_selection(&owner.selection.policy, &owner.selection.store, owner.kind)?;
        let purpose = if complete {
            crate::security_epoch::serving::RuntimeServingUse::ResponseComplete
        } else {
            crate::security_epoch::serving::RuntimeServingUse::Response
        };
        crate::security_epoch::serving::with_current_runtime_response(
            participant,
            &mut stage,
            scope,
            purpose,
            identity,
            |current, same| {
                let mut consumer = RuntimeConsumer {
                    source: RuntimeSource::Native {
                        current,
                        stage: same,
                    },
                    runtime: None,
                };
                consumer.run(|_| operation())
            },
        )
    })
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
        self.require_signature_intent(expected)?;
        self.check(role)
    }

    fn require_signature_intent(&self, expected: &FreshIntent) -> Result<()> {
        ensure!(
            self.phase == Phase::Signature && self.intent == expected,
            "native signature phase required"
        );
        Ok(())
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
/// settlement. Native construction additionally requires the sealed S3 serving
/// phase; the simulator can never construct that variant.
pub(crate) struct Consumer<'a, 'role, 'original> {
    source: ConsumerSource<'a, 'role>,
    original: &'a mut OriginalPhase<'original>,
    armed: &'a std::cell::Cell<bool>,
    finalized: bool,
}

enum ConsumerSource<'stage, 'role> {
    Native {
        stage: &'stage mut EnrolledRoleStage<'role>,
        current: &'stage mut dyn CurrentServingPhase,
    },
    #[cfg(test)]
    Simulated(&'stage mut fixtures::SimulationStage),
}

impl Consumer<'_, '_, '_> {
    /// A provider observation is consumed only inside the genuine Shell
    /// session/signature phase for this exact retained original. No simulator,
    /// serialized observation or registry DATA can supply native permission.
    pub(super) fn require_management_producer(&mut self, intent: &FreshIntent) -> Result<()> {
        intent.require_oauth_management()?;
        ensure!(
            self.original.intent == intent
                && matches!(self.original.phase, Phase::Session | Phase::Signature),
            "management producer original or consumer changed"
        );
        match &self.source {
            ConsumerSource::Native { .. } => self.check(),
            #[cfg(test)]
            ConsumerSource::Simulated(_) => {
                anyhow::bail!("native management producer supplier unavailable")
            }
        }
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        let result = match &mut self.source {
            ConsumerSource::Native { stage, current } => current
                .check(stage)
                .and_then(|()| self.original.check_with_native(stage, self.original.wall)),
            #[cfg(test)]
            ConsumerSource::Simulated(stage) => self
                .original
                .check_at(BorrowedRoleStage::Simulated(stage), self.original.wall),
        };
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn require_signature(&mut self, expected: &FreshIntent) -> Result<()> {
        self.original.require_signature_intent(expected)?;
        let result = self.prepare_finalization();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Enter only immediately before the actual mutation/disclosure. Pure
    /// input refusals remain known exclusions and cannot burn another human's
    /// valid original. Once armed, error/unwind is permanently unresolved.
    pub(crate) fn arm(&mut self) -> Result<()> {
        self.check()?;
        if self.armed.replace(true) {
            self.refuse();
            anyhow::bail!("native consumer attempt already armed");
        }
        let result = match &mut self.source {
            ConsumerSource::Native { stage, current } => current.arm(stage),
            #[cfg(test)]
            ConsumerSource::Simulated(_) => Ok(()),
        };
        if result.is_err() {
            self.refuse();
        }
        result?;
        self.check()
    }

    /// Hold the same borrow before COMMIT, through the actual SQLite result,
    /// and afterwards. An error (even after a possibly successful commit) never
    /// returns a dispatch permit or rearms the original.
    pub(crate) fn commit(&mut self, tx: rusqlite::Transaction<'_>) -> Result<()> {
        let result = (|| {
            self.prepare_finalization()?;
            tx.commit()?;
            self.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    pub(crate) fn commit_write(
        &mut self,
        tx: crate::write_queue::WriteTransaction<'_>,
    ) -> Result<()> {
        let result = (|| {
            self.prepare_finalization()?;
            tx.commit()?;
            self.check()
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    fn prepare_finalization(&mut self) -> Result<()> {
        ensure!(
            !self.finalized,
            "native consumer finalization already attempted"
        );
        if self.armed.get() {
            self.check()?;
        } else {
            self.arm()?;
        }
        // Close before the actual COMMIT/signature, including a lost result.
        self.finalized = true;
        Ok(())
    }

    pub(super) fn require_context(&mut self, intent: &FreshIntent, phase: Phase) -> Result<()> {
        ensure!(
            self.original.intent == intent && self.original.phase == phase,
            "native consumer original or phase changed"
        );
        self.check()
    }

    fn refuse(&mut self) {
        self.original.refuse();
        match &mut self.source {
            ConsumerSource::Native { current, .. } => current.refuse(),
            #[cfg(test)]
            ConsumerSource::Simulated(_) => {}
        }
    }

    fn run<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let mut excluded = false;
        // Catch only to record terminal disposition while the genuine S3
        // borrow is still held, then resume the ORIGINAL unwind. Never retry
        // or convert a panic into a success or a new native acquisition.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check()?;
            let output = operation(self);
            let checked = self.check();
            match output {
                Ok(output) => {
                    checked?;
                    match &mut self.source {
                        ConsumerSource::Native { current, stage } => {
                            current.finish_known(stage)?;
                            // finish_known has not released the owner scope. A
                            // later original failure still refuses that owner.
                            self.original.check_with_native(stage, self.original.wall)?;
                        }
                        #[cfg(test)]
                        ConsumerSource::Simulated(_) => {}
                    }
                    Ok(output)
                }
                Err(error) => {
                    if checked.is_err() {
                        // Preserve the original commit/send cause. The failed
                        // check has already refused both retained owners.
                        return Err(error
                            .context("consumer current check also refused after the operation"));
                    }
                    if !self.armed.get() {
                        match &mut self.source {
                            ConsumerSource::Native { current, .. } => current.finish_excluded()?,
                            #[cfg(test)]
                            ConsumerSource::Simulated(_) => {}
                        }
                        excluded = true;
                    }
                    Err(error)
                }
            }
        }));
        match result {
            Ok(result) => {
                if result.is_err() && !excluded {
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
}

// Terminal DATA lookup only: this can refuse an existing owner, never construct
// one or authorize an action. Kept OUTSIDE its registry borrow so unwinding can
// release the borrow before this guard records the unknown outcome.
struct ConsumerGuard {
    intent: FreshIntent,
    role: NativeRole,
    armed: std::cell::Cell<bool>,
    settled: bool,
    local: std::marker::PhantomData<Rc<()>>,
}

impl Drop for ConsumerGuard {
    fn drop(&mut self) {
        if self.armed.get() && !self.settled {
            let _ = refuse_original(&self.intent, self.role);
        }
    }
}

pub(crate) fn with_consumer<T>(
    intent: &FreshIntent,
    phase: Phase,
    wall: i64,
    operation: impl FnOnce(&mut Consumer<'_, '_, '_>) -> Result<T>,
) -> Result<T> {
    let role = match phase {
        Phase::Session | Phase::Signature | Phase::ShellAuthentication => NativeRole::SecurityShell,
        Phase::Pending
        | Phase::StartCommit
        | Phase::DispatchCommit
        | Phase::ProviderSend
        | Phase::FinishCommit
        | Phase::DisconnectCommit
        | Phase::Verification
        | Phase::Callback
        | Phase::Claim
        | Phase::Publication => NativeRole::AppHost,
        _ => anyhow::bail!("native consumer purpose unsupported"),
    };
    with_consumer_for_role(intent, phase, wall, role, None, operation)
}

fn serving_use(phase: Phase, role: NativeRole) -> Result<ServingUse> {
    Ok(match phase {
        Phase::Pending => ServingUse::Pending,
        Phase::Claim => ServingUse::Claim,
        Phase::Publication => ServingUse::Publication,
        Phase::StartCommit => ServingUse::StartCommit,
        Phase::DispatchCommit => ServingUse::DispatchCommit,
        Phase::ProviderSend => ServingUse::ProviderSend,
        Phase::FinishCommit => ServingUse::FinishCommit,
        Phase::DisconnectCommit => ServingUse::DisconnectCommit,
        Phase::Session => ServingUse::Session,
        Phase::Signature => ServingUse::Signature,
        Phase::ShellAuthentication => ServingUse::Authentication,
        Phase::Verification => ServingUse::Verification,
        Phase::Callback => ServingUse::Callback,
        Phase::Response => ServingUse::Response,
        Phase::ResponseComplete => match role {
            NativeRole::AppHost => ServingUse::AppResponseComplete,
            NativeRole::SecurityShell => ServingUse::ShellResponseComplete,
            _ => anyhow::bail!("native response completion role refused"),
        },
        _ => anyhow::bail!("native serving consumer purpose unsupported"),
    })
}

fn with_consumer_for_role<T>(
    intent: &FreshIntent,
    phase: Phase,
    wall: i64,
    role: NativeRole,
    response: Option<&ResponseIdentity>,
    operation: impl FnOnce(&mut Consumer<'_, '_, '_>) -> Result<T>,
) -> Result<T> {
    let purpose = serving_use(phase, role)?;
    let mut guard = ConsumerGuard {
        intent: intent.clone(),
        role,
        armed: std::cell::Cell::new(false),
        settled: false,
        local: std::marker::PhantomData,
    };
    let result = with_current_for_role(
        intent,
        phase,
        wall,
        Some(role),
        response,
        |role, original, participant| match &mut role.source {
            RoleSource::Native(stage) => crate::security_epoch::serving::with_current_serving(
                participant.context("native serving participant unavailable")?,
                stage,
                intent,
                purpose,
                response,
                |current, same_stage| {
                    Consumer {
                        source: ConsumerSource::Native {
                            stage: same_stage,
                            current,
                        },
                        original,
                        armed: &guard.armed,
                        finalized: false,
                    }
                    .run(operation)
                },
            ),
            #[cfg(test)]
            RoleSource::Simulated(stage) => Consumer {
                source: ConsumerSource::Simulated(stage),
                original,
                armed: &guard.armed,
                finalized: false,
            }
            .run(operation),
        },
    );
    guard.settled = result.is_ok();
    result
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
    with_current_for_role(intent, phase, wall, None, None, |role, original, _| {
        use_current(role, original)
    })
}

fn with_current_for_role<T>(
    intent: &FreshIntent,
    phase: Phase,
    wall: i64,
    expected: Option<NativeRole>,
    response: Option<&ResponseIdentity>,
    use_current: impl FnOnce(
        &mut RoleStage<'_>,
        &mut OriginalPhase<'_>,
        Option<&mut ServingParticipant>,
    ) -> Result<T>,
) -> Result<T> {
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::with_current(
            intent,
            phase,
            wall,
            expected,
            response,
            |role, original| use_current(role, original, None),
        );
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
            Phase::Pending
            | Phase::StartCommit
            | Phase::DispatchCommit
            | Phase::ProviderSend
            | Phase::FinishCommit
            | Phase::DisconnectCommit
            | Phase::Verification
            | Phase::Claim
            | Phase::Publication => ensure!(
                owners.kind == NativeRole::AppHost,
                "native phase requires App owner"
            ),
            Phase::Session | Phase::Signature | Phase::ShellFlow | Phase::ShellAuthentication => {
                ensure!(
                    owners.kind == NativeRole::SecurityShell,
                    "native phase requires Shell owner"
                )
            }
            _ => {}
        }
        let stored = owners
            .originals
            .get_mut(intent.attempt())
            .context("native original absent; rows cannot restore it")?;
        if let Some(identity) = response {
            stored.response.require_bound(intent, identity)?;
        } else {
            validate_enlist(owners.kind, intent, &stored.response)?;
        }
        if expected.is_some() {
            let AppStorage::Participant(participant) = &mut owners.storage else {
                anyhow::bail!("native serving participant unavailable");
            };
            participant.prepare_current()?;
        }
        let role = stored.original.clock.role.clone();
        let mut role = role.try_borrow_mut()?;
        let mut enrolled = role.begin_current_stage()?;
        enrolled.check_selection(
            &owners.selection.policy,
            &owners.selection.store,
            owners.kind,
        )?;
        let mut stage = RoleStage {
            source: RoleSource::Native(Box::new(enrolled)),
        };
        let mut original = OriginalPhase {
            original: PhaseOriginal::Native(&mut stored.original),
            intent,
            wall,
            phase,
        };
        original.check(&mut stage)?;
        if response.is_none() {
            enlist(
                owners.kind,
                intent,
                &mut stored.response,
                Some(&mut owners.storage),
            )?;
        }
        let participant = match &mut owners.storage {
            AppStorage::Participant(participant) => Some(participant.as_mut()),
            _ => None,
        };
        let value = use_current(&mut stage, &mut original, participant)?;
        let checked = stage.with_native(|enrolled| {
            enrolled.check_selection(
                &owners.selection.policy,
                &owners.selection.store,
                owners.kind,
            )
        });
        if let Err(error) = checked {
            original.refuse();
            owners.storage.refuse();
            return Err(error);
        }
        Ok(value)
    })
}

/// A connection-local list of DATA indexes, never a transferable permit. The
/// actual socket resolves them back to the retained executor owners on every
/// write/flush/shutdown. Disconnect drops this list, not the originals.
#[derive(Clone)]
pub(super) struct Sink {
    identity: ResponseIdentity,
    bindings: Rc<RefCell<BTreeMap<(NativeRole, String), SinkBinding>>>,
    state: Rc<std::cell::Cell<SinkState>>,
    runtime: Rc<RefCell<Option<RuntimeBinding>>>,
    prepared: Rc<std::cell::Cell<bool>>,
    finite_app_io: Rc<std::cell::Cell<bool>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkState {
    Open,
    Complete,
    Refused,
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

#[derive(Clone)]
struct RuntimeBinding {
    scope: AuthorityScope,
    effects: crate::managed_credentials::effects::Captured,
}

impl Sink {
    pub(super) fn new() -> Self {
        Self {
            identity: ResponseIdentity::new(),
            bindings: Rc::new(RefCell::new(BTreeMap::new())),
            state: Rc::new(std::cell::Cell::new(SinkState::Open)),
            runtime: Rc::new(RefCell::new(None)),
            prepared: Rc::new(std::cell::Cell::new(false)),
            finite_app_io: Rc::new(std::cell::Cell::new(false)),
        }
    }

    /// Called at response creation before Hyper can poll its headers/body.
    /// Human precedence selects the ACTUAL human helper, never an early bypass.
    pub(super) fn prepare_response(
        &self,
        scope: Option<AuthorityScope>,
        finite_app_candidate: bool,
    ) -> Result<()> {
        let result = self.prepare_response_inner(scope, finite_app_candidate);
        if result.is_ok() {
            self.prepared.set(true);
        }
        result
    }

    fn prepare_response_inner(
        &self,
        scope: Option<AuthorityScope>,
        finite_app_candidate: bool,
    ) -> Result<()> {
        // Scripted originals are DATA, never enrolled native role/storage
        // owners. Keep their existing per-poll model checks; they cannot enter
        // the driver that leases actual production owners.
        #[cfg(test)]
        let finite_app_candidate = finite_app_candidate && !fixtures::active();
        ensure!(
            self.state.get() == SinkState::Open,
            "native response sink closed"
        );
        if !self.bindings.try_borrow()?.is_empty() {
            ensure!(
                self.runtime.try_borrow()?.is_none(),
                "native response ownership cannot be reclassified"
            );
            if finite_app_candidate
                && self
                    .bindings
                    .try_borrow()?
                    .keys()
                    .all(|(role, _)| *role == NativeRole::AppHost)
            {
                // Classification/binding only. Fully preparing this bounded
                // body performs no transport I/O; the actual native scope is
                // acquired once by the driver immediately before disclosure.
                return response::require_finite_binding(self);
            }
            return self.with_current_result(Phase::Response, || Ok(()));
        }
        let Some(scope) = scope else { return Ok(()) };
        let mut binding = self.runtime.try_borrow_mut()?;
        if let Some(current) = binding.as_ref() {
            ensure!(
                current.scope == scope,
                "native runtime response scope changed"
            );
        }
        OWNERS.with(|owners| {
            let mut owners = owners.try_borrow_mut()?;
            let owner = owners
                .get_mut(scope.app.as_str())
                .context("native runtime response executor missing")?;
            ensure!(
                owner.kind == NativeRole::AppHost,
                "native runtime response requires App owner"
            );
            let AppStorage::Participant(participant) = &mut owner.storage else {
                anyhow::bail!("native runtime response participant unavailable")
            };
            crate::security_epoch::serving::bind_runtime_response(
                participant,
                &scope,
                &self.identity,
            )
        })?;
        if binding.is_none() {
            *binding = Some(RuntimeBinding {
                scope,
                effects: crate::managed_credentials::effects::capture(),
            });
        }
        Ok(())
    }

    pub(super) fn is_open(&self) -> bool {
        self.state.get() == SinkState::Open
    }

    pub(super) fn is_complete(&self) -> bool {
        self.state.get() == SinkState::Complete
    }

    /// Classification DATA only. Acquisition still resolves the same actual
    /// owner and exact response hold before any buffered byte reaches a socket.
    pub(super) fn can_retain_app_response(&self) -> Result<bool> {
        ensure!(
            self.is_open() && self.prepared.get(),
            "native response not prepared"
        );
        #[cfg(test)]
        if fixtures::active() {
            return Ok(false);
        }
        let bindings = self.bindings.try_borrow()?;
        ensure!(
            bindings.is_empty() || self.runtime.try_borrow()?.is_none(),
            "native response ownership conflict"
        );
        Ok(match bindings.keys().next() {
            Some((role, _)) => bindings.len() == 1 && *role == NativeRole::AppHost,
            None => self.runtime.try_borrow()?.is_some(),
        })
    }

    pub(super) fn retain_finite_app_io(&self) -> Result<()> {
        ensure!(
            self.can_retain_app_response()?,
            "native finite response requires App owner"
        );
        self.finite_app_io.set(true);
        Ok(())
    }

    pub(super) fn uses_retained_app_io(&self) -> bool {
        self.finite_app_io.get()
    }

    /// Metadata fixture only. There is NO native registry owner or response
    /// hold behind this value; the actual driver must refuse before socket I/O.
    #[cfg(test)]
    pub(super) fn fixture_unowned_app_response(scope: AuthorityScope) -> Self {
        let sink = Self::new();
        *sink.runtime.borrow_mut() = Some(RuntimeBinding {
            scope,
            effects: crate::managed_credentials::effects::capture(),
        });
        sink.prepared.set(true);
        sink
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
        self.with_current_result(Phase::Response, || Ok(operation()))
    }

    /// Only the actual successful HTTP connection completion calls this. Poll
    /// completion/partial progress never takes this terminal branch.
    pub(super) fn finish(&self) -> Result<()> {
        self.with_current_result(Phase::ResponseComplete, || Ok(()))?;
        for ((role, _), binding) in self.bindings.try_borrow()?.iter() {
            complete_response(&binding.intent, *role, &self.identity)?;
        }
        self.state.set(SinkState::Complete);
        Ok(())
    }

    fn with_current_result<T>(
        &self,
        phase: Phase,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        ensure!(
            self.state.get() == SinkState::Open,
            "native response outcome unknown or excluded"
        );
        let intents: Vec<_> = self
            .bindings
            .try_borrow()?
            .iter()
            .map(|((role, _), binding)| (*role, binding.clone()))
            .collect();
        match intents.as_slice() {
            [] => match self.runtime.try_borrow()?.clone() {
                Some(binding) => binding.effects.run(|| {
                    with_runtime_response(
                        &binding.scope,
                        &self.identity,
                        phase == Phase::ResponseComplete,
                        operation,
                    )
                }),
                None => operation(),
            },
            [(role, binding)] => binding.effects.clone().run(|| {
                ensure!(
                    self.runtime.try_borrow()?.is_none(),
                    "native response ownership conflict"
                );
                with_consumer_for_role(
                    &binding.intent,
                    phase,
                    super::effects::wall_time()?,
                    *role,
                    Some(&self.identity),
                    |consumer| {
                        consumer.arm()?;
                        operation()
                    },
                )
            }),
            _ => anyhow::bail!("native response must have exactly one original"),
        }
    }

    /// Retain uncertainty in each ORIGINAL owner, independently for App and
    /// Shell. Neither a handler/RPC success nor a later socket can erase it.
    pub(super) fn abort(&self) {
        if self.state.get() == SinkState::Complete {
            return;
        }
        self.state.set(SinkState::Refused);
        response::refuse_leased(self);
        let Ok(bindings) = self.bindings.try_borrow() else {
            return;
        };
        for ((role, _), binding) in bindings.iter() {
            // Terminal exclusion is not a new action. It must not depend on
            // acquiring a still-current stage or a successful clock read.
            let _ = binding
                .effects
                .clone()
                .run(|| -> Result<()> { refuse_response(&binding.intent, *role, &self.identity) });
        }
        if let Ok(binding) = self.runtime.try_borrow()
            && let Some(binding) = binding.as_ref()
        {
            let _ = binding.effects.clone().run(|| {
                OWNERS.with(|owners| {
                    let mut owners = owners.try_borrow_mut()?;
                    let owner = owners
                        .get_mut(binding.scope.app.as_str())
                        .context("native runtime terminal executor missing")?;
                    ensure!(
                        owner.kind == NativeRole::AppHost,
                        "native runtime terminal role changed"
                    );
                    let AppStorage::Participant(participant) = &mut owner.storage else {
                        anyhow::bail!("native runtime terminal participant unavailable")
                    };
                    crate::security_epoch::serving::refuse_runtime_response(
                        participant,
                        &binding.scope,
                        &self.identity,
                    )
                })
            });
        }
    }

    pub(super) fn poll_io<T>(
        &self,
        operation: impl FnOnce() -> Poll<std::io::Result<T>>,
    ) -> Poll<std::io::Result<T>> {
        match self.with_current_result(Phase::Response, || match operation() {
            Poll::Ready(Err(error)) => Err(error.into()),
            output => Ok(output),
        }) {
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
        let owners = owners
            .get_mut(intent.app())
            .context("native original executor missing")?;
        ensure!(owners.kind == kind, "native terminal owner changed");
        owners
            .originals
            .get_mut(intent.attempt())
            .context("native terminal original missing")?
            .original
            .refuse();
        Ok(())
    })
}

fn complete_response(
    intent: &FreshIntent,
    kind: NativeRole,
    identity: &ResponseIdentity,
) -> Result<()> {
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::complete_response(intent, kind, identity);
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners
            .get_mut(intent.app())
            .context("native response executor missing")?;
        ensure!(owners.kind == kind, "native response owner changed");
        let original = owners
            .originals
            .get_mut(intent.attempt())
            .context("native response original missing")?;
        original.response.require_bound(intent, identity)?;
        original.response.connection = None;
        Ok(())
    })
}

fn refuse_response(
    intent: &FreshIntent,
    kind: NativeRole,
    identity: &ResponseIdentity,
) -> Result<()> {
    #[cfg(test)]
    if fixtures::active() {
        return fixtures::refuse_response(intent, kind, identity);
    }
    OWNERS.with(|owners| {
        let mut owners = owners.try_borrow_mut()?;
        let owners = owners
            .get_mut(intent.app())
            .context("native response executor missing")?;
        ensure!(owners.kind == kind, "native response owner changed");
        let original = owners
            .originals
            .get_mut(intent.attempt())
            .context("native response original missing")?;
        original.response.require_bound(intent, identity)?;
        let AppStorage::Participant(participant) = &mut owners.storage else {
            anyhow::bail!("native response participant unavailable")
        };
        // Exact S3 hold first: a retired/losing sink cannot burn an original
        // after a different connection acquired this participant.
        crate::security_epoch::serving::refuse_current_serving(
            participant,
            intent,
            ServingUse::Response,
            identity,
        )?;
        original.original.refuse();
        Ok(())
    })
}

/// Reject a different connection before touching the paused owner's clock or
/// role. This only validates DATA; creation of an actual hold waits for the
/// current original check, before the protected callback or first I/O poll.
fn validate_enlist(
    role: NativeRole,
    intent: &FreshIntent,
    response: &ResponseBinding,
) -> Result<()> {
    ACTIVE_SINK.with(|slot| {
        if let Some(sink) = slot.try_borrow()?.as_ref() {
            ensure!(
                sink.state.get() == SinkState::Open,
                "native response sink closed"
            );
            let indexes = sink.bindings.try_borrow()?;
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
            }
            response.require(intent, &sink.identity)?;
        }
        Ok(())
    })
}

fn enlist(
    role: NativeRole,
    intent: &FreshIntent,
    response: &mut ResponseBinding,
    storage: Option<&mut AppStorage>,
) -> Result<()> {
    ACTIVE_SINK.with(|slot| {
        if let Some(sink) = slot.try_borrow()?.as_ref() {
            ensure!(
                sink.state.get() == SinkState::Open,
                "native response sink closed"
            );
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
            }
            response.require(intent, &sink.identity)?;
            if let Some(storage) = storage {
                let AppStorage::Participant(participant) = storage else {
                    anyhow::bail!("native response participant unavailable")
                };
                crate::security_epoch::serving::bind_response(participant, intent, &sink.identity)?;
            }
            response.connection = Some(sink.identity.clone());
            indexes.entry(key).or_insert_with(|| SinkBinding {
                intent: intent.clone(),
                effects: crate::managed_credentials::effects::capture(),
            });
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

    #[test]
    fn prerequisite_only_selection_cannot_capture_or_consume_an_original() -> Result<()> {
        let instance = super::super::clients::tests::security_instance("workspace", true)?;
        assert!(
            instance
                .apps
                .values()
                .any(|app| !app.oauth_connections.is_empty())
        );
        assert!(
            !instance
                .control
                .as_ref()
                .unwrap()
                .security_epochs
                .is_empty()
        );
        assert!(instance.native_bootstrap_for("workspace")?.is_none());
        assert!(selected_scopes(&instance, None)?.is_empty());
        assert!(selected_scopes(&instance, Some("workspace"))?.is_empty());
        assert!(instance.native_bootstrap_for("unknown").is_err());

        // Desired OAuth/epoch metadata is not a live native supplier. This
        // control deliberately installs no simulated or native role/owner.
        assert!(!simulation_installed());
        install(
            &selected_profiles(&instance, None)?,
            NativeRole::SecurityShell,
        )?;
        let intent = original_intent("prerequisite-only", 305)?;
        assert!(reserve_shell(&intent, 5).is_err());
        let entered = std::cell::Cell::new(false);
        assert!(
            with_consumer(&intent, Phase::Session, 5, |_| {
                entered.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!entered.get());
        Ok(())
    }

    #[test]
    fn active_app_storage_cannot_resolve_a_native_holder_from_simulated_roles() -> Result<()> {
        let world = super::super::simulation::World::new(451);
        super::super::effects::scope(world, || -> Result<()> {
            let scope = AuthorityScope {
                installation: "example".to_owned().try_into()?,
                environment: "development".to_owned().try_into()?,
                app: "reports".to_owned().try_into()?,
            };
            let entered = std::cell::Cell::new(false);
            let result = with_app_participant(&scope, |_, _| {
                entered.set(true);
                Ok(())
            });
            assert_eq!(
                result.unwrap_err().to_string(),
                "native App executor missing"
            );
            assert!(!entered.get());
            Ok(())
        })
    }

    #[test]
    fn native_runtime_metadata_and_scripted_role_cannot_supply_runtime_or_response_permission()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let (ordinary, _, _) =
            super::super::admission::tests::management_fixture(directory.path())?;
        let metadata_only = crate::store::Runtime::from_artifact_for_tests(
            ordinary.instance_path().to_owned(),
            ordinary.app().into(),
            std::path::PathBuf::from("/state/day2-native/day2-initial.sqlite"),
            ordinary.artifact().clone(),
        )?;
        assert!(metadata_only.uses_native_storage());
        assert!(!ordinary.uses_native_storage());
        let instance = crate::artifact::Instance::load(ordinary.instance_path())?;
        let scope = AuthorityScope {
            installation: instance.installation.try_into()?,
            environment: instance.environment.try_into()?,
            app: ordinary.app().to_owned().try_into()?,
        };
        let world = super::super::simulation::World::new(458);
        super::super::effects::scope(world, || -> Result<()> {
            fixtures::select_app_scope(&scope)?;
            for phase in [
                RuntimePhase::Registration,
                RuntimePhase::Read,
                RuntimePhase::Refresh,
            ] {
                let entered = std::cell::Cell::new(false);
                let error = with_runtime_consumer(&metadata_only, phase, |_| {
                    entered.set(true);
                    Ok(())
                })
                .unwrap_err();
                assert_eq!(error.to_string(), "native runtime executor missing");
                assert!(!entered.get());
            }
            assert!(runtime_response_scope(&metadata_only).is_err());
            let sink = Sink::new();
            assert!(sink.prepare_response(Some(scope.clone()), false).is_err());
            assert!(sink.runtime.borrow().is_none());
            assert!(sink.bindings.borrow().is_empty());
            with_runtime_consumer(&ordinary, RuntimePhase::Read, |current| {
                current.require_runtime(&ordinary)?;
                let other = ordinary.clone();
                assert!(current.require_runtime(&other).is_err());
                let mut db = rusqlite::Connection::open_in_memory()?;
                db.execute_batch("CREATE TABLE runtime_probe(value INTEGER)")?;
                let tx = db.transaction()?;
                tx.execute("INSERT INTO runtime_probe VALUES(1)", [])?;
                current.commit(tx)?;
                assert_eq!(
                    db.query_row("SELECT count(*) FROM runtime_probe", [], |r| r
                        .get::<_, i64>(0))?,
                    1
                );
                Ok(())
            })
        })
    }

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

    fn committed_management_intent() -> Result<(tempfile::TempDir, FreshIntent)> {
        use super::super::management::app::{Call, Manager, Reply};
        let directory = tempfile::tempdir()?;
        let (runtime, authority, _) =
            super::super::admission::tests::management_fixture(directory.path())?;
        let identity = crate::iap::Verified {
            email: "alice@example.com".into(),
            subject: "accounts.google.com:alice".into(),
        };
        let Reply::Pending { view } = Manager::new(runtime, authority).dispatch(
            Call::Capture {
                registration: "calendar".into(),
                operation: super::super::management::Action::Connect,
            },
            &identity,
            100,
        )?
        else {
            anyhow::bail!("management fixture did not commit Pending")
        };
        Ok((directory, FreshIntent::management(&view, &identity)?))
    }

    #[test]
    fn finite_human_app_preparation_is_pure_and_foreign_sink_cannot_burn_its_original() -> Result<()>
    {
        for finite in [false, true] {
            let world = super::super::simulation::World::new(if finite { 490 } else { 491 });
            world.advance(95);
            super::super::effects::scope(world, || -> Result<()> {
                let winner = Sink::new();
                let (_directory, intent) = winner.run(committed_management_intent)?;
                let before = fixtures::stage_entries();
                winner.prepare_response(None, finite)?;
                assert_eq!(
                    fixtures::stage_entries() - before,
                    u64::from(!finite),
                    "finite preparation does not create a second serving stage"
                );
                let loser = Sink::new();
                *loser.bindings.borrow_mut() = winner.bindings.borrow().clone();
                let before = fixtures::stage_entries();
                assert!(loser.prepare_response(None, true).is_err());
                assert_eq!(
                    fixtures::stage_entries(),
                    before,
                    "foreign identity fails before touching the winner's clock"
                );
                loser.abort();
                with_consumer_for_role(
                    &intent,
                    Phase::Response,
                    100,
                    NativeRole::AppHost,
                    Some(&winner.identity),
                    |consumer| consumer.arm(),
                )?;
                Ok(())
            })?;
        }
        Ok(())
    }

    #[test]
    fn consumer_cannot_commit_a_second_mutation_with_the_same_phase() -> Result<()> {
        let world = super::super::simulation::World::new(398);
        super::super::effects::scope(world, || -> Result<()> {
            let intent = original_intent("consumer-single-commit", 305)?;
            reserve_shell(&intent, 5)?;
            let mut db = rusqlite::Connection::open_in_memory()?;
            db.execute_batch("CREATE TABLE receipt(value INTEGER)")?;
            let result = with_consumer(&intent, Phase::Session, 5, |current| {
                current.arm()?;
                let first = db.transaction()?;
                first.execute("INSERT INTO receipt VALUES(1)", [])?;
                current.commit(first)?;
                let second = db.transaction()?;
                second.execute("INSERT INTO receipt VALUES(2)", [])?;
                assert!(current.commit(second).is_err());
                Ok(()) // Swallowing the refusal still cannot report success.
            });
            assert!(result.is_err());
            assert_eq!(
                db.query_row("SELECT sum(value) FROM receipt", [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
            assert!(with_consumer(&intent, Phase::Session, 5, |_| Ok(())).is_err());
            Ok(())
        })
    }

    #[test]
    fn consumer_pure_refusal_is_excluded_and_cannot_burn_a_valid_original() -> Result<()> {
        let world = super::super::simulation::World::new(399);
        super::super::effects::scope(world, || -> Result<()> {
            let intent = original_intent("consumer-input-exclusion", 305)?;
            reserve_shell(&intent, 5)?;
            let mut db = rusqlite::Connection::open_in_memory()?;
            db.execute_batch("CREATE TABLE receipt(value INTEGER)")?;
            let refused = with_consumer(&intent, Phase::Session, 5, |_| -> Result<()> {
                let tx = db.transaction()?;
                tx.execute("INSERT INTO receipt VALUES(1)", [])?;
                anyhow::bail!("controlled input refusal BEFORE COMMIT")
            });
            assert!(refused.is_err());
            assert_eq!(
                db.query_row("SELECT count(*) FROM receipt", [], |row| row
                    .get::<_, i64>(0))?,
                0
            );
            reserve_shell(&intent, 5)?;
            with_consumer(&intent, Phase::Session, 5, |current| {
                let tx = db.transaction()?;
                tx.execute("INSERT INTO receipt VALUES(1)", [])?;
                current.commit(tx)
            })?;
            assert_eq!(
                db.query_row("SELECT count(*) FROM receipt", [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
            Ok(())
        })
    }

    #[test]
    fn retained_pending_selection_cannot_sign_or_replace_a_current_original() -> Result<()> {
        let world = super::super::simulation::World::new(459);
        world.advance(95);
        super::super::effects::scope(world.clone(), || -> Result<()> {
            let (_directory, intent) = committed_management_intent()?;
            let identity = crate::iap::Verified {
                email: "alice@example.com".into(),
                subject: "accounts.google.com:alice".into(),
            };
            let foreign = crate::iap::Verified {
                email: identity.email.clone(),
                subject: "accounts.google.com:other".into(),
            };
            assert!(pending_intent(intent.app(), intent.attempt(), &foreign).is_err());
            assert!(pending_intent("other_app", intent.attempt(), &identity).is_err());
            assert!(pending_intent(intent.app(), "unknown", &identity).is_err());
            assert!(pending_intent(intent.app(), intent.attempt(), &identity)? == intent);
            with_consumer(&intent, Phase::Pending, 100, |current| {
                assert!(current.require_signature(&intent).is_err());
                assert!(current.require_management_producer(&intent).is_err());
                current.arm()?;
                current.check()
            })?;
            world.advance(301);
            // A retained DATA selection still exists, but cannot renew time or
            // turn an expired original into a currently authorized read.
            let retained = pending_intent(intent.app(), intent.attempt(), &identity)?;
            let entered = std::cell::Cell::new(false);
            assert!(
                with_consumer(&retained, Phase::Pending, 100, |_| {
                    entered.set(true);
                    Ok(())
                })
                .is_err()
            );
            assert!(!entered.get());
            Ok(())
        })
    }

    #[test]
    fn prearmed_signature_can_finalize_once_and_duplicate_refusal_cannot_be_swallowed() -> Result<()>
    {
        let world = super::super::simulation::World::new(462);
        world.advance(95);
        super::super::effects::scope(world, || -> Result<()> {
            let (_directory, intent) = committed_management_intent()?;
            reserve_shell(&intent, 100)?;
            let result = with_consumer(&intent, Phase::Signature, 100, |current| {
                current.arm()?;
                current.require_signature(&intent)?;
                assert!(current.require_signature(&intent).is_err());
                Ok(())
            });
            assert!(result.is_err());
            let entered = std::cell::Cell::new(false);
            assert!(
                with_consumer(&intent, Phase::Signature, 100, |_| {
                    entered.set(true);
                    Ok(())
                })
                .is_err()
            );
            assert!(!entered.get());
            Ok(())
        })
    }

    #[test]
    fn simulated_original_and_serving_phase_cannot_supply_the_native_management_producer()
    -> Result<()> {
        let world = super::super::simulation::World::new(454);
        world.advance(95);
        super::super::effects::scope(world, || -> Result<()> {
            let (_directory, intent) = committed_management_intent()?;
            reserve_shell(&intent, 100)?;
            let error = with_consumer(&intent, Phase::Session, 100, |current| {
                current.require_management_producer(&intent)
            })
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "native management producer supplier unavailable"
            );
            // This known exclusion made no native action and cannot burn an
            // unrelated valid simulated operation or turn into native material.
            with_consumer(&intent, Phase::Session, 100, |current| current.check())
        })
    }

    #[test]
    fn shell_original_cannot_claim_or_publish_an_app_original() -> Result<()> {
        let world = super::super::simulation::World::new(455);
        super::super::effects::scope(world, || -> Result<()> {
            let intent = original_intent("wrong-role-app-original", 305)?;
            reserve_shell(&intent, 5)?;
            for phase in [Phase::Pending, Phase::Claim, Phase::Publication] {
                let entered = std::cell::Cell::new(false);
                assert!(
                    with_consumer(&intent, phase, 5, |_| {
                        entered.set(true);
                        Ok(())
                    })
                    .is_err()
                );
                assert!(!entered.get());
            }
            with_consumer(&intent, Phase::Session, 5, |_| Ok(()))
        })
    }

    #[test]
    fn provider_authentication_scope_cannot_become_a_session_or_signature() -> Result<()> {
        let world = super::super::simulation::World::new(457);
        world.advance(95);
        super::super::effects::scope(world, || -> Result<()> {
            let (_directory, intent) = committed_management_intent()?;
            reserve_shell(&intent, 100)?;
            assert!(
                with_consumer(&intent, Phase::ShellAuthentication, 100, |current| {
                    current.require_management_producer(&intent)
                })
                .is_err()
            );
            assert!(
                with_consumer(&intent, Phase::ShellAuthentication, 100, |current| {
                    current.require_signature(&intent)
                })
                .is_err()
            );
            with_consumer(&intent, Phase::ShellAuthentication, 100, |current| {
                current.check()
            })
        })
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
    fn consumer_completed_socket_cannot_send_or_complete_again() -> Result<()> {
        let world = super::super::simulation::World::new(431);
        super::super::effects::scope(world, || -> Result<()> {
            let intent = original_intent("consumer-body-completed", 305)?;
            let sink = Sink::new();
            sink.run(|| reserve_shell(&intent, 5))?;
            assert!(matches!(
                sink.poll_io(|| Poll::Ready(Ok(3))),
                Poll::Ready(Ok(3))
            ));
            sink.finish()?;
            let mut wrote_again = false;
            assert!(matches!(
                sink.poll_io(|| {
                    wrote_again = true;
                    Poll::Ready(Ok(1))
                }),
                Poll::Ready(Err(_))
            ));
            assert!(!wrote_again);
            assert!(sink.finish().is_err());
            sink.abort(); // Late cleanup cannot turn known completion into a regrant.
            with_consumer(&intent, Phase::Session, 5, |_| Ok(()))?;
            Ok(())
        })
    }

    #[test]
    fn response_loser_and_retired_identity_cannot_refuse_a_paused_winner() -> Result<()> {
        let world = super::super::simulation::World::new(452);
        super::super::effects::scope(world, || -> Result<()> {
            let intent = original_intent("response-paused-winner", 305)?;
            let winner = Sink::new();
            winner.run(|| reserve_shell(&intent, 5))?;
            let loser = Sink::new();
            assert!(loser.run(|| reserve_shell(&intent, 5)).is_err());
            let entered = std::cell::Cell::new(false);
            assert!(
                with_consumer_for_role(
                    &intent,
                    Phase::ResponseComplete,
                    5,
                    NativeRole::SecurityShell,
                    Some(&loser.identity),
                    |_| {
                        entered.set(true);
                        Ok(())
                    }
                )
                .is_err()
            );
            assert!(!entered.get());
            assert!(refuse_response(&intent, NativeRole::SecurityShell, &loser.identity).is_err());
            loser.abort();
            assert!(
                winner
                    .clone()
                    .poll_io::<usize>(|| Poll::Pending)
                    .is_pending()
            );
            winner.finish()?;
            let replacement = Sink::new();
            replacement.run(|| reserve_shell(&intent, 5))?;
            assert!(refuse_response(&intent, NativeRole::SecurityShell, &winner.identity).is_err());
            winner.abort();
            assert!(matches!(
                replacement.poll_io(|| Poll::Ready(Ok(7))),
                Poll::Ready(Ok(7))
            ));
            replacement.finish()?;
            with_consumer(&intent, Phase::Session, 5, |_| Ok(()))
        })
    }

    #[test]
    fn pre_poll_owner_abort_is_terminal_without_a_clock_or_new_native_stage() -> Result<()> {
        let world = super::super::simulation::World::new(453);
        super::super::effects::scope(world.clone(), || -> Result<()> {
            let intent = original_intent("response-before-poll-abort", 305)?;
            let winner = Sink::new();
            winner.run(|| reserve_shell(&intent, 5))?;
            world.advance(301);
            refuse_response(&intent, NativeRole::SecurityShell, &winner.identity)?;
            winner.abort();
            let replacement = Sink::new();
            assert!(replacement.run(|| reserve_shell(&intent, 306)).is_err());
            let entered = std::cell::Cell::new(false);
            assert!(
                with_consumer(&intent, Phase::Session, 306, |_| {
                    entered.set(true);
                    Ok(())
                })
                .is_err()
            );
            assert!(!entered.get());
            Ok(())
        })
    }

    #[test]
    fn expired_unbound_request_cannot_acquire_a_response_hold() -> Result<()> {
        let world = super::super::simulation::World::new(456);
        super::super::effects::scope(world.clone(), || -> Result<()> {
            let intent = original_intent("expired-before-response-bind", 6)?;
            reserve_shell(&intent, 5)?;
            world.advance(1);
            let sink = Sink::new();
            assert!(sink.run(|| reserve_shell(&intent, 6)).is_err());
            assert!(sink.bindings.borrow().is_empty());
            // A literal empty refusal may complete; it neither carries the
            // expired original nor restores a protected consumer permission.
            sink.with_current(|| ())?;
            sink.finish()?;
            assert!(with_consumer(&intent, Phase::Session, 6, |_| Ok(())).is_err());
            Ok(())
        })
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
        static STAGE_ENTRIES: Cell<u64> = const { Cell::new(0) };
        static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
        // Scope switches/polls do not recreate a simulated process. Retained
        // entries use weak suppliers, are pruned when a world ends, and cannot
        // move across OS threads. Explicit restart discards native ownership.
        static RETAINED: RefCell<BTreeMap<u64, Fixture>> = const { RefCell::new(BTreeMap::new()) };
    }

    pub(super) fn stage_entries() -> u64 {
        STAGE_ENTRIES.with(Cell::get)
    }

    /// Exact response matching DATA only; never a native/current-stage factory.
    pub(super) fn require_response(
        intent: &FreshIntent,
        role: NativeRole,
        identity: &ResponseIdentity,
    ) -> Result<()> {
        FIXTURE.with(|slot| {
            let slot = slot.try_borrow()?;
            let fixture = slot
                .as_ref()
                .context("native simulation supplier missing")?;
            fixture
                .originals
                .get(&(role, intent.attempt().into()))
                .context("fixture original absent")?
                .response
                .require_bound(intent, identity)
        })
    }
    struct Fixture {
        hooks: std::sync::Weak<dyn Hooks>,
        domain: u64,
        originals: BTreeMap<(NativeRole, String), StoredOriginal<SimulationClock>>,
        scopes: BTreeMap<String, AuthorityScope>,
        roles: BTreeMap<(NativeRole, String), Rc<Cell<bool>>>,
    }
    pub(super) struct SimulationClock {
        hooks: std::sync::Weak<dyn Hooks>,
        origin: Duration,
        latest: Duration,
        owner_refused: Rc<Cell<bool>>,
        role: NativeRole,
        scope: Option<AuthorityScope>,
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
        pub(super) fn refuse(&mut self) {
            self.refused = true;
            self.owner_refused.set(true);
        }

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
                ensure!(
                    !self.refused
                        && !self.owner_refused.get()
                        && super::super::effects::current_domain() == Some(self.hooks.domain())
                        && self.thread == std::thread::current().id(),
                    "simulated native owner or executor changed"
                );
                self.hooks.native_check(self.role, self.scope.as_ref())?;
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
            if let Err(error) = hooks.native_check(self.role, self.scope.as_ref()) {
                self.owner_refused.set(true);
                return Err(error);
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
            role,
            scope: fixture.scopes.get(app).cloned(),
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
                pending: PendingCaptureState::Captured,
            }))
        })
    }

    pub(super) fn with_pending<T>(
        original: &mut Original<SimulationClock>,
        operation: impl FnOnce(&mut PendingWriter<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        let hooks = original
            .clock
            .hooks
            .upgrade()
            .context("fixture Pending supplier ended")?;
        let origin = hooks.monotonic();
        let stage = SimulationStage {
            hooks,
            origin,
            latest: origin,
            thread: std::thread::current().id(),
            refused: false,
            role: NativeRole::AppHost,
            scope: original.clock.scope.clone(),
            owner_refused: original.clock.owner_refused.clone(),
        };
        PendingWriter {
            source: PendingSource::Simulated { original, stage },
            committed: false,
        }
        .run(operation)
    }
    pub(super) fn bind_app(
        intent: &FreshIntent,
        original: Original<SimulationClock>,
    ) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let fixture = slot.as_mut().context("fixture executor missing")?;
            let key = (NativeRole::AppHost, intent.attempt().into());
            ensure!(
                !fixture.originals.contains_key(&key),
                "fixture original replaced"
            );
            fixture
                .originals
                .insert(key, StoredOriginal::new(original, intent));
            enlist(
                NativeRole::AppHost,
                intent,
                &mut fixture
                    .originals
                    .get_mut(&(NativeRole::AppHost, intent.attempt().into()))
                    .unwrap()
                    .response,
                None,
            )
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
                validate_enlist(NativeRole::SecurityShell, intent, &original.response)?;
                original.original.check(intent, wall)?;
                enlist(
                    NativeRole::SecurityShell,
                    intent,
                    &mut original.response,
                    None,
                )?;
            } else {
                ensure!(
                    fixture.originals.len() < 1024,
                    "fixture native original capacity"
                );
                let mut original = capture(fixture, NativeRole::SecurityShell, intent.app())?;
                original.bind(intent, wall)?;
                fixture
                    .originals
                    .insert(key.clone(), StoredOriginal::new(original, intent));
                enlist(
                    NativeRole::SecurityShell,
                    intent,
                    &mut fixture.originals.get_mut(&key).unwrap().response,
                    None,
                )?;
            }
            Ok(true)
        })
    }
    pub(super) fn active() -> bool {
        FIXTURE.with(|slot| slot.try_borrow().map_or(true, |fixture| fixture.is_some()))
    }

    pub(super) fn pending_intent(
        app: &str,
        attempt: &str,
        identity: &crate::iap::Verified,
    ) -> Result<FreshIntent> {
        FIXTURE.with(|slot| {
            let slot = slot.try_borrow()?;
            let original = slot
                .as_ref()
                .context("native simulation supplier missing")?
                .originals
                .get(&(NativeRole::AppHost, attempt.into()))
                .context("native Pending original absent; rows cannot restore it")?;
            selected_pending_intent(&original.response.intent, app, attempt, identity)
        })
    }

    pub(super) fn refuse_original(intent: &FreshIntent, kind: NativeRole) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            slot.as_mut()
                .context("fixture executor missing")?
                .originals
                .get_mut(&(kind, intent.attempt().into()))
                .context("fixture original missing")?
                .original
                .refuse();
            Ok(())
        })
    }

    pub(super) fn complete_response(
        intent: &FreshIntent,
        kind: NativeRole,
        identity: &ResponseIdentity,
    ) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let original = slot
                .as_mut()
                .context("fixture executor missing")?
                .originals
                .get_mut(&(kind, intent.attempt().into()))
                .context("fixture original missing")?;
            original.response.require_bound(intent, identity)?;
            original.response.connection = None;
            Ok(())
        })
    }

    pub(super) fn refuse_response(
        intent: &FreshIntent,
        kind: NativeRole,
        identity: &ResponseIdentity,
    ) -> Result<()> {
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let original = slot
                .as_mut()
                .context("fixture executor missing")?
                .originals
                .get_mut(&(kind, intent.attempt().into()))
                .context("fixture original missing")?;
            original.response.require_bound(intent, identity)?;
            original.original.refuse();
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

    /// Complete allowlisted simulator owner DATA, never a native owner factory.
    pub(crate) fn observation() -> Result<serde_json::Value> {
        FIXTURE.with(|slot| {
            let slot = slot.try_borrow()?;
            let fixture = slot.as_ref().context("native fixture observation absent")?;
            let originals = fixture.originals.iter().map(|((role, attempt), stored)| {
                Ok::<_, anyhow::Error>(serde_json::json!({"role":role,"attempt":attempt,
                    "intent":stored.response.intent.commitment()?,"scope":stored.original.clock.scope,
                    "clock":{"origin":stored.original.clock.origin,"latest":stored.original.clock.latest,
                        "supplier_alive":stored.original.clock.hooks.strong_count() > 0},
                    "original":stored.original.observation(),"role_refused":stored.original.clock.owner_refused.get(),
                    "response_bound":stored.response.connection.is_some()}))
            }).collect::<Result<Vec<_>>>()?;
            let roles = fixture.roles.iter().map(|((role, app), refused)| {
                serde_json::json!({"role":role,"app":app,"refused":refused.get()})
            }).collect::<Vec<_>>();
            Ok(serde_json::json!({"scopes":fixture.scopes,"roles":roles,"originals":originals,
                "selected_domain":super::super::effects::current_domain() == Some(fixture.domain)}))
        })
    }

    pub(super) fn runtime_scope(runtime: &crate::store::Runtime) -> Result<Option<AuthorityScope>> {
        FIXTURE.with(|slot| {
            let slot = slot.try_borrow()?;
            let Some(fixture) = slot.as_ref() else {
                return Ok(None);
            };
            let hooks = fixture
                .hooks
                .upgrade()
                .context("native simulation supplier ended")?;
            if !hooks.simulate_runtime_owner() {
                return Ok(None);
            }
            let selected = fixture
                .scopes
                .get(runtime.app())
                .context("simulated runtime scope missing")?;
            ensure!(
                runtime.scope()
                    == format!(
                        "{}/{}/{}",
                        selected.installation.as_str(),
                        selected.environment.as_str(),
                        selected.app.as_str()
                    ),
                "simulated runtime namespace changed"
            );
            Ok(Some(selected.clone()))
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
        response: Option<&ResponseIdentity>,
        use_current: impl FnOnce(&mut RoleStage<'_>, &mut OriginalPhase<'_>) -> Result<T>,
    ) -> Result<T> {
        STAGE_ENTRIES.with(|entries| {
            entries.set(
                entries
                    .get()
                    .checked_add(1)
                    .expect("fixture stage counter overflow"),
            )
        });
        FIXTURE.with(|slot| {
            let mut slot = slot.try_borrow_mut()?;
            let fixture = slot
                .as_mut()
                .context("native simulation supplier missing")?;
            let kind = expected.unwrap_or_else(|| match phase {
                Phase::ShellFlow
                | Phase::Session
                | Phase::Signature
                | Phase::ShellAuthentication => NativeRole::SecurityShell,
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
                .original
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
            let stored = fixture
                .originals
                .get_mut(&(kind, intent.attempt().into()))
                .context("fixture original absent; SQL cannot restore it")?;
            if let Some(identity) = response {
                stored.response.require_bound(intent, identity)?;
            } else {
                validate_enlist(kind, intent, &stored.response)?;
            }
            let mut original = OriginalPhase {
                original: PhaseOriginal::Simulated(&mut stored.original),
                intent,
                wall,
                phase,
            };
            original.check(&mut stage)?;
            if response.is_none() {
                enlist(kind, intent, &mut stored.response, None)?;
            }
            use_current(&mut stage, &mut original)
        })
    }
}
