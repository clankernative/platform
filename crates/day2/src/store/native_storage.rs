//! Native-only existing-file Runtime admission under its actual serving scope.
//! This never initializes, creates, adopts or migrates an installation.
use super::{InitialStoreMetadata, Runtime, check_storage_binding, configure_connection};
use crate::oauth::native_management::SqlOwner;
use crate::security_epoch::{native_enrollment::EnrolledRoleStage, serving::CurrentServingPhase};
use anyhow::{Context, Result, ensure};
use rusqlite::{
    Connection, OpenFlags,
    hooks::{AuthAction, AuthContext, Authorization, TransactionOperation},
};
use std::{
    cell::RefCell,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

const DATABASE: &str = "/state/day2-native/day2-initial.sqlite";
const NATIVE_DIRECTORY: &str = "/state/day2-native";

/// Selected location DATA, constructed only inside this fixed owning child.
/// It does not contain a keeper or grant Current/SQL authority. Every open
/// still requires the actual SqlOwner and its original/physical postchecks.
#[derive(Clone)]
pub(super) struct NativeDatabaseSelection {
    path: PathBuf,
}

impl NativeDatabaseSelection {
    #[cfg(test)]
    pub(super) fn metadata_fixture(path: PathBuf) -> Self {
        Self { path }
    }

    fn require_path(&self, selected: &Path) -> Result<&Path> {
        ensure!(
            self.path == selected,
            "native_runtime_database_selection_changed"
        );
        Ok(&self.path)
    }
}

mod authentication_store;
pub(crate) use authentication_store::{check_authentication_sqlite, open_authentication_sqlite};
mod controller_admins;
mod keeper;
pub(crate) use controller_admins::check_controller_sqlite_files;
pub(crate) use controller_admins::check_controller_sqlite_opened_files;
pub(crate) use controller_admins::{ControllerAdminData, ControllerAdminSqlite};
mod opened_files;
pub(crate) use keeper::require_unopened as require_unopened_native_sqlite;

/// Actual first SQLite connection, retained by the genuine App file owner.
/// The handles are resources, not a native permission or immutable-content proof.
/// Only load_native_storage constructs this resource, before any SQL activation.
pub(crate) struct NativeSqliteKeeper {
    connection: Connection,
    layout: SqliteKeeperLayout,
    files: Option<opened_files::Handles>,
    refused: bool,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// Fixed mechanical filenames only. This DATA cannot construct an App,
/// keeper, native file, writer or restore activation. Native factories choose
/// their own layout; no operator path or flag supplies it.
#[derive(Clone, Copy)]
pub(crate) enum SqliteKeeperLayout {
    Initial,
    Restored,
}

impl NativeSqliteKeeper {
    /// Fixed existing-only birth under the actual nonescaping App loan. The
    /// first connection is owned before ANY configuration/schema/WAL work.
    pub(crate) fn create_restored(
        birth: &mut crate::security_epoch::native_enrollment::RestoredKeeperBirth<'_>,
        path: &Path,
        artifact: &crate::artifact::LoadedArtifact,
        scope: &str,
    ) -> Result<Self> {
        birth.before_open(path, artifact, scope)?;
        let mut keeper = Self {
            connection: open_existing(path)?,
            layout: SqliteKeeperLayout::Restored,
            files: None,
            refused: false,
            local: std::marker::PhantomData,
        };
        birth.require_opened(&keeper.connection)?;
        let configured = configure_connection(&mut keeper.connection);
        let checked = birth.check_database(&keeper.connection);
        configured?;
        checked?;
        birth.admit_database(&mut keeper.connection)?;
        // Every validation SQL unit is closed before this provider read.
        // No business transaction spans provider work or future transport.
        birth.reobserve_database(&keeper.connection)?;
        let wal = keeper.connection.pragma_update(None, "journal_mode", "WAL");
        let checked = birth.check_database(&keeper.connection);
        wal?;
        checked?;
        let captured = keeper.capture_created_files();
        let checked = birth.check_database(&keeper.connection);
        captured?;
        checked?;
        birth.reobserve_database(&keeper.connection)?;
        birth.require_keeper(&mut keeper)?;
        Ok(keeper)
    }
}

/// Existing validators only. This never initializes or repairs schema, and
/// desired private OAuth units come from the ACTUAL authenticated Instance
/// binding, never from declaration inference or a caller boolean.
pub(crate) fn admit_restored_snapshot(
    connection: &mut Connection,
    artifact: &crate::artifact::LoadedArtifact,
    scope: &str,
    instance: &crate::artifact::Instance,
    app: &str,
) -> Result<()> {
    ensure!(
        connection.is_autocommit(),
        "restore_keeper_sql_unit_still_open"
    );
    super::validate_storage_snapshot(connection, artifact, scope)?;
    let active = crate::authority_state::current(connection)?;
    ensure!(
        active.artifact_id == artifact.id(),
        "restore_keeper_authority_artifact_changed"
    );
    active.document.validate(artifact)?;
    if let Some(requirements) = &active.document.security {
        requirements.validate(artifact)?;
        requirements.require_runtime()?;
    }
    let binding = instance
        .apps
        .get(app)
        .context("restore_keeper_app_missing")?;
    if !binding.oauth_connections.is_empty() {
        require_existing_oauth_schema(connection)?;
    }
    ensure!(
        connection.is_autocommit(),
        "restore_keeper_sql_unit_still_open"
    );
    Ok(())
}

impl Runtime {
    /// Build Runtime metadata for the SAME restored keeper. The borrow is
    /// genuine and opaque, and no SQLite open, initializer, repair or serving
    /// completion occurs. Its result stays private in the pending installation.
    pub(crate) fn load_restored_storage(
        birth: &mut crate::security_epoch::native_enrollment::RestoredRuntimeBirth<'_>,
    ) -> Result<Self> {
        birth.check()?;
        let requested = (|| {
            let (path, selector, db, app, scope, artifact, desired) =
                birth.runtime_inputs_data()?;
            let metadata =
                InitialStoreMetadata::admit(path, selector, &app, desired.clone(), artifact)?;
            ensure!(metadata.scope == scope, "restore_runtime_scope_changed");
            let integrations = Arc::new(crate::integration_host::Host::local(
                &metadata.instance_path,
            )?);
            let inputs = crate::host_inputs::Inputs::default();
            Ok(Self {
                integrations,
                app_calls: None,
                credentials: None,
                connections: None,
                rolling: false,
                scope,
                hosted_domain: desired.hosted_domain().map(str::to_owned),
                instance_path: metadata.instance_path,
                restore_registry_selector: Some(metadata.instance_selector),
                app,
                db: db.clone(),
                native_database: Some(NativeDatabaseSelection { path: db }),
                artifact: Arc::new(metadata.artifact),
                host: Arc::new(crate::host::System(inputs.clone())),
                inputs,
            })
        })();
        // Even failed metadata construction takes a fresh writer read and
        // full native/keeper posts before the Runtime enters Pending. The first
        // connection is autocommit and never replaced or reopened here.
        let checked = birth.reobserve();
        if requested.is_err() || checked.is_err() {
            birth.refuse();
        }
        let runtime = requested?;
        checked?;
        Ok(runtime)
    }

    /// The sealed native scope is retained before SQLite open/recovery and
    /// through the actual result and physical/provider postchecks. No pathname
    /// argument, CREATE flag, initializer or activated-path fallback exists.
    pub(crate) fn load_native_storage(
        metadata: InitialStoreMetadata,
        current: &mut dyn CurrentServingPhase,
        stage: &mut EnrolledRoleStage<'_>,
    ) -> Result<Self> {
        let result = (|| {
            current.check_runtime_selection(stage, &metadata)?;
            // SQLite open can recover a journal; arm BEFORE any such attempt.
            current.arm(stage)?;
            current.begin_runtime_database(stage, &metadata)?;
            // Own the FIRST connection before configuration, recovery, schema
            // inspection or WAL activation. It is never closed and readopted.
            let mut keeper = NativeSqliteKeeper {
                connection: open_existing(Path::new(DATABASE))?,
                layout: SqliteKeeperLayout::Initial,
                files: None,
                refused: false,
                local: std::marker::PhantomData,
            };
            let connection = &mut keeper.connection;
            current.check_runtime_opened_database(stage, connection)?;
            configure_connection(connection)?;
            current.admit_runtime_database(stage, &metadata, connection)?;
            check_storage_binding(connection, &metadata.artifact, &metadata.scope)?;
            let active = crate::authority_state::current(connection)?;
            ensure!(
                active.artifact_id == metadata.artifact.id(),
                "native_runtime_activated_artifact_changed"
            );
            active.document.validate(&metadata.artifact)?;
            if let Some(requirements) = &active.document.security {
                requirements.validate(&metadata.artifact)?;
                requirements.require_runtime()?;
            }
            let desired = crate::artifact::Instance::load(&metadata.instance_path)?;
            current.check_runtime_selection(stage, &metadata)?;
            if !desired
                .apps
                .get(&metadata.app)
                .ok_or_else(|| anyhow::anyhow!("native_runtime_app_missing"))?
                .oauth_connections
                .is_empty()
            {
                require_existing_oauth_schema(connection)?;
            }
            // Recheck the retained original schema/seed after the bounded,
            // read-only admission; there is no initializer or repair fallback.
            current.admit_runtime_database(stage, &metadata, connection)?;
            connection.pragma_update(None, "journal_mode", "WAL")?;
            current.admit_runtime_database(stage, &metadata, connection)?;
            keeper.capture_created_files()?;
            current.check(stage)?;
            let desired = crate::artifact::Instance::load(&metadata.instance_path)?;
            current.check_runtime_selection(stage, &metadata)?;
            let inputs = crate::host_inputs::Inputs::default();
            let integrations = Arc::new(crate::integration_host::Host::local(
                &metadata.instance_path,
            )?);
            current.check_runtime_selection(stage, &metadata)?;
            let runtime = Self {
                integrations,
                app_calls: None,
                credentials: None,
                connections: None,
                rolling: false,
                scope: metadata.scope,
                hosted_domain: desired.hosted_domain().map(str::to_owned),
                instance_path: metadata.instance_path,
                restore_registry_selector: Some(metadata.instance_selector),
                app: metadata.app,
                db: PathBuf::from(DATABASE),
                native_database: Some(NativeDatabaseSelection {
                    path: PathBuf::from(DATABASE),
                }),
                artifact: Arc::new(metadata.artifact),
                host: Arc::new(crate::host::System(inputs.clone())),
                inputs,
            };
            // Move the same live connection/cohort into the same App file
            // continuation before recording a known load or publishing Runtime.
            current.retain_runtime_database(stage, keeper)?;
            current.check(stage)?;
            current.finish_known(stage)?;
            Ok(runtime)
        })();
        if result.is_err() {
            current.refuse();
        }
        result
    }
}

/// The authoritative current-schema validators run on the owned connection
/// with SQLite writes disabled. Their absent-unit branch therefore refuses
/// before any DDL/DML; it cannot create, repair or restamp native state. The
/// existing permanent runtime hook and cumulative admission budget are retained.
fn require_existing_oauth_schema(db: &Connection) -> Result<()> {
    ensure!(
        !db.pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))?,
        "native_runtime_unexpected_connection_mode"
    );
    db.pragma_update(None, "query_only", true)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::oauth::schema::admit_with_runtime_hook(db, crate::oauth::connect::install_schema)
    }));
    let restored = db.pragma_update(None, "query_only", false);
    match result {
        Ok(result) => {
            restored?;
            result
        }
        Err(payload) => {
            let _ = restored;
            std::panic::resume_unwind(payload)
        }
    }
}

// Lower SQLite adapter only. Production passes the fixed native leaf above;
// the native scope, selection and postchecks remain mandatory at its caller.
fn open_existing(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

// Adapter selection DATA only: the fixed Runtime constructor and actual
// retained native scope remain mandatory. No permission is derived from this.
pub(super) fn is_native_database_path(path: &Path) -> Result<bool> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    native_database_path_data(&absolute)
}

fn native_database_path_data(absolute: &Path) -> Result<bool> {
    use std::path::Component;
    ensure!(
        absolute.is_absolute(),
        "database_absolute_location_required"
    );
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(_) => anyhow::bail!("database_path_prefix_unsupported"),
        }
    }
    // Negative lexical classification, including normalized traversal names.
    // This is not a physical/symlink-alias proof and never selects native
    // execution. The closed native open still joins the actual original,
    // role, keeper and held file identity independently of pathname DATA.
    Ok(normalized.starts_with(Path::new(NATIVE_DIRECTORY)))
}

/// A deliberate business rollback is a known result only after SQLite confirms
/// it and the same owner passes its postchecks. An error is never such a result.
pub(crate) enum SqlDecision<T> {
    Commit(T),
    Rollback(T),
}

/// One nonescaping connection under an actual existing owning borrow. There is
/// no raw/mutable connection getter, owned transaction result, role acquisition,
/// clock replacement or finalization factory in this facade.
pub(crate) struct RuntimeSql<'owner, 'stage, 'role, 'original> {
    connection: Option<Connection>,
    owner: SqlOwner<'owner, 'stage, 'role, 'original>,
    scope: String,
    failed: bool,
}

impl<'owner, 'stage, 'role, 'original> RuntimeSql<'owner, 'stage, 'role, 'original> {
    pub(crate) fn with_owner<T>(
        runtime: &Runtime,
        mut owner: SqlOwner<'owner, 'stage, 'role, 'original>,
        operation: impl for<'sql> FnOnce(&'sql mut Self) -> Result<T>,
    ) -> Result<T> {
        // Runtime/Pending are already armed. A human adapter arms only its
        // first actual SQL attempt. The actual same borrow remains held below.
        if let Err(error) = owner.prepare(runtime) {
            owner.refuse();
            return Err(error);
        }
        let opened = if let Some(selected) = &runtime.native_database {
            (|| {
                let path = selected.require_path(runtime.db())?;
                let mut connection = open_existing(path)?;
                configure_connection(&mut connection)?;
                Ok(connection)
            })()
        } else {
            super::open(runtime.db())
        };
        let connection = match opened {
            Ok(connection) => connection,
            Err(error) => {
                owner.refuse();
                return Err(error);
            }
        };
        let mut sql = Self {
            connection: Some(connection),
            owner,
            scope: runtime.scope().to_owned(),
            failed: false,
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            sql.check()?;
            // This facade binds the actual file/owner and installation scope.
            // Current work checks the active artifact in its callback; an
            // already-admitted effect instead checks its original invocation
            // and captured authority stamp before recording its result.
            super::check_database_scope(
                sql.connection.as_ref().context("SQL connection closed")?,
                &sql.scope,
            )?;
            operation(&mut sql)
        }));
        // Close/recovery/rollback cleanup happens while the genuine owner is
        // still borrowed, before its outer finish_known and final postchecks.
        let closed = sql.close();
        match result {
            Ok(Ok(value)) => {
                closed?;
                sql.check()?;
                Ok(value)
            }
            Ok(Err(error)) => {
                sql.fail();
                if closed.is_err() {
                    return Err(error.context("SQL cleanup also refused"));
                }
                Err(error)
            }
            Err(payload) => {
                sql.fail();
                let _ = closed;
                resume_unwind(payload)
            }
        }
    }

    pub(crate) fn check(&mut self) -> Result<()> {
        ensure!(!self.failed, "native SQL unit already refused");
        if let Err(error) = self.owner.check() {
            self.fail();
            return Err(error);
        }
        Ok(())
    }

    fn fail(&mut self) {
        self.failed = true;
        self.owner.refuse();
    }

    pub(crate) fn require_native_registry_read(&mut self, runtime: &Runtime) -> Result<()> {
        self.unit(|sql| sql.owner.require_native_registry_read(runtime))
    }

    pub(crate) fn refuse_registry(&mut self) {
        self.fail();
    }

    fn unit<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.check()?;
        match catch_unwind(AssertUnwindSafe(|| operation(self))) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                self.fail();
                Err(error)
            }
            Err(payload) => {
                self.fail();
                resume_unwind(payload)
            }
        }
    }

    pub(crate) fn read<T>(
        &mut self,
        operation: impl for<'db> FnOnce(&'db Connection) -> Result<T>,
    ) -> Result<T> {
        self.unit(|sql| {
            let connection = sql.connection.as_mut().context("SQL connection closed")?;
            connection.pragma_update(None, "query_only", true)?;
            let callbacks = CallbackHooks::install(connection, SqlMode::Read)?;
            let control = callbacks.control.clone();
            let result = (|| {
                sql.owner.check()?;
                let tx = callbacks.db.transaction()?;
                sql.owner.check()?;
                let policy = CallbackPolicy::activate(&tx, control)?;
                let value = (|| {
                    super::check_database_scope(&tx, &sql.scope)?;
                    // Diagnostic model/state reads remain available after a
                    // refusal. Protected history/outcome readers admit their
                    // audit guards at the actual return boundary instead.
                    operation(&tx)
                })();
                let admitted = policy.finish();
                match (value, admitted) {
                    (Ok(value), Ok(())) => {
                        sql.owner.commit_read(tx)?;
                        Ok(value)
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        let rolled_back = tx.rollback();
                        if rolled_back.is_err() {
                            return Err(error.context("SQL rollback also refused"));
                        }
                        Err(error)
                    }
                }
            })();
            let cleared = callbacks.finish();
            let result = match (result, cleared) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), _) | (_, Err(error)) => Err(error),
            };
            let restored = connection.pragma_update(None, "query_only", false);
            match result {
                Ok(value) => {
                    restored?;
                    Ok(value)
                }
                Err(error) => Err(error),
            }
        })
    }

    pub(crate) fn write<T>(
        &mut self,
        operation: impl for<'db> FnOnce(&'db rusqlite::Transaction<'_>) -> Result<SqlDecision<T>>,
    ) -> Result<T> {
        self.unit(|sql| {
            sql.owner.require_write()?;
            sql.owner.check()?;
            let connection = sql.connection.as_mut().context("SQL connection closed")?;
            let callbacks = CallbackHooks::install(connection, SqlMode::Write)?;
            let control = callbacks.control.clone();
            let result = (|| {
                // Preserve the ordinary FIFO, its bounds and SQLite busy handler.
                let tx = crate::write_queue::immediate(callbacks.db)?;
                sql.owner.check()?;
                let policy = CallbackPolicy::activate(&tx, control)?;
                let value = (|| {
                    super::check_database_scope(&tx, &sql.scope)?;
                    crate::audit::require_current_schema(&tx)?;
                    operation(&tx)
                })();
                let admitted = policy.finish();
                match (value, admitted) {
                    (Ok(SqlDecision::Commit(value)), Ok(())) => {
                        sql.owner.commit_write(tx)?;
                        Ok(value)
                    }
                    (Ok(SqlDecision::Rollback(value)), Ok(())) => {
                        sql.owner.rollback_write(tx)?;
                        Ok(value)
                    }
                    (Err(error), _) | (_, Err(error)) => {
                        let rolled_back = tx.rollback();
                        if rolled_back.is_err() {
                            return Err(error.context("SQL rollback also refused"));
                        }
                        Err(error)
                    }
                }
            })();
            let cleared = callbacks.finish();
            match (result, cleared) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        })
    }

    fn close(&mut self) -> Result<()> {
        let Some(connection) = self.connection.take() else {
            self.fail();
            anyhow::bail!("SQL connection already closed");
        };
        if let Err((connection, error)) = connection.close() {
            self.fail();
            // Owned cleanup only. A failed close never becomes Known or a
            // retry, even if dropping the remaining handle later succeeds.
            drop(connection);
            return Err(error).context("native SQL close refused");
        }
        // Closing the owned SQLite handle is cleanup, not a successful unit.
        // Preserve the original callback error after a known close; the unit
        // and actual owner stay refused, and the Ok path checks that latch.
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum SqlMode {
    Read,
    Write,
}

struct CallbackControl {
    // Lookup identity of the actual borrowed Connection, never native evidence.
    // CallbackPolicy holds that borrow until unregistration; it cannot move or
    // be replaced while this address is registered. No pointer is dereferenced.
    connection: usize,
    mode: SqlMode,
    denied: AtomicBool,
    scoped: AtomicBool,
    active_step: AtomicBool,
    ticket: AtomicU8,
}

thread_local! {
    static CALLBACK_CONTROLS: RefCell<Vec<Arc<CallbackControl>>> = const { RefCell::new(Vec::new()) };
}

fn connection_identity(connection: &Connection) -> usize {
    std::ptr::from_ref(connection).addr()
}

fn current_control(connection: &Connection) -> Result<Option<Arc<CallbackControl>>> {
    let control = CALLBACK_CONTROLS.with(|controls| controls.borrow().last().cloned());
    if let Some(control) = &control {
        if control.connection != connection_identity(connection) {
            control.denied.store(true, Ordering::SeqCst);
            anyhow::bail!("budget SQL connection changed");
        }
        ensure!(
            !control.denied.load(Ordering::SeqCst),
            "native SQL callback control refused"
        );
    }
    Ok(control)
}

/// A raw schema adapter cannot replace a native business callback or its
/// permanent VM budget. Latch the same unit's refusal before any hook mutation.
pub(crate) fn refuse_raw_schema_admission(db: &Connection) -> Result<()> {
    if let Some(control) = current_control(db)? {
        control.denied.store(true, Ordering::SeqCst);
        anyhow::bail!("native SQL raw schema admission refused");
    }
    Ok(())
}

fn unregister_control(control: &Arc<CallbackControl>) -> Result<()> {
    CALLBACK_CONTROLS.with(|controls| {
        let mut controls = controls.borrow_mut();
        if controls.last().is_some_and(|top| Arc::ptr_eq(top, control)) {
            controls.pop();
            return Ok(());
        }
        // Do not leave a stale registration, or remove another actual owner.
        // Out-of-order cleanup refuses all affected nested callbacks.
        control.denied.store(true, Ordering::SeqCst);
        for active in controls.iter() {
            active.denied.store(true, Ordering::SeqCst);
        }
        controls.retain(|active| !Arc::ptr_eq(active, control));
        anyhow::bail!("native SQL callback registration changed")
    })
}

#[derive(Clone, Copy)]
enum BudgetStep {
    Begin = 1,
    Rollback = 2,
    Release = 3,
}

impl BudgetStep {
    fn sql(self) -> &'static str {
        match self {
            Self::Begin => "SAVEPOINT day2_budget_atomic",
            Self::Rollback => "ROLLBACK TO day2_budget_atomic",
            Self::Release => "RELEASE day2_budget_atomic",
        }
    }
}

struct BudgetStepGuard {
    control: Option<Arc<CallbackControl>>,
    complete: bool,
}

impl BudgetStepGuard {
    fn enter(connection: &Connection, step: BudgetStep) -> Result<Self> {
        let control = current_control(connection)?;
        if connection.is_autocommit() {
            if let Some(control) = &control {
                control.denied.store(true, Ordering::SeqCst);
            }
            anyhow::bail!("budget_requires_transaction");
        }
        if let Some(control) = &control {
            if !matches!(control.mode, SqlMode::Write)
                || control
                    .active_step
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
            {
                control.denied.store(true, Ordering::SeqCst);
                anyhow::bail!("budget SQL command scope refused");
            }
            // Only this fixed command's prepare may consume this ticket. The
            // active flag separately forbids reentry after consumption.
            control.ticket.store(step as u8, Ordering::SeqCst);
        }
        Ok(Self {
            control,
            complete: false,
        })
    }

    fn finish(&mut self, connection: &Connection) -> Result<()> {
        if let Some(control) = &self.control {
            let accepted = control.connection == connection_identity(connection)
                && !control.denied.load(Ordering::SeqCst)
                && control.ticket.load(Ordering::SeqCst) == 0
                && !connection.is_autocommit();
            if !accepted {
                control.denied.store(true, Ordering::SeqCst);
                anyhow::bail!("budget SQL command did not preserve its outer transaction");
            }
        } else {
            ensure!(
                !connection.is_autocommit(),
                "budget SQL outer transaction ended"
            );
        }
        self.complete = true;
        Ok(())
    }
}

impl Drop for BudgetStepGuard {
    fn drop(&mut self) {
        if let Some(control) = &self.control {
            if !self.complete {
                control.denied.store(true, Ordering::SeqCst);
            }
            control.ticket.store(0, Ordering::SeqCst);
            control.active_step.store(false, Ordering::SeqCst);
        }
    }
}

fn budget_step(connection: &Connection, step: BudgetStep) -> Result<()> {
    let mut guard = BudgetStepGuard::enter(connection, step)?;
    let result = connection.execute_batch(step.sql());
    if result.is_err()
        && let Some(control) = &guard.control
    {
        control.denied.store(true, Ordering::SeqCst);
    }
    result?;
    guard.finish(connection)
}

/// Only budget::atomic can construct the consuming control. Each fixed SQL
/// command receives one ticket; no ticket or RefCell borrow spans the body.
/// Ordinary SQLite and native callbacks use this same atomicity operation.
pub(crate) fn budget_atomic<T>(
    connection: &Connection,
    _control: crate::budget::AtomicControl,
    body: impl FnOnce() -> Result<T>,
) -> Result<T> {
    budget_step(connection, BudgetStep::Begin)?;
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(value)) => {
            budget_step(connection, BudgetStep::Release)?;
            Ok(value)
        }
        Ok(Err(error)) => {
            if budget_step(connection, BudgetStep::Rollback)
                .and_then(|()| budget_step(connection, BudgetStep::Release))
                .is_err()
            {
                return Err(error.context("budget SQL rollback also refused"));
            }
            Err(error)
        }
        Err(payload) => {
            // Owned rollback only. Even if cleanup succeeds, catching this
            // panic cannot turn this SAME native callback into a known result.
            let _ = budget_step(connection, BudgetStep::Rollback)
                .and_then(|()| budget_step(connection, BudgetStep::Release));
            if let Ok(Some(control)) = current_control(connection) {
                control.denied.store(true, Ordering::SeqCst);
            }
            resume_unwind(payload)
        }
    }
}

/// Own the SQLite callback while the actual connection is exclusively borrowed.
/// The callback is inactive for owner transaction control, and is removed only
/// after every transaction/statement loan has ended.
struct CallbackHooks<'db> {
    db: &'db mut Connection,
    control: Arc<CallbackControl>,
    installed: bool,
    local: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl<'db> CallbackHooks<'db> {
    fn install(db: &'db mut Connection, mode: SqlMode) -> Result<Self> {
        let control = Arc::new(CallbackControl {
            connection: connection_identity(db),
            mode,
            denied: AtomicBool::new(false),
            scoped: AtomicBool::new(false),
            active_step: AtomicBool::new(false),
            ticket: AtomicU8::new(0),
        });
        let callback = control.clone();
        let owner = Self {
            db,
            control,
            installed: true,
            local: std::marker::PhantomData,
        };
        owner.db.authorizer(Some(move |context: AuthContext<'_>| {
            if !callback.scoped.load(Ordering::SeqCst) || callback.allows(context.action) {
                Authorization::Allow
            } else {
                callback.denied.store(true, Ordering::SeqCst);
                Authorization::Deny
            }
        }))?;
        Ok(owner)
    }

    fn finish(mut self) -> Result<()> {
        ensure!(
            !self.control.scoped.load(Ordering::SeqCst),
            "native SQL callback scope remains active"
        );
        let cleared = self
            .db
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        self.installed = cleared.is_err();
        if cleared.is_err() {
            self.control.denied.store(true, Ordering::SeqCst);
        }
        cleared?;
        Ok(())
    }
}

impl Drop for CallbackHooks<'_> {
    fn drop(&mut self) {
        self.control.scoped.store(false, Ordering::SeqCst);
        if self.installed
            && self
                .db
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
                .is_err()
        {
            self.control.denied.store(true, Ordering::SeqCst);
        }
    }
}

/// Only the business callback activates the already installed hook. Dropping
/// this guard deactivates it before Transaction rolls back during unwinding.
struct CallbackPolicy<'db> {
    db: &'db Connection,
    control: Arc<CallbackControl>,
    registered: bool,
}

impl<'db> CallbackPolicy<'db> {
    fn activate(db: &'db Connection, control: Arc<CallbackControl>) -> Result<Self> {
        ensure!(
            control.connection == connection_identity(db) && !control.scoped.load(Ordering::SeqCst),
            "native SQL callback connection changed"
        );
        CALLBACK_CONTROLS.with(|controls| -> Result<()> {
            let mut controls = controls.borrow_mut();
            ensure!(controls.len() < 64, "native SQL callback nesting bound");
            ensure!(
                !controls
                    .iter()
                    .any(|active| active.connection == control.connection),
                "native SQL callback already installed"
            );
            controls.push(control.clone());
            Ok(())
        })?;
        control.scoped.store(true, Ordering::SeqCst);
        Ok(Self {
            db,
            control,
            registered: true,
        })
    }

    fn finish(mut self) -> Result<()> {
        if self.db.is_autocommit() {
            self.control.denied.store(true, Ordering::SeqCst);
        }
        self.control.scoped.store(false, Ordering::SeqCst);
        let unregistered = unregister_control(&self.control);
        self.registered = false;
        unregistered?;
        ensure!(
            !self.control.denied.load(Ordering::SeqCst),
            "native SQL callback control refused"
        );
        Ok(())
    }
}

impl Drop for CallbackPolicy<'_> {
    fn drop(&mut self) {
        self.control.scoped.store(false, Ordering::SeqCst);
        if self.registered {
            let _ = unregister_control(&self.control);
        }
    }
}

impl CallbackControl {
    fn allows(&self, action: AuthAction<'_>) -> bool {
        // SQLite authorizes preparation, not every later VM step. Deny all
        // further preparation after refusal; finish() still rejects the whole
        // unit, including work through statements prepared before the denial.
        if self.denied.load(Ordering::SeqCst) {
            return false;
        }
        if let AuthAction::Savepoint {
            operation,
            savepoint_name,
        } = action
        {
            let expected = match operation {
                TransactionOperation::Begin => BudgetStep::Begin as u8,
                TransactionOperation::Rollback => BudgetStep::Rollback as u8,
                TransactionOperation::Release => BudgetStep::Release as u8,
                _ => return false,
            };
            return matches!(self.mode, SqlMode::Write)
                && savepoint_name == "day2_budget_atomic"
                && self.active_step.load(Ordering::SeqCst)
                && self
                    .ticket
                    .compare_exchange(expected, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok();
        }
        // No second statement (including ordinary DML) belongs to the fixed
        // command window. Business SQL runs only after BudgetStepGuard drops.
        if self.active_step.load(Ordering::SeqCst) {
            return false;
        }
        allowed_sql(action, self.mode)
    }
}

fn allowed_sql(action: AuthAction<'_>, mode: SqlMode) -> bool {
    match action {
        AuthAction::Select | AuthAction::Read { .. } | AuthAction::Recursive => true,
        AuthAction::Function { function_name } => {
            !["load_extension", "readfile", "writefile", "fts3_tokenizer"]
                .iter()
                .any(|name| function_name.eq_ignore_ascii_case(name))
        }
        AuthAction::Insert { .. } | AuthAction::Update { .. } | AuthAction::Delete { .. } => {
            matches!(mode, SqlMode::Write)
        }
        AuthAction::Pragma {
            pragma_name,
            pragma_value,
        } => {
            (pragma_name.eq_ignore_ascii_case("foreign_key_check") && pragma_value.is_none())
                || [
                    "table_info",
                    "table_xinfo",
                    "index_list",
                    "index_info",
                    "index_xinfo",
                    "foreign_key_list",
                ]
                .iter()
                .any(|name| pragma_name.eq_ignore_ascii_case(name))
        }
        // BEGIN/COMMIT/ROLLBACK, savepoints, attach/detach, DDL, unknown codes
        // and state-changing pragmas belong to the facade, never its callback.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn raw_open_refuses_initial_restored_and_traversal_native_paths_before_sqlite() -> Result<()> {
        for path in [
            "/state/day2-native/day2-initial.sqlite",
            "/state/day2-native/component/app.sqlite",
            "/state/../state/day2-native/component/app.sqlite",
            "/state/day2-native/./component/../component/app.sqlite",
            "/../../state/day2-native/component/app.sqlite",
        ] {
            let path = Path::new(path);
            assert!(is_native_database_path(path)?);
            assert_eq!(
                super::super::require_ordinary_database(path)
                    .unwrap_err()
                    .to_string(),
                "native_runtime_sql_owner_required"
            );
            assert_eq!(
                super::super::open(path).unwrap_err().to_string(),
                "native_runtime_sql_owner_required"
            );
        }
        for path in [
            "/state/day2-native-lookalike/app.sqlite",
            "/state/day2-native/../ordinary/app.sqlite",
            "/tmp/ordinary.sqlite",
        ] {
            assert!(!native_database_path_data(Path::new(path))?);
        }
        assert!(native_database_path_data(Path::new("relative.sqlite")).is_err());
        let mut relative = PathBuf::new();
        for _ in std::env::current_dir()?.components() {
            relative.push("..");
        }
        relative.push("state/day2-native/component/app.sqlite");
        assert!(is_native_database_path(&relative)?);
        assert_eq!(
            super::super::open(&relative).unwrap_err().to_string(),
            "native_runtime_sql_owner_required"
        );
        Ok(())
    }

    #[test]
    fn selected_database_metadata_never_substitutes_another_path() -> Result<()> {
        // DATA/mechanical selection only, no native role, keeper or Current.
        let selection = NativeDatabaseSelection::metadata_fixture(PathBuf::from(
            "/state/day2-native/component/app.sqlite",
        ));
        assert_eq!(
            selection.require_path(Path::new("/state/day2-native/component/app.sqlite"))?,
            Path::new("/state/day2-native/component/app.sqlite")
        );
        assert!(selection.require_path(Path::new(DATABASE)).is_err());
        assert!(
            selection
                .require_path(Path::new("/state/day2-native/another/app.sqlite"))
                .is_err()
        );
        assert!(
            selection
                .require_path(Path::new("/tmp/ordinary.sqlite"))
                .is_err()
        );
        Ok(())
    }

    fn budget_database() -> Result<Connection> {
        let mut db = Connection::open_in_memory()?;
        let tx = db.transaction()?;
        crate::budget::initialize_in(&tx, "sql-control-test")?;
        tx.execute_batch("CREATE TABLE control_probe(value INTEGER PRIMARY KEY)")?;
        tx.commit()?;
        Ok(db)
    }

    fn budget_request(fail: bool) -> crate::budget::ReservationRequest {
        use day2_capabilities::resources::{BudgetDefinition, BudgetLimits, BudgetScope};
        let definition = |calls| BudgetDefinition {
            revision: 1,
            scope: BudgetScope::App,
            period_seconds: 60,
            limits: BudgetLimits {
                calls: Some(calls),
                ..BudgetLimits::default()
            },
        };
        let mut budgets = std::collections::BTreeMap::from([("a".into(), definition(10))]);
        if fail {
            budgets.insert("z".into(), definition(1));
        }
        crate::budget::ReservationRequest {
            id: if fail { "excluded" } else { "accepted" }.into(),
            binding: "same-budget-binding".into(),
            context: crate::budget::BudgetContext {
                app: "app".into(),
                actor: "alice".into(),
                connection: "connection".into(),
                invocation_root: "root".into(),
                now: 100,
            },
            budgets,
            quote: crate::budget::Consumption {
                calls: if fail { 2 } else { 1 },
                ..Default::default()
            },
        }
    }

    #[test]
    fn budget_sql_real_nested_accounting_preserves_caught_exclusion_and_other_outer_work()
    -> Result<()> {
        let mut db = budget_database()?;
        let callbacks = CallbackHooks::install(&mut db, SqlMode::Write)?;
        let control = callbacks.control.clone();
        let tx = callbacks.db.transaction()?;
        let policy = CallbackPolicy::activate(&tx, control)?;
        tx.execute("INSERT INTO control_probe VALUES(1)", [])?;
        // reserve_in calls sync_definitions_in, a genuinely nested atomic
        // operation. The later exhausted account must roll back both levels.
        let excluded = crate::budget::reserve_in(&tx, &budget_request(true)).unwrap_err();
        assert_eq!(excluded.to_string(), "budget_exhausted:z:calls");
        for table in [
            "day2_budget_accounts",
            "day2_budget_reservations",
            "day2_budget_definition_state",
        ] {
            assert_eq!(
                tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
                0
            );
        }
        assert!(!policy.control.active_step.load(Ordering::SeqCst));
        assert_eq!(policy.control.ticket.load(Ordering::SeqCst), 0);
        let reservation = crate::budget::reserve_in(&tx, &budget_request(false))?;
        assert_eq!(reservation.id, "accepted");
        tx.execute("INSERT INTO control_probe VALUES(2)", [])?;
        policy.finish()?;
        assert!(!tx.is_autocommit(), "only the outer owner may commit");
        tx.commit()?;
        callbacks.finish()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM control_probe", [], |r| r
                .get::<_, i64>(0))?,
            2
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_budget_reservations", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            1
        );
        Ok(())
    }

    #[test]
    fn budget_sql_raw_same_name_and_outer_control_remain_denied() -> Result<()> {
        for sql in [
            "SAVEPOINT day2_budget_atomic",
            "ROLLBACK TO day2_budget_atomic",
            "RELEASE day2_budget_atomic",
            "COMMIT",
            "ROLLBACK",
        ] {
            let mut db = budget_database()?;
            let callbacks = CallbackHooks::install(&mut db, SqlMode::Write)?;
            let control = callbacks.control.clone();
            let tx = callbacks.db.transaction()?;
            let policy = CallbackPolicy::activate(&tx, control)?;
            crate::budget::reserve_in(&tx, &budget_request(false))?;
            assert!(tx.execute_batch(sql).is_err(), "{sql}");
            assert!(policy.finish().is_err(), "caught denial stays latched");
            tx.rollback()?;
            callbacks.finish()?;
            assert_eq!(
                db.query_row("SELECT count(*) FROM day2_budget_reservations", [], |r| r
                    .get::<_, i64>(
                    0
                ))?,
                0
            );
        }
        Ok(())
    }

    #[test]
    fn budget_sql_caught_control_denial_blocks_further_preparation() -> Result<()> {
        for following in [
            "SELECT 1",
            "SELECT abs(-1)",
            "PRAGMA table_info(control_probe)",
        ] {
            let mut db = budget_database()?;
            let callbacks = CallbackHooks::install(&mut db, SqlMode::Write)?;
            let control = callbacks.control.clone();
            let tx = callbacks.db.transaction()?;
            let policy = CallbackPolicy::activate(&tx, control)?;
            assert!(tx.execute_batch("COMMIT").is_err());
            assert!(policy.control.denied.load(Ordering::SeqCst));
            assert!(tx.execute_batch(following).is_err(), "{following}");
            assert!(policy.finish().is_err());
            tx.rollback()?;
            callbacks.finish()?;
        }
        Ok(())
    }

    #[test]
    fn budget_sql_denied_raw_admission_leaves_the_permanent_vm_budget_intact() -> Result<()> {
        // Ordinary real-SQLite conformance only. No native owner is created or
        // continued after refusal; its adapter policy ends before the VM probe.
        let mut db = Connection::open_in_memory()?;
        configure_connection(&mut db)?;
        let callbacks = CallbackHooks::install(&mut db, SqlMode::Read)?;
        let control = callbacks.control.clone();
        let tx = callbacks.db.transaction()?;
        let policy = CallbackPolicy::activate(&tx, control)?;
        assert!(crate::oauth::schema::admit(&tx, |_| Ok(())).is_err());
        assert!(tx.execute_batch("SELECT 1").is_err());
        assert!(policy.finish().is_err());
        tx.rollback()?;
        callbacks.finish()?;
        let error = db.query_row(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT sum(x) FROM n",
            [], |row| row.get::<_, i64>(0),
        ).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::OperationInterrupted)
        );
        Ok(())
    }

    #[test]
    fn budget_sql_read_and_foreign_connections_refuse_before_account_mutation() -> Result<()> {
        let mut db = budget_database()?;
        let callbacks = CallbackHooks::install(&mut db, SqlMode::Read)?;
        let control = callbacks.control.clone();
        let tx = callbacks.db.transaction()?;
        let policy = CallbackPolicy::activate(&tx, control)?;
        assert!(crate::budget::reserve_in(&tx, &budget_request(false)).is_err());
        assert!(policy.finish().is_err());
        tx.rollback()?;
        callbacks.finish()?;
        let mut other = budget_database()?;
        let callbacks = CallbackHooks::install(&mut db, SqlMode::Write)?;
        let control = callbacks.control.clone();
        let tx = callbacks.db.transaction()?;
        let foreign = other.transaction()?;
        let policy = CallbackPolicy::activate(&tx, control)?;
        assert!(crate::budget::reserve_in(&foreign, &budget_request(false)).is_err());
        assert_eq!(
            foreign.query_row("SELECT count(*) FROM day2_budget_reservations", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert!(policy.finish().is_err());
        foreign.rollback()?;
        tx.rollback()?;
        callbacks.finish()?;
        Ok(())
    }

    #[test]
    fn budget_sql_lost_outer_transaction_cannot_start_or_release_a_replacement() -> Result<()> {
        let mut db = budget_database()?;
        let callbacks = CallbackHooks::install(&mut db, SqlMode::Write)?;
        let control = callbacks.control.clone();
        let tx = callbacks.db.transaction()?;
        let policy = CallbackPolicy::activate(&tx, control)?;
        tx.execute("INSERT INTO control_probe VALUES(1)", [])?;
        assert!(
            tx.execute("INSERT OR ROLLBACK INTO control_probe VALUES(1)", [])
                .is_err()
        );
        assert!(tx.is_autocommit());
        // Actual production budget entry must reach the lower precondition,
        // refuse before SAVEPOINT and latch even if this error is caught.
        let error = crate::budget::reserve_in(&tx, &budget_request(false)).unwrap_err();
        assert_eq!(error.to_string(), "budget_requires_transaction");
        assert!(policy.control.denied.load(Ordering::SeqCst));
        assert!(tx.is_autocommit());
        assert!(
            tx.execute("INSERT INTO control_probe VALUES(2)", [])
                .is_err()
        );
        assert!(policy.finish().is_err());
        assert!(tx.rollback().is_err());
        callbacks.finish()?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM control_probe", [], |r| r
                .get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM day2_budget_reservations", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            0
        );
        Ok(())
    }

    #[test]
    fn budget_sql_ticket_is_one_command_and_drop_or_unwind_never_leaves_permission() -> Result<()> {
        for panic in [false, true] {
            let mut db = budget_database()?;
            let callbacks = CallbackHooks::install(&mut db, SqlMode::Write)?;
            let control = callbacks.control.clone();
            let tx = callbacks.db.transaction()?;
            let policy = CallbackPolicy::activate(&tx, control)?;
            let control = policy.control.clone();
            let result = catch_unwind(AssertUnwindSafe(|| {
                let guard = BudgetStepGuard::enter(&tx, BudgetStep::Begin).unwrap();
                if panic {
                    panic!("controlled budget step interruption");
                }
                tx.execute_batch("SAVEPOINT day2_budget_atomic").unwrap();
                assert_eq!(control.ticket.load(Ordering::SeqCst), 0);
                assert!(control.active_step.load(Ordering::SeqCst));
                assert!(BudgetStepGuard::enter(&tx, BudgetStep::Release).is_err());
                assert!(tx.execute_batch("SAVEPOINT day2_budget_atomic").is_err());
                drop(guard);
            }));
            assert_eq!(result.is_err(), panic);
            assert!(!control.active_step.load(Ordering::SeqCst));
            assert_eq!(control.ticket.load(Ordering::SeqCst), 0);
            assert!(tx.execute_batch("SAVEPOINT day2_budget_atomic").is_err());
            assert!(policy.finish().is_err());
            tx.rollback()?;
            callbacks.finish()?;
        }
        Ok(())
    }

    #[test]
    fn budget_sql_consumed_ticket_does_not_authorize_a_second_statement() -> Result<()> {
        for sql in [
            "SAVEPOINT day2_budget_atomic",
            "RELEASE day2_budget_atomic",
            "SAVEPOINT foreign",
            "INSERT INTO control_probe VALUES(1)",
        ] {
            let mut db = budget_database()?;
            let callbacks = CallbackHooks::install(&mut db, SqlMode::Write)?;
            let control = callbacks.control.clone();
            let tx = callbacks.db.transaction()?;
            let policy = CallbackPolicy::activate(&tx, control)?;
            let guard = BudgetStepGuard::enter(&tx, BudgetStep::Begin)?;
            tx.execute_batch("SAVEPOINT day2_budget_atomic")?;
            assert_eq!(policy.control.ticket.load(Ordering::SeqCst), 0);
            // No intervening reentry or denial can explain this refusal.
            assert!(!policy.control.denied.load(Ordering::SeqCst));
            assert!(tx.execute_batch(sql).is_err(), "{sql}");
            drop(guard);
            assert!(policy.finish().is_err());
            tx.rollback()?;
            callbacks.finish()?;
            assert_eq!(
                db.query_row("SELECT count(*) FROM control_probe", [], |row| row
                    .get::<_, i64>(0))?,
                0
            );
        }
        Ok(())
    }

    #[test]
    fn sqlite_native_adapter_never_creates_repairs_or_follows_a_final_symlink() {
        // Filesystem/SQLite controls only: no native serving owner is made.
        let directory = tempfile::tempdir().unwrap();
        // macOS /var is itself a symlink; exercise the actual directory.
        let root = directory.path().canonicalize().unwrap();
        let missing = root.join("missing.sqlite");
        assert!(open_existing(&missing).is_err());
        assert!(!missing.exists());
        let existing = root.join("existing.sqlite");
        let db = Connection::open(&existing).unwrap();
        db.execute_batch("CREATE TABLE unchanged(value TEXT) STRICT")
            .unwrap();
        drop(db);
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).unwrap();
        let db = open_existing(&existing).unwrap();
        let sql: String = db
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name='unchanged'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(sql, "CREATE TABLE unchanged(value TEXT) STRICT");
        drop(db);
        assert_eq!(
            std::fs::metadata(&existing).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let link = root.join("link.sqlite");
        symlink(&existing, &link).unwrap();
        assert!(open_existing(&link).is_err());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn existing_oauth_admission_never_installs_repairs_or_restamps_native_state()
    -> anyhow::Result<()> {
        let mut db = Connection::open_in_memory()?;
        super::configure_connection(&mut db)?;
        assert!(require_existing_oauth_schema(&db).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM sqlite_master", [], |row| row
                .get::<_, i64>(0))?,
            0
        );
        assert!(!db.pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))?);
        crate::oauth::schema::admit_with_runtime_hook(&db, crate::oauth::connect::install_schema)?;
        let definitions =
            |db: &Connection| -> anyhow::Result<Vec<(String, String, Option<String>)>> {
                Ok(db
                    .prepare("SELECT type,name,sql FROM sqlite_master ORDER BY type,name")?
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()?)
            };
        let before = definitions(&db)?;
        let changes = db.total_changes();
        require_existing_oauth_schema(&db)?;
        assert_eq!(definitions(&db)?, before);
        assert_eq!(db.total_changes(), changes);
        db.execute("DELETE FROM oauth_schema_version", [])?;
        let changes = db.total_changes();
        assert!(require_existing_oauth_schema(&db).is_err());
        assert_eq!(definitions(&db)?, before);
        assert_eq!(db.total_changes(), changes);
        assert_eq!(
            db.query_row("SELECT count(*) FROM oauth_schema_version", [], |row| row
                .get::<_, i64>(
                0
            ))?,
            0
        );
        assert!(!db.pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))?);
        Ok(())
    }
}
