//! Native-only existing-file Runtime admission under its actual serving scope.
//! This never initializes, creates, adopts or migrates an installation.
use super::{InitialStoreMetadata, Runtime, check_storage_binding, configure_connection};
use crate::oauth::native_management::SqlOwner;
use crate::security_epoch::{native_enrollment::EnrolledRoleStage, serving::CurrentServingPhase};
use anyhow::{Context, Result, ensure};
use rusqlite::{
    Connection, OpenFlags,
    hooks::{AuthAction, AuthContext, Authorization},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const DATABASE: &str = "/state/day2-native/day2-initial.sqlite";

impl Runtime {
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
            let mut connection = open_existing(Path::new(DATABASE))?;
            configure_connection(&mut connection)?;
            current.admit_runtime_database(stage, &metadata, &connection)?;
            check_storage_binding(&connection, &metadata.artifact, &metadata.scope)?;
            let active = crate::authority_state::current(&connection)?;
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
                require_existing_oauth_schema(&connection)?;
            }
            // Recheck the retained original schema/seed after the bounded,
            // read-only admission; there is no initializer or repair fallback.
            current.admit_runtime_database(stage, &metadata, &connection)?;
            connection.pragma_update(None, "journal_mode", "WAL")?;
            current.admit_runtime_database(stage, &metadata, &connection)?;
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
                scope: metadata.scope,
                hosted_domain: desired.hosted_domain().map(str::to_owned),
                instance_path: metadata.instance_path,
                app: metadata.app,
                db: PathBuf::from(DATABASE),
                artifact: Arc::new(metadata.artifact),
                host: Arc::new(crate::host::System(inputs.clone())),
                inputs,
            };
            if let Err((connection, error)) = connection.close() {
                current.refuse();
                drop(connection);
                return Err(error).context("native initial SQL close refused");
            }
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
pub(super) fn is_native_database(path: &Path) -> bool {
    path == Path::new(DATABASE)
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
pub(crate) struct RuntimeSql<'owner> {
    connection: Option<Connection>,
    owner: SqlOwner<'owner>,
    failed: bool,
}

impl<'owner> RuntimeSql<'owner> {
    pub(crate) fn with_owner<T>(
        runtime: &Runtime,
        mut owner: SqlOwner<'owner>,
        operation: impl for<'sql> FnOnce(&'sql mut Self) -> Result<T>,
    ) -> Result<T> {
        // Runtime/Pending are already armed. A human adapter arms only its
        // first actual SQL attempt. The actual same borrow remains held below.
        owner.prepare(runtime)?;
        let opened = if runtime.uses_native_storage() {
            (|| {
                let mut connection = open_existing(Path::new(DATABASE))?;
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
            failed: false,
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            sql.check()?;
            runtime.check_binding(sql.connection.as_ref().context("SQL connection closed")?)?;
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
            let result = (|| {
                sql.owner.check()?;
                let tx = connection.transaction()?;
                sql.owner.check()?;
                let policy = CallbackPolicy::install(&tx, SqlMode::Read)?;
                let value = operation(&tx);
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
            // Preserve the ordinary FIFO, its bounds and SQLite busy handler.
            let tx = crate::write_queue::immediate(connection)?;
            sql.owner.check()?;
            let policy = CallbackPolicy::install(&tx, SqlMode::Write)?;
            let value = operation(&tx);
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
        ensure!(!self.failed, "native SQL unit already refused");
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum SqlMode {
    Read,
    Write,
}

struct CallbackPolicy<'db> {
    db: &'db Connection,
    denied: Arc<AtomicBool>,
    installed: bool,
}

impl<'db> CallbackPolicy<'db> {
    fn install(db: &'db Connection, mode: SqlMode) -> Result<Self> {
        let denied = Arc::new(AtomicBool::new(false));
        let callback_denied = denied.clone();
        db.authorizer(Some(move |context: AuthContext<'_>| {
            if allowed_sql(context.action, mode) {
                Authorization::Allow
            } else {
                callback_denied.store(true, Ordering::SeqCst);
                Authorization::Deny
            }
        }))?;
        Ok(Self {
            db,
            denied,
            installed: true,
        })
    }

    fn finish(mut self) -> Result<()> {
        self.installed = false;
        self.db
            .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
        ensure!(
            !self.denied.load(Ordering::SeqCst),
            "native SQL callback control refused"
        );
        Ok(())
    }
}

impl Drop for CallbackPolicy<'_> {
    fn drop(&mut self) {
        // Restore control before Transaction's rollback during unwinding. The
        // surrounding unit records terminal refusal and resumes the panic.
        if self.installed
            && self
                .db
                .authorizer(None::<fn(AuthContext<'_>) -> Authorization>)
                .is_err()
        {
            self.denied.store(true, Ordering::SeqCst);
        }
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
