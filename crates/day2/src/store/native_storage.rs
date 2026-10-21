//! Native-only existing-file Runtime admission under its actual serving scope.
//! This never initializes, creates, adopts or migrates an installation.
use super::{InitialStoreMetadata, Runtime, check_storage_binding, configure_connection};
use crate::security_epoch::{native_enrollment::EnrolledRoleStage, serving::CurrentServingPhase};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
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
            let connection = open_existing(Path::new(DATABASE))?;
            configure_connection(&connection)?;
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
pub(super) fn open_existing(path: &Path) -> Result<Connection> {
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
        let db = Connection::open_in_memory()?;
        super::configure_connection(&db)?;
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
