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
}
