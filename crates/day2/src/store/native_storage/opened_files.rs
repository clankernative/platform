//! Real-SQLite observations and replacement counterexamples for the pinned
//! Unix VFS. Test-only foundation: never native admission or file provenance.
//! Matching actual handles does not establish creator MAIN/WAL/SHM continuity.
use anyhow::{Result, ensure};
use rusqlite::{Connection, Transaction};
use serde_json::Value;

const MAX_OBSERVATION: usize = 8192;

#[derive(PartialEq, Eq)]
struct Handles {
    main: i32,
    journal: Option<i32>,
    shm: Option<i32>,
}

/// Borrows the actual transaction. No connection/handle getter, codec, clone,
/// scalar constructor, permission or completion is supplied by this view.
struct OpenedFiles<'transaction> {
    connection: &'transaction Connection,
    handles: Handles,
}

fn descriptor(value: &Value) -> Result<i32> {
    let fd = value
        .as_i64()
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("native_sqlite_handle_shape"))?;
    ensure!(fd >= 0, "native_sqlite_handle_shape");
    Ok(fd)
}

fn unix_file(value: &Value) -> Result<i32> {
    ensure!(
        value.get("vfs").and_then(Value::as_str) == Some("unix"),
        "native_sqlite_vfs_unsupported"
    );
    descriptor(
        value
            .get("h")
            .ok_or_else(|| anyhow::anyhow!("native_sqlite_handle_missing"))?,
    )
}

fn decode(bytes: &[u8]) -> Result<Handles> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_OBSERVATION,
        "native_sqlite_observation_bound"
    );
    let value: Value = crate::json::decode(bytes)?;
    let root = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("native_sqlite_observation_shape"))?;
    let db = root
        .get("db")
        .ok_or_else(|| anyhow::anyhow!("native_sqlite_main_missing"))?;
    let main = unix_file(db)?;
    let journal = root.get("journal").map(unix_file).transpose()?;
    let shm = db
        .get("shm")
        .map(|v| {
            descriptor(
                v.get("h")
                    .ok_or_else(|| anyhow::anyhow!("native_sqlite_shm_missing"))?,
            )
        })
        .transpose()?;
    ensure!(
        journal != Some(main) && shm != Some(main) && (shm.is_none() || shm != journal),
        "native_sqlite_handle_alias"
    );
    Ok(Handles { main, journal, shm })
}

fn read(connection: &Connection) -> Result<Handles> {
    ensure!(
        !connection.is_autocommit(),
        "native_sqlite_transaction_not_retained"
    );
    // Force the actual read snapshot before inspecting the opened WAL/SHM.
    let _: i64 =
        connection.query_row("SELECT count(*) FROM main.sqlite_schema", [], |r| r.get(0))?;
    let text: String =
        connection.query_row("SELECT substr(sqlite_filestat('main'),1,8193)", [], |r| {
            r.get(0)
        })?;
    decode(text.as_bytes())
}

fn inspect<'transaction>(
    transaction: &'transaction Transaction<'_>,
) -> Result<OpenedFiles<'transaction>> {
    let handles = read(transaction)?;
    Ok(OpenedFiles {
        connection: transaction,
        handles,
    })
}

impl OpenedFiles<'_> {
    fn check_live(&self) -> Result<()> {
        ensure!(
            read(self.connection)? == self.handles,
            "native_sqlite_opened_handles_changed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, fs, os::unix::fs::MetadataExt, path::Path, process::Command};

    const FIXTURE_ENV: &str = "DAY2_SQLITE_OPENED_FILES_FIXTURE";
    const CHILD_CASE: &str =
        "store::native_storage::opened_files::tests::retained_sidecar_fixture_child";
    const OLD_ADMIN: &str = "removed-admin@example.test";
    const CURRENT_ADMIN: &str = "current-admin@example.test";
    const LOCK_ENV: &str = "DAY2_SQLITE_OPENED_FILES_LOCK_PROBE";
    const LOCK_CHILD: &str =
        "store::native_storage::opened_files::tests::independent_writer_probe_child";

    fn authority_document(admin: &str) -> crate::authority_state::AuthorityDocument {
        crate::authority_state::AuthorityDocument {
            security: None,
            enabled: true,
            hosted_domain: None,
            readers: BTreeSet::new(),
            writers: BTreeSet::new(),
            policy: Some(crate::authority::Policy {
                version: 1,
                admins: BTreeSet::from([admin.to_owned()]),
                operations: Default::default(),
                constraints: Default::default(),
                delegations: Default::default(),
            }),
            resources: Default::default(),
            credentials: Default::default(),
        }
    }

    fn inode(fd: i32) -> Result<(u64, u64)> {
        // Metadata only: never open/close a duplicate database fd, which could
        // release this process's POSIX SQLite locks. Not a native owner fixture.
        let file = fs::metadata(format!("/dev/fd/{fd}"))?;
        Ok((file.dev(), file.ino()))
    }

    fn named_inode(path: impl AsRef<Path>) -> Result<(u64, u64)> {
        let file = fs::metadata(path)?;
        Ok((file.dev(), file.ino()))
    }

    fn sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
        path.with_file_name(format!("actual.sqlite{suffix}"))
    }

    #[test]
    fn independent_writer_probe_child() -> Result<()> {
        let Some(root) = std::env::var_os(LOCK_ENV) else {
            return Ok(());
        };
        let root = Path::new(&root);
        let connection = Connection::open_with_flags(
            root.join("actual.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        let acquired = match connection.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => {
                connection.execute_batch("ROLLBACK")?;
                true
            }
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy =>
            {
                false
            }
            Err(error) => return Err(error.into()),
        };
        fs::write(
            root.join("writer-acquired.json"),
            serde_json::to_vec(&acquired)?,
        )?;
        Ok(())
    }

    #[test]
    fn actual_fd_metadata_preserves_locks_but_opening_and_closing_the_same_inode_does_not()
    -> Result<()> {
        for close_duplicate in [false, true] {
            let directory = tempfile::tempdir()?;
            let root = directory.path().canonicalize()?;
            let path = root.join("actual.sqlite");
            let mut connection = Connection::open(&path)?;
            connection.execute_batch("CREATE TABLE records(value TEXT)")?;
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let files = inspect(&transaction)?;
            assert_eq!(inode(files.handles.main)?, named_inode(&path)?);
            files.check_live()?;
            if close_duplicate {
                // Intentional negative control on this disposable fixture.
                // POSIX locks belong to the process/inode: closing another fd
                // can release them even while SQLite retains its own fd.
                // No transaction writes occur in either process.
                drop(fs::File::open(&path)?);
            }
            let output = Command::new(std::env::current_exe()?)
                .args(["--exact", LOCK_CHILD, "--nocapture"])
                .env(LOCK_ENV, &root)
                .output()?;
            ensure!(
                output.status.success(),
                "SQLite independent writer probe refused"
            );
            let bytes = fs::read(root.join("writer-acquired.json"))?;
            ensure!(bytes.len() <= 5, "SQLite writer probe bound");
            let acquired: bool = crate::json::decode(&bytes)?;
            assert_eq!(acquired, close_duplicate);
            drop(files);
            transaction.rollback()?;
        }
        Ok(())
    }

    #[test]
    fn retained_sidecar_fixture_child() -> Result<()> {
        let Some(root) = std::env::var_os(FIXTURE_ENV) else {
            return Ok(());
        };
        let root = Path::new(&root);
        let path = root.join("actual.sqlite");
        let mut connection = Connection::open(&path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        // Baseline MAIN is the same inode and schema for both later versions.
        crate::authority_state::upgrade(&connection)?;
        connection.execute(
            "INSERT INTO day2_authority VALUES(1,?1,1,?2,'fixture-artifact','fixture-artifact-path')",
            rusqlite::params![
                day2_capabilities::Digest::new(b"opened-files-authority-epoch").as_str(),
                serde_json::to_string(&authority_document("baseline@example.test"))?,
            ],
        )?;
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        connection.execute(
            "UPDATE day2_authority SET revision=2,document=?1",
            [serde_json::to_string(&authority_document(OLD_ADMIN))?],
        )?;
        fs::copy(sidecar(&path, "-wal"), root.join("older-wal"))?;
        fs::copy(sidecar(&path, "-shm"), root.join("older-shm"))?;
        connection.execute(
            "UPDATE day2_authority SET revision=3,document=?1",
            [serde_json::to_string(&authority_document(CURRENT_ADMIN))?],
        )?;
        let transaction = connection.transaction()?;
        let current = crate::authority_state::current(&transaction)?;
        assert_eq!(current.stamp.revision, 3);
        assert_eq!(
            current.policy()?.admins,
            BTreeSet::from([CURRENT_ADMIN.to_owned()])
        );
        fs::write(
            root.join("current-authority.json"),
            serde_json::to_vec(&current)?,
        )?;
        let files = inspect(&transaction)?;
        let expected = [
            inode(files.handles.main)?,
            inode(files.handles.journal.expect("writer WAL"))?,
            inode(files.handles.shm.expect("writer SHM"))?,
        ];
        fs::write(
            root.join("creator-identities.json"),
            serde_json::to_vec(&expected)?,
        )?;
        // Deliberate child death leaves the real WAL/SHM on disk and avoids
        // SQLite's last-connection cleanup. No native owner is simulated.
        // The parent is a separate process, so SQLite cannot reuse the child's
        // cached unixInodeInfo/pShm node during its read.
        std::process::exit(0);
    }

    fn retained_sidecars(root: &Path) -> Result<[(u64, u64); 3]> {
        let output = Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD_CASE, "--nocapture"])
            .env(FIXTURE_ENV, root)
            .output()?;
        ensure!(
            output.status.success(),
            "SQLite sidecar fixture child refused"
        );
        let bytes = fs::read(root.join("creator-identities.json"))?;
        ensure!(bytes.len() < 512, "SQLite sidecar fixture bound");
        Ok(crate::json::decode(&bytes)?)
    }

    fn current_authority(root: &Path) -> Result<crate::authority_state::ActiveAuthority> {
        let bytes = fs::read(root.join("current-authority.json"))?;
        ensure!(bytes.len() < 4096, "SQLite authority fixture bound");
        Ok(crate::json::decode(&bytes)?)
    }

    #[test]
    fn compatible_older_wal_and_shm_can_remain_installed_for_the_entire_read() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let path = root.join("actual.sqlite");
        let expected = retained_sidecars(&root)?;
        for (old, suffix) in [("older-wal", "-wal"), ("older-shm", "-shm")] {
            fs::rename(
                sidecar(&path, suffix),
                root.join(format!("creator{suffix}")),
            )?;
            fs::rename(root.join(old), sidecar(&path, suffix))?;
        }
        let installed = [
            named_inode(&path)?,
            named_inode(sidecar(&path, "-wal"))?,
            named_inode(sidecar(&path, "-shm"))?,
        ];
        assert_eq!(installed[0], expected[0]);
        assert_ne!(installed[1], expected[1]);
        assert_ne!(installed[2], expected[2]);
        let mut connection = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let transaction = connection.transaction()?;
        let expected_current = current_authority(&root)?;
        let stale = crate::authority_state::current(&transaction)?;
        assert_eq!(stale.stamp.epoch, expected_current.stamp.epoch);
        assert_eq!(stale.artifact_id, expected_current.artifact_id);
        assert_eq!(stale.stamp.revision, 2);
        assert_eq!(expected_current.stamp.revision, 3);
        assert_eq!(
            stale.policy()?.admins,
            BTreeSet::from([OLD_ADMIN.to_owned()])
        );
        assert_eq!(
            expected_current.policy()?.admins,
            BTreeSet::from([CURRENT_ADMIN.to_owned()])
        );
        assert!(!stale.policy()?.admins.contains(CURRENT_ADMIN));
        assert!(!expected_current.policy()?.admins.contains(OLD_ADMIN));
        let files = inspect(&transaction)?;
        assert_eq!(inode(files.handles.main)?, expected[0]);
        assert_eq!(named_inode(&path)?, expected[0]);
        assert_eq!(
            inode(files.handles.journal.expect("substituted WAL"))?,
            installed[1]
        );
        assert_eq!(
            inode(files.handles.shm.expect("substituted SHM"))?,
            installed[2]
        );
        assert_eq!(named_inode(sidecar(&path, "-wal"))?, installed[1]);
        assert_eq!(named_inode(sidecar(&path, "-shm"))?, installed[2]);
        // No ABA restore occurs: the compatible old sidecars stay named for
        // the complete read. MAIN/path/seed checks and a stable observed view
        // can all pass; genuine creator-sidecar comparison must still refuse.
        files.check_live()?;
        drop(files);
        transaction.rollback()?;
        Ok(())
    }

    #[test]
    fn matching_all_three_inodes_still_does_not_prevent_in_place_authority_rollback() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let path = root.join("actual.sqlite");
        let expected = retained_sidecars(&root)?;
        // Deliberate corruption while no creator process is alive. Preserve
        // each existing inode and replace only its bytes: inode continuity is
        // not content continuity or evidence of a live, exclusive writer.
        for (old, suffix) in [("older-wal", "-wal"), ("older-shm", "-shm")] {
            let bytes = fs::read(root.join(old))?;
            fs::write(sidecar(&path, suffix), bytes)?;
        }
        assert_eq!(named_inode(&path)?, expected[0]);
        assert_eq!(named_inode(sidecar(&path, "-wal"))?, expected[1]);
        assert_eq!(named_inode(sidecar(&path, "-shm"))?, expected[2]);
        let mut connection = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let transaction = connection.transaction()?;
        let stale = crate::authority_state::current(&transaction)?;
        let current = current_authority(&root)?;
        assert_eq!(stale.stamp.epoch, current.stamp.epoch);
        assert_eq!(stale.artifact_id, current.artifact_id);
        assert_eq!(stale.stamp.revision, 2);
        assert_eq!(current.stamp.revision, 3);
        assert_eq!(
            stale.policy()?.admins,
            BTreeSet::from([OLD_ADMIN.to_owned()])
        );
        assert_eq!(
            current.policy()?.admins,
            BTreeSet::from([CURRENT_ADMIN.to_owned()])
        );
        let files = inspect(&transaction)?;
        assert_eq!(inode(files.handles.main)?, expected[0]);
        assert_eq!(
            inode(files.handles.journal.expect("same-inode WAL"))?,
            expected[1]
        );
        assert_eq!(
            inode(files.handles.shm.expect("same-inode SHM"))?,
            expected[2]
        );
        files.check_live()?;
        drop(files);
        transaction.rollback()?;
        Ok(())
    }

    #[test]
    fn sqlite_recreates_missing_shm_without_proving_creator_continuity() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let path = root.join("actual.sqlite");
        let expected = retained_sidecars(&root)?;
        fs::rename(sidecar(&path, "-shm"), root.join("creator-shm"))?;
        assert_eq!(named_inode(root.join("creator-shm"))?, expected[2]);
        assert!(!sidecar(&path, "-shm").try_exists()?);
        let mut connection = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let transaction = connection.transaction()?;
        assert_eq!(
            crate::authority_state::current(&transaction)?,
            current_authority(&root)?
        );
        let files = inspect(&transaction)?;
        assert_eq!(inode(files.handles.main)?, expected[0]);
        assert_eq!(
            inode(files.handles.journal.expect("current WAL"))?,
            expected[1]
        );
        assert_ne!(
            inode(files.handles.shm.expect("recreated SHM"))?,
            expected[2]
        );
        assert_eq!(
            inode(files.handles.shm.expect("recreated SHM"))?,
            named_inode(sidecar(&path, "-shm"))?,
        );
        assert_eq!(named_inode(root.join("creator-shm"))?, expected[2]);
        files.check_live()?;
        drop(files);
        transaction.rollback()?;
        Ok(())
    }

    #[test]
    fn pinned_builtin_reports_actual_main_wal_and_shm_under_the_same_transaction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?.join("actual.sqlite");
        let mut connection = Connection::open(&path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "CREATE TABLE records(value TEXT); INSERT INTO records VALUES('current')",
        )?;
        let transaction = connection.transaction()?;
        let files = inspect(&transaction)?;
        let main = fs::metadata(&path)?;
        assert_eq!(inode(files.handles.main)?, (main.dev(), main.ino()));
        for (fd, suffix) in [(files.handles.journal, "-wal"), (files.handles.shm, "-shm")] {
            let named = fs::metadata(format!("{}{suffix}", path.display()))?;
            assert_eq!(
                inode(fd.expect("actual WAL/SHM handle"))?,
                (named.dev(), named.ino())
            );
        }
        files.check_live()?;
        drop(files);
        transaction.rollback()?;
        assert!(read(&connection).is_err());
        Ok(())
    }

    #[test]
    fn regular_file_aba_keeps_the_foreign_opened_inode_visible() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let live = root.join("actual.sqlite");
        let old = root.join("older.sqlite");
        let held = root.join("held.sqlite");
        for (path, value) in [(&live, "current"), (&old, "older")] {
            let connection = Connection::open(path)?;
            connection.execute_batch("CREATE TABLE records(value TEXT)")?;
            connection.execute("INSERT INTO records VALUES(?1)", [value])?;
            connection.close().map_err(|(_, e)| e)?;
        }
        let expected = fs::metadata(&live)?;
        fs::rename(&live, &held)?;
        fs::rename(&old, &live)?;
        let mut connection = Connection::open(&live)?;
        fs::rename(&live, &old)?;
        fs::rename(&held, &live)?;
        let transaction = connection.transaction()?;
        assert_eq!(
            transaction.query_row("SELECT value FROM records", [], |r| r.get::<_, String>(0))?,
            "older"
        );
        let files = inspect(&transaction)?;
        assert_ne!(inode(files.handles.main)?, (expected.dev(), expected.ino()));
        assert_eq!(fs::metadata(&live)?.ino(), expected.ino());
        // A live matching handle view alone is deliberately NOT current-file
        // permission. The future owner must compare genuine creator handles.
        files.check_live()?;
        drop(files);
        transaction.rollback()?;
        Ok(())
    }

    #[test]
    fn missing_memory_unsupported_alias_and_oversized_observations_refuse() -> Result<()> {
        for raw in [
            b"{}".as_slice(),
            b"{\"db\":null}",
            b"{\"db\":{\"h\":-1,\"vfs\":\"unix\"}}",
            b"{\"db\":{\"h\":3,\"vfs\":\"foreign\"}}",
            b"{\"db\":{\"h\":3,\"vfs\":\"unix\"},\"journal\":null}",
            b"{\"db\":{\"h\":3,\"vfs\":\"unix\",\"shm\":{\"h\":3}}}",
        ] {
            assert!(decode(raw).is_err());
        }
        assert!(decode(&vec![b' '; MAX_OBSERVATION + 1]).is_err());
        let mut memory = Connection::open_in_memory()?;
        let transaction = memory.transaction()?;
        assert!(inspect(&transaction).is_err());
        transaction.rollback()?;
        Ok(())
    }
}
