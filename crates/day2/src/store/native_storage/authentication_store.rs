//! Mechanical SQLite half of the fixed native authentication-store admission.
//! Neither an ordinary Connection nor PRAGMA output supplies native permission.
use super::opened_files;
use crate::security_epoch::AuthenticationStoreFiles;
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags};

fn compare(
    files: &mut AuthenticationStoreFiles,
    connection: &Connection,
    complete: bool,
) -> Result<()> {
    let actual = opened_files::held(connection)?;
    files.require_opened(
        (actual.main.fd, actual.main.device, actual.main.inode),
        actual
            .journal
            .map(|file| (file.fd, file.device, file.inode)),
        actual.shm.map(|file| (file.fd, file.device, file.inode)),
        complete,
    )
}

/// Factory, not a connection getter. The unconstructible native file owner is
/// already held before open and is retained by the consuming action afterwards.
pub(crate) fn open_authentication_sqlite(
    files: &mut AuthenticationStoreFiles,
) -> Result<Box<Connection>> {
    files.check()?;
    let path = files.path()?;
    let mut connection = open_existing(&path)?;
    // Compare the VFS's actual MAIN before ANY configuration or schema read.
    compare(files, &connection, false)?;
    configure_existing(&mut connection)?;
    // No explicit BEGIN, schema initialization or mode switch. Every actual
    // present sidecar must join its retained native named-file pin.
    files.capture_cohort()?;
    compare(files, &connection, true)?;
    Ok(Box::new(connection))
}

fn open_existing(path: &std::path::Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

fn configure_existing(connection: &mut Connection) -> Result<()> {
    super::configure_connection(connection)?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    ensure!(
        journal.eq_ignore_ascii_case("wal"),
        "restore_auth_wal_required"
    );
    let synchronous: u32 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    ensure!(synchronous == 2, "restore_auth_full_required");
    ensure!(
        connection.is_autocommit(),
        "restore_auth_activation_transaction_open"
    );
    Ok(())
}

pub(crate) fn check_authentication_sqlite(
    files: &mut AuthenticationStoreFiles,
    connection: &Connection,
) -> Result<()> {
    compare(files, connection, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_rw_open_never_creates_or_follows_a_main_symlink() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let absent = directory.path().join("absent.sqlite");
        assert!(open_existing(&absent).is_err());
        assert!(!absent.exists());
        let actual = directory.path().join("actual.sqlite");
        let db = Connection::open(&actual)?;
        db.execute_batch("CREATE TABLE actual(value INTEGER)")?;
        let link = directory.path().join("link.sqlite");
        std::os::unix::fs::symlink(&actual, &link)?;
        assert!(open_existing(&link).is_err());
        let memory = directory.path().join("file:missing?mode=memory");
        assert!(open_existing(&memory).is_err());
        Ok(())
    }

    #[test]
    fn existing_profile_admission_refuses_journal_mode_without_switching_it() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("ledger.sqlite");
        let creator = Connection::open(&path)?;
        creator.execute_batch("CREATE TABLE ledger(value INTEGER)")?;
        let mut db = open_existing(&path)?;
        assert!(configure_existing(&mut db).is_err());
        let mode: String = db.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        assert_eq!(mode, "delete");
        drop(db);
        creator.pragma_update(None, "journal_mode", "WAL")?;
        let mut db = open_existing(&path)?;
        configure_existing(&mut db)?;
        let actual = opened_files::held(&db)?;
        assert!(actual.main.inode > 0);
        Ok(())
    }

    #[test]
    fn real_auth_connection_transaction_state_is_not_an_app_reader_flag() -> Result<()> {
        let auth = Connection::open_in_memory()?;
        let app = Connection::open_in_memory()?;
        assert!(auth.is_autocommit() && app.is_autocommit());
        auth.execute_batch("BEGIN")?;
        assert!(!auth.is_autocommit());
        assert!(app.is_autocommit());
        auth.execute_batch("ROLLBACK")?;
        assert!(auth.is_autocommit());
        Ok(())
    }
    #[test]
    fn actual_adapter_forwards_actual_vfs_fd_and_file_identity_for_every_member() {
        use quote::ToTokens;
        fn wired(source: &str) -> bool {
            let Ok(file) = syn::parse_file(source) else {
                return false;
            };
            let Some(compare) = file.items.iter().find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "compare" => Some(item),
                _ => None,
            }) else {
                return false;
            };
            let expected: syn::Block = syn::parse_quote!({
                let actual = opened_files::held(connection)?;
                files.require_opened(
                    (actual.main.fd, actual.main.device, actual.main.inode),
                    actual
                        .journal
                        .map(|file| (file.fd, file.device, file.inode)),
                    actual.shm.map(|file| (file.fd, file.device, file.inode)),
                    complete,
                )
            });
            compare.block.to_token_stream().to_string() == expected.to_token_stream().to_string()
        }
        let source = include_str!("authentication_store.rs");
        assert!(wired(source));
        let normalized = syn::parse_file(source)
            .unwrap()
            .to_token_stream()
            .to_string();
        for (old, new) in [
            ("actual . main . fd", "0"),
            ("file . fd", "0"),
            (
                "opened_files :: held (connection)",
                "unobserved (connection)",
            ),
        ] {
            let mutant = normalized.replacen(old, new, 1);
            assert_ne!(normalized, mutant);
            assert!(!wired(&mutant));
        }
    }
}
