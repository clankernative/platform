//! Mechanical custody of the first SQLite connection. This resource supplies
//! no admission, immutable contents, writer exclusion or Controller read loan.
use super::{NativeSqliteKeeper, SqliteKeeperLayout, opened_files};
use anyhow::{Result, ensure};
use rusqlite::Connection;
use std::{fs::File, os::unix::fs::MetadataExt};

struct Names {
    #[cfg(test)]
    main: &'static str,
    wal: &'static str,
    shm: &'static str,
    journal: &'static str,
}

impl SqliteKeeperLayout {
    fn names(self) -> Names {
        match self {
            Self::Initial => Names {
                #[cfg(test)]
                main: "day2-initial.sqlite",
                wal: "day2-initial.sqlite-wal",
                shm: "day2-initial.sqlite-shm",
                journal: "day2-initial.sqlite-journal",
            },
            Self::Restored => Names {
                #[cfg(test)]
                main: "app.sqlite",
                wal: "app.sqlite-wal",
                shm: "app.sqlite-shm",
                journal: "app.sqlite-journal",
            },
        }
    }
}

// Only the actual App file owner calls this before the first SQLite open. A
// pre-existing sidecar is never adopted, recovered or relabelled as our birth.
pub(crate) fn require_unopened(directory: &File, layout: SqliteKeeperLayout) -> Result<()> {
    let names = layout.names();
    for name in [names.wal, names.shm, names.journal] {
        match rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => anyhow::bail!("native_sqlite_sidecar_before_birth"),
        }
    }
    Ok(())
}

fn require_main(files: &opened_files::Handles, original: &File) -> Result<()> {
    let retained = original.metadata()?;
    ensure!(
        retained.is_file()
            && retained.nlink() == 1
            && files.main.device == retained.dev()
            && files.main.inode == retained.ino(),
        "native_sqlite_main_not_original"
    );
    Ok(())
}

fn identity_number(value: impl TryInto<u64>) -> Result<u64> {
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("native_sqlite_identity_width"))
}

fn require_sidecar(
    directory: &File,
    name: &str,
    file: opened_files::Handle,
    uid: u32,
) -> Result<()> {
    let named = rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(named.st_mode) == rustix::fs::FileType::RegularFile
            && named.st_nlink == 1
            && named.st_uid == uid
            && named.st_mode & 0o077 == 0
            && identity_number(named.st_dev)? == file.device
            && identity_number(named.st_ino)? == file.inode,
        "native_sqlite_sidecar_not_retained"
    );
    Ok(())
}

impl NativeSqliteKeeper {
    /// Mechanical MAIN comparison for the actual birth loan after SQLite
    /// legitimately created sidecars. No owner or writer is returned here.
    pub(crate) fn require_original_main(db: &Connection, original: &File) -> Result<()> {
        require_main(&opened_files::held(db)?, original)
    }

    /// Inspect the first opened MAIN before configuration/schema/WAL work.
    /// The caller still supplies its actual admitted App file/phase; this is
    /// a comparison of existing resources, never a scalar-to-owner factory.
    pub(crate) fn require_creator_main(db: &Connection, original: &File) -> Result<()> {
        let files = opened_files::held(db)?;
        require_main(&files, original)?;
        ensure!(
            files.journal.is_none() && files.shm.is_none(),
            "native_sqlite_open_adopted_sidecars"
        );
        Ok(())
    }

    // Only the owning Runtime load calls this after its checked WAL activation.
    // Roll back the observation transaction: no business transaction is retained.
    pub(super) fn capture_created_files(&mut self) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.refused && self.files.is_none() && self.connection.is_autocommit(),
                "native_sqlite_keeper_already_bound"
            );
            let tx = self.connection.transaction()?;
            let files = opened_files::snapshot(&tx)?;
            ensure!(
                files.journal.is_some() && files.shm.is_some(),
                "native_sqlite_keeper_cohort_incomplete"
            );
            tx.rollback()?;
            self.files = Some(files);
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Fresh handle/path continuity only. Matching identities does NOT freeze
    /// WAL contents; a Controller read still needs the actual writer-exclusion
    /// loan and authenticated same-original lifetime, which are not added here.
    pub(crate) fn check(&mut self, directory: &File, original: &File) -> Result<()> {
        let result = (|| {
            ensure!(
                !self.refused && self.connection.is_autocommit(),
                "native_sqlite_keeper_refused_or_transaction_open"
            );
            let retained = self
                .files
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_sqlite_keeper_cohort_not_bound"))?;
            let actual = opened_files::held(&self.connection)?;
            ensure!(actual == *retained, "native_sqlite_keeper_handles_changed");
            require_main(&actual, original)?;
            let uid = original.metadata()?.uid();
            let names = self.layout.names();
            require_sidecar(
                directory,
                names.wal,
                actual
                    .journal
                    .ok_or_else(|| anyhow::anyhow!("native_sqlite_keeper_wal_missing"))?,
                uid,
            )?;
            require_sidecar(
                directory,
                names.shm,
                actual
                    .shm
                    .ok_or_else(|| anyhow::anyhow!("native_sqlite_keeper_shm_missing"))?,
                uid,
            )?;
            match rustix::fs::statat(
                directory,
                names.journal,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => anyhow::bail!("native_sqlite_unexpected_rollback_journal"),
            }
            Ok(())
        })();
        if result.is_err() {
            self.refuse();
        }
        result
    }

    /// Historical cohort DATA. The caller must keep and check the genuine App
    /// owner; this neither borrows that owner nor grants a read or writer.
    pub(crate) fn cohort_data(
        &self,
    ) -> Result<crate::security_epoch::native_enrollment::SqliteCohort> {
        ensure!(!self.refused, "native_sqlite_keeper_refused");
        opened_files::cohort(
            self.files
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("native_sqlite_keeper_cohort_not_bound"))?,
        )
    }

    /// Retain the connection even on refusal. Closing an auxiliary same-inode
    /// descriptor while another SQLite unit is alive can release its locks.
    /// Actual resource teardown follows the App owner's borrowed lifetime.
    pub(crate) fn refuse(&mut self) {
        self.refused = true;
    }
}

const _: () = {
    macro_rules! assert_not_impl {
        ($bound:path) => {{
            trait Ambiguous<T> {
                fn check() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            impl<T: ?Sized + $bound> Ambiguous<u8> for T {}
            let _ = <NativeSqliteKeeper as Ambiguous<_>>::check;
        }};
    }
    assert_not_impl!(Clone);
    assert_not_impl!(Copy);
    assert_not_impl!(Default);
    assert_not_impl!(std::fmt::Debug);
    assert_not_impl!(Send);
    assert_not_impl!(Sync);
    assert_not_impl!(serde::Serialize);
    assert_not_impl!(serde::Deserialize<'static>);
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::OpenOptionsExt, path::Path};

    // Actual SQLite resources only, with no native role/file grant fixture.
    fn opened(path: &Path, layout: SqliteKeeperLayout) -> Result<(File, NativeSqliteKeeper)> {
        let original = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let keeper = NativeSqliteKeeper {
            connection: super::super::open_existing(path)?,
            layout,
            files: None,
            refused: false,
            local: std::marker::PhantomData,
        };
        Ok((original, keeper))
    }

    fn activate(keeper: &mut NativeSqliteKeeper) -> Result<()> {
        super::super::configure_connection(&mut keeper.connection)?;
        keeper.connection.execute_batch("CREATE TABLE current_admin(email TEXT NOT NULL); INSERT INTO current_admin VALUES('old@example.test')")?;
        keeper
            .connection
            .pragma_update(None, "journal_mode", "WAL")?;
        keeper.capture_created_files()
    }

    #[test]
    fn active_main_comparison_uses_actual_first_sqlite_handle_and_refuses_a_foreign_inode()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().canonicalize()?;
        let (original, mut keeper) =
            opened(&path.join("app.sqlite"), SqliteKeeperLayout::Restored)?;
        NativeSqliteKeeper::require_creator_main(&keeper.connection, &original)?;
        activate(&mut keeper)?;
        NativeSqliteKeeper::require_original_main(&keeper.connection, &original)?;
        let foreign = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("other.sqlite"))?;
        assert!(NativeSqliteKeeper::require_original_main(&keeper.connection, &foreign).is_err());
        // A separate connection really opened on the foreign MAIN also cannot
        // impersonate the retained original. This is resource DATA only.
        let other = super::super::open_existing(&path.join("other.sqlite"))?;
        assert!(NativeSqliteKeeper::require_original_main(&other, &original).is_err());
        assert!(keeper.connection.is_autocommit());
        keeper.check(&File::open(&path)?, &original)?;
        Ok(())
    }

    #[test]
    fn first_connection_keeps_actual_sidecars_alive_without_a_business_transaction() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fixture_root = directory.path().canonicalize()?;
        let anchor = File::open(fixture_root.as_path())?;
        require_unopened(&anchor, SqliteKeeperLayout::Initial)?;
        let path = fixture_root.as_path().join("day2-initial.sqlite");
        let (original, mut keeper) = opened(&path, SqliteKeeperLayout::Initial)?;
        NativeSqliteKeeper::require_creator_main(&keeper.connection, &original)?;
        activate(&mut keeper)?;
        assert!(keeper.connection.is_autocommit());
        keeper.check(&anchor, &original)?;
        let before = opened_files::held(&keeper.connection)?;
        for _ in 0..3 {
            let mut other = super::super::open_existing(&path)?;
            let tx = other.transaction()?;
            assert_eq!(
                tx.query_row("SELECT email FROM current_admin", [], |r| r
                    .get::<_, String>(0))?,
                "old@example.test"
            );
            let actual = opened_files::snapshot(&tx)?;
            assert_eq!(
                (actual.main.device, actual.main.inode),
                (before.main.device, before.main.inode)
            );
            let observed = actual.journal.unwrap();
            let retained = before.journal.unwrap();
            assert_eq!(
                (observed.device, observed.inode),
                (retained.device, retained.inode)
            );
            let observed = actual.shm.unwrap();
            let retained = before.shm.unwrap();
            assert_eq!(
                (observed.device, observed.inode),
                (retained.device, retained.inode)
            );
            tx.rollback()?;
            other.close().map_err(|(_, e)| e)?;
            assert!(keeper.connection.is_autocommit());
            keeper.check(&anchor, &original)?;
        }
        // No connection reopen replaces the first resource. Only teardown
        // ends its cohort; this supplies no later adoption/activation path.
        Ok(())
    }

    #[test]
    fn both_fixed_layouts_keep_the_same_creator_and_auxiliary_handles_without_adoption()
    -> Result<()> {
        for layout in [SqliteKeeperLayout::Initial, SqliteKeeperLayout::Restored] {
            let directory = tempfile::tempdir()?;
            let path = directory.path().canonicalize()?;
            let anchor = File::open(&path)?;
            let names = layout.names();
            require_unopened(&anchor, layout)?;
            let (original, mut keeper) = opened(&path.join(names.main), layout)?;
            NativeSqliteKeeper::require_creator_main(&keeper.connection, &original)?;
            activate(&mut keeper)?;
            keeper.check(&anchor, &original)?;
            let before = keeper.cohort_data()?;
            // A later complete unit can share the actual retained cohort.
            // This is a mechanical test, never native writer authorization.
            let mut other = super::super::open_existing(&path.join(names.main))?;
            let tx = other.transaction()?;
            assert_eq!(
                tx.query_row("SELECT count(*) FROM current_admin", [], |row| row
                    .get::<_, i64>(0))?,
                1
            );
            let observed = opened_files::cohort(&opened_files::snapshot(&tx)?)?;
            assert!(observed == before);
            tx.rollback()?;
            other.close().map_err(|(_, error)| error)?;
            keeper.check(&anchor, &original)?;
            assert!(require_unopened(&anchor, layout).is_err());
            // Merely selecting another filename set cannot adopt the same
            // SQLite connection/cohort, nor can restoring the enum repair it.
            keeper.layout = match layout {
                SqliteKeeperLayout::Initial => SqliteKeeperLayout::Restored,
                SqliteKeeperLayout::Restored => SqliteKeeperLayout::Initial,
            };
            assert!(keeper.check(&anchor, &original).is_err());
            keeper.layout = layout;
            assert!(keeper.check(&anchor, &original).is_err());
        }
        Ok(())
    }

    #[test]
    fn either_layout_refuses_preexisting_sidecars_before_the_first_sqlite_open() -> Result<()> {
        for layout in [SqliteKeeperLayout::Initial, SqliteKeeperLayout::Restored] {
            let directory = tempfile::tempdir()?;
            let anchor = File::open(directory.path())?;
            let names = layout.names();
            for name in [names.wal, names.shm, names.journal] {
                let path = directory.path().join(name);
                fs::write(&path, b"already-owned")?;
                assert!(require_unopened(&anchor, layout).is_err());
                assert_eq!(fs::read(&path)?, b"already-owned");
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    #[test]
    fn existing_sidecar_or_another_main_cannot_supply_the_first_cohort() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fixture_root = directory.path().canonicalize()?;
        let anchor = File::open(fixture_root.as_path())?;
        for name in {
            let names = SqliteKeeperLayout::Initial.names();
            [names.wal, names.shm, names.journal]
        } {
            fs::write(fixture_root.as_path().join(name), b"foreign")?;
            assert!(require_unopened(&anchor, SqliteKeeperLayout::Initial).is_err());
            fs::remove_file(fixture_root.as_path().join(name))?;
        }
        let (original, keeper) = opened(
            &fixture_root.as_path().join("day2-initial.sqlite"),
            SqliteKeeperLayout::Initial,
        )?;
        let (foreign, other) = opened(
            &fixture_root.as_path().join("foreign.sqlite"),
            SqliteKeeperLayout::Initial,
        )?;
        NativeSqliteKeeper::require_creator_main(&keeper.connection, &original)?;
        assert!(NativeSqliteKeeper::require_creator_main(&other.connection, &original).is_err());
        assert!(NativeSqliteKeeper::require_creator_main(&keeper.connection, &foreign).is_err());
        Ok(())
    }

    #[test]
    fn sidecar_replacement_and_repair_cannot_restore_a_refused_keeper() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fixture_root = directory.path().canonicalize()?;
        let anchor = File::open(fixture_root.as_path())?;
        let (original, mut keeper) = opened(
            &fixture_root.as_path().join("day2-initial.sqlite"),
            SqliteKeeperLayout::Initial,
        )?;
        activate(&mut keeper)?;
        keeper.check(&anchor, &original)?;
        let shm = fixture_root
            .as_path()
            .join(SqliteKeeperLayout::Initial.names().shm);
        let retained = fixture_root.as_path().join("held-shm");
        fs::rename(&shm, &retained)?;
        fs::copy(&retained, &shm)?;
        assert!(keeper.check(&anchor, &original).is_err());
        fs::remove_file(&shm)?;
        fs::rename(&retained, &shm)?;
        assert!(keeper.check(&anchor, &original).is_err());
        assert!(keeper.capture_created_files().is_err());
        Ok(())
    }

    #[test]
    fn a_live_keeper_is_not_writer_exclusion_or_fresh_admin_authority() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let fixture_root = directory.path().canonicalize()?;
        let anchor = File::open(fixture_root.as_path())?;
        let path = fixture_root.as_path().join("day2-initial.sqlite");
        let (original, mut keeper) = opened(&path, SqliteKeeperLayout::Initial)?;
        activate(&mut keeper)?;
        let mut reader = super::super::open_existing(&path)?;
        let snapshot = reader.transaction()?;
        assert_eq!(
            snapshot.query_row("SELECT email FROM current_admin", [], |r| r
                .get::<_, String>(0))?,
            "old@example.test"
        );
        let mut writer = super::super::open_existing(&path)?;
        let tx = writer.transaction()?;
        tx.execute("UPDATE current_admin SET email='current@example.test'", [])?;
        tx.commit()?;
        keeper.check(&anchor, &original)?;
        // Independent expected state: the writer committed a current admin,
        // while the retained snapshot still sees the old one. All handles can
        // match. An accepting reader MUST also exclude that intervening writer.
        assert_eq!(
            writer.query_row("SELECT email FROM current_admin", [], |r| r
                .get::<_, String>(0))?,
            "current@example.test"
        );
        assert_eq!(
            snapshot.query_row("SELECT email FROM current_admin", [], |r| r
                .get::<_, String>(0))?,
            "old@example.test"
        );
        snapshot.rollback()?;
        writer.close().map_err(|(_, e)| e)?;
        reader.close().map_err(|(_, e)| e)?;
        keeper.check(&anchor, &original)?;
        Ok(())
    }

    fn load_is_first_owned_connection(source: &str) -> Result<bool> {
        use quote::ToTokens;
        let file = syn::parse_file(source)?;
        let methods = file.items.into_iter().filter_map(|item| match item {
            syn::Item::Impl(i) if matches!(&*i.self_ty, syn::Type::Path(p) if p.path.is_ident("Runtime")) => Some(i),
            _ => None,
        }).flat_map(|i| i.items).filter_map(|i| match i {
            syn::ImplItem::Fn(f) if f.sig.ident == "load_native_storage" => Some(f), _ => None,
        }).collect::<Vec<_>>();
        if methods.len() != 1 {
            return Ok(false);
        }
        let body = methods[0].block.to_token_stream().to_string();
        let ordered = [
            "current . arm (stage) ?",
            "current . begin_runtime_database (stage , & metadata) ?",
            "let mut keeper = NativeSqliteKeeper",
            "connection : open_existing (Path :: new (DATABASE)) ?",
            "let connection = & mut keeper . connection",
            "current . check_runtime_opened_database (stage , connection) ?",
            "configure_connection (connection) ?",
            "keeper . capture_created_files () ?",
            "current . retain_runtime_database (stage , keeper) ?",
            "current . finish_known (stage) ?",
            "Ok (runtime)",
        ];
        let mut prior = 0;
        for token in ordered {
            if body.matches(token).count() != 1 {
                return Ok(false);
            }
            let at = body.find(token).unwrap();
            if at < prior {
                return Ok(false);
            }
            prior = at;
        }
        Ok(!body.contains(". close (") && body.matches("open_existing (").count() == 1)
    }

    #[test]
    fn actual_runtime_load_owns_the_first_connection_through_retention_before_publication()
    -> Result<()> {
        let source = include_str!("../native_storage.rs");
        assert!(load_is_first_owned_connection(source)?);
        for (from, to) in [
            (
                "current.begin_runtime_database(stage, &metadata)?;",
                "Ok::<(), anyhow::Error>(())?;",
            ),
            (
                "current.check_runtime_opened_database(stage, connection)?;",
                "Ok::<(), anyhow::Error>(())?;",
            ),
            (
                "connection: open_existing(Path::new(DATABASE))?",
                "connection: adopted_existing_connection()?",
            ),
            (
                "let connection = &mut keeper.connection;",
                "let connection = &mut replacement.connection;",
            ),
            (
                "keeper.capture_created_files()?;",
                "Ok::<(), anyhow::Error>(())?;",
            ),
            (
                "current.retain_runtime_database(stage, keeper)?;",
                "drop(keeper);",
            ),
            (
                "current.retain_runtime_database(stage, keeper)?;",
                "current.finish_known(stage)?; current.retain_runtime_database(stage, keeper)?;",
            ),
        ] {
            assert_eq!(
                source.matches(from).count(),
                1,
                "actual source mutation target"
            );
            assert!(!load_is_first_owned_connection(&source.replace(from, to))?);
        }
        Ok(())
    }

    #[test]
    fn app_custody_is_one_attempt_and_required_before_known_load() -> Result<()> {
        use quote::ToTokens;
        fn body(source: &str, owner: &str, name: &str) -> Result<String> {
            let found=syn::parse_file(source)?.items.into_iter().filter_map(|item|match item {
                syn::Item::Impl(i) if matches!(&*i.self_ty,syn::Type::Path(p)if p.path.segments.last().is_some_and(|s|s.ident==owner))=>Some(i),_=>None,
            }).flat_map(|i|i.items).filter_map(|item|match item {syn::ImplItem::Fn(f)if f.sig.ident==name=>Some(f.block.to_token_stream().to_string()),_=>None}).collect::<Vec<_>>();
            ensure!(found.len() == 1, "actual owner method");
            Ok(found.into_iter().next().unwrap())
        }
        fn valid(source: &str) -> Result<bool> {
            let begin = body(source, "AppFileContinuity", "begin_sqlite")?;
            let retain = body(source, "AppFileContinuity", "retain_sqlite")?;
            let physical = body(source, "AppFileContinuity", "check_physical")?;
            let refuse = body(source, "AppFileContinuity", "refuse")?;
            Ok(
                begin.contains("! self . sqlite_started && self . sqlite . is_none ()")
                    && begin.matches("self . sqlite_started = true").count() == 1
                    && begin.find("self . sqlite_started = true")
                        < begin.find("require_unopened_native_sqlite")
                    && retain.contains("self . sqlite_started && self . sqlite . is_none ()")
                    && retain.contains("keeper . check (& self . directory , & self . file) ?")
                    && retain.contains("self . sqlite = Some (keeper)")
                    && retain.find("keeper . check") < retain.find("self . sqlite = Some (keeper)")
                    && physical.contains("keeper . check (& self . directory , & self . file) ?")
                    && refuse.contains("self . valid = false")
                    && refuse.contains("keeper . refuse ()"),
            )
        }
        let source = include_str!("../../security_epoch/storage_authority/preparation/app.rs");
        assert!(valid(source)?);
        for (from, to) in [
            (
                "self.sqlite_started = true;",
                "self.sqlite_started = false;",
            ),
            ("self.sqlite = Some(keeper);", "drop(keeper);"),
            (
                "keeper.check(&self.directory, &self.file)?;",
                "Ok::<(), anyhow::Error>(())?;",
            ),
        ] {
            assert!(source.contains(from));
            assert!(!valid(&source.replace(from, to))?);
        }
        let phase = include_str!("../../security_epoch/bootstrap/app_serving.rs");
        let finish = body(phase, "CurrentAppServingPhase", "finish_known")?;
        assert!(finish.contains("RuntimeServingUse :: InitialStorage"));
        assert_eq!(
            finish
                .matches("self . physical . require_sqlite (stage)")
                .count(),
            1
        );
        assert!(
            finish.find("self . physical . require_sqlite")
                < finish.find("self . disposition = ServingDisposition :: Known")
        );
        Ok(())
    }
}
