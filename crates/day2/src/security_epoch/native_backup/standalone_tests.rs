use super::super::tests::{complete, source, writer};
use super::*;
use std::{
    io::Write,
    os::unix::fs::{FileExt, PermissionsExt},
};

fn content() -> Result<SnapshotContent> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.sqlite");
    let write = writer(&path)?;
    write.execute_batch(
        "INSERT INTO public_markers VALUES(1,11);
        CREATE TABLE payload(id INTEGER PRIMARY KEY,value BLOB);
        INSERT INTO payload VALUES(1,zeroblob(300000));",
    )?;
    let mut read = source(&path)?;
    let mut tx = read.transaction()?;
    let mut memory = super::super::MemorySnapshot::new()?;
    complete(&mut memory, &mut tx)?;
    let result = memory.finish()?;
    tx.commit()?;
    Ok(result)
}

fn copy_all(destination: &mut StandaloneSnapshot, content: SnapshotContent) -> Result<()> {
    let mut copy = destination.start(content)?;
    while copy.step()? != CopyProgress::Complete {}
    Ok(())
}

#[test]
fn raw_wal_serialization_stays_forbidden_while_real_conversion_succeeds() -> Result<()> {
    let mut source = content()?;
    let bytes = source.db.serialize(MAIN_DB)?;
    assert!(image_shape(&bytes).is_err());
    drop(bytes);
    let mut destination = StandaloneSnapshot::new()?;
    copy_all(&mut destination, source)?;
    let image = destination.finish()?;
    image_shape(&image.bytes)?;
    Ok(())
}

#[test]
fn explicit_conversion_abandonment_unwind_and_completion_misuse_are_absorbing() -> Result<()> {
    for cut in 0..4 {
        let mut destination = StandaloneSnapshot::new()?;
        match cut {
            0 => {
                drop(destination.start(content()?)?);
            }
            1 => {
                let mut copy = destination.start(content()?)?;
                assert!(copy.step()? == CopyProgress::More);
            }
            2 => {
                let caught =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                        let _copy = destination.start(content()?)?;
                        panic!("controlled_image_abandonment");
                    }));
                assert!(caught.is_err());
            }
            _ => {
                let mut copy = destination.start(content()?)?;
                while copy.step()? != CopyProgress::Complete {}
                assert!(copy.step().is_err());
            }
        }
        assert!(destination.start(content()?).is_err());
        assert!(destination.finish().is_err());
    }
    assert!(StandaloneSnapshot::new()?.finish().is_err());
    Ok(())
}

#[test]
fn replacement_or_mode_loss_cannot_be_repaired_into_the_same_conversion() -> Result<()> {
    for cut in 0..3 {
        let mut destination = StandaloneSnapshot::new()?;
        {
            let mut copy = destination.start(content()?)?;
            let path = copy.tree.path().join("app.sqlite");
            match cut {
                0 => {
                    let retained = copy.tree.path().join("held.sqlite");
                    std::fs::rename(&path, &retained)?;
                    let replacement = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)?;
                    assert!(copy.step().is_err());
                    drop(replacement);
                    std::fs::remove_file(&path)?;
                    std::fs::rename(&retained, &path)?;
                }
                1 => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
                    assert!(copy.step().is_err());
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                }
                _ => {
                    let retained = copy.tree.path().join("held.sqlite");
                    std::fs::rename(&path, &retained)?;
                    std::os::unix::fs::symlink(&retained, &path)?;
                    assert!(copy.step().is_err());
                    std::fs::remove_file(&path)?;
                    std::fs::rename(&retained, &path)?;
                }
            }
            assert!(copy.step().is_err());
        }
        assert!(destination.finish().is_err());
    }
    Ok(())
}

#[test]
fn in_place_target_write_is_detected_before_another_sqlite_step() -> Result<()> {
    let mut destination = StandaloneSnapshot::new()?;
    {
        let mut copy = destination.start(content()?)?;
        assert!(copy.step()? == CopyProgress::More);
        let previous = copy.file.metadata()?.len();
        copy.file.write_at(b"external", previous)?;
        assert!(copy.step().is_err());
        copy.file.set_len(previous)?;
        assert!(copy.step().is_err());
    }
    assert!(destination.finish().is_err());
    Ok(())
}

#[test]
fn valid_sql_mutation_is_refused_even_if_the_test_rebaselines_its_data_file_identity() -> Result<()>
{
    let mut destination = StandaloneSnapshot::new()?;
    copy_all(&mut destination, content()?)?;
    destination
        .db
        .execute("UPDATE public_markers SET value=99 WHERE id=1", [])?;
    // Test-only corruption model deliberately removes the metadata signal.
    // The independent captured-page commitment must still refuse wrong rows.
    destination
        .current
        .set(Identity::of(&destination.file.metadata()?));
    assert!(destination.finish().is_err());
    Ok(())
}

#[test]
fn page_commitment_ignores_only_documented_sqlite_bookkeeping_and_never_admits_raw_wal()
-> Result<()> {
    let image = super::super::tests::standalone(content()?)?;
    let baseline = page_contents(&image.bytes)?;
    let ignored = [18, 19, 24, 25, 26, 27, 40, 41, 42, 43, 92, 93, 94, 95];
    for at in (0..100).chain([100, 1024, image.bytes.len() - 1]) {
        let mut changed = Zeroizing::new(image.bytes.to_vec());
        changed[at] ^= 0x80;
        let actual = page_contents(&changed);
        if ignored.contains(&at) {
            assert!(actual? == baseline);
        } else {
            assert!(actual.map_or(true, |digest| digest != baseline));
        }
        if [18, 19].contains(&at) {
            assert!(image_shape(&changed).is_err());
        }
    }
    Ok(())
}

#[test]
fn a_busy_private_destination_refuses_without_retry_or_reuse() -> Result<()> {
    let mut destination = StandaloneSnapshot::new()?;
    let timeout: i64 = destination
        .db
        .pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    assert_eq!(timeout, 0, "no hidden SQLite busy-handler wait");
    let held = Connection::open_with_flags(
        destination.tree.path().join("app.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    held.busy_timeout(Duration::ZERO)?;
    held.execute_batch("BEGIN EXCLUSIVE")?;
    let failed = match destination.start(content()?) {
        Err(_) => true,
        Ok(mut copy) => copy.step().is_err(),
    };
    assert!(failed);
    held.execute_batch("ROLLBACK")?;
    assert!(destination.start(content()?).is_err());
    assert!(destination.finish().is_err());
    Ok(())
}

#[test]
fn private_creator_never_overwrites_or_follows_aliases() -> Result<()> {
    let tree = PrivateTree::new()?;
    let mut first = tree.create_file(Path::new("retained"), false)?;
    first.write_all(b"retained")?;
    assert!(tree.create_file(Path::new("retained"), false).is_err());
    assert_eq!(std::fs::read(tree.path().join("retained"))?, b"retained");
    tree.create_directory(Path::new("real"))?;
    std::os::unix::fs::symlink("real", tree.path().join("alias"))?;
    for path in [
        "../outside",
        "/absolute",
        "real/../outside",
        "real//output",
        "real/./output",
        "alias/output",
    ] {
        assert!(tree.create_file(Path::new(path), false).is_err(), "{path}");
    }
    assert!(!tree.path().join("real/output").exists());
    Ok(())
}

#[test]
fn excluded_bookkeeping_mutations_fail_the_separate_final_header_contract() -> Result<()> {
    let image = super::super::tests::standalone(content()?)?;
    // This production constructor owns a new zero-length DB with cookie0.
    conversion_header(&image.bytes, 1)?;
    let baseline = page_contents(&image.bytes)?;
    for at in [18, 19, 24, 25, 26, 27, 40, 41, 42, 43, 92, 93, 94, 95] {
        let mut changed = Zeroizing::new(image.bytes.to_vec());
        changed[at] ^= 0x80;
        assert!(page_contents(&changed)? == baseline);
        assert!(conversion_header(&changed, 1).is_err(), "offset{at}");
    }
    assert!(conversion_header(&image.bytes, 2).is_err());
    Ok(())
}

#[test]
fn sqlite_actual_opened_file_cannot_be_substituted_by_restoring_its_named_creator() -> Result<()> {
    let destination = StandaloneSnapshot::new()?;
    crate::store::NativeSqliteKeeper::require_original_main(&destination.db, &destination.file)?;
    let root = destination.tree.path();
    let original = root.join("app.sqlite");
    let saved = root.join("saved.sqlite");
    let foreign = root.join("foreign.sqlite");
    let other = Connection::open(&foreign)?;
    drop(other);
    std::fs::rename(&original, &saved)?;
    std::fs::rename(&foreign, &original)?;
    let substituted = Connection::open_with_flags(
        &original,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    std::fs::rename(&original, &foreign)?;
    std::fs::rename(&saved, &original)?;
    destination.tree.check_file(
        Path::new("app.sqlite"),
        &destination.file,
        destination.creator,
    )?;
    assert!(
        crate::store::NativeSqliteKeeper::require_original_main(&substituted, &destination.file)
            .is_err()
    );
    crate::store::NativeSqliteKeeper::require_original_main(&destination.db, &destination.file)?;
    Ok(())
}

#[test]
#[ignore = "subprocess fixture, exercised by private_creator_checks_preserve_sqlite_write_exclusion"]
fn private_creator_lock_child() -> Result<()> {
    let path = std::env::var_os("DAY2_BACKUP_CREATOR_LOCK").context("private lock child input")?;
    let expected = std::env::var("DAY2_BACKUP_CREATOR_LOCK_HELD")? == "yes";
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    db.busy_timeout(std::time::Duration::ZERO)?;
    let held = match db.execute_batch("BEGIN IMMEDIATE") {
        Ok(()) => {
            db.execute_batch("ROLLBACK")?;
            false
        }
        Err(rusqlite::Error::SqliteFailure(e, _))
            if matches!(
                e.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            true
        }
        Err(e) => return Err(e.into()),
    };
    ensure!(held == expected, "backup_test_exclusion_mismatch");
    Ok(())
}

#[test]
fn private_creator_checks_preserve_sqlite_write_exclusion() -> Result<()> {
    const CHILD: &str =
        "security_epoch::native_backup::standalone::tests::private_creator_lock_child";
    fn probe(path: &Path, held: bool) -> Result<()> {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", CHILD, "--ignored", "--test-threads=1"])
            .env("DAY2_BACKUP_CREATOR_LOCK", path)
            .env(
                "DAY2_BACKUP_CREATOR_LOCK_HELD",
                if held { "yes" } else { "no" },
            )
            .output()?;
        let text = std::str::from_utf8(&output.stdout)?;
        ensure!(
            output.status.success()
                && text.contains(&format!("test {CHILD} ... ok"))
                && text.contains("1 passed; 0 failed; 0 ignored"),
            "backup_test_exclusion_child_refused"
        );
        Ok(())
    }
    let mut target = StandaloneSnapshot::new()?;
    let path = target.tree.path().join("app.sqlite");
    probe(&path, false)?;
    {
        let mut copying = target.start(content()?)?;
        assert!(copying.step()? == CopyProgress::More);
        // This exact production check used to open/close another same-inode fd.
        copying
            .tree
            .check_file(Path::new("app.sqlite"), copying.file, copying.creator)?;
        probe(&path, true)?;
        while copying.step()? != CopyProgress::Complete {}
    }
    target.finish()?;
    Ok(())
}
