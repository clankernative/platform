use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

#[test]
fn snapshot_rejects_aliases_and_incomplete_or_inconsistent_trees() {
    for relative in [
        "",
        "pages//index.html",
        "pages/./index.html",
        "pages/../index.html",
        "pages/",
        "/index.html",
        "pages\\index.html",
    ] {
        let snapshot = UiSnapshot {
            files: BTreeMap::from([(relative.into(), vec![])]),
            directories: BTreeSet::from(["pages".into()]),
        };
        assert!(snapshot.validate().is_err(), "{relative}");
    }
    let mut snapshot = UiSnapshot {
        files: BTreeMap::from([("pages/index.html".into(), vec![])]),
        directories: BTreeSet::new(),
    };
    assert!(snapshot.validate().is_err());
    snapshot.directories.insert("pages".into());
    snapshot.validate().unwrap();
    snapshot.files.insert("pages".into(), vec![]);
    assert!(snapshot.validate().is_err());
    snapshot.files.remove("pages");
    snapshot.directories.insert("pages//nested".into());
    assert!(snapshot.validate().is_err());
    let oversized = "x".repeat(256);
    let snapshot = UiSnapshot {
        files: BTreeMap::from([(oversized.clone(), vec![])]),
        directories: BTreeSet::new(),
    };
    assert!(snapshot.validate().is_err());
    assert!(UiSnapshot::default().check_output(&oversized).is_err());
}

#[test]
fn real_capture_and_copy_keep_the_original_entry_budget_before_sorting() {
    let temp = tempfile::tempdir().unwrap();
    let ui = temp.path().join("ui");
    fs::create_dir(&ui).unwrap();
    for index in (0..MAX_FILES).rev() {
        fs::write(ui.join(format!("{index:04}.txt")), []).unwrap();
    }
    let mut publication = FilePublication {
        captured: temp.path(),
    };
    let snapshot = publication.capture().unwrap();
    assert_eq!(snapshot.files.len(), MAX_FILES);
    let mut count = 0;
    let entries = publication::ordered_entries(&ui, &mut count).unwrap();
    assert_eq!(count, MAX_FILES);
    assert!(
        entries
            .windows(2)
            .all(|pair| pair[0].file_name() < pair[1].file_name())
    );
    copy_tree_checked(&ui, &temp.path().join("copy")).unwrap();
    // Directories, not just files, consume the same global budget.
    fs::create_dir(ui.join("extra-directory")).unwrap();
    count = 0;
    assert!(publication::ordered_entries(&ui, &mut count).is_err());
    assert_eq!(count, MAX_FILES + 1);
    assert!(publication.capture().is_err());
    assert!(copy_tree_checked(&ui, &temp.path().join("overflow-copy")).is_err());
}

#[test]
fn real_capture_retains_ui_file_budget_but_claimed_inputs_use_max_file() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("ui")).unwrap();
    let bytes = vec![0; MAX_UI_FILE];
    fs::write(temp.path().join("ui/image.bin"), &bytes).unwrap();
    let mut publication = FilePublication {
        captured: temp.path(),
    };
    let snapshot = publication.capture().unwrap();
    assert_eq!(snapshot.files["image.bin"].len(), MAX_UI_FILE);
    assert!(snapshot.input("image.bin").is_err());
    let oversized = fs::OpenOptions::new()
        .write(true)
        .open(temp.path().join("ui/image.bin"))
        .unwrap();
    oversized.set_len(MAX_UI_FILE as u64 + 1).unwrap();
    assert!(publication.capture().is_err());
    fs::write(temp.path().join("ui/image.bin"), &bytes).unwrap();
    for index in 0..4 {
        fs::write(temp.path().join(format!("ui/{index}.bin")), &bytes).unwrap();
    }
    assert!(
        publication.capture().is_err(),
        "aggregate byte budget must not widen"
    );
}

#[test]
fn real_publication_revalidates_unused_files_and_consumed_sources_before_any_write() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("ui/pages")).unwrap();
    fs::write(temp.path().join("ui/pages/index.html"), b"source").unwrap();
    fs::write(temp.path().join("ui/unused.js"), b"unused").unwrap();
    fs::write(temp.path().join("ui/source.txt"), b"consumed").unwrap();
    let mut publication = FilePublication {
        captured: temp.path(),
    };
    let snapshot = publication.capture().unwrap();
    let plan = PublicationPlan {
        writes: BTreeMap::from([
            ("pages/index.html".into(), b"expanded".to_vec()),
            ("nested/assets/new.css".into(), b"style".to_vec()),
        ]),
        removes: BTreeSet::from(["source.txt".into()]),
    };
    for tampered in ["unused.js", "source.txt"] {
        fs::write(temp.path().join("ui").join(tampered), b"tampered").unwrap();
        assert!(publication.publish(&snapshot, &plan).is_err());
        assert_eq!(
            fs::read(temp.path().join("ui/pages/index.html")).unwrap(),
            b"source"
        );
        assert!(!temp.path().join("ui/nested/assets/new.css").exists());
        assert!(temp.path().join("ui/source.txt").exists());
        fs::write(
            temp.path().join("ui").join(tampered),
            &snapshot.files[tampered],
        )
        .unwrap();
    }
    publication.publish(&snapshot, &plan).unwrap();
    assert_eq!(
        fs::read(temp.path().join("ui/pages/index.html")).unwrap(),
        b"expanded"
    );
    assert_eq!(
        fs::read(temp.path().join("ui/nested/assets/new.css")).unwrap(),
        b"style"
    );
    assert!(!temp.path().join("ui/source.txt").exists());
}

#[cfg(unix)]
#[test]
fn real_capture_rejects_links_including_unused_files_and_the_ui_root() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("ui")).unwrap();
    symlink("missing", temp.path().join("ui/unused.js")).unwrap();
    assert!(
        FilePublication {
            captured: temp.path()
        }
        .capture()
        .is_err()
    );
    fs::remove_file(temp.path().join("ui/unused.js")).unwrap();
    fs::remove_dir(temp.path().join("ui")).unwrap();
    fs::create_dir(temp.path().join("other")).unwrap();
    symlink("other", temp.path().join("ui")).unwrap();
    assert!(
        FilePublication {
            captured: temp.path()
        }
        .capture()
        .is_err()
    );
}

#[test]
fn real_staging_failure_leaves_the_valid_private_capture_untouched() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("ui")).unwrap();
    fs::write(temp.path().join("ui/app.css"), b"source").unwrap();
    let snapshot = FilePublication {
        captured: temp.path(),
    }
    .capture()
    .unwrap();
    let plan = PublicationPlan {
        writes: BTreeMap::from([("app.css".into(), b"expanded".to_vec())]),
        removes: BTreeSet::new(),
    };
    let unavailable = temp.path().join("unavailable");
    fs::write(&unavailable, b"not a staging directory").unwrap();
    assert!(
        FilePublication {
            captured: Path::new(&unavailable)
        }
        .publish(&snapshot, &plan)
        .is_err()
    );
    assert_eq!(
        FilePublication {
            captured: temp.path()
        }
        .capture()
        .unwrap(),
        snapshot
    );
}
