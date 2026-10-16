//! Real local descriptor controls with an explicitly unqualified test issuer.
//! Linux-only cases do not establish GKE role/volume or crash durability.

use super::*;
use crate::security_epoch::{preparation_image::tests as image_fixture, tests as epoch_fixture};
use std::time::Duration;

fn acquisition() -> NativeAcquisition {
    NativeAcquisition::fixture(
        Digest::new(b"original-file-fixture"),
        std::process::id(),
        Duration::from_secs(100),
        Duration::from_secs(5),
    )
}

fn layout() -> (
    tempfile::TempDir,
    ReviewedStorageSelection,
    ReviewedFileLayout,
    NativeAcquisition,
) {
    let (directory, runtime) = image_fixture::runtime();
    let store = epoch_fixture::selection();
    let policy = image_fixture::policy(&runtime, &store);
    let seed = OriginalSeedCore::new(&policy, &store, image_fixture::incarnations()).unwrap();
    let selection = ReviewedStorageSelection::decode(
        &serde_json::to_vec(&serde_json::json!({
            "policy":policy,"store":store,"seed":seed,
        }))
        .unwrap(),
    )
    .unwrap();
    let mut interval = acquisition();
    let plan = ReviewedFileLayout::prepare(&runtime, &selection, &mut interval).unwrap();
    (directory, selection, plan, interval)
}

#[test]
fn complete_layout_is_bound_to_the_original_selection_and_image() {
    let (_directory, selection, plan, mut interval) = layout();
    assert_eq!(plan.proposal.selection, *selection.digest());
    assert_eq!(plan.proposal.core, *selection.seed());
    assert_eq!(plan.proposal.store, *selection.store());
    assert_eq!(plan.proposal.marker, selection.seed().marker().unwrap());
    assert_eq!(plan.proposal.image, Digest::new(plan.image.bytes()));
    let db = plan
        .image
        .decode_exact_readback(plan.image.bytes(), &mut interval)
        .unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count(*) FROM day2_initial_security_seed",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn wrong_selected_schema_cannot_prepare_a_layout_or_renew_the_acquisition() {
    let (_directory, runtime) = image_fixture::runtime();
    let store = epoch_fixture::selection();
    let mut policy = image_fixture::policy(&runtime, &store);
    policy.fresh_storage.schema_contract = Digest::new(b"wrong-file-schema");
    let seed = OriginalSeedCore::new(&policy, &store, image_fixture::incarnations()).unwrap();
    let selection = ReviewedStorageSelection::decode(
        &serde_json::to_vec(&serde_json::json!({
            "policy":policy,"store":store,"seed":seed,
        }))
        .unwrap(),
    )
    .unwrap();
    let mut interval = acquisition();
    assert!(ReviewedFileLayout::prepare(&runtime, &selection, &mut interval).is_err());
    assert!(interval.remaining().is_err());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::{
        fs::{FileExt, MetadataExt, symlink},
        io::AsRawFd,
    };

    fn authority(
        directory: &tempfile::TempDir,
        selection: ReviewedStorageSelection,
        interval: &mut NativeAcquisition,
    ) -> NativeStorageCreationAuthority {
        NativeStorageCreationAuthority::filesystem_fixture(
            selection,
            File::open(directory.path()).unwrap(),
            interval,
        )
        .unwrap()
    }

    #[test]
    fn complete_exact_file_has_independent_read_only_sqlite_oracle() {
        let (directory, selected, plan, mut interval) = layout();
        let auth = authority(&directory, selected, &mut interval);
        let NativeOriginalPreparationOutcome::Prepared(owner) =
            prepare_original_file(auth, &plan, &mut interval)
        else {
            panic!("unqualified local filesystem fixture failed");
        };
        assert_eq!(owner.proposal.image, Digest::new(plan.image.bytes()));
        assert_eq!(owner.file.metadata().unwrap().ino(), owner.identity.inode);
        assert_eq!(
            owner.file.metadata().unwrap().len(),
            plan.image.bytes().len() as u64
        );
        assert_eq!(owner.file.metadata().unwrap().mode() & 0o7777, 0o600);
        assert_eq!(owner.file.metadata().unwrap().nlink(), 1);
        // This independently opens a TEST oracle after success. Production code
        // never opens/adopts an existing file or obtains readiness from it.
        let db = rusqlite::Connection::open_with_flags(
            directory.path().join(INITIAL_FILE),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        let (store, core, marker): (Vec<u8>, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT store,core,marker FROM day2_initial_security_seed WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(store, serde_json::to_vec(&owner.proposal.store).unwrap());
        assert_eq!(core, serde_json::to_vec(&owner.proposal.core).unwrap());
        assert_eq!(marker, serde_json::to_vec(&owner.proposal.marker).unwrap());
        let items: i64 = db
            .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(items, 0);
        assert!(
            db.execute(
                "INSERT INTO items(id,version,created_at,value) VALUES(1,1,0,'forbidden')",
                []
            )
            .is_err()
        );
        assert!(owner.authority.refusal.is_none());
    }

    #[test]
    fn existing_file_symlink_directory_and_hardlink_are_never_reopened_or_truncated() {
        for kind in ["file", "symlink", "directory", "hardlink"] {
            let (directory, selected, plan, mut interval) = layout();
            let old = directory.path().join("preserve.sqlite");
            std::fs::write(&old, b"persisted original bytes").unwrap();
            let leaf = directory.path().join(INITIAL_FILE);
            match kind {
                "file" => std::fs::write(&leaf, b"existing leaf").unwrap(),
                "symlink" => symlink(&old, &leaf).unwrap(),
                "directory" => std::fs::create_dir(&leaf).unwrap(),
                "hardlink" => std::fs::hard_link(&old, &leaf).unwrap(),
                _ => unreachable!(),
            }
            let auth = authority(&directory, selected, &mut interval);
            let NativeOriginalPreparationOutcome::RefusedAfterAttempt(mut owner) =
                prepare_original_file(auth, &plan, &mut interval)
            else {
                panic!("existing leaf was not refused: {kind}");
            };
            assert!(owner.file.is_none()); // No FD returned, not a noncreation claim.
            assert!(owner.phase == PreparationPhase::ExclusiveCreate);
            assert_eq!(std::fs::read(&old).unwrap(), b"persisted original bytes");
            if kind == "file" {
                assert_eq!(std::fs::read(&leaf).unwrap(), b"existing leaf");
            }
            let mut later = acquisition();
            assert!(owner.authority.check_current(&mut later).is_err());
        }
    }

    #[test]
    fn mismatched_proposal_refuses_before_any_create_and_keeps_anchor() {
        let (directory, selected, mut plan, mut interval) = layout();
        let auth = authority(&directory, selected, &mut interval);
        let anchor = auth.directory.as_raw_fd();
        plan.proposal.selection = Digest::new(b"not-the-original-selection");
        let NativeOriginalPreparationOutcome::RefusedBeforeAttempt(owner) =
            prepare_original_file(auth, &plan, &mut interval)
        else {
            panic!("mismatched proposal dispatched create");
        };
        assert!(!directory.path().join(INITIAL_FILE).exists());
        assert_eq!(owner.authority.directory.as_raw_fd(), anchor);
        assert!(owner.phase == PreparationPhase::BeforeAttempt);
        assert_eq!(owner.proposal.selection, plan.proposal.selection);
        assert!(interval.remaining().is_err());
    }

    #[test]
    fn every_after_create_error_cut_retains_the_exact_file_anchor_and_proposal() {
        for phase in [
            PreparationPhase::ExclusiveCreate,
            PreparationPhase::Write,
            PreparationPhase::FileSync,
            PreparationPhase::DirectorySync,
            PreparationPhase::Readback,
            PreparationPhase::Decode,
        ] {
            let (directory, selected, mut plan, mut interval) = layout();
            let auth = authority(&directory, selected, &mut interval);
            let anchor = auth.directory.as_raw_fd();
            plan.fixture_refusal = Some(phase);
            let NativeOriginalPreparationOutcome::RefusedAfterAttempt(mut owner) =
                prepare_original_file(auth, &plan, &mut interval)
            else {
                panic!("fixture error lost owning outcome");
            };
            assert!(owner.phase == phase);
            assert_eq!(owner.authority.directory.as_raw_fd(), anchor);
            assert_eq!(owner.proposal.image, plan.proposal.image);
            let file = owner
                .file
                .as_ref()
                .expect("returned descriptor lost on error");
            let meta = file.metadata().unwrap();
            assert_eq!(
                meta.ino(),
                std::fs::metadata(directory.path().join(INITIAL_FILE))
                    .unwrap()
                    .ino()
            );
            if phase == PreparationPhase::ExclusiveCreate {
                assert_eq!(meta.len(), 0);
            } else {
                let mut bytes = vec![0; meta.len() as usize];
                file.read_exact_at(&mut bytes, 0).unwrap();
                assert_eq!(bytes, plan.image.bytes()[..bytes.len()]);
            }
            let mut later = acquisition();
            assert!(owner.authority.check_current(&mut later).is_err());
            assert!(interval.remaining().is_err());
        }
    }

    #[test]
    fn held_descriptor_cannot_hide_replaced_leaf_added_link_or_tampered_length() {
        for change in ["replacement", "hardlink", "length"] {
            let (directory, selected, plan, mut interval) = layout();
            let auth = authority(&directory, selected, &mut interval);
            let NativeOriginalPreparationOutcome::Prepared(original) =
                prepare_original_file(auth, &plan, &mut interval)
            else {
                panic!("fixture failed");
            };
            let mut coordinator = PreparationCoordinator {
                authority: original.authority,
                proposal: original.proposal,
                file: Some(original.file),
                identity: Some(original.identity),
                phase: PreparationPhase::FinalCheck,
            };
            let file_number = coordinator.file.as_ref().unwrap().as_raw_fd();
            let inode = coordinator.file.as_ref().unwrap().metadata().unwrap().ino();
            let leaf = directory.path().join(INITIAL_FILE);
            match change {
                "replacement" => {
                    std::fs::rename(&leaf, directory.path().join("held-original.sqlite")).unwrap();
                    std::fs::write(&leaf, plan.image.bytes()).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&leaf, directory.path().join("extra.sqlite")).unwrap()
                }
                "length" => coordinator.file.as_ref().unwrap().set_len(1).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                coordinator
                    .check_file(plan.image.bytes().len(), &mut interval)
                    .is_err()
            );
            assert_eq!(coordinator.file.as_ref().unwrap().as_raw_fd(), file_number);
            assert_eq!(
                coordinator.file.as_ref().unwrap().metadata().unwrap().ino(),
                inode
            );
            coordinator.authority.refuse_preparation(&mut interval);
            assert!(
                coordinator
                    .authority
                    .check_current(&mut acquisition())
                    .is_err()
            );
        }
    }

    #[test]
    fn unchanged_initial_file_checks_keep_the_original_owner_and_budget() {
        let (directory, selected, plan, mut interval) = layout();
        let auth = authority(&directory, selected, &mut interval);
        let NativeOriginalPreparationOutcome::Prepared(mut owner) =
            prepare_original_file(auth, &plan, &mut interval)
        else {
            panic!("fixture failed");
        };
        let file = owner.file.as_raw_fd();
        let anchor = owner.authority.directory.as_raw_fd();
        owner
            .check_unchanged_initial_file(&plan, &mut interval)
            .unwrap();
        owner
            .check_unchanged_initial_file(&plan, &mut interval)
            .unwrap();
        assert_eq!(owner.file.as_raw_fd(), file);
        assert_eq!(owner.authority.directory.as_raw_fd(), anchor);
        // A test clock with the same domain and a new live interval cannot
        // renew the retained authority's original deadline at105 seconds.
        let mut later = NativeAcquisition::fixture(
            Digest::new(b"original-file-fixture"),
            std::process::id(),
            Duration::from_secs(106),
            Duration::from_secs(5),
        );
        assert!(
            owner
                .check_unchanged_initial_file(&plan, &mut later)
                .is_err()
        );
        assert!(later.remaining().is_err());
        assert!(
            owner
                .check_unchanged_initial_file(&plan, &mut interval)
                .is_err()
        );
        assert_eq!(owner.file.as_raw_fd(), file);
        assert_eq!(owner.authority.directory.as_raw_fd(), anchor);
    }

    #[test]
    fn initial_continuity_refusal_keeps_owner_after_leaf_link_mode_or_length_change() {
        for change in ["replacement", "hardlink", "mode", "length"] {
            let (directory, selected, plan, mut interval) = layout();
            let auth = authority(&directory, selected, &mut interval);
            let NativeOriginalPreparationOutcome::Prepared(mut owner) =
                prepare_original_file(auth, &plan, &mut interval)
            else {
                panic!("fixture failed");
            };
            let file = owner.file.as_raw_fd();
            let inode = owner.file.metadata().unwrap().ino();
            let anchor = owner.authority.directory.as_raw_fd();
            let leaf = directory.path().join(INITIAL_FILE);
            match change {
                "replacement" => {
                    std::fs::rename(&leaf, directory.path().join("original.sqlite")).unwrap();
                    std::fs::write(&leaf, plan.image.bytes()).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(&leaf, directory.path().join("extra.sqlite")).unwrap()
                }
                "mode" => {
                    use std::os::unix::fs::PermissionsExt;
                    owner
                        .file
                        .set_permissions(std::fs::Permissions::from_mode(0o640))
                        .unwrap();
                }
                "length" => owner.file.set_len(1).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                owner
                    .check_unchanged_initial_file(&plan, &mut interval)
                    .is_err()
            );
            assert!(
                owner
                    .check_unchanged_initial_file(&plan, &mut acquisition())
                    .is_err()
            );
            assert_eq!(owner.file.as_raw_fd(), file);
            assert_eq!(owner.file.metadata().unwrap().ino(), inode);
            assert_eq!(owner.authority.directory.as_raw_fd(), anchor);
        }
    }

    #[test]
    fn restoring_changed_initial_bytes_never_clears_the_owning_refusal() {
        let (directory, selected, plan, mut interval) = layout();
        let auth = authority(&directory, selected, &mut interval);
        let NativeOriginalPreparationOutcome::Prepared(mut owner) =
            prepare_original_file(auth, &plan, &mut interval)
        else {
            panic!("fixture failed");
        };
        let file = owner.file.as_raw_fd();
        let anchor = owner.authority.directory.as_raw_fd();
        let byte = plan.image.bytes()[100];
        owner.file.write_all_at(&[byte ^ 1], 100).unwrap();
        let error = owner
            .check_unchanged_initial_file(&plan, &mut interval)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "original_file_continuity_bytes");
        owner.file.write_all_at(&[byte], 100).unwrap();
        assert!(
            owner
                .check_unchanged_initial_file(&plan, &mut acquisition())
                .is_err()
        );
        assert_eq!(owner.file.as_raw_fd(), file);
        assert_eq!(owner.authority.directory.as_raw_fd(), anchor);
    }

    #[test]
    fn a_changed_layout_cannot_replace_the_initial_owner_or_clear_refusal() {
        let (directory, selected, mut plan, mut interval) = layout();
        let auth = authority(&directory, selected, &mut interval);
        let NativeOriginalPreparationOutcome::Prepared(mut owner) =
            prepare_original_file(auth, &plan, &mut interval)
        else {
            panic!("fixture failed");
        };
        let file = owner.file.as_raw_fd();
        let anchor = owner.authority.directory.as_raw_fd();
        let original = plan.proposal.clone();
        plan.proposal.image = Digest::new(b"replacement image");
        let error = owner
            .check_unchanged_initial_file(&plan, &mut interval)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "original_file_continuity_layout");
        assert_eq!(
            std::fs::read(directory.path().join(INITIAL_FILE)).unwrap(),
            plan.image.bytes()
        );
        plan.proposal = original;
        assert!(
            owner
                .check_unchanged_initial_file(&plan, &mut acquisition())
                .is_err()
        );
        assert_eq!(owner.file.as_raw_fd(), file);
        assert_eq!(owner.authority.directory.as_raw_fd(), anchor);
    }

    #[test]
    fn valid_sqlite_write_refuses_initial_continuity_without_claiming_serving_integrity() {
        let (directory, selected, plan, mut interval) = layout();
        let auth = authority(&directory, selected, &mut interval);
        let NativeOriginalPreparationOutcome::Prepared(mut owner) =
            prepare_original_file(auth, &plan, &mut interval)
        else {
            panic!("fixture failed");
        };
        let db = rusqlite::Connection::open(directory.path().join(INITIAL_FILE)).unwrap();
        db.execute(
            "INSERT INTO items(id,version,created_at,value) VALUES(1,1,0,'later')",
            [],
        )
        .unwrap();
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        drop(db);
        assert!(
            owner
                .check_unchanged_initial_file(&plan, &mut interval)
                .is_err()
        );
        assert!(
            owner
                .check_unchanged_initial_file(&plan, &mut acquisition())
                .is_err()
        );
        assert!(owner.file.metadata().is_ok());
    }
}
