use super::*;
use anyhow::bail;
use std::{cell::Cell, os::unix::fs::symlink, rc::Rc};

pub(super) struct Schedule {
    checks: usize,
    now: u64,
    latest: u64,
    deadline: u64,
    pub(super) refused: bool,
    change: Option<(usize, Change)>,
}

enum Change {
    Time(u64),
    Replace(PathBuf),
    Grow(PathBuf),
    Overwrite(PathBuf),
    Unlink(PathBuf),
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            checks: 0,
            now: 1,
            latest: 0,
            deadline: 1_000_000_000,
            refused: false,
            change: None,
        }
    }
}

impl Schedule {
    pub(super) fn expire_on(cut: usize) -> Self {
        let mut schedule = Self::default();
        schedule.change = Some((cut, Change::Time(schedule.deadline)));
        schedule
    }

    pub(super) fn check_count(&self) -> usize {
        self.checks
    }

    pub(super) fn check(&mut self) -> Result<()> {
        if self.refused {
            bail!("fixture_capture_refused");
        }
        self.checks += 1;
        if self
            .change
            .as_ref()
            .is_some_and(|(cut, _)| *cut == self.checks)
        {
            let (_, change) = self.change.take().unwrap();
            match change {
                Change::Time(now) => self.now = now,
                Change::Replace(path) => {
                    std::fs::rename(&path, path.with_extension("old"))?;
                    std::fs::write(path, b"wrong-world")?;
                }
                Change::Grow(path) => {
                    OpenOptions::new()
                        .append(true)
                        .open(path)?
                        .write_all(b"growth")?;
                }
                Change::Unlink(path) => std::fs::remove_file(path)?,
                Change::Overwrite(path) => std::fs::write(path, b"changed")?,
            }
        }
        if self.now < self.latest || self.now >= self.deadline {
            self.refused = true;
            bail!("fixture_capture_clock_refused");
        }
        self.latest = self.now;
        Ok(())
    }

    pub(super) fn remaining(&mut self) -> Result<Duration> {
        self.check()?;
        Ok(Duration::from_nanos(self.deadline - self.now))
    }
}

fn root(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(i32::try_from(
            (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits(),
        )?)
        .open(path)?)
}

#[test]
fn same_captured_file_is_exact_and_remains_independent_of_later_path_replacement() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let bytes = vec![19; CHUNK + 17];
    std::fs::write(directory.path().join("image"), &bytes)?;
    let mut schedule = Schedule::default();
    let captured = read_file(
        &mut Capture::Fixture(&mut schedule),
        &root(directory.path())?,
        "image",
        MAX_BYTES,
    )?;
    assert_eq!(&captured.bytes[..], &bytes);
    std::fs::remove_file(directory.path().join("image"))?;
    std::fs::write(directory.path().join("image"), b"replacement")?;
    assert_eq!(Digest::new(&captured.bytes[..]), Digest::new(&bytes));
    Ok(())
}

#[test]
fn real_descriptor_capture_rejects_symlink_hardlink_oversize_and_special_members() -> Result<()> {
    for fault in 0..4 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("image");
        match fault {
            0 => {
                std::fs::write(directory.path().join("other"), b"bytes")?;
                symlink("other", &path)?;
            }
            1 => {
                std::fs::write(&path, b"bytes")?;
                std::fs::hard_link(&path, directory.path().join("alias"))?;
            }
            2 => {
                File::create(&path)?.set_len(17)?;
            }
            3 => {
                std::fs::create_dir(&path)?;
            }
            _ => unreachable!(),
        }
        let mut schedule = Schedule::default();
        assert!(
            read_file(
                &mut Capture::Fixture(&mut schedule),
                &root(directory.path())?,
                "image",
                16
            )
            .is_err()
        );
        assert!(schedule.refused);
    }
    Ok(())
}

#[test]
fn replacement_growth_and_unlink_during_real_chunked_read_cannot_publish_changed_bytes()
-> Result<()> {
    for fault in 0..3 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("image");
        let expected = vec![7; CHUNK * 2 + 1];
        std::fs::write(&path, &expected)?;
        let change = match fault {
            0 => Change::Replace(path),
            1 => Change::Grow(path),
            _ => Change::Unlink(path),
        };
        // After the retained FD and first chunk, before the next actual read.
        let mut schedule = Schedule {
            change: Some((5, change)),
            ..Schedule::default()
        };
        let result = read_file(
            &mut Capture::Fixture(&mut schedule),
            &root(directory.path())?,
            "image",
            MAX_BYTES,
        );
        assert!(result.is_err());
        assert!(schedule.refused);
        assert!(schedule.check().is_err());
    }
    Ok(())
}

#[test]
fn directory_capture_is_bounded_and_rejects_symlink_recursion() -> Result<()> {
    for fault in 0..3 {
        let directory = tempfile::tempdir()?;
        match fault {
            0 => {
                symlink(".", directory.path().join("cycle"))?;
            }
            1 => {
                std::fs::create_dir_all(directory.path().join("a/b/c/d/e/f/g/h/i"))?;
            }
            2 => {
                File::create(directory.path().join("large"))?.set_len(ARTIFACT_FILE_BYTES + 1)?;
            }
            _ => unreachable!(),
        }
        let mut schedule = Schedule::default();
        let mut files = BTreeMap::new();
        let mut directories = BTreeMap::new();
        assert!(
            read_tree(
                &mut Capture::Fixture(&mut schedule),
                &root(directory.path())?,
                Path::new(""),
                0,
                &mut TreeBudget {
                    count: &mut 0,
                    bytes: &mut 0
                },
                &mut files,
                &mut directories
            )
            .is_err()
        );
        // The outer native capture owns and terminally drops its actual
        // executor even for a pure bounds/layout refusal, before publication.
    }
    Ok(())
}

#[test]
fn directory_capture_keeps_one_cumulative_budget_across_siblings() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for (child, bytes) in [("a", b"x".as_slice()), ("b", b"yz".as_slice())] {
        std::fs::create_dir(directory.path().join(child))?;
        std::fs::write(directory.path().join(child).join("file"), bytes)?;
    }
    // Two directories plus two files, and three bytes in total. Start near
    // both independent ceilings so resetting either counter in a child loses.
    for (entry_headroom, byte_headroom, expected) in [(4, 3, true), (3, 3, false), (4, 2, false)] {
        let mut count = MAX_ENTRIES - entry_headroom;
        let mut bytes = ARTIFACT_BYTES - byte_headroom;
        let mut files = BTreeMap::new();
        let mut directories = BTreeMap::new();
        let mut schedule = Schedule::default();
        let result = read_tree(
            &mut Capture::Fixture(&mut schedule),
            &root(directory.path())?,
            Path::new(""),
            0,
            &mut TreeBudget {
                count: &mut count,
                bytes: &mut bytes,
            },
            &mut files,
            &mut directories,
        );
        assert_eq!(result.is_ok(), expected);
        if expected {
            assert_eq!(count, MAX_ENTRIES);
            assert_eq!(bytes, ARTIFACT_BYTES);
            assert_eq!(files.len(), 2);
            assert_eq!(directories.len(), 2);
            assert_eq!(&files[Path::new("a/file")].bytes[..], b"x");
            assert_eq!(&files[Path::new("b/file")].bytes[..], b"yz");
        }
    }
    Ok(())
}

#[test]
fn captured_private_file_identity_refuses_replacement_even_with_equal_content() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("worker");
    std::fs::write(&path, b"same bytes")?;
    let file = File::open(&path)?;
    let held = BTreeMap::from([(
        PathBuf::from("worker"),
        HeldFile {
            identity: Identity::of(&file.metadata()?),
            file,
        },
    )]);
    check_captured_files(directory.path(), &held)?;
    std::fs::rename(&path, directory.path().join("old"))?;
    std::fs::write(&path, b"same bytes")?;
    assert!(check_captured_files(directory.path(), &held).is_err());
    Ok(())
}

#[test]
fn fresh_worker_budget_shrinks_and_clock_repair_cannot_regrant() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let files = BTreeMap::new();
    let tree = CapturedTree::pin(directory.path(), files)?;
    let mut schedule = Schedule {
        deadline: 100,
        now: 10,
        ..Schedule::default()
    };
    assert_eq!(
        Capture::Fixture(&mut schedule).worker_remaining()?,
        Duration::from_nanos(90)
    );
    schedule.now = 75;
    assert_eq!(
        Capture::Fixture(&mut schedule).worker_remaining()?,
        Duration::from_nanos(25)
    );
    schedule.now = 100;
    assert!(
        RestoreArtifactAdmission {
            capture: &mut Capture::Fixture(&mut schedule),
            tree: &tree,
            worker: None
        }
        .check()
        .is_err()
    );
    schedule.now = 76;
    assert!(Capture::Fixture(&mut schedule).worker_remaining().is_err());
    Ok(())
}

#[derive(Debug)]
struct Primary;
impl std::fmt::Display for Primary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("capture_primary")
    }
}
impl std::error::Error for Primary {}

struct ChildLifetime(Rc<Cell<bool>>);
impl Drop for ChildLifetime {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[test]
fn worker_postcheck_runs_on_primary_error_and_drops_successful_result_before_refusal_escapes()
-> Result<()> {
    for primary in [false, true] {
        let directory = tempfile::tempdir()?;
        let files = BTreeMap::new();
        let tree = CapturedTree::pin(directory.path(), files)?;
        let mut schedule = Schedule {
            now: 100,
            deadline: 100,
            ..Schedule::default()
        };
        let dropped = Rc::new(Cell::new(false));
        let requested = if primary {
            Err(anyhow::Error::new(Primary))
        } else {
            Ok(ChildLifetime(Rc::clone(&dropped)))
        };
        let result = RestoreArtifactAdmission {
            capture: &mut Capture::Fixture(&mut schedule),
            tree: &tree,
            worker: None,
        }
        .finish(requested);
        assert!(result.is_err());
        assert!(schedule.refused);
        assert_eq!(schedule.checks, 1);
        if primary {
            assert!(result.err().unwrap().is::<Primary>());
        } else {
            assert!(dropped.get());
        }
    }
    Ok(())
}

#[test]
fn independent_model_checks_real_capture_pre_post_and_primary_error_selection() -> Result<()> {
    // This oracle tracks a separately specified synchronous unit: fresh pre,
    // the actual operation once, unconditional fresh post, primary precedence.
    // It exercises Capture::observe, not a second copy of its implementation.
    for seed in 0..64_u64 {
        let mut random = seed + 1;
        let mut previous = 0;
        let mut model_refused = false;
        let mut actual = Schedule {
            deadline: 100,
            ..Schedule::default()
        };
        for step in 0..12 {
            random = random
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let pre = if step < 3 {
                step * 4 + 1
            } else {
                (random >> 32) % 121
            };
            let post = if step < 3 {
                pre + 1
            } else {
                (random >> 24) % 121
            };
            let primary = random & 3 == 0;
            let pre_allowed = !model_refused && pre >= previous && pre < 100;
            let post_allowed = pre_allowed && post >= pre && post < 100;
            let expected_ok = post_allowed && !primary;
            model_refused |= !expected_ok;
            if post_allowed {
                previous = post;
            }
            actual.now = pre;
            actual.change = Some((actual.checks + 2, Change::Time(post)));
            let mut entered = false;
            let result = Capture::Fixture(&mut actual).observe(|| {
                entered = true;
                if primary {
                    Err(anyhow::Error::new(Primary))
                } else {
                    Ok(())
                }
            });
            assert_eq!(entered, pre_allowed, "seed={seed},step={step}");
            assert_eq!(result.is_ok(), expected_ok, "seed={seed},step={step}");
            assert_eq!(actual.refused, model_refused, "seed={seed},step={step}");
            if pre_allowed && primary {
                assert!(result.err().unwrap().is::<Primary>());
            }
        }
    }
    Ok(())
}

#[test]
fn expiry_between_read_and_postcheck_never_returns_partial_capture() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("image"), vec![1; CHUNK + 1])?;
    let mut schedule = Schedule {
        deadline: 100,
        change: Some((4, Change::Time(100))),
        ..Schedule::default()
    };
    assert!(
        read_file(
            &mut Capture::Fixture(&mut schedule),
            &root(directory.path())?,
            "image",
            MAX_BYTES
        )
        .is_err()
    );
    assert!(schedule.refused);
    schedule.now = 50;
    assert!(schedule.check().is_err());
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn real_worker_fixture(directory: &Path) -> Result<(LoadedArtifact, BTreeMap<PathBuf, HeldFile>)> {
    // An actual child lifetime, deliberately NOT a compiled/admitted app. The
    // fixture-only contract constructor cannot construct Native Capture.
    let bytes = std::fs::read("/bin/cat")?;
    let path = directory.join("worker");
    std::fs::write(&path, &bytes)?;
    let file = File::open(path)?;
    let files = BTreeMap::from([(
        PathBuf::from("worker"),
        HeldFile {
            identity: Identity::of(&file.metadata()?),
            file,
        },
    )]);
    let contract = serde_json::from_value(serde_json::json!({
        "format":1,"verification_limits":crate::artifact::VerificationLimits::QUALIFIED,
        "roc_version":"fixture","worker_digest":crate::digest(&bytes),
        "schema_digest":"fixture","schema":{"models":{},"inputs":{},"foreign_keys":[]},
        "operations":[],"sources":{},"admission":"local-spike-only"
    }))?;
    Ok((
        LoadedArtifact::from_contract_for_tests("fixture".into(), directory.into(), contract),
        files,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn actual_child_cannot_escape_failed_spawn_postcheck_or_expired_exchange_entry() -> Result<()> {
    for at_spawn in [false, true] {
        let directory = tempfile::tempdir()?;
        let (artifact, files) = real_worker_fixture(directory.path())?;
        let tree = CapturedTree::pin(directory.path(), files)?;
        let mut schedule = Schedule {
            deadline: 100,
            change: at_spawn.then_some((2, Change::Time(100))),
            ..Schedule::default()
        };
        let mut capture = Capture::Fixture(&mut schedule);
        let mut guard = RestoreArtifactAdmission {
            capture: &mut capture,
            tree: &tree,
            worker: None,
        };
        if at_spawn {
            assert!(guard.start(&artifact).is_err());
            assert!(guard.worker.is_none());
        } else {
            let executable = guard.start(&artifact)?;
            assert!(guard.worker.is_some());
            assert!(executable.exists());
            let Capture::Fixture(schedule) = &mut *guard.capture else {
                unreachable!()
            };
            schedule.now = 100;
            assert!(guard.exchange(crate::artifact::ContractQuery::App).is_err());
            assert!(guard.worker.is_none());
        }
        assert!(schedule.refused);
    }
    Ok(())
}

#[test]
fn private_capture_tree_refuses_unlisted_member_and_directory_alias() -> Result<()> {
    for alias in [false, true] {
        let directory = tempfile::tempdir()?;
        let owned = directory.path().join("owned");
        std::fs::create_dir(&owned)?;
        std::fs::write(owned.join("worker"), b"captured")?;
        let file = File::open(owned.join("worker"))?;
        let files = BTreeMap::from([(
            PathBuf::from("worker"),
            HeldFile {
                identity: Identity::of(&file.metadata()?),
                file,
            },
        )]);
        let tree = CapturedTree::pin(&owned, files)?;
        if alias {
            let retained = directory.path().join("retained");
            std::fs::rename(&owned, &retained)?;
            symlink(&retained, &owned)?;
        } else {
            std::fs::write(owned.join("unlisted"), b"uncommitted")?;
        }
        assert!(tree.check().is_err());
    }
    Ok(())
}

fn manifest_fixture() -> Result<Manifest> {
    let artifact = Digest::new(b"artifact");
    let database = Digest::new(b"database");
    Ok(serde_json::from_value(serde_json::json!({
        "format":3,"scope":"installation/environment/app","artifact":artifact,"database":database,
        "rollout_artifacts":null,"companion_state":{},"app":"app",
        "authority":{"epoch":"historical-sql-identity","revision":1},
        "instance":{"installation":"installation","environment":"environment","apps":{
            "app":{"artifact":format!("artifacts/{}",day2_assets::hash_part(artifact.as_str())?),"readers":[],"writers":[]}
        }}
    }))?)
}

#[test]
fn complete_capture_commitment_matches_independent_wire_vector_and_is_not_manifest_digest()
-> Result<()> {
    let manifest = manifest_fixture()?;
    let semantic = manifest.security_restore_digest()?;
    let raw_manifest = serde_json::to_vec(&manifest)?;
    let sqlite = b"database";
    let worker = b"worker";
    let manifest_sha = Digest::new(&raw_manifest);
    let sqlite_sha = Digest::new(sqlite);
    let worker_sha = Digest::new(worker);
    let inventory = BTreeMap::from([
        (String::new(), ArchiveMember::Directory { mode: 448 }),
        (
            "app.sqlite".into(),
            ArchiveMember::File {
                bytes: 8,
                sha256: sqlite_sha.clone(),
                mode: 384,
            },
        ),
        ("artifacts".into(), ArchiveMember::Directory { mode: 448 }),
        (
            "artifacts/example".into(),
            ArchiveMember::Directory { mode: 448 },
        ),
        (
            "artifacts/example/worker".into(),
            ArchiveMember::File {
                bytes: 6,
                sha256: worker_sha.clone(),
                mode: 320,
            },
        ),
        (
            "backup.json".into(),
            ArchiveMember::File {
                bytes: raw_manifest.len() as u64,
                sha256: manifest_sha.clone(),
                mode: 384,
            },
        ),
    ]);
    // Fixed external wire schema/order; no production inventory encoder call.
    let wire = format!(
        r#"["day2-native-restore-archive-v1","sqlite-current-artifact-only","{semantic}",{{"":{{"kind":"directory","mode":448}},"app.sqlite":{{"kind":"file","bytes":8,"sha256":"{sqlite_sha}","mode":384}},"artifacts":{{"kind":"directory","mode":448}},"artifacts/example":{{"kind":"directory","mode":448}},"artifacts/example/worker":{{"kind":"file","bytes":6,"sha256":"{worker_sha}","mode":320}},"backup.json":{{"kind":"file","bytes":{},"sha256":"{manifest_sha}","mode":384}}}}]"#,
        raw_manifest.len(),
        semantic = semantic.as_str(),
        sqlite_sha = sqlite_sha.as_str(),
        worker_sha = worker_sha.as_str(),
        manifest_sha = manifest_sha.as_str()
    );
    let expected = Digest::new(wire.as_bytes());
    assert_eq!(full_archive_commitment(&manifest, &inventory)?, expected);
    assert_ne!(expected, semantic);
    Ok(())
}

#[test]
fn raw_manifest_mode_empty_directory_database_and_artifact_changes_require_distinct_approval()
-> Result<()> {
    let manifest = manifest_fixture()?;
    let compact = serde_json::to_vec(&manifest)?;
    let pretty = serde_json::to_vec_pretty(&manifest)?;
    assert_ne!(compact, pretty);
    let same_manifest: Manifest = serde_json::from_slice(&pretty)?;
    assert_eq!(
        same_manifest.security_restore_digest()?,
        manifest.security_restore_digest()?
    );
    let build = || {
        BTreeMap::from([
            (String::new(), ArchiveMember::Directory { mode: 448 }),
            (
                "backup.json".into(),
                ArchiveMember::File {
                    bytes: compact.len() as u64,
                    sha256: Digest::new(&compact),
                    mode: 384,
                },
            ),
            (
                "app.sqlite".into(),
                ArchiveMember::File {
                    bytes: 8,
                    sha256: Digest::new(b"database"),
                    mode: 384,
                },
            ),
            (
                "artifacts/example/worker".into(),
                ArchiveMember::File {
                    bytes: 6,
                    sha256: Digest::new(b"worker"),
                    mode: 320,
                },
            ),
        ])
    };
    let approved = full_archive_commitment(&manifest, &build())?;
    for changed in 0..5 {
        let mut members = build();
        match changed {
            0 => {
                members.insert(
                    "backup.json".into(),
                    ArchiveMember::File {
                        bytes: pretty.len() as u64,
                        sha256: Digest::new(&pretty),
                        mode: 384,
                    },
                );
            }
            1 => {
                members.insert(
                    "artifacts/example/worker".into(),
                    ArchiveMember::File {
                        bytes: 6,
                        sha256: Digest::new(b"worker"),
                        mode: 384,
                    },
                );
            }
            2 => {
                members.insert(
                    "artifacts/example/empty".into(),
                    ArchiveMember::Directory { mode: 448 },
                );
            }
            3 => {
                members.insert(
                    "app.sqlite".into(),
                    ArchiveMember::File {
                        bytes: 8,
                        sha256: Digest::new(b"wrong-db"),
                        mode: 384,
                    },
                );
            }
            4 => {
                members.insert(
                    "artifacts/example/worker".into(),
                    ArchiveMember::File {
                        bytes: 6,
                        sha256: Digest::new(b"other!"),
                        mode: 320,
                    },
                );
            }
            _ => unreachable!(),
        }
        assert_ne!(
            full_archive_commitment(&manifest, &members)?,
            approved,
            "change={changed}"
        );
    }
    Ok(())
}

#[test]
fn complete_native_root_refuses_declared_or_unlisted_sidecars_and_extra_graph_members() -> Result<()>
{
    for extra in [
        "app.sqlite-wal",
        "app.sqlite-shm",
        "app.sqlite-journal",
        "providers",
        "unlisted",
    ] {
        for dangling in [false, true] {
            let directory = tempfile::tempdir()?;
            for name in ["app.sqlite", "backup.json"] {
                std::fs::write(directory.path().join(name), b"fixture")?;
            }
            std::fs::create_dir(directory.path().join("artifacts"))?;
            let held = root(directory.path())?;
            let mut count = 0;
            require_root_members(&entries(&held, &mut count)?)?;
            if dangling {
                symlink("absent", directory.path().join(extra))?;
            } else if extra == "providers" {
                std::fs::create_dir(directory.path().join(extra))?;
            } else {
                std::fs::write(directory.path().join(extra), b"not captured")?;
            }
            assert!(
                require_root_members(&entries(&held, &mut 0)?).is_err(),
                "{extra},dangling={dangling}"
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn actual_sealed_capture_descriptor_refuses_write_growth_and_shrink_through_a_duplicate()
-> Result<()> {
    use std::io::{Seek, SeekFrom};
    let image = vec![83; CHUNK + 1];
    let mut schedule = Schedule::default();
    let mut file = sealed_source(&mut Capture::Fixture(&mut schedule), &image)?;
    let mut duplicate = file.try_clone()?;
    assert!(duplicate.write_all(b"changed").is_err());
    assert!(duplicate.set_len(image.len() as u64 + 1).is_err());
    assert!(duplicate.set_len(0).is_err());
    file.seek(SeekFrom::Start(0))?;
    let mut actual = Vec::new();
    file.read_to_end(&mut actual)?;
    assert_eq!(actual, image);
    assert!(!schedule.refused);
    Ok(())
}

#[test]
fn failed_private_file_check_still_observes_actual_owner_post_and_keeps_file_error_primary()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let tree = CapturedTree::pin(directory.path(), BTreeMap::new())?;
    std::fs::write(directory.path().join("unlisted"), b"changed")?;
    let mut schedule = Schedule {
        now: 100,
        deadline: 100,
        ..Schedule::default()
    };
    let error = RestoreArtifactAdmission {
        capture: &mut Capture::Fixture(&mut schedule),
        tree: &tree,
        worker: None,
    }
    .check()
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "restore_archive_captured_directory_changed"
    );
    assert_eq!(schedule.checks, 1);
    assert!(schedule.refused);
    Ok(())
}

#[test]
fn private_cache_retains_actual_created_fds_and_all_committed_members() -> Result<()> {
    let relative = format!(
        "artifacts/{}",
        day2_assets::hash_part(Digest::new(b"artifact").as_str())?
    );
    let expected = vec![29; CHUNK + 3];
    let files = BTreeMap::from([(
        PathBuf::from("nested/worker"),
        SourceFile {
            bytes: Zeroizing::new(expected.clone()),
            mode: 0o500,
        },
    )]);
    let empty = BTreeMap::from([
        (PathBuf::from("assets"), 0o755),
        (PathBuf::from("nested"), 0o755),
    ]);
    let mut schedule = Schedule::default();
    let (_directory, tree) = create_cache(
        &mut Capture::Fixture(&mut schedule),
        &relative,
        &files,
        &empty,
    )?;
    tree.check()?;
    assert!(tree.directories.contains_key(Path::new("assets")));
    let held = &tree.files[Path::new("nested/worker")];
    assert_eq!(held.identity.length, expected.len() as u64);
    assert_eq!(held.identity.mode & 0o7777, 0o600);
    let path = tree.root.join("nested/worker");
    std::fs::rename(&path, path.with_extension("old"))?;
    std::fs::write(&path, &expected)?;
    assert!(tree.check().is_err());
    assert_ne!(held.file.metadata()?.ino(), std::fs::metadata(&path)?.ino());
    Ok(())
}

#[test]
fn cache_creation_does_not_adopt_a_replaced_path_and_readback_detects_content_change() -> Result<()>
{
    for cut in [3, 5, 6] {
        let directory = tempfile::tempdir()?;
        let parent = root(directory.path())?;
        let path = directory.path().join("worker");
        let change = if cut == 3 {
            Change::Replace(path.clone())
        } else {
            Change::Overwrite(path.clone())
        };
        let mut schedule = Schedule {
            change: Some((cut, change)),
            ..Schedule::default()
        };
        let result = create_cache_file(
            &mut Capture::Fixture(&mut schedule),
            &parent,
            "worker",
            b"capture",
        );
        if cut == 5 {
            // Same-length wrong bytes are already present when identity is
            // captured. Stable metadata cannot substitute for SHA readback.
            assert_eq!(
                result.err().unwrap().to_string(),
                "restore_archive_cache_bytes_changed"
            );
        } else if cut == 6 {
            assert_eq!(
                result.err().unwrap().to_string(),
                "restore_archive_cache_creator_changed"
            );
            assert!(schedule.refused);
        } else {
            let held = result?;
            // The returned resource is still the ACTUAL creator; the outer
            // tree admission rejects the substituted pathname before loading.
            assert_ne!(held.file.metadata()?.ino(), std::fs::metadata(&path)?.ino());
            let files = BTreeMap::from([(PathBuf::from("worker"), held)]);
            let dirs = BTreeMap::from([(PathBuf::new(), parent)]);
            assert!(CapturedTree::from_created(directory.path(), files, dirs).is_err());
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn artifact_binding_uses_actual_full_commitment_and_refuses_the_distinct_inventory_domain()
-> Result<()> {
    // Component DATA/resource fixture only: no NativeArchive, authenticated
    // executor, approval, native staging State, keeper or writer is supplied.
    let manifest = manifest_fixture()?;
    let inventory = BTreeMap::from([(
        "artifacts/worker".into(),
        ArchiveMember::File {
            bytes: 6,
            sha256: Digest::new(b"worker"),
            mode: 0o500,
        },
    )]);
    let full_archive = full_archive_commitment(&manifest, &inventory)?;
    let inventory_digest = Digest::of(&("day2-native-restore-inventory-v1", &inventory))?;
    assert_ne!(full_archive, inventory_digest);
    let directory = Arc::new(tempfile::tempdir()?);
    let (artifact, files) = real_worker_fixture(directory.path())?;
    let tree = CapturedTree::pin(directory.path(), files)?;
    let fixture = super::super::application::tests::Fixture::new()?;
    let previous = crate::authority_state::current(&fixture.db)?;
    let artifact_id: Digest = manifest.artifact.clone().try_into()?;
    let database: Digest = manifest.database.clone().try_into()?;
    let snapshot = Snapshot {
        manifest,
        image: Zeroizing::new(Vec::new()),
        source: None,
        artifact,
        previous,
        directory,
        tree,
        inventory: inventory_digest.clone(),
        full_archive: full_archive.clone(),
    };
    let captured = CapturedRestoreArtifact {
        snapshot: &snapshot,
        local: std::marker::PhantomData,
    };
    let mut intent = Intent {
        operation: Digest::new(b"component-operation"),
        target_incarnation: Digest::new(b"component-target"),
        archive: crate::security_epoch::kernel::restore::Backup {
            scope: day2_capabilities::security_epoch::AuthorityScope {
                installation: "installation".to_owned().try_into()?,
                environment: "environment".to_owned().try_into()?,
                app: "app".to_owned().try_into()?,
            },
            authority: Digest::new(b"authority"),
            source_incarnation: Digest::new(b"source"),
            security_epoch: 1,
            full_archive_digest: full_archive.clone(),
            image: database.clone(),
            schema: Digest::new(b"schema"),
            artifact: artifact_id.clone(),
            key_set: Digest::new(b"keys"),
            required_keys: Vec::new(),
        },
    };
    captured.require_input(&intent)?;
    intent.archive.full_archive_digest = inventory_digest;
    assert!(captured.require_input(&intent).is_err());
    intent.archive.full_archive_digest = full_archive;
    intent.archive.artifact = Digest::new(b"other-artifact");
    assert!(captured.require_input(&intent).is_err());
    intent.archive.artifact = artifact_id;
    intent.archive.image = Digest::new(b"other-database");
    assert!(captured.require_input(&intent).is_err());
    intent.archive.image = database;
    captured.require_input(&intent)?;
    Ok(())
}

#[test]
fn snapshot_retains_the_actual_complete_digest_without_importing_approval_data() -> Result<()> {
    use quote::ToTokens;
    use syn::visit::Visit;
    #[derive(Default)]
    struct Origin {
        calculations: usize,
        snapshots: usize,
        inventory_hashes: usize,
        actual: bool,
    }
    impl<'ast> Visit<'ast> for Origin {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "full_archive") {
                self.calculations += 1;
                self.actual |= matches!(local.init.as_ref().map(|init| &*init.expr), Some(syn::Expr::Try(value))
                    if matches!(&*value.expr, syn::Expr::Call(call)
                        if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("full_archive_commitment"))
                        && call.args.len() == 2 && call.args.iter().zip(["manifest", "inventory"]).all(|(arg, name)|
                            matches!(arg, syn::Expr::Reference(reference)
                                if matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident(name))))));
            }
            if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "inventory")
                && let Some(syn::Expr::Try(value)) = local.init.as_ref().map(|init| &*init.expr)
                && let syn::Expr::Call(call) = &*value.expr
                && matches!(&*call.func, syn::Expr::Path(path) if path.path.segments.len() == 2
                    && path.path.segments[0].ident == "Digest" && path.path.segments[1].ident == "of")
                && call.args.len() == 1
                && let Some(syn::Expr::Reference(reference)) = call.args.first()
                && let syn::Expr::Tuple(tuple) = &*reference.expr
                && tuple.elems.len() == 2
                && matches!(&tuple.elems[0], syn::Expr::Lit(value) if matches!(&value.lit, syn::Lit::Str(value) if value.value() == "day2-native-restore-inventory-v1"))
                && matches!(&tuple.elems[1], syn::Expr::Reference(reference) if matches!(&*reference.expr, syn::Expr::Path(path) if path.path.is_ident("inventory")))
            {
                self.inventory_hashes += 1;
            }
            syn::visit::visit_local(self, local);
        }
        fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
            if value.path.is_ident("Snapshot") {
                self.snapshots += 1;
                for name in ["full_archive", "inventory"] {
                    self.actual &= value.fields.iter().any(|field|
                        matches!(&field.member, syn::Member::Named(member) if member == name)
                        && matches!(&field.expr, syn::Expr::Path(path) if path.path.is_ident(name)));
                }
            }
            syn::visit::visit_expr_struct(self, value);
        }
    }
    fn full_check(statement: &syn::Stmt) -> Result<bool> {
        use syn::parse::Parser;
        let mac = match statement {
            syn::Stmt::Macro(value) => &value.mac,
            syn::Stmt::Expr(syn::Expr::Macro(value), _) => &value.mac,
            _ => return Ok(false),
        };
        if !mac.path.is_ident("ensure") {
            return Ok(false);
        }
        let arguments = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
            .parse2(mac.tokens.clone())?;
        let expected: syn::Expr =
            syn::parse_quote!(full_archive == intent.archive.full_archive_digest);
        Ok(arguments.first().is_some_and(|arg| {
            arg.to_token_stream().to_string() == expected.to_token_stream().to_string()
        }))
    }
    fn actual(source: &str) -> Result<bool> {
        let file = syn::parse_file(source)?;
        let methods = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "capture_snapshot" => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [method] = methods.as_slice() else {
            return Ok(false);
        };
        let mut origin = Origin::default();
        origin.visit_block(&method.block);
        let checked = method
            .block
            .stmts
            .iter()
            .position(|statement| full_check(statement).unwrap_or(false));
        struct Worker(bool);
        impl<'ast> Visit<'ast> for Worker {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                self.0 |= matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|name| name.ident == "create_cache" || name.ident == "load_restore"));
                syn::visit::visit_expr_call(self, call);
            }
        }
        let first_worker = method.block.stmts.iter().position(|statement| {
            let mut worker = Worker(false);
            worker.visit_stmt(statement);
            worker.0
        });
        Ok(origin.actual
            && origin.calculations == 1
            && origin.snapshots == 1
            && origin.inventory_hashes == 1
            && matches!((checked, first_worker), (Some(checked), Some(worker)) if checked < worker))
    }
    let source = include_str!("../archive.rs");
    assert!(actual(source)?);
    for fault in 0..5 {
        let mut parsed = syn::parse_file(source)?;
        let function = parsed
            .items
            .iter_mut()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == "capture_snapshot" => Some(item),
                _ => None,
            })
            .unwrap();
        if fault == 3 {
            let index = function
                .block
                .stmts
                .iter()
                .position(|statement| full_check(statement).unwrap_or(false))
                .unwrap();
            function.block.stmts.remove(index);
        } else if fault == 4 {
            let index = function.block.stmts.len() - 1;
            function.block.stmts.insert(
                index,
                syn::parse_quote!(let full_archive = intent.archive.full_archive_digest.clone();),
            );
        } else {
            let Some(syn::Stmt::Expr(syn::Expr::Call(call), _)) = function.block.stmts.last_mut()
            else {
                anyhow::bail!("actual Snapshot return constructor");
            };
            let Some(syn::Expr::Struct(value)) = call.args.first_mut() else {
                anyhow::bail!("actual returned Snapshot literal");
            };
            assert!(value.path.is_ident("Snapshot"));
            let mut count = 0;
            for field in &mut value.fields {
                if matches!(&field.member, syn::Member::Named(name) if name == "full_archive") {
                    field.colon_token = Some(Default::default());
                    field.expr = if fault == 0 {
                        syn::parse_quote!(intent.archive.full_archive_digest.clone())
                    } else {
                        syn::parse_quote!(inventory.clone())
                    };
                    count += 1;
                } else if fault == 2
                    && matches!(&field.member, syn::Member::Named(name) if name == "inventory")
                {
                    field.colon_token = Some(Default::default());
                    field.expr = syn::parse_quote!(full_archive.clone());
                    count += 1;
                }
            }
            assert_eq!(count, if fault == 2 { 2 } else { 1 });
        }
        assert!(
            !actual(&parsed.to_token_stream().to_string())?,
            "fault {fault}"
        );
    }
    Ok(())
}
