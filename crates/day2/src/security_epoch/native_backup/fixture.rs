//! Normally built artifact regression; controlled SQLite, not native owners.
use super::tests::{complete, source, standalone};
use super::*;

#[test]
fn normal_fixture_image_matches_canonical_verifier_and_refuses_substitutions() -> Result<()> {
    // Both artifacts must be produced by the normal build. The fresh SQLite
    // initializer below is controlled metadata, NOT a native owner or archive
    // provenance. Full verification supplies these fixtures; FAST declares this
    // one artifact-dependent case separately rather than treating absence as OK.
    let artifact_path = std::path::PathBuf::from(
        std::env::var_os("DAY2_TEST_RESTORE_NATIVE_ARTIFACT")
            .context("build-restore-native artifact required")?,
    );
    let foreign_path = std::path::PathBuf::from(
        std::env::var_os("DAY2_TEST_REPORTS_ARTIFACT")
            .context("normally built Reports artifact required")?,
    );
    let artifact = crate::artifact::LoadedArtifact::load(&artifact_path)?;
    let foreign = crate::artifact::LoadedArtifact::load(&foreign_path)?;
    ensure!(
        artifact.id() != foreign.id(),
        "backup_foreign_artifact_not_distinct"
    );
    let mut instance =
        crate::development::verification_instance_data(&artifact_path, None, "alice@example.com")?;
    let directory = tempfile::tempdir()?;
    let instance_path = directory.path().join("instance.json");
    std::fs::write(&instance_path, serde_json::to_vec(&instance)?)?;
    let metadata = crate::store::InitialStoreMetadata::load(&instance_path, "app")?;
    let path = directory.path().join("controlled.sqlite");
    let mut write = Connection::open(&path)?;
    crate::store::configure_connection(&mut write)?;
    // Controlled real WAL source; this creates metadata, not native owners.
    write.pragma_update(None, "journal_mode", "WAL")?;
    let tx = write.transaction()?;
    metadata.initialize_in_transaction(&tx)?;
    tx.commit()?;
    let active = crate::authority_state::current(&write)?;
    let binding = instance
        .apps
        .get_mut("app")
        .context("backup_test_binding")?;
    binding.artifact = format!("artifacts/{}", day2_assets::hash_part(artifact.id())?);
    binding.readers = active.document.readers.clone();
    binding.writers = active.document.writers.clone();
    binding.authority = active.document.policy.clone();
    binding.resource_policies.clear();
    let mut read = source(&path)?;
    let mut tx = read.transaction()?;
    let mut snapshot = MemorySnapshot::new()?;
    complete(&mut snapshot, &mut tx)?;
    let content = snapshot.finish()?;
    tx.commit()?;
    let image = standalone(content)?;
    let manifest = crate::backup_archive::Manifest {
        format: 3,
        scope: metadata.scope().into(),
        artifact: artifact.id().into(),
        database: crate::digest(&image.bytes),
        provider_databases: Default::default(),
        rollout_artifacts: None,
        companion_state: Default::default(),
        app: "app".into(),
        authority: active.stamp,
        resources: active.document.resources,
        instance,
    };
    image.verify(&manifest, &artifact)?;
    assert!(image.verify(&manifest, &foreign).is_err());
    let clone_manifest = || -> Result<crate::backup_archive::Manifest> {
        Ok(serde_json::from_slice(&serde_json::to_vec(&manifest)?)?)
    };
    let mut altered = clone_manifest()?;
    altered.database = crate::digest(b"foreign image");
    assert!(image.verify(&altered, &artifact).is_err());
    let mut altered = clone_manifest()?;
    altered.authority.revision += 1;
    assert!(image.verify(&altered, &artifact).is_err());
    let mut altered = clone_manifest()?;
    altered.instance.installation = "other".into();
    altered.scope = altered.instance.scope("app")?;
    assert!(image.verify(&altered, &artifact).is_err());
    for graph in 0..3 {
        let mut altered = clone_manifest()?;
        match graph {
            0 => {
                altered
                    .provider_databases
                    .insert("foreign.sqlite".into(), crate::digest(b"foreign"));
            }
            1 => altered.rollout_artifacts = Some(crate::digest(b"foreign")),
            _ => {
                altered
                    .companion_state
                    .insert("foreign".into(), crate::digest(b"foreign"));
            }
        }
        assert!(image.verify(&altered, &artifact).is_err());
    }
    super::archive::refusal_cuts(&image, &manifest, &artifact)?;
    // Use the real production historical encoder. Its returned tree/commitment
    // is DATA, never a manufactured native owner or a completed handoff.
    for replay in 0..2 {
        let copied = SnapshotImage {
            bytes: Zeroizing::new(image.bytes.to_vec()),
        };
        let mut writer = super::archive::ArchiveWriter::new(copied, clone_manifest()?, &artifact)?;
        while writer.step()? != CopyProgress::Complete {}
        let archive = writer.finish()?;
        archive.check()?;
        let source_mode: String = write.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        ensure!(source_mode == "wal", "backup_fixture_source_changed");
        let path = archive.directory();
        let mut names = std::fs::read_dir(path)?
            .map(|entry| entry.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        names.sort();
        ensure!(
            names == ["app.sqlite", "artifacts", "backup.json"].map(std::ffi::OsString::from),
            "backup_fixture_root_members"
        );
        let reopened = crate::artifact::LoadedArtifact::load(
            &path.join(archive.manifest().artifact_relative()?),
        )?;
        let mut db = Connection::open_with_flags(
            path.join("app.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        crate::backup_archive::verify_snapshot(archive.manifest(), &reopened, &mut db)?;
        ensure!(
            archive.commitment().as_str().starts_with("sha256:"),
            "backup_fixture_commitment"
        );
        // The independent whole-file check must stay permanently refused even
        // if the changed on-disk bytes are later repaired.
        let original = std::fs::read(path.join("backup.json"))?;
        std::fs::write(path.join("backup.json"), b"{}")?;
        assert!(archive.check().is_err(), "replay{replay}");
        std::fs::write(path.join("backup.json"), original)?;
        assert!(archive.check().is_err(), "replay{replay}");
    }
    let mut damaged = SnapshotImage {
        bytes: Zeroizing::new(image.bytes.to_vec()),
    };
    let end = damaged.bytes.len() - 1;
    damaged.bytes[end] ^= 1;
    assert!(damaged.verify(&manifest, &artifact).is_err());
    Ok(())
}
