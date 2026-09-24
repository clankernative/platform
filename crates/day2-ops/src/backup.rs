//! Online SQLite snapshots and restore into a new directory. Never copy a live
//! main database file without its WAL, overwrite an instance, or resume commands.
use anyhow::{Context, Result, ensure};
use day2::{artifact::Instance, authority_state, store::Runtime};
use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub scope: String,
    pub artifact: String,
    pub database: String,
    /// Reviewed local provider stores. Older format-2 backups predate this field.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_databases: BTreeMap<String, String>,
    pub app: String,
    pub authority: authority_state::AuthorityStamp,
    #[serde(default)]
    pub resources: day2::authority_state::ResolvedResources,
    pub instance: Instance,
}

fn private_new(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(path).context("operation requires a new output directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn database_digest(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= 256 * 1024 * 1024,
        "bounded regular database required"
    );
    Ok(day2::digest(&fs::read(path)?))
}

fn copy_tree(source: &Path, target: &Path, budget: &mut u64, depth: u32) -> Result<()> {
    ensure!(
        depth <= 8 && fs::symlink_metadata(source)?.file_type().is_dir(),
        "artifact directory"
    );
    private_new(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(
                &entry.path(),
                &target.join(entry.file_name()),
                budget,
                depth + 1,
            )?;
        } else {
            ensure!(
                kind.is_file(),
                "artifact symlinks and special files forbidden"
            );
            *budget += entry.metadata()?.len();
            ensure!(*budget <= 256 * 1024 * 1024, "artifact copy budget");
            fs::copy(entry.path(), target.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn integrity(path: &Path) -> Result<()> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let result: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    ensure!(
        result == "ok",
        "backup database failed SQLite integrity check"
    );
    Ok(())
}

fn snapshot_database(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(source)?.file_type().is_file(),
        "provider database must be a regular file"
    );
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut destination_db = Connection::open(destination)?;
    let backup = Backup::new(&source, &mut destination_db)?;
    let start = Instant::now();
    loop {
        ensure!(
            start.elapsed() < Duration::from_secs(15),
            "online provider backup deadline"
        );
        match backup.step(256)? {
            StepResult::Done => break,
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => std::thread::sleep(Duration::from_millis(10)),
            _ => anyhow::bail!("unsupported provider backup result"),
        }
    }
    drop(backup);
    drop(destination_db);
    integrity(destination)
}

fn snapshot_providers(app_database: &Path, output: &Path) -> Result<BTreeMap<String, String>> {
    let mut providers = BTreeMap::new();
    for name in day2::capabilities::LOCAL_PROVIDER_DATABASES {
        let source = app_database.with_file_name(name);
        match fs::symlink_metadata(&source) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            result => {
                result?;
            }
        }
        if providers.is_empty() {
            private_new(&output.join("providers"))?;
        }
        let destination = output.join("providers").join(name);
        snapshot_database(&source, &destination)?;
        providers.insert((*name).into(), database_digest(&destination)?);
    }
    Ok(providers)
}

fn verify_providers(backup: &Path, providers: &BTreeMap<String, String>) -> Result<()> {
    for (name, digest) in providers {
        ensure!(
            day2::capabilities::LOCAL_PROVIDER_DATABASES.contains(&name.as_str()),
            "unknown provider database in backup"
        );
        let path = backup.join("providers").join(name);
        ensure!(
            database_digest(&path)? == *digest,
            "provider database digest mismatch"
        );
        integrity(&path)?;
    }
    Ok(())
}

pub fn take(instance_path: &Path, app: &str, output: &Path) -> Result<Manifest> {
    let instance = Instance::load(instance_path)?;
    let runtime = Runtime::load(instance_path, app)?;
    ensure!(
        runtime.db().is_file(),
        "backup requires an initialized database"
    );
    private_new(output)?;
    let database = output.join("app.sqlite");
    let source = Connection::open_with_flags(runtime.db(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut destination = Connection::open(&database)?;
    let backup = Backup::new(&source, &mut destination)?;
    let start = Instant::now();
    loop {
        ensure!(
            start.elapsed() < Duration::from_secs(15),
            "online backup deadline"
        );
        match backup.step(256)? {
            StepResult::Done => break,
            StepResult::More => {}
            StepResult::Busy | StepResult::Locked => std::thread::sleep(Duration::from_millis(10)),
            _ => anyhow::bail!("unsupported backup result"),
        }
    }
    drop(backup);
    // Read binding and grants from the completed snapshot itself. The desired
    // file and a separately sampled runtime may change during online backup.
    let active = authority_state::current(&destination)?;
    let artifact = PathBuf::from(&active.artifact_path);
    day2::store::validate_storage_snapshot(
        &mut destination,
        &day2::artifact::LoadedArtifact::load(&artifact)?,
        runtime.scope(),
    )?;
    drop(destination);
    integrity(&database)?;
    // Each file is an online SQLite snapshot. Cross-store coherence requires
    // quiesced provider work, as the managed local checkpoint does before take.
    // This is not an atomic distributed snapshot of arbitrary active executors.
    let provider_databases = snapshot_providers(runtime.db(), output)?;
    let artifact_relative = format!(
        "artifacts/{}",
        day2::assets::hash_part(&active.artifact_id)?
    );
    private_new(&output.join("artifacts"))?;
    copy_tree(&artifact, &output.join(&artifact_relative), &mut 0, 0)?;
    ensure!(
        day2::artifact::LoadedArtifact::load(&output.join(&artifact_relative))?.id()
            == active.artifact_id,
        "backup artifact changed"
    );
    let mut binding = instance.apps.get(app).context("app not installed")?.clone();
    binding.artifact = artifact_relative;
    binding.readers = active.document.readers;
    binding.writers = active.document.writers;
    binding.auditors = active.document.auditors;
    binding.authority = active.document.policy;
    binding.resource_policies.clear();
    let manifest = Manifest {
        format: 2,
        scope: runtime.scope().to_owned(),
        artifact: active.artifact_id,
        database: database_digest(&database)?,
        provider_databases,
        app: app.into(),
        authority: active.stamp,
        resources: active.document.resources,
        instance: Instance {
            installation: instance.installation,
            environment: instance.environment,
            branding: None,
            control: None,
            resources: None,
            // The binding keeps its edge, so the manifest keeps the provider
            // that edge is verified against.
            identity: instance.identity,
            apps: BTreeMap::from([(app.into(), binding)]),
        },
    };
    // The manifest is the completion marker. A partial directory is not a backup.
    fs::write(
        output.join("backup.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

pub fn verify(backup: &Path) -> Result<Manifest> {
    ensure!(
        fs::metadata(backup.join("backup.json"))?.len() <= 1_048_576,
        "backup manifest budget"
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(backup.join("backup.json"))?)?;
    ensure!(
        manifest.format == 2
            && manifest.instance.apps.len() == 1
            && manifest.instance.scope(&manifest.app)? == manifest.scope,
        "invalid backup scope"
    );
    let artifact_relative = format!("artifacts/{}", day2::assets::hash_part(&manifest.artifact)?);
    ensure!(
        manifest.instance.control.is_none()
            && manifest.instance.branding.is_none()
            && manifest.instance.apps[&manifest.app].artifact == artifact_relative,
        "backup instance must refer to its bundled artifact"
    );
    ensure!(
        database_digest(&backup.join("app.sqlite"))? == manifest.database,
        "backup database digest mismatch"
    );
    verify_providers(backup, &manifest.provider_databases)?;
    let artifact = day2::artifact::LoadedArtifact::load(&backup.join(&artifact_relative))?;
    ensure!(
        artifact.id() == manifest.artifact,
        "backup artifact mismatch"
    );
    integrity(&backup.join("app.sqlite"))?;
    let mut db =
        Connection::open_with_flags(backup.join("app.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    day2::store::validate_storage_snapshot(&mut db, &artifact, &manifest.scope)?;
    let active = authority_state::current(&db)?;
    let binding = &manifest.instance.apps[&manifest.app];
    ensure!(
        active.stamp == manifest.authority
            && active.artifact_id == manifest.artifact
            && active.document.readers == binding.readers
            && active.document.writers == binding.writers
            && active.document.auditors == binding.auditors
            && active.document.policy == binding.authority
            && active.document.resources == manifest.resources,
        "backup authority snapshot mismatch"
    );
    Ok(manifest)
}

pub fn restore(backup: &Path, output: &Path) -> Result<PathBuf> {
    // Revalidate at the write boundary even if the Roc recipe already checked.
    let manifest = verify(backup)?;
    let artifact_relative = format!("artifacts/{}", day2::assets::hash_part(&manifest.artifact)?);
    private_new(output)?;
    private_new(&output.join("artifacts"))?;
    copy_tree(
        &backup.join(&artifact_relative),
        &output.join(&artifact_relative),
        &mut 0,
        0,
    )?;
    private_new(&output.join(".state"))?;
    fs::copy(
        backup.join("app.sqlite"),
        output
            .join(".state")
            .join(format!("{}.sqlite", manifest.app)),
    )?;
    for name in manifest.provider_databases.keys() {
        fs::copy(
            backup.join("providers").join(name),
            output.join(".state").join(name),
        )?;
    }
    let database = output
        .join(".state")
        .join(format!("{}.sqlite", manifest.app));
    let mut db = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    authority_state::invalidate_restored(&tx, &output.join(&artifact_relative))?;
    // A backup is not a current login grant. Rotate browser authentication and
    // ticket signing as part of the same restore fence; preserve execution evidence.
    for table in ["day2_web_sessions", "day2_web_secret"] {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists {
            tx.execute(&format!("DELETE FROM {table}"), [])?;
        }
    }
    tx.commit()?;
    drop(db);
    // Backup grants are historical evidence, never current company approval.
    // The operator must supply and explicitly activate current desired policy.
    let mut instance = manifest.instance;
    let binding = instance
        .apps
        .get_mut(&manifest.app)
        .context("restore app")?;
    binding.readers.clear();
    binding.writers.clear();
    binding.auditors.clear();
    binding.authority = None;
    binding.resource_policies.clear();
    let path = output.join("instance.json");
    fs::write(&path, serde_json::to_vec_pretty(&instance)?)?;
    let runtime = Runtime::load(&path, &manifest.app)?;
    runtime.validate_storage()?;
    Ok(path.canonicalize()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_snapshots_include_wal_and_reject_missing_changed_or_unknown_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        fs::create_dir(&source)?;
        let provider = source.join("carta.synthetic.sqlite");
        let writer = Connection::open(&provider)?;
        writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE captures(id INTEGER PRIMARY KEY, body TEXT NOT NULL); INSERT INTO captures VALUES(1,'immutable original');")?;
        let output = directory.path().join("backup");
        fs::create_dir(&output)?;
        let providers = snapshot_providers(&source.join("app.sqlite"), &output)?;
        assert_eq!(providers.len(), 1);
        verify_providers(&output, &providers)?;
        let copied = output.join("providers/carta.synthetic.sqlite");
        let read = Connection::open_with_flags(&copied, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(
            read.query_row("SELECT body FROM captures", [], |row| row
                .get::<_, String>(0))?,
            "immutable original"
        );
        assert!(read.execute("DELETE FROM captures", []).is_err());
        writer.execute("INSERT INTO captures VALUES(2,'later source write')", [])?;
        assert_eq!(
            read.query_row("SELECT COUNT(*) FROM captures", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        verify_providers(&output, &providers)?;
        drop(read);
        let missing = output.join("providers/moved.sqlite");
        fs::rename(&copied, &missing)?;
        assert!(verify_providers(&output, &providers).is_err());
        fs::rename(&missing, &copied)?;
        Connection::open(&copied)?.execute("UPDATE captures SET body='tampered'", [])?;
        assert!(verify_providers(&output, &providers).is_err());
        assert!(
            verify_providers(
                &output,
                &BTreeMap::from([("../outside.sqlite".into(), "unused".into())])
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn absent_providers_are_not_fabricated_and_symlinks_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        let output = directory.path().join("backup");
        fs::create_dir(&source)?;
        fs::create_dir(&output)?;
        assert!(snapshot_providers(&source.join("app.sqlite"), &output)?.is_empty());
        assert!(!output.join("providers").exists());
        let unrelated = directory.path().join("unrelated.sqlite");
        Connection::open(&unrelated)?.execute("CREATE TABLE private(value TEXT)", [])?;
        std::os::unix::fs::symlink(&unrelated, source.join("carta.synthetic.sqlite"))?;
        assert!(snapshot_providers(&source.join("app.sqlite"), &output).is_err());
        Ok(())
    }
}
