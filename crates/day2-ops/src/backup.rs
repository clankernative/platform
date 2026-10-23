//! Online SQLite snapshots and restore into a new directory. Never copy a live
//! main database file without its WAL, overwrite an instance, or resume commands.
use anyhow::{Context, Result, bail, ensure};
use day2::{artifact::Instance, authority_state, store::Runtime};
use ring::digest::{Context as DigestContext, SHA256};
use rusqlite::{
    Connection, ErrorCode, OpenFlags,
    backup::{Backup, StepResult},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::c_int,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Bounds of one online snapshot. The copy reads inside a single read
/// transaction on the source, so it is one consistent snapshot: commits by
/// other connections neither appear in it nor restart it, however long it
/// takes. (Without that transaction SQLite restarts an online backup from the
/// first page whenever another connection writes, so a large database that the
/// app writes more often than one full copy takes is never copied.) In WAL mode
/// the snapshot never blocks the app's writers; it only keeps checkpoints from
/// passing it until it ends. A rollback-journal source blocks writers' commits
/// for the copy, which only the small synthetic provider stores use.
#[derive(Clone, Copy)]
struct Pace {
    /// Pages per `sqlite3_backup_step`, between progress and deadline checks.
    step_pages: c_int,
    /// Fails once the copy has not advanced for this long, including waiting
    /// for a lock to start the snapshot (a writer that never releases it).
    stall: Duration,
    /// Fails once the copy takes longer than `stall` plus the snapshot's size
    /// at this rate: progress too slow to finish in reasonable time.
    floor_bytes_per_second: u64,
}

/// A 2.5 GiB database may take up to 15 s + 320 s. The GKE backup Job's
/// `backup_active_deadline_seconds` (default 1800) bounds the whole run,
/// including integrity checks, verification and upload, and must stay above it.
const ONLINE: Pace = Pace {
    step_pages: 1024,
    stall: Duration::from_secs(15),
    floor_bytes_per_second: 8 << 20,
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
    /// Additional durable companion state, keyed by its path beneath `.state`.
    pub companion_state: BTreeMap<String, String>,
    pub app: String,
    pub authority: authority_state::AuthorityStamp,
    #[serde(default)]
    pub resources: day2::authority_state::ResolvedResources,
    pub instance: Instance,
}

impl Manifest {
    /// Binds the stable restore request to the complete verified snapshot graph.
    /// This is historical identity, never live security authority.
    pub fn security_restore_digest(&self) -> Result<day2_capabilities::Digest> {
        day2_capabilities::Digest::of(&("day2-security-backup-v1", self))
    }
}

fn has_security_selection(instance: &Instance, app: &str) -> bool {
    instance.apps.get(app).is_some_and(|binding| {
        !binding.credential_families.is_empty() || !binding.oauth_connections.is_empty()
    }) || instance
        .credential_runtime
        .as_ref()
        .is_some_and(|runtime| runtime.apps.keys().any(|name| name.as_str() == app))
        || instance
            .oauth_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.apps.keys().any(|name| name.as_str() == app))
        || instance.control.as_ref().is_some_and(|control| {
            control
                .security_epochs
                .values()
                .any(|store| store.scope.app.as_str() == app)
        })
}

/// Historical catalogs keep immutable selector validation meaningful. No live
/// epoch/key proof is stored in the backup, and restore does not admit these
/// selectors as its current resource selection.
fn historical_projection(
    mut instance: Instance,
    app: &str,
    binding: day2::artifact::AppBinding,
) -> Instance {
    let security = has_security_selection(&instance, app);
    instance.branding = None;
    instance.apps = BTreeMap::from([(app.to_owned(), binding)]);
    if !security {
        instance.control = None;
        instance.resources = None;
        instance.security_shell = None;
        instance.oauth_shell_transport = None;
        instance.oauth_clients = None;
        instance.oauth_runtime = None;
        instance.credential_runtime = None;
        return instance;
    }
    if let Some(control) = &mut instance.control {
        // A backup preserves selector history, never an executable initial
        // bootstrap intent for an existing or restored app database.
        control.security_bootstraps.clear();
        control.apps.retain(|name, _| name.as_str() == app);
        control
            .sources
            .retain(|name, _| control.apps.values().any(|binding| binding.source == *name));
        control
            .security_epochs
            .retain(|_, store| store.scope.app.as_str() == app);
    }
    instance.oauth_runtime = instance.oauth_runtime.take().map(|mut catalog| {
        catalog.apps.retain(|name, _| name.as_str() == app);
        catalog
    });
    instance.credential_runtime = instance.credential_runtime.take().and_then(|mut catalog| {
        catalog.apps.retain(|name, _| name.as_str() == app);
        (!catalog.apps.is_empty()).then_some(catalog)
    });
    instance
}

fn private_new(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(path).context("operation requires a new output directory")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Streams the file, so the digest needs no memory proportional to its size;
/// the same `sha256:` form as `day2::digest`.
fn database_digest(path: &Path) -> Result<String> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "regular database file required"
    );
    let mut hasher = DigestContext::new(&SHA256);
    let mut file = fs::File::open(path)?;
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = match file.read(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let hex: String = hasher
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("sha256:{hex}"))
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

/// Copies `source` into the new database `destination` as one consistent
/// online snapshot (see [`Pace`]) and returns the open destination.
/// `elapsed` is the time since the caller started the snapshot.
fn online_snapshot(
    source: &Path,
    destination: &Path,
    pace: Pace,
    mut elapsed: impl FnMut() -> Duration,
) -> Result<Connection> {
    let mut source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    // SQLite waits for a source lock up to this long before it reports busy,
    // both to start the snapshot and in a step, so a busy result is a stall.
    source.busy_timeout(pace.stall)?;
    let snapshot = source.transaction()?;
    // The first read starts the snapshot; the transaction keeps it until the end.
    let value =
        |pragma: &str| snapshot.pragma_query_value(None, pragma, |row| row.get::<_, i64>(0));
    let bytes = match value("page_count").and_then(|pages| Ok(pages * value("page_size")?)) {
        Err(error) if error.sqlite_error_code() == Some(ErrorCode::DatabaseBusy) => bail!(
            "online backup stalled: the source stayed locked for {} s",
            pace.stall.as_secs_f64()
        ),
        result => u64::try_from(result?)?,
    };
    let bound =
        pace.stall + Duration::from_secs_f64(bytes as f64 / pace.floor_bytes_per_second as f64);
    let mut destination = Connection::open(destination)?;
    let backup = Backup::new(&snapshot, &mut destination)?;
    let (mut remaining, mut advanced) = (c_int::MAX, Duration::ZERO);
    loop {
        let result = backup.step(pace.step_pages)?;
        let now = elapsed();
        let progress = backup.progress();
        match result {
            StepResult::Done => break,
            StepResult::More if progress.remaining < remaining => {
                (remaining, advanced) = (progress.remaining, now);
            }
            StepResult::More | StepResult::Busy => {}
            // Only a write through the backup's own source connection (or a
            // shared cache) reports locked; this read-only connection has none.
            _ => bail!("unsupported online backup result"),
        }
        ensure!(
            now.saturating_sub(advanced) < pace.stall,
            "online backup stalled: no page copied for {} s ({} of {} pages left)",
            pace.stall.as_secs_f64(),
            progress.remaining,
            progress.pagecount
        );
        ensure!(
            now < bound,
            "online backup too slow: {} of {} pages left after {} s, the bound for {bytes} bytes",
            progress.remaining,
            progress.pagecount,
            bound.as_secs_f64()
        );
    }
    drop(backup);
    Ok(destination)
}

fn snapshot_database(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(source)?.file_type().is_file(),
        "provider database must be a regular file"
    );
    let start = Instant::now();
    drop(online_snapshot(source, destination, ONLINE, || {
        start.elapsed()
    })?);
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
        snapshot_database(&source, &destination)
            .with_context(|| format!("provider database {name}"))?;
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

const MAX_COMPANION_STATE_FILES: usize = 16_384;
const MAX_COMPANION_STATE_ENTRIES: usize = 65_536;
const MAX_COMPANION_STATE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

#[derive(Default)]
struct CompanionBudget {
    files: usize,
    entries: usize,
    bytes: u64,
}

fn sorted_companion_entries(
    directory: &Path,
    budget: &mut CompanionBudget,
) -> Result<Vec<fs::DirEntry>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)? {
        budget.entries += 1;
        ensure!(
            budget.entries <= MAX_COMPANION_STATE_ENTRIES,
            "companion state entry budget exceeded"
        );
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

pub fn validate_companion_state_subpath(path: &str) -> Result<()> {
    ensure!(
        path.starts_with("companions/") && path.len() <= 220 && path.split('/').count() <= 5,
        "companion state path must be beneath companions/"
    );
    validate_relative_state_path(path)
}

pub fn validate_companion_sqlite_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with("companions/")
            && path.ends_with(".sqlite")
            && path.len() <= 256
            && path.split('/').count() <= 15,
        "companion SQLite path must name a .sqlite file beneath companions/"
    );
    validate_relative_state_path(path)
}

fn validate_relative_state_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            }),
        "invalid companion state path"
    );
    Ok(())
}

fn validate_companion_selection(subpaths: &[String], databases: &[String]) -> Result<()> {
    ensure!(subpaths.len() <= 8, "companion state path budget");
    let unique: std::collections::BTreeSet<_> = subpaths.iter().collect();
    ensure!(
        unique.len() == subpaths.len(),
        "duplicate companion state path"
    );
    for path in subpaths {
        validate_companion_state_subpath(path)?;
    }
    for (index, path) in subpaths.iter().enumerate() {
        ensure!(
            !subpaths.iter().enumerate().any(|(other_index, other)| {
                index != other_index && other.starts_with(&format!("{path}/"))
            }),
            "overlapping companion state paths"
        );
    }
    let unique: std::collections::BTreeSet<_> = databases.iter().collect();
    ensure!(
        unique.len() == databases.len(),
        "duplicate companion SQLite path"
    );
    for database in databases {
        validate_companion_sqlite_path(database)?;
        ensure!(
            subpaths
                .iter()
                .filter(|subpath| database.starts_with(&format!("{subpath}/")))
                .count()
                == 1,
            "companion SQLite path must belong to one selected state directory"
        );
    }
    Ok(())
}

fn private_parent(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            fs::symlink_metadata(path)?.file_type().is_dir(),
            "companion backup parent must be a directory"
        );
        return Ok(());
    }
    let parent = path.parent().context("companion backup parent")?;
    if parent.exists() {
        ensure!(
            fs::symlink_metadata(parent)?.file_type().is_dir(),
            "companion backup parent must be a directory"
        );
    } else {
        private_parent(parent)?;
    }
    private_new(path)
}

fn copy_companion_tree(
    source: &Path,
    target: &Path,
    relative: &Path,
    excluded: &std::collections::BTreeSet<String>,
    budget: &mut CompanionBudget,
    depth: usize,
) -> Result<()> {
    ensure!(
        depth <= 10 && fs::symlink_metadata(source)?.file_type().is_dir(),
        "invalid companion state directory"
    );
    private_parent(target.parent().context("companion backup parent")?)?;
    private_new(target)?;
    for entry in sorted_companion_entries(source, budget)? {
        let kind = entry.file_type()?;
        let child_relative = relative.join(entry.file_name());
        let child_name = child_relative
            .to_str()
            .context("companion state path must be UTF-8")?
            .to_owned();
        if excluded.contains(&child_name)
            || excluded.contains(&format!("{child_name}-wal"))
            || excluded.contains(&format!("{child_name}-shm"))
        {
            continue;
        }
        let source_child = entry.path();
        let target_child = target.join(entry.file_name());
        if kind.is_dir() {
            copy_companion_tree(
                &source_child,
                &target_child,
                &child_relative,
                excluded,
                budget,
                depth + 1,
            )?;
        } else {
            ensure!(
                kind.is_file(),
                "companion state links and special files forbidden"
            );
            budget.files += 1;
            budget.bytes = budget.bytes.saturating_add(entry.metadata()?.len());
            ensure!(
                budget.files <= MAX_COMPANION_STATE_FILES
                    && budget.bytes <= MAX_COMPANION_STATE_BYTES,
                "companion state backup budget exceeded"
            );
            fs::copy(source_child, target_child)?;
        }
    }
    Ok(())
}

fn tree_digest_with_budget(path: &Path, budget: &mut CompanionBudget) -> Result<String> {
    fn visit(
        root: &Path,
        directory: &Path,
        hasher: &mut DigestContext,
        budget: &mut CompanionBudget,
        depth: usize,
    ) -> Result<()> {
        ensure!(
            depth <= 10 && fs::symlink_metadata(directory)?.file_type().is_dir(),
            "invalid companion state directory"
        );
        for entry in sorted_companion_entries(directory, budget)? {
            let kind = entry.file_type()?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("companion state path must be UTF-8")?;
            if kind.is_dir() {
                hasher.update(relative.as_bytes());
                hasher.update(&[0]);
                visit(root, &path, hasher, budget, depth + 1)?;
            } else {
                ensure!(
                    kind.is_file(),
                    "companion state links and special files forbidden"
                );
                let file_size = entry.metadata()?.len();
                budget.files += 1;
                budget.bytes = budget.bytes.saturating_add(file_size);
                ensure!(
                    budget.files <= MAX_COMPANION_STATE_FILES
                        && budget.bytes <= MAX_COMPANION_STATE_BYTES,
                    "companion state verification budget exceeded"
                );
                hasher.update(relative.as_bytes());
                hasher.update(&[0]);
                hasher.update(&file_size.to_be_bytes());
                let mut file = fs::File::open(path)?;
                let mut buffer = [0; 64 * 1024];
                loop {
                    let count = match file.read(&mut buffer) {
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        result => result?,
                    };
                    if count == 0 {
                        break;
                    }
                    hasher.update(&buffer[..count]);
                }
                hasher.update(&[0xff]);
            }
        }
        Ok(())
    }

    let mut hasher = DigestContext::new(&SHA256);
    visit(path, path, &mut hasher, budget, 0)?;
    let hex: String = hasher
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!("sha256:{hex}"))
}

fn state_source_path(root: &Path, relative: &str, directory: bool) -> Result<PathBuf> {
    validate_relative_state_path(relative)?;
    let mut path = root.to_path_buf();
    let segments: Vec<_> = relative.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        path.push(segment);
        let metadata = fs::symlink_metadata(&path)?;
        let final_segment = index + 1 == segments.len();
        ensure!(
            if final_segment && !directory {
                metadata.file_type().is_file()
            } else {
                metadata.file_type().is_dir()
            },
            "companion state paths cannot contain links or special files"
        );
    }
    Ok(path)
}

fn snapshot_companion_state(
    state_root: &Path,
    output: &Path,
    subpaths: &[String],
    databases: &[String],
) -> Result<BTreeMap<String, String>> {
    validate_companion_selection(subpaths, databases)?;
    if !subpaths.is_empty() {
        private_parent(&output.join("companion-state"))?;
    }
    let database_set: std::collections::BTreeSet<_> = databases.iter().cloned().collect();
    let mut budget = CompanionBudget::default();
    let mut digest_budget = CompanionBudget::default();
    let mut digests = BTreeMap::new();
    for subpath in subpaths {
        let source = state_source_path(state_root, subpath, true)
            .context("companion state directory is missing or unsafe")?;
        let target = output.join("companion-state").join(subpath);
        let excluded: std::collections::BTreeSet<_> = database_set
            .iter()
            .filter_map(|database| database.strip_prefix(&format!("{subpath}/")))
            .map(str::to_owned)
            .collect();
        copy_companion_tree(&source, &target, Path::new(""), &excluded, &mut budget, 0)?;
        for database in databases.iter().filter_map(|database| {
            database
                .strip_prefix(&format!("{subpath}/"))
                .map(|relative| (database, relative))
        }) {
            let (database_path, relative) = database;
            let source_database = state_source_path(state_root, database_path, false)
                .context("companion SQLite database is missing or unsafe")?;
            budget.files += 1;
            ensure!(
                budget.files <= MAX_COMPANION_STATE_FILES,
                "companion state backup budget exceeded"
            );
            let destination = target.join(relative);
            private_parent(destination.parent().context("companion database parent")?)?;
            let start = Instant::now();
            drop(online_snapshot(
                &source_database,
                &destination,
                ONLINE,
                || start.elapsed(),
            )?);
            integrity(&destination)?;
            budget.bytes = budget
                .bytes
                .saturating_add(fs::metadata(&destination)?.len());
            ensure!(
                budget.bytes <= MAX_COMPANION_STATE_BYTES,
                "companion state backup budget exceeded"
            );
        }
        digests.insert(
            subpath.clone(),
            tree_digest_with_budget(&target, &mut digest_budget)?,
        );
    }
    Ok(digests)
}

fn verify_companion_state(backup: &Path, state: &BTreeMap<String, String>) -> Result<()> {
    validate_companion_selection(&state.keys().cloned().collect::<Vec<_>>(), &[])?;
    let mut budget = CompanionBudget::default();
    for (subpath, digest) in state {
        ensure!(
            tree_digest_with_budget(&backup.join("companion-state").join(subpath), &mut budget)?
                == *digest,
            "companion state digest mismatch"
        );
    }
    Ok(())
}

pub fn take(instance_path: &Path, app: &str, output: &Path) -> Result<Manifest> {
    take_with_companion_state(instance_path, app, output, &[], &[])
}

pub fn take_with_companion_state(
    instance_path: &Path,
    app: &str,
    output: &Path,
    state_subpaths: &[String],
    sqlite_paths: &[String],
) -> Result<Manifest> {
    validate_companion_selection(state_subpaths, sqlite_paths)?;
    let instance = Instance::load(instance_path)?;
    let runtime = Runtime::load(instance_path, app)?;
    ensure!(
        runtime.db().is_file(),
        "backup requires an initialized database"
    );
    private_new(output)?;
    let database = output.join("app.sqlite");
    let start = Instant::now();
    let mut destination = online_snapshot(runtime.db(), &database, ONLINE, || start.elapsed())
        .context("app database")?;
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
    let companion_state = snapshot_companion_state(
        runtime.db().parent().context("app state directory")?,
        output,
        state_subpaths,
        sqlite_paths,
    )?;
    let artifact_relative = format!("artifacts/{}", day2_assets::hash_part(&active.artifact_id)?);
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
    binding.authority = active.document.policy;
    binding.resource_policies.clear();
    let manifest = Manifest {
        format: 3,
        scope: runtime.scope().to_owned(),
        artifact: active.artifact_id,
        database: database_digest(&database)?,
        provider_databases,
        companion_state,
        app: app.into(),
        authority: active.stamp,
        resources: active.document.resources,
        instance: historical_projection(instance, app, binding),
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
        manifest.format == 3
            && manifest.instance.apps.len() == 1
            && manifest.instance.scope(&manifest.app)? == manifest.scope,
        "invalid backup scope"
    );
    let artifact_relative = format!("artifacts/{}", day2_assets::hash_part(&manifest.artifact)?);
    ensure!(
        manifest.instance.branding.is_none()
            && manifest.instance.apps[&manifest.app].artifact == artifact_relative,
        "backup instance must refer to its bundled artifact"
    );
    ensure!(
        database_digest(&backup.join("app.sqlite"))? == manifest.database,
        "backup database digest mismatch"
    );
    verify_providers(backup, &manifest.provider_databases)?;
    verify_companion_state(backup, &manifest.companion_state)?;
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
            && active.document.policy == binding.authority
            && active.document.resources == manifest.resources,
        "backup authority snapshot mismatch"
    );
    Ok(manifest)
}

fn require_unsecured_restore(
    manifest: &Manifest,
    artifact: &day2::artifact::LoadedArtifact,
) -> Result<()> {
    ensure!(
        artifact.id() == manifest.artifact,
        "backup artifact changed before restore"
    );
    ensure!(
        !has_security_selection(&manifest.instance, &manifest.app)
            && artifact.contract().credential_declarations.is_empty()
            && artifact.contract().connection_declarations.is_empty(),
        "security_restore_preflight_required"
    );
    Ok(())
}

pub fn restore(backup: &Path, output: &Path) -> Result<PathBuf> {
    // Revalidate at the write boundary even if the Roc recipe already checked.
    let manifest = verify(backup)?;
    let artifact_relative = format!("artifacts/{}", day2_assets::hash_part(&manifest.artifact)?);
    let artifact = day2::artifact::LoadedArtifact::load(&backup.join(&artifact_relative))?;
    require_unsecured_restore(&manifest, &artifact)?;
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
    let mut companion_budget = CompanionBudget::default();
    for subpath in manifest.companion_state.keys() {
        copy_companion_tree(
            &backup.join("companion-state").join(subpath),
            &output.join(".state").join(subpath),
            Path::new(""),
            &std::collections::BTreeSet::new(),
            &mut companion_budget,
            0,
        )?;
    }
    let database = output
        .join(".state")
        .join(format!("{}.sqlite", manifest.app));
    let mut db = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = day2::write_queue::immediate(&mut db)?;
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
    fn database_digest_matches_known_answers_across_read_boundaries() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("snapshot");
        for (bytes, expected) in [
            (
                Vec::new(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".to_vec(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                vec![0; 131_073],
                "d281209cc72d47b090175b22621840d9eb8267d09cc05dc122bfaa759a82830f",
            ),
        ] {
            fs::write(&path, &bytes)?;
            assert_eq!(database_digest(&path)?, format!("sha256:{expected}"));
        }
        Ok(())
    }

    #[test]
    fn target_runtime_selection_is_preserved_but_foreign_only_runtime_does_not_secure_target()
    -> Result<()> {
        let name = |value: &str| day2_capabilities::Name::try_from(value.to_owned()).unwrap();
        let mut instance: Instance = serde_json::from_value(serde_json::json!({
            "installation":"company","environment":"test",
            "apps":{"target":{"artifact":"/artifact","readers":[],"writers":[]},
                "foreign":{"artifact":"/foreign","readers":[],"writers":[]}},
            "credential_runtime":{"version":1,"apps":{"target":{
                "service_account":"app@example-tools.iam.gserviceaccount.com",
                "attestation":{"id":"attestation","revision":day2_capabilities::Digest::new(b"desired attestation")},
                "attestation_secret":"attest","families":{"clients":{"verifier_secret":"verify",
                    "custody":{"kind":"verifier_only"},"max_active_lineages":12}}}}},
            "oauth_runtime":{"version":1,"shell":{"project":"example-tools","backend_service":"shell",
                "url_map":"shell","https_proxy":"shell","forwarding_rule":"shell","kubernetes_service":"security/security-shell"},
                "apps":{"target":{"service_account":"app@example-tools.iam.gserviceaccount.com",
                    "accounts":{"calendar":{"kind":"iap_subject"}}}}}
        }))?;
        // Historical data with stripped declarations must retain exact target
        // runtime selection, without pretending it is CURRENT admission.
        for credentials in [true, false] {
            let mut target = instance.clone();
            if credentials {
                target.oauth_runtime = None;
            } else {
                target.credential_runtime = None;
            }
            assert!(has_security_selection(&target, "target"));
            assert!(!has_security_selection(&target, "foreign"));
            let projected =
                historical_projection(target.clone(), "target", target.apps["target"].clone());
            assert_eq!(projected.credential_runtime, target.credential_runtime);
            assert_eq!(projected.oauth_runtime, target.oauth_runtime);
            let unsecured =
                historical_projection(target.clone(), "foreign", target.apps["foreign"].clone());
            assert!(unsecured.credential_runtime.is_none() && unsecured.oauth_runtime.is_none());
        }
        let selected = instance
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .remove(&name("target"))
            .unwrap();
        instance
            .credential_runtime
            .as_mut()
            .unwrap()
            .apps
            .insert(name("foreign"), selected);
        let selected = instance
            .oauth_runtime
            .as_mut()
            .unwrap()
            .apps
            .remove(&name("target"))
            .unwrap();
        instance
            .oauth_runtime
            .as_mut()
            .unwrap()
            .apps
            .insert(name("foreign"), selected);
        assert!(!has_security_selection(&instance, "target"));
        assert!(has_security_selection(&instance, "foreign"));
        let projected =
            historical_projection(instance.clone(), "target", instance.apps["target"].clone());
        assert!(projected.credential_runtime.is_none() && projected.oauth_runtime.is_none());
        instance.credential_runtime = None;
        instance.oauth_runtime = None;
        assert!(!has_security_selection(&instance, "target"));
        Ok(())
    }

    fn multi_source_security_projection_fixture() -> Result<Instance> {
        use day2_capabilities::{Name, SourceProvider, security_epoch::EpochStore};
        let name = |value: &str| Name::try_from(value.to_owned()).unwrap();
        // The existing deployment oracle is complete metadata, not an admitted
        // artifact or a live provider observation. Require its full loader first.
        let mut instance = Instance::from_bytes(include_bytes!(
            "../../../deploy/gke/stacks/day2-app/tests/oauth-instance.json"
        ))?;
        let mut sibling = instance.apps["example_app"].clone();
        sibling.artifact = "/unmounted/sibling/artifact".into();
        sibling.edge.as_mut().unwrap().origin = "https://other.test.example.com".into();
        sibling.edge.as_mut().unwrap().iap_audience =
            "/projects/123456789012/global/backendServices/987654323".into();
        for connection in sibling.oauth_connections.values_mut() {
            connection.namespace.app = name("other_app");
        }
        instance.apps.insert("other_app".into(), sibling);
        let runtime = instance.oauth_runtime.as_mut().unwrap();
        let selected = runtime.apps[&name("example_app")].clone();
        runtime.apps.insert(name("other_app"), selected);
        let control = instance.control.as_mut().unwrap();
        control.sources.insert(
            name("other_source"),
            SourceProvider::LocalGit {
                repository: "/unmounted/sibling/source".into(),
            },
        );
        control.apps.insert(
            name("other_app"),
            serde_json::from_value(serde_json::json!({"source":"other_source"}))?,
        );
        for app in ["example_app", "other_app"] {
            let selected = &instance.oauth_runtime.as_ref().unwrap().apps[&name(app)];
            let epoch: EpochStore = serde_json::from_value(serde_json::json!({
                "scope":{"installation":instance.installation,"environment":instance.environment,"app":app},
                "provider":{"kind":"firestore_native_v1","project":"example-tools","project_number":123456789012_u64,
                    "database":"security","database_uid":"01234567-89ab-4cde-8fab-0123456789ab",
                    "iam_source":{"kind":"gke_workload_identity_v1","service_account":selected.service_account,"service_account_uid":"100000000000000000007"}},
                "key_set":instance.security_key_set(app)?,"max_lease_seconds":30,
            }))?;
            let control = instance.control.as_mut().unwrap();
            control
                .security_epochs
                .retain(|_, selected| selected.scope.app.as_str() != app);
            control.security_epochs.insert(name(app), epoch);
        }
        Instance::from_bytes(&serde_json::to_vec(&instance)?)
    }

    #[test]
    fn historical_projection_reloads_only_selected_sources_and_epoch_catalog() -> Result<()> {
        use day2_capabilities::Name;
        let all = multi_source_security_projection_fixture()?;
        assert_eq!(all.apps.len(), 2);
        assert_eq!(all.control.as_ref().unwrap().sources.len(), 2);
        assert_eq!(all.control.as_ref().unwrap().security_epochs.len(), 2);
        for app in ["example_app", "other_app"] {
            let selected = historical_projection(all.clone(), app, all.apps[app].clone());
            let reloaded = Instance::from_bytes(&serde_json::to_vec(&selected)?)?;
            let name = Name::try_from(app.to_owned())?;
            let source = &all.control.as_ref().unwrap().apps[&name].source;
            let control = reloaded.control.as_ref().unwrap();
            assert_eq!(reloaded.apps.len(), 1);
            assert_eq!(control.apps.len(), 1);
            assert_eq!(control.sources.len(), 1);
            assert_eq!(
                control.sources[source],
                all.control.as_ref().unwrap().sources[source]
            );
            assert_eq!(control.security_epochs.len(), 1);
            assert_eq!(
                control.security_epochs[&name],
                all.control.as_ref().unwrap().security_epochs[&name]
            );
            assert_eq!(
                reloaded.apps[app].oauth_connections,
                all.apps[app].oauth_connections
            );
            let manifest = Manifest {
                format: 3,
                scope: reloaded.scope(app)?,
                artifact: day2::digest(b"historical artifact"),
                database: day2::digest(b"historical database"),
                provider_databases: BTreeMap::new(),
                companion_state: BTreeMap::new(),
                app: app.into(),
                authority: authority_state::AuthorityStamp {
                    epoch: "local-history".into(),
                    revision: 1,
                },
                resources: Default::default(),
                instance: reloaded,
            };
            let restored: Manifest = day2::json::decode(&serde_json::to_vec(&manifest)?)?;
            assert_eq!(
                manifest.security_restore_digest()?,
                restored.security_restore_digest()?
            );
            Instance::from_bytes(&serde_json::to_vec(&restored.instance)?)?;
        }
        Ok(())
    }

    #[test]
    fn historical_projection_refuses_missing_foreign_or_stale_selections() -> Result<()> {
        use day2_capabilities::{Digest, Name};
        let name = |value: &str| Name::try_from(value.to_owned()).unwrap();
        let all = multi_source_security_projection_fixture()?;
        let projected =
            historical_projection(all.clone(), "example_app", all.apps["example_app"].clone());
        let mut changed = projected.clone();
        changed.control.as_mut().unwrap().sources.insert(
            name("other_source"),
            all.control.as_ref().unwrap().sources[&name("other_source")].clone(),
        );
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("unused source binding"),
            "{error:#}"
        );
        let mut changed = projected.clone();
        changed.control.as_mut().unwrap().sources.clear();
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("unknown source binding"),
            "{error:#}"
        );
        let mut changed = projected.clone();
        changed
            .control
            .as_mut()
            .unwrap()
            .apps
            .get_mut(&name("example_app"))
            .unwrap()
            .source = name("other_source");
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("unknown source binding"),
            "{error:#}"
        );
        let mut changed = projected.clone();
        changed.control.as_mut().unwrap().security_epochs.insert(
            name("other_app"),
            all.control.as_ref().unwrap().security_epochs[&name("other_app")].clone(),
        );
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("security_epoch_app_not_installed"),
            "{error:#}"
        );
        let mut changed = projected;
        changed
            .control
            .as_mut()
            .unwrap()
            .security_epochs
            .get_mut(&name("example_app"))
            .unwrap()
            .key_set = Digest::of(&"substituted historical key set")?;
        let error = Instance::from_bytes(&serde_json::to_vec(&changed)?).unwrap_err();
        assert!(
            format!("{error:#}").contains("security_epoch_complete_key_set_mismatch"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn historical_projection_preserves_scoped_epoch_keys_and_shared_shell_metadata() -> Result<()> {
        let digest = day2_capabilities::Digest::new(b"historical selection");
        let pin = serde_json::json!({"id":"historical", "revision":digest});
        let mut epoch = serde_json::json!({"scope":{"installation":"company","environment":"staging","app":"primary"},
            "provider":{"kind":"firestore_native_v1","project":"company-tools","project_number":7,"database":"security",
                "database_uid":"01234567-89ab-4cde-8fab-0123456789ab","iam_source":{"kind":"gke_workload_identity_v1",
                    "service_account":"epochs@company-tools.iam.gserviceaccount.com","service_account_uid":"100000000000000000007"}},"key_set":digest,"max_lease_seconds":30});
        let mut other_epoch = epoch.clone();
        other_epoch["scope"]["app"] = "other".into();
        let family = serde_json::json!({"verifier_secret":"verify","custody":{"kind":"verifier_only"},"max_active_lineages":12});
        let runtime = serde_json::json!({"service_account":"app@company-tools.iam.gserviceaccount.com",
            "attestation":pin,"attestation_secret":"attest","families":{"agents":family}});
        let store: day2_capabilities::security_epoch::EpochStore =
            serde_json::from_value(epoch.clone())?;
        let selected_epoch =
            serde_json::json!({"id":"primary","revision":day2_capabilities::Digest::of(&store)?});
        let role = |name: &str, uid: &str| {
            serde_json::json!({
                "namespace":{"name":"native","uid":"namespace-uid"},
                "kubernetes_service_account":{"name":name,"uid":format!("{name}-ksa-uid")},
                "google_service_account":{"kind":"gke_workload_identity_v1",
                    "service_account":format!("{name}@company-tools.iam.gserviceaccount.com"),"service_account_uid":uid},
                "workload_kind":"deployment_v1","workload":{"name":name,"uid":format!("{name}-workload-uid")},
                "container":{"name":name,"image":digest},
                "token_review_audience":"https://kubernetes.default.svc"
            })
        };
        let bootstrap = serde_json::json!({
            "scope":store.scope,"epoch_store":selected_epoch,
            "cluster":{"project":"company-tools","location":"us-central1","name":"native","uid":"cluster-uid",
                "api_origin":"https://10.0.0.1","certificate_authority":digest},
            "controller":role("controller","200000000000000000007"),"app":role("epochs","100000000000000000007"),
            "shell":role("shell","300000000000000000007"),
            "control_store":{"kind":"firestore_authority_database_v1","epoch_store":selected_epoch},
            "runtime_profile":{"kind":"gke_linux_trusted_native_v1","manifest":digest,"controller_code":digest,"app_host_code":digest,"security_shell_code":digest,"app_artifact":digest},
            "fresh_storage":{"provider_volume_uid":"volume-uid","mount_binding":digest,"schema_contract":digest,"marker_format":"initial-v1"}
        });
        let instance: Instance = serde_json::from_value(
            serde_json::json!({"installation":"company","environment":"staging",
                "apps":{"primary":{"artifact":"original","readers":[],"writers":[]},"other":{"artifact":"other","readers":[],"writers":[]}},
                "control":{"version":1,"state_directory":"/control","operators":["operator"],"sources":{},"apps":{},
                    "security_epochs":{"primary":epoch,"other":other_epoch},
                    "security_bootstraps":{"initial":bootstrap},
                    "secrets":{"verify":{"kind":"gcp_version","project_number":7,"secret":"verifier","version":3}}},
                "credential_runtime":{"version":1,"apps":{"primary":runtime,"other":runtime}},
                "oauth_runtime":{"version":1,"shell":{"project":"company-tools","backend_service":"shell-backend","url_map":"shell-map",
                    "https_proxy":"shell-proxy","forwarding_rule":"shell-https","kubernetes_service":"tools/security-shell"},"apps":{}}
            }),
        )?;
        // These are historical wire selectors, not current admission or native
        // readiness. The projection must retain their exact identity as recorded.
        let primary = day2_capabilities::Name::try_from("primary".to_owned())?;
        let projected = historical_projection(
            instance.clone(),
            "primary",
            instance.apps["primary"].clone(),
        );
        assert_eq!(projected.apps.len(), 1);
        let selected = projected.control.as_ref().unwrap();
        assert_eq!(
            instance.control.as_ref().unwrap().security_bootstraps.len(),
            1
        );
        assert!(selected.security_bootstraps.is_empty());
        assert_eq!(selected.security_epochs.len(), 1);
        assert_eq!(
            serde_json::to_value(&selected.security_epochs[&primary])?,
            epoch
        );
        assert_eq!(projected.credential_runtime.as_ref().unwrap().apps.len(), 1);
        assert_eq!(
            projected.credential_runtime.as_ref().unwrap().apps[&primary],
            instance.credential_runtime.as_ref().unwrap().apps[&primary]
        );
        assert!(projected.oauth_runtime.as_ref().unwrap().apps.is_empty());
        assert_eq!(
            projected.oauth_runtime.as_ref().unwrap().shell,
            instance.oauth_runtime.as_ref().unwrap().shell
        );
        let manifest = Manifest {
            format: 3,
            scope: projected.scope("primary")?,
            artifact: day2::digest(b"artifact"),
            database: day2::digest(b"database"),
            provider_databases: BTreeMap::new(),
            companion_state: BTreeMap::new(),
            app: "primary".into(),
            authority: authority_state::AuthorityStamp {
                epoch: "local-history".into(),
                revision: 1,
            },
            resources: Default::default(),
            instance: projected,
        };
        let identity = manifest.security_restore_digest()?;
        let roundtrip: Manifest = day2::json::decode(&serde_json::to_vec(&manifest)?)?;
        assert_eq!(identity, roundtrip.security_restore_digest()?);
        epoch["provider"]["database_uid"] = "11234567-89ab-4cde-8fab-0123456789ab".into();
        let mut changed = roundtrip;
        changed
            .instance
            .control
            .as_mut()
            .unwrap()
            .security_epochs
            .insert(
                "primary".to_owned().try_into()?,
                serde_json::from_value(epoch)?,
            );
        assert_ne!(identity, changed.security_restore_digest()?);
        Ok(())
    }

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
    fn companion_state_nested_subpaths_snapshot_and_restore() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let state_root = directory.path().join(".state");
        let service_state = state_root.join("companions/services/executor");
        fs::create_dir_all(&service_state)?;
        fs::write(service_state.join("private.json"), b"operator metadata")?;
        let source_database = service_state.join("executor.sqlite");
        let writer = Connection::open(&source_database)?;
        writer.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE valueset(value TEXT NOT NULL); INSERT INTO valueset VALUES('before');",
        )?;
        let backup_root = directory.path().join("backup");
        fs::create_dir(&backup_root)?;
        let subpaths = vec!["companions/services/executor".to_owned()];
        let databases = vec!["companions/services/executor/executor.sqlite".to_owned()];
        let snapshot = snapshot_companion_state(&state_root, &backup_root, &subpaths, &databases)?;
        verify_companion_state(&backup_root, &snapshot)?;
        let copied_database =
            backup_root.join("companion-state/companions/services/executor/executor.sqlite");
        let copied =
            Connection::open_with_flags(&copied_database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(
            copied.query_row("SELECT value FROM valueset", [], |row| row
                .get::<_, String>(0))?,
            "before"
        );
        writer.execute("INSERT INTO valueset VALUES('after')", [])?;
        assert_eq!(
            copied.query_row("SELECT COUNT(*) FROM valueset", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        verify_companion_state(&backup_root, &snapshot)?;

        let restored_root = directory.path().join("restored/.state");
        fs::create_dir_all(&restored_root)?;
        let mut budget = CompanionBudget::default();
        copy_companion_tree(
            &backup_root.join("companion-state/companions/services/executor"),
            &restored_root.join("companions/services/executor"),
            Path::new(""),
            &std::collections::BTreeSet::new(),
            &mut budget,
            0,
        )?;
        let restored = Connection::open_with_flags(
            restored_root.join("companions/services/executor/executor.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        assert_eq!(
            restored.query_row("SELECT COUNT(*) FROM valueset", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        assert_eq!(
            fs::read(restored_root.join("companions/services/executor/private.json"))?,
            b"operator metadata"
        );
        fs::write(
            backup_root.join("companion-state/companions/services/executor/private.json"),
            b"changed",
        )?;
        assert!(verify_companion_state(&backup_root, &snapshot).is_err());
        Ok(())
    }

    #[test]
    fn companion_state_selection_rejects_overlap_and_unscoped_sqlite_paths() {
        assert!(
            validate_companion_selection(
                &["companions/a".into(), "companions/a/nested".into()],
                &[]
            )
            .is_err()
        );
        assert!(
            validate_companion_selection(
                &["companions/a".into()],
                &["companions/other/store.sqlite".into()]
            )
            .is_err()
        );
        assert!(validate_companion_state_subpath("companions/../escape").is_err());
        assert!(validate_companion_state_subpath("companions/a/b/c/d/e").is_err());
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

    /// Appends `rows` one-page rows in one transaction that keeps `total`
    /// equal to the row count, so a torn snapshot is detectable.
    fn append(connection: &Connection, rows: i64) -> rusqlite::Result<()> {
        connection.execute_batch("BEGIN IMMEDIATE")?;
        connection.execute(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1) INSERT INTO entries(body) SELECT randomblob(4000) FROM n",
            [rows],
        )?;
        connection.execute("UPDATE total SET n = n + ?1", [rows])?;
        connection.execute_batch("COMMIT")
    }

    fn ledger(path: &Path, journal: &str, rows: i64) -> Result<Connection> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", journal)?;
        connection.execute_batch("CREATE TABLE entries(id INTEGER PRIMARY KEY, body BLOB NOT NULL); CREATE TABLE total(n INTEGER NOT NULL); INSERT INTO total VALUES(0);")?;
        append(&connection, rows)?;
        Ok(connection)
    }

    /// Rows of an intact, internally consistent copy.
    fn consistent_rows(path: &Path) -> Result<i64> {
        integrity(path)?;
        let copy = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let (rows, total): (i64, i64) = copy.query_row(
            "SELECT (SELECT COUNT(*) FROM entries), (SELECT n FROM total)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(rows, total, "torn snapshot");
        Ok(rows)
    }

    #[test]
    fn slow_large_snapshots_are_bounded_by_progress_and_size_not_a_fixed_budget() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("large.sqlite");
        drop(ledger(&source, "WAL", 256)?);
        // About 1 MiB in 16-page steps, against a floor of 32 KiB/s: the bound
        // is 15 s + ~33 s. The injected clock charges simulated seconds per step.
        let pace = Pace {
            step_pages: 16,
            floor_bytes_per_second: 32 << 10,
            ..ONLINE
        };
        let mut simulated = Duration::ZERO;
        // 64 KiB per second, twice the floor: well past the old fixed 15 s.
        let mut steady = || {
            simulated += Duration::from_secs(1);
            simulated
        };
        let copy = directory.path().join("copy.sqlite");
        drop(online_snapshot(&source, &copy, pace, &mut steady)?);
        assert!(simulated > Duration::from_secs(15));
        assert_eq!(consistent_rows(&copy)?, 256);
        // Below the floor (16 pages per 3 s) the copy fails at its size bound.
        let mut simulated = Duration::ZERO;
        let mut crawling = || {
            simulated += Duration::from_secs(3);
            simulated
        };
        let slow = directory.path().join("slow.sqlite");
        let error = online_snapshot(&source, &slow, pace, &mut crawling).unwrap_err();
        assert!(
            format!("{error:#}").contains("online backup too slow"),
            "{error:#}"
        );
        assert!(
            simulated > Duration::from_secs(45) && simulated < Duration::from_secs(55),
            "{simulated:?}"
        );
        Ok(())
    }

    #[test]
    fn commits_between_every_step_neither_restart_nor_tear_the_snapshot() -> Result<()> {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("busy.sqlite");
        let writer = ledger(&source, "WAL", 512)?;
        let (commits, stop) = (AtomicU64::new(0), AtomicBool::new(false));
        let copy = directory.path().join("copy.sqlite");
        let (snapshot, during) = std::thread::scope(|scope| {
            let (commits, stop) = (&commits, &stop);
            let app = scope.spawn(move || -> rusqlite::Result<()> {
                while !stop.load(SeqCst) {
                    append(&writer, 1)?;
                    commits.fetch_add(1, SeqCst);
                }
                Ok(())
            });
            // Each step waits for another app commit, so the source changes
            // between every pair of steps: an online backup without its own
            // read transaction restarts on each one and never finishes.
            let started = Instant::now();
            let mut after_a_commit = || {
                let (seen, waited) = (commits.load(SeqCst), Instant::now());
                while commits.load(SeqCst) == seen {
                    assert!(!app.is_finished(), "the app writer stopped");
                    assert!(waited.elapsed() < Duration::from_secs(10));
                    std::thread::sleep(Duration::from_millis(1));
                }
                started.elapsed()
            };
            let before = commits.load(SeqCst);
            let pace = Pace {
                step_pages: 8,
                ..ONLINE
            };
            let snapshot = online_snapshot(&source, &copy, pace, &mut after_a_commit);
            let during = commits.load(SeqCst) - before;
            stop.store(true, SeqCst);
            app.join().unwrap().unwrap();
            (snapshot, during)
        });
        drop(snapshot?);
        // 512 rows take ~64 steps, one app commit apart. The copy is the
        // consistent state when its snapshot began, without those commits.
        assert!(during >= 60, "{during} commits during the snapshot");
        let rows = consistent_rows(&copy)?;
        let later = consistent_rows(&source)?;
        assert!(rows >= 512 && later - rows >= 60, "{rows} of {later}");
        Ok(())
    }

    #[test]
    fn a_source_locked_by_a_writer_that_never_releases_fails_within_the_stall_bound() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("locked.sqlite");
        // A rollback-journal writer's exclusive lock keeps every reader out.
        let writer = ledger(&source, "DELETE", 16)?;
        writer.execute_batch("BEGIN EXCLUSIVE; UPDATE total SET n = n;")?;
        let pace = Pace {
            stall: Duration::from_millis(200),
            ..ONLINE
        };
        let started = Instant::now();
        let copy = directory.path().join("copy.sqlite");
        let error = online_snapshot(&source, &copy, pace, || started.elapsed()).unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            format!("{error:#}").contains("online backup stalled: the source stayed locked"),
            "{error:#}"
        );
        writer.execute_batch("ROLLBACK")?;
        let retry = directory.path().join("retry.sqlite");
        drop(online_snapshot(&source, &retry, pace, || {
            started.elapsed()
        })?);
        assert_eq!(consistent_rows(&retry)?, 16);
        Ok(())
    }
}
