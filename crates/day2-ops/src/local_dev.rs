//! Private local-development capabilities. LocalDev.roc owns startup, seeding,
//! rebuild and recovery order. This host owns local state and process lifetimes.
use anyhow::{Context, Result, bail, ensure};
use day2::{
    artifact::{Instance, LoadedArtifact},
    development::Campaign,
    store::Runtime,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub source: String,
    pub directory: String,
    pub action: String,
    pub example: String,
    pub generated: u64,
    pub seed: String,
    pub actor: String,
    pub port: String,
    pub watch: String,
    pub reset: bool,
    pub backup: String,
    pub detach: bool,
    pub data_requested: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    format: u32,
    source: PathBuf,
    actor: String,
    port: u16,
    watch: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Current {
    format: u32,
    source: PathBuf,
    instance: PathBuf,
    actor: String,
    port: u16,
}

struct Live {
    shutdown: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<()>>,
}

#[derive(Clone)]
struct Logger {
    directory: PathBuf,
    console: bool,
    lock: Arc<Mutex<()>>,
}

impl Logger {
    fn event(&self, kind: &str, detail: Value) -> Result<()> {
        let _lock = self.lock.lock().expect("local log lock");
        let record = json!({"event":kind,"detail":detail});
        let log = self.directory.join("events.jsonl");
        if log.exists() {
            ensure!(
                fs::symlink_metadata(&log)?.file_type().is_file(),
                "regular local log required"
            );
            if fs::metadata(&log)?.len() > 4 * 1024 * 1024 {
                fs::rename(&log, self.directory.join("events.previous.jsonl"))?;
            }
        }
        let mut bytes = serde_json::to_vec(&record)?;
        bytes.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(log)?;
        file.write_all(&bytes)?;
        if self.console {
            eprintln!("{record}");
        }
        Ok(())
    }
}

pub struct Session {
    pub options: Options,
    directory: PathBuf,
    executable: PathBuf,
    logger: Logger,
    lock: Option<fs::File>,
    stopped: Arc<AtomicBool>,
    status: Arc<Mutex<Value>>,
    control: Option<std::thread::JoinHandle<()>>,
    executor: Option<tokio::runtime::Runtime>,
    live: Option<Live>,
    active: Option<Runtime>,
    candidate: Option<Runtime>,
    checkpoint: Option<PathBuf>,
    checked: bool,
    pub campaign: Option<Campaign>,
    observed: Option<String>,
    last_build_log: Option<PathBuf>,
    port: u16,
}

fn regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_file() && meta.len() <= limit,
        "bounded regular local file required: {}",
        path.display()
    );
    Ok(fs::read(path)?)
}

fn private(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path)?;
    }
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "local directory must not be a symlink"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    atomic_bytes(path, &serde_json::to_vec_pretty(value)?)
}

fn atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("local file parent")?)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

// Contract-only ports: no app authority, watcher clocks, or random scheduling.
trait ContractCapture {
    fn capture(&mut self, artifact_directory: &Path) -> Result<Vec<u8>>;
}

trait ContractPublisher {
    fn remove_stale(&mut self, path: &Path) -> Result<()>;

    fn publish(&mut self, path: &Path, bytes: &[u8]) -> Result<()>;
}

struct FilesystemContractCapture;
struct FilesystemContractPublisher;

impl ContractCapture for FilesystemContractCapture {
    fn capture(&mut self, artifact_directory: &Path) -> Result<Vec<u8>> {
        // Normal artifact admission is mandatory, even for a previously served artifact.
        day2::app_contracts::export_bytes(artifact_directory)
    }
}

impl ContractPublisher for FilesystemContractPublisher {
    fn remove_stale(&mut self, path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(_) => fs::remove_file(path).map_err(Into::into),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn publish(&mut self, path: &Path, bytes: &[u8]) -> Result<()> {
        // Entropy for temporary names and all atomic filesystem effects belong to
        // this adapter. Cleanup made the output absent; races must not clobber it.
        let mut file =
            tempfile::NamedTempFile::new_in(path.parent().context("local file parent")?)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(path)?;
        Ok(())
    }
}

enum ContractStep {
    Cleanup,
    Capture,
    Publish { bytes: Vec<u8>, digest: String },
    Done(Value),
}

enum ContractObservation {
    Cleaned(Result<()>),
    Captured(Result<Vec<u8>>),
    Published(Result<()>),
}

impl ContractStep {
    // Pure reducer: observations are data. Failures never advertise an output,
    // and identity validation happens before requesting any publication.
    fn advance(self, path: &Path, artifact_id: &str, observation: ContractObservation) -> Self {
        let next = (|| -> Result<Self> {
            match (self, observation) {
                (Self::Cleanup, ContractObservation::Cleaned(result)) => {
                    result.context("remove stale app contracts")?;
                    Ok(Self::Capture)
                }
                (Self::Capture, ContractObservation::Captured(result)) => {
                    let bytes = result?;
                    ensure!(
                        bytes.len() <= 4 * 1024 * 1024,
                        "app contract export byte budget exceeded"
                    );
                    let document: Value = serde_json::from_slice(&bytes)?;
                    ensure!(
                        document["artifact"].as_str() == Some(artifact_id),
                        "exported app contract artifact differs from served artifact"
                    );
                    let digest = day2::digest(&bytes);
                    Ok(Self::Publish { bytes, digest })
                }
                (Self::Publish { digest, .. }, ContractObservation::Published(result)) => {
                    result.context("write app contracts")?;
                    Ok(Self::Done(json!({
                        "path":path,
                        "artifact":artifact_id,
                        "sha256":digest.strip_prefix("sha256:").unwrap_or(&digest),
                    })))
                }
                _ => bail!("invalid app contract publication observation"),
            }
        })();
        next.unwrap_or_else(|error| {
            Self::Done(json!({"error":format!("{error:#}"),"artifact":artifact_id}))
        })
    }
}

fn contract_status_with(
    path: &Path,
    artifact_directory: &Path,
    artifact_id: &str,
    capture: &mut impl ContractCapture,
    publisher: &mut impl ContractPublisher,
) -> Value {
    let mut step = ContractStep::Cleanup;
    loop {
        let observation = match &step {
            ContractStep::Cleanup => ContractObservation::Cleaned(publisher.remove_stale(path)),
            ContractStep::Capture => {
                ContractObservation::Captured(capture.capture(artifact_directory))
            }
            ContractStep::Publish { bytes, .. } => {
                ContractObservation::Published(publisher.publish(path, bytes))
            }
            ContractStep::Done(status) => return status.clone(),
        };
        step = step.advance(path, artifact_id, observation);
    }
}

fn control(directory: &Path, action: &str) -> Result<Option<Value>> {
    let socket = directory.join("control.sock");
    if !socket.exists() {
        return Ok(None);
    }
    use std::os::unix::fs::FileTypeExt;
    ensure!(
        fs::symlink_metadata(&socket)?.file_type().is_socket(),
        "invalid local control socket"
    );
    let mut connection = match UnixStream::connect(&socket) {
        Ok(connection) => connection,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    connection.set_read_timeout(Some(Duration::from_secs(2)))?;
    connection.set_write_timeout(Some(Duration::from_secs(2)))?;
    writeln!(connection, "{action}")?;
    let mut response = String::new();
    BufReader::new(connection)
        .take(65_537)
        .read_to_string(&mut response)?;
    ensure!(response.len() <= 65_536, "local status budget");
    Ok(Some(day2::json::decode(response.as_bytes())?))
}

impl Session {
    pub fn resolve(platform: &Path, mut options: Options) -> Result<Self> {
        ensure!(
            ["start", "status", "stop", "logs", "follow"].contains(&options.action.as_str()),
            "unknown local action"
        );
        let source = PathBuf::from(&options.source)
            .canonicalize()
            .context("local app source")?;
        ensure!(
            source.join("App.roc").is_file(),
            "local-dev requires an app directory containing App.roc"
        );
        let default_root = platform.join("artifacts/local-dev");
        let mut directory = if options.directory.is_empty() {
            default_root.join(&day2::digest(source.as_os_str().as_encoded_bytes())[7..27])
        } else {
            std::path::absolute(&options.directory)?
        };
        let parent = directory.parent().context("local directory parent")?;
        if options.action == "start" && options.directory.is_empty() {
            fs::create_dir_all(parent)?;
        }
        if parent.exists() {
            directory = parent
                .canonicalize()?
                .join(directory.file_name().context("local directory name")?);
        }
        ensure!(
            !directory.starts_with(&source) && !source.starts_with(&directory),
            "local state must live outside app source and its ancestors"
        );
        if directory.exists() {
            ensure!(
                fs::symlink_metadata(&directory)?.file_type().is_dir(),
                "local directory must be regular"
            );
            ensure!(
                directory.join("config.json").is_file()
                    || fs::read_dir(&directory)?.next().is_none(),
                "existing directory is not managed local-dev state"
            );
        }
        if options.action == "start" {
            private(&directory)?;
        }
        let config_path = directory.join("config.json");
        let config: Config = if config_path.exists() {
            day2::json::decode(&regular(&config_path, 65_536)?)?
        } else {
            let config = Config {
                format: 1,
                source: source.clone(),
                actor: if options.actor.is_empty() {
                    "developer".into()
                } else {
                    options.actor.clone()
                },
                port: if options.port.is_empty() {
                    0
                } else {
                    options.port.parse().context("port must be 0..65535")?
                },
                watch: options.watch != "off",
            };
            if options.action == "start" {
                atomic(&config_path, &config)?;
            }
            config
        };
        ensure!(
            config.format == 1 && config.source == source,
            "local directory belongs to another source"
        );
        if options.actor.is_empty() {
            options.actor = config.actor;
        }
        ensure!(
            !options.actor.is_empty()
                && options.actor.len() <= 256
                && options.actor.trim() == options.actor
                && !options.actor.chars().any(char::is_control),
            "invalid local actor"
        );
        if options.port.is_empty() {
            options.port = config.port.to_string();
        }
        let port: u16 = options.port.parse().context("port must be 0..65535")?;
        if options.watch.is_empty() {
            options.watch = if config.watch { "on" } else { "off" }.into();
        }
        ensure!(
            ["on", "off"].contains(&options.watch.as_str()),
            "invalid watch setting"
        );
        ensure!(
            options.generated <= 100 && options.seed.parse::<u64>().is_ok(),
            "invalid generation settings"
        );
        ensure!(
            [
                !options.example.is_empty(),
                options.generated > 0,
                !options.backup.is_empty()
            ]
            .into_iter()
            .filter(|value| *value)
            .count()
                <= 1,
            "choose one data source"
        );
        if !options.backup.is_empty() {
            options.backup = PathBuf::from(&options.backup)
                .canonicalize()?
                .to_string_lossy()
                .into_owned();
        }
        options.source = source.to_string_lossy().into_owned();
        options.directory = directory.to_string_lossy().into_owned();
        let status = json!({"state":"stopped", "running":false, "source":source, "directory":directory, "config":config_path, "log":directory.join("events.jsonl")});
        let logger = Logger {
            directory: directory.clone(),
            console: true,
            lock: Arc::new(Mutex::new(())),
        };
        Ok(Self {
            options,
            directory,
            executable: std::env::current_exe()?,
            logger,
            lock: None,
            stopped: Arc::new(AtomicBool::new(false)),
            status: Arc::new(Mutex::new(status)),
            control: None,
            executor: None,
            live: None,
            active: None,
            candidate: None,
            checkpoint: None,
            checked: false,
            campaign: None,
            observed: None,
            last_build_log: None,
            port,
        })
    }

    pub fn cancelled(&self) -> Arc<AtomicBool> {
        self.stopped.clone()
    }

    pub fn failed(&self, error: &anyhow::Error) {
        let _ = self.event("session-failed", json!({"error":format!("{error:#}")}));
    }

    pub fn build_log(&mut self, path: &Path) -> Result<()> {
        self.last_build_log = Some(path.into());
        self.event("building", json!({"build_log":path}))
    }

    pub fn detach_output(&mut self) {
        self.logger.console = false;
    }

    fn event(&self, kind: &str, detail: Value) -> Result<()> {
        self.logger.event(kind, detail)
    }

    fn current(&self) -> Result<Option<Current>> {
        let path = self.directory.join("current.json");
        if !path.exists() {
            return Ok(None);
        }
        let value: Current = day2::json::decode(&regular(&path, 65_536)?)?;
        ensure!(
            value.format == 1 && value.source == Path::new(&self.options.source),
            "invalid local instance binding"
        );
        let instance = value.instance.canonicalize()?;
        ensure!(
            instance.starts_with(self.directory.canonicalize()?.join("instances"))
                && instance
                    .file_name()
                    .is_some_and(|name| name == "instance.json"),
            "instance outside managed local state"
        );
        Ok(Some(value))
    }

    fn status(&self) -> Result<Value> {
        Ok(control(&self.directory, "status")?
            .unwrap_or_else(|| self.status.lock().expect("status lock").clone()))
    }

    fn prepare(&mut self) -> Result<Value> {
        if let Some(existing) = control(&self.directory, "status")? {
            ensure!(
                !self.options.reset
                    && !self.options.data_requested
                    && existing["actor"] == self.options.actor
                    && (self.port == 0 || existing["port"] == self.port),
                "session already running; stop it before changing settings"
            );
            return Ok(json!({"running":true}));
        }
        let lock_path = self.directory.join("session.lock");
        if lock_path.exists() {
            let _ = regular(&lock_path, 128)?;
        }
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(lock_path)?;
        lock.try_lock()
            .context("another local-dev session owns this directory")?;
        self.lock = Some(lock);
        if let Some(current) = self.current()? {
            ensure!(
                self.options.reset || !self.options.data_requested,
                "existing development data: use --reset to select new seed or backup data"
            );
            ensure!(
                self.options.reset || current.actor == self.options.actor,
                "changing the local actor requires --reset"
            );
            if self.port == 0 {
                self.port = current.port;
            }
        }
        private(&self.directory.join("instances"))?;
        let socket = self.directory.join("control.sock");
        if socket.exists() {
            use std::os::unix::fs::FileTypeExt;
            ensure!(
                fs::symlink_metadata(&socket)?.file_type().is_socket(),
                "invalid stale control socket"
            );
            fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket).context(
            "local control socket; choose a shorter --directory if its path exceeds the OS limit",
        )?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        *self.status.lock().expect("status lock") = json!({"state":"starting","running":true,"source":self.options.source,"directory":self.directory,"actor":self.options.actor,"port":self.port,"log":self.directory.join("events.jsonl"),"config":self.directory.join("config.json")});
        let stopped = self.stopped.clone();
        let state = self.status.clone();
        self.control = Some(std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut connection, _)) => {
                        let _ = connection.set_read_timeout(Some(Duration::from_secs(1)));
                        let _ = connection.set_write_timeout(Some(Duration::from_secs(1)));
                        let mut action = String::new();
                        if BufReader::new(&connection)
                            .take(65)
                            .read_line(&mut action)
                            .is_ok()
                        {
                            let value = match action.trim() {
                                "status" => state.lock().expect("status lock").clone(),
                                "stop" => {
                                    stopped.store(true, Ordering::SeqCst);
                                    json!({"stopping":true})
                                }
                                _ => json!({"error":"unknown control request"}),
                            };
                            let _ = writeln!(connection, "{value}");
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(40))
                    }
                    Err(_) => break,
                }
            }
        }));
        self.executor = Some(tokio::runtime::Runtime::new()?);
        let stopped = self.stopped.clone();
        self.executor.as_ref().expect("executor").spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            stopped.store(true, Ordering::SeqCst);
        });
        self.observed = Some(source_digest(Path::new(&self.options.source))?);
        Ok(json!({"running":false}))
    }

    fn fresh_directory(&self, prefix: &str) -> Result<PathBuf> {
        Ok(tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(self.directory.join("instances"))?
            .keep()
            .join("data"))
    }

    fn target(&self) -> Result<&Runtime> {
        self.candidate
            .as_ref()
            .or(self.active.as_ref())
            .context("local instance required")
    }

    fn open(&mut self, artifact: &Path) -> Result<Value> {
        ensure!(
            self.lock.is_some() && self.active.is_none(),
            "prepared session required"
        );
        let previous = if self.options.reset {
            None
        } else {
            self.current()?
        };
        if let Some(current) = previous {
            self.active = Some(Runtime::load(&current.instance, "app")?);
            return Ok(json!({"fresh":false}));
        }
        self.candidate = Some(day2::development::create_for(
            artifact,
            &self.fresh_directory("run-")?,
            None,
            &self.options.actor,
        )?);
        Ok(json!({"fresh":true}))
    }

    fn import(&mut self) -> Result<Value> {
        let runtime = self
            .candidate
            .as_ref()
            .context("fresh local instance required")?;
        ensure!(
            self.active.is_none() && !self.options.backup.is_empty(),
            "backup import is only allowed into a fresh session"
        );
        let manifest = crate::backup::verify(Path::new(&self.options.backup))?;
        let old = LoadedArtifact::load(
            &Path::new(&self.options.backup).join(&manifest.instance.apps[&manifest.app].artifact),
        )?;
        ensure!(
            old.contract().schema == runtime.artifact().contract().schema,
            "backup schema differs from the dev build; use a compatible source revision"
        );
        // Only admitted business tables cross into a clean local installation.
        // Provider config, production identity, pending commands and audit history do not.
        let mut db = rusqlite::Connection::open_with_flags(
            runtime.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        db.busy_timeout(Duration::from_secs(15))?;
        db.pragma_update(None, "foreign_keys", true)?;
        db.pragma_update(None, "trusted_schema", false)?;
        db.execute(
            "ATTACH DATABASE ?1 AS imported",
            [Path::new(&self.options.backup)
                .join("app.sqlite")
                .to_string_lossy()
                .as_ref()],
        )?;
        let tx = day2::write_queue::immediate(&mut db)?;
        tx.execute_batch("PRAGMA defer_foreign_keys=ON")?;
        for model in runtime.artifact().contract().schema.models.keys() {
            day2::schema::identifier(model)?;
            let count: i64 =
                tx.query_row(&format!("SELECT COUNT(*) FROM \"{model}\""), [], |row| {
                    row.get(0)
                })?;
            ensure!(count == 0, "backup import target must be empty");
            tx.execute(
                &format!("INSERT INTO \"{model}\" SELECT * FROM imported.\"{model}\""),
                [],
            )?;
        }
        ensure!(
            tx.prepare("PRAGMA foreign_key_check")?
                .query([])?
                .next()?
                .is_none(),
            "backup relationship violation"
        );
        crate::backup::verify(Path::new(&self.options.backup))?;
        tx.commit()?;
        let snapshot = runtime.inspect()?;
        self.event(
            "backup-imported",
            json!({"backup":self.options.backup,"artifact":old.id(),"pending_invocations_imported":false}),
        )?;
        Ok(json!({"models":snapshot.as_object().context("snapshot")?.len()}))
    }

    fn pause(&mut self) -> Result<()> {
        if let Some(mut live) = self.live.take() {
            let _ = live.shutdown.send(true);
            let result = self.executor.as_ref().context("executor")?.block_on(async {
                tokio::time::timeout(Duration::from_secs(35), async {
                    (&mut live.server).await??;
                    Ok::<(), anyhow::Error>(())
                })
                .await
                .context("local shutdown deadline")?
            });
            if result.is_err() {
                live.server.abort();
            }
            result?;
        }
        Ok(())
    }

    fn snapshot(&mut self) -> Result<Value> {
        ensure!(
            self.live.is_none(),
            "pause local HTTP and commands before snapshot"
        );
        let runtime = self
            .active
            .as_ref()
            .context("active local instance required")?;
        let path = self.fresh_directory("checkpoint-")?;
        crate::backup::take(runtime.instance_path(), "app", &path)?;
        self.checkpoint = Some(path);
        Ok(json!({}))
    }

    fn migrate(&mut self, artifact: &Path) -> Result<Value> {
        ensure!(
            self.live.is_none(),
            "pause local processes before migration"
        );
        let backup = self
            .checkpoint
            .as_ref()
            .context("local checkpoint required")?;
        let target = LoadedArtifact::load(artifact)?;
        let instance = crate::backup::restore(backup, &self.fresh_directory("candidate-")?)?;
        let old = Runtime::load(&instance, "app")?;
        ensure!(
            target.contract().namespace == old.artifact().contract().namespace,
            "rebuild changed app namespace"
        );
        let (prior_catalog, prior_attachments) = day2::development::resource_fixture_for_artifact(
            "app",
            old.artifact(),
            &day2::development::local_policy_for(old.artifact(), &self.options.actor)?,
        )?;
        let prior_db = rusqlite::Connection::open_with_flags(
            old.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let prior = day2::authority_state::current(&prior_db)?;
        // Automatic local rebuilds may recreate only the explicit disposable
        // fixture. Never detach a customized budget or widen topics/limits when
        // a checkpoint omits the original desired authoring catalog.
        ensure!(
            prior.document.resources == prior_catalog.resolve("app", &prior_attachments, 0)?,
            "local_custom_resource_authority_requires_explicit_activation"
        );
        drop(prior_db);
        let plan = day2::migration::plan(&old, &target)?;
        day2::migration::apply(&old, &target, &plan)?;
        let mut config = Instance::load(&instance)?;
        let app = config.apps.get_mut("app").context("local app")?;
        app.artifact = target.directory().to_string_lossy().into_owned();
        app.readers = [self.options.actor.clone()].into();
        app.writers = [self.options.actor.clone()].into();
        app.authority = Some(day2::development::local_policy_for(
            &target,
            &self.options.actor,
        )?);
        let (resources, attachments) = day2::development::resource_fixture_for_artifact(
            "app",
            &target,
            app.authority.as_ref().context("local authority")?,
        )?;
        app.resource_policies = attachments;
        config.resources = Some(resources);
        // This file prepares desired configuration. A single native activation
        // below publishes both the new artifact and its freshly approved grants.
        atomic(&instance, &config)?;
        let mut db = rusqlite::Connection::open_with_flags(
            old.db(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        let operator = day2::authority_state::LocalOperator::assert_local("local-development")?;
        let tx = day2::write_queue::immediate(&mut db)?;
        let expected = day2::authority_state::current(&tx)?.stamp;
        // This checkpoint is a deliberate disposable local cutover. Retain all
        // usage and unknown holds while recovering its fenced accounting. Empty
        // allocations fail if any company-backed capacity was ever installed.
        day2::budget::prepare_restore_recovery_in(&tx, &operator)?;
        day2::budget::recover_restored_in(&tx, None, &[], &operator)?;
        tx.commit()?;
        drop(db);
        day2::migration::activate_checked(
            &old,
            &target,
            &operator,
            &expected,
            "local-development-activation",
        )?;
        self.candidate = Some(Runtime::load(&instance, "app")?);
        self.checked = false;
        self.event(
            "migration-checked",
            json!({"plan":plan.id()?,"artifact":target.id()}),
        )?;
        Ok(json!({}))
    }

    fn start(&mut self, runtime: Runtime) -> Result<Value> {
        ensure!(
            self.live.is_none() && !self.stopped.load(Ordering::SeqCst),
            "local session is stopping or already serving"
        );
        let executor = self.executor.as_ref().context("executor")?;
        let server = executor.block_on(day2::web::LocalServer::bind(
            runtime.clone(),
            &self.options.actor,
            self.port,
        ))?;
        self.port = server
            .origin
            .rsplit_once(':')
            .context("loopback origin")?
            .1
            .parse()?;
        let info = json!({"state":"ready","running":true,"source":self.options.source,"directory":self.directory,"actor":self.options.actor,"port":self.port,"origin":server.origin,"login_url":server.login_url,"instance":runtime.instance_path(),"artifact":runtime.artifact().id(),"watch":self.options.watch=="on","log":self.directory.join("events.jsonl"),"config":self.directory.join("config.json")});
        let (shutdown, mut closing) = tokio::sync::watch::channel(false);
        let server = executor.spawn(server.serve(async move {
            let _ = closing.changed().await;
        }));
        self.live = Some(Live { shutdown, server });
        Ok(info)
    }

    fn contracts(&self, artifact_directory: &Path, artifact_id: &str) -> Value {
        contract_status_with(
            &self.directory.join("app-contracts.json"),
            artifact_directory,
            artifact_id,
            &mut FilesystemContractCapture,
            &mut FilesystemContractPublisher,
        )
    }

    fn ready(&self, info: Value) -> Result<()> {
        self.event("ready", json!({"origin":info["origin"],"artifact":info["artifact"],"instance":info["instance"]}))?;
        *self.status.lock().expect("status lock") = info.clone();
        if self.logger.console {
            println!("{info}");
        }
        Ok(())
    }

    fn activate(&mut self) -> Result<Value> {
        ensure!(
            self.checked,
            "local property checks required before serving"
        );
        let candidate = self
            .candidate
            .as_ref()
            .context("checked candidate required")?
            .clone();
        let mut info = self.start(candidate.clone())?;
        let current = Current {
            format: 1,
            source: self.options.source.clone().into(),
            instance: candidate.instance_path().to_path_buf(),
            actor: self.options.actor.clone(),
            port: self.port,
        };
        if let Err(error) = atomic(&self.directory.join("current.json"), &current) {
            self.pause()?;
            return Err(error);
        }
        self.active = self.candidate.take();
        self.checkpoint = None;
        self.campaign = None;
        info["contracts"] =
            self.contracts(candidate.artifact().directory(), candidate.artifact().id());
        self.ready(info)?;
        Ok(json!({}))
    }

    fn wait(&mut self) -> Result<Value> {
        let start = Instant::now();
        let mut changed: Option<(String, Instant)> = None;
        loop {
            if self.stopped.load(Ordering::SeqCst) {
                return Ok(json!({"changed":false,"stopped":true}));
            }
            if let Some(live) = &self.live {
                ensure!(
                    !live.server.is_finished(),
                    "local HTTP server stopped unexpectedly"
                );
            }
            if self.options.watch == "on" {
                let digest = source_digest(Path::new(&self.options.source))
                    .unwrap_or_else(|error| format!("unreadable-source:{error:#}"));
                if self.observed.as_ref() != Some(&digest) {
                    match &changed {
                        Some((previous, since))
                            if previous == &digest
                                && since.elapsed() >= Duration::from_millis(500) =>
                        {
                            self.observed = Some(digest);
                            return Ok(json!({"changed":true,"stopped":false}));
                        }
                        Some((previous, _)) if previous == &digest => {}
                        _ => changed = Some((digest, Instant::now())),
                    }
                } else {
                    changed = None;
                }
            }
            if start.elapsed() >= Duration::from_secs(20) {
                return Ok(json!({"changed":false,"stopped":false}));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn logs(&self, follow: bool) -> Result<Value> {
        let path = self.directory.join("events.jsonl");
        let mut offset = 0;
        loop {
            if path.exists() {
                let bytes = regular(&path, 8 * 1024 * 1024)?;
                if offset > bytes.len() {
                    offset = 0;
                }
                if offset == 0 {
                    offset = bytes.len().saturating_sub(65_536);
                }
                print!("{}", String::from_utf8_lossy(&bytes[offset..]));
                std::io::stdout().flush()?;
                offset = bytes.len();
            }
            if !follow || control(&self.directory, "status")?.is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        Ok(json!({"log":path}))
    }

    fn launch(&self, options: Value) -> Result<Value> {
        if let Some(status) = control(&self.directory, "status")? {
            ensure!(
                !self.options.reset
                    && !self.options.data_requested
                    && status["actor"] == self.options.actor
                    && (self.port == 0 || status["port"] == self.port),
                "stop running local-dev before changing settings"
            );
            return Ok(status);
        }
        let log = tempfile::Builder::new()
            .prefix("launch-")
            .suffix(".log")
            .tempfile_in(&self.directory)?
            .keep()?
            .0;
        let mut child = Command::new(&self.executable)
            .arg(
                json!({"protocol":1,"action":"local-session","input":options.to_string()})
                    .to_string(),
            )
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log.try_clone()?)
            .process_group(0)
            .spawn()?;
        let start = Instant::now();
        loop {
            if let Some(status) = control(&self.directory, "status")?
                && status["state"] == "ready"
            {
                return Ok(status);
            }
            if let Some(status) = child.try_wait()? {
                let mut text = String::new();
                let mut log = log;
                log.seek(SeekFrom::Start(0))?;
                log.take(65_536).read_to_string(&mut text)?;
                bail!("local session failed ({status}): {text}");
            }
            if start.elapsed() > Duration::from_secs(600) || log.metadata()?.len() > 8 * 1024 * 1024
            {
                if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::TERM);
                }
                let _ = child.kill();
                let _ = child.wait();
                bail!("local session startup deadline or log budget");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn effect(&mut self, request: day2::automation::Request) -> Result<Value> {
        let value: Value = request.decode()?;
        if request.action.starts_with("dev-") {
            return self
                .campaign
                .as_mut()
                .context("local seed campaign required")?
                .effect(request);
        }
        if !["local-open", "local-migrate", "local-error", "local-launch"]
            .contains(&request.action.as_str())
        {
            ensure!(value == json!({}), "local capability accepts no parameters");
        }
        match request.action.as_str() {
            "local-status" => self.status(),
            "local-stop" => {
                let response = control(&self.directory, "stop")?
                    .unwrap_or(json!({"stopped":true,"running":false}));
                let started = Instant::now();
                let path = self.directory.join("session.lock");
                if path.exists() {
                    let file = fs::File::open(path)?;
                    while file.try_lock().is_err() {
                        ensure!(
                            started.elapsed() < Duration::from_secs(45),
                            "local shutdown still pending"
                        );
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                Ok(response)
            }
            "local-logs" => self.logs(false),
            "local-follow" => self.logs(true),
            "local-launch" => self.launch(value),
            "local-prepare" => self.prepare(),
            "local-open" => self.open(Path::new(
                value["artifact"].as_str().context("artifact path")?,
            )),
            "local-import" => self.import(),
            "local-campaign" => {
                ensure!(
                    self.campaign.is_none() && self.active.is_none(),
                    "seeding is only allowed in a fresh instance"
                );
                self.campaign = Some(Campaign::for_actor(
                    self.target()?.clone(),
                    (!self.options.example.is_empty()).then_some(self.options.example.as_str()),
                    self.options.seed.parse()?,
                    self.options.generated,
                    &self.options.actor,
                    !self.options.example.is_empty(),
                )?);
                Ok(json!({}))
            }
            "local-properties" => {
                if let Some(campaign) = &self.campaign {
                    ensure!(campaign.is_complete(), "local seeding incomplete");
                }
                let runtime = self.target()?;
                day2::properties::require(
                    runtime.artifact(),
                    &runtime.inspect()?,
                    runtime
                        .instance_path()
                        .parent()
                        .context("local instance directory")?,
                )?;
                self.checked = true;
                Ok(json!({}))
            }
            "local-pause" => {
                self.pause()?;
                Ok(json!({}))
            }
            "local-drain" => {
                ensure!(
                    self.live.is_none(),
                    "pause local requests before draining commands"
                );
                let runtime = self.active.as_ref().context("previous runtime required")?;
                day2::invocations::drain(runtime, 256)?;
                Ok(json!({}))
            }
            "local-snapshot" => self.snapshot(),
            "local-migrate" => self.migrate(Path::new(
                value["artifact"].as_str().context("artifact path")?,
            )),
            "local-activate" => self.activate(),
            "local-wait" => self.wait(),
            "local-error" => {
                self.event("rebuild-failed", value)?;
                if let Some(path) = &self.last_build_log
                    && let Ok(bytes) = regular(path, 8 * 1024 * 1024)
                {
                    self.event("compiler-diagnostics", json!({"text":String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(32_768)..])}))?;
                }
                Ok(json!({}))
            }
            "local-recover" => {
                self.candidate = None;
                self.checked = false;
                self.checkpoint = None;
                if self.live.is_none() && !self.stopped.load(Ordering::SeqCst) {
                    let active = self
                        .active
                        .as_ref()
                        .context("previous local instance required")?
                        .clone();
                    let mut info = self.start(active.clone())?;
                    info["contracts"] =
                        self.contracts(active.artifact().directory(), active.artifact().id());
                    self.ready(info)?;
                }
                Ok(json!({}))
            }
            "local-shutdown" => {
                self.pause()?;
                self.event("stopped", json!({}))?;
                Ok(json!({"stopped":true,"directory":self.directory}))
            }
            _ => bail!("unknown local development capability"),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.pause();
        if let Some(campaign) = &mut self.campaign {
            let _ = campaign
                .persist((!campaign.is_complete()).then(|| "local seeding interrupted".into()));
        }
        if let Some(control) = self.control.take() {
            let _ = control.join();
        }
        if self.lock.is_some() {
            let _ = fs::remove_file(self.directory.join("control.sock"));
        }
        if let Some(executor) = self.executor.take() {
            executor.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

/// Changes to compiler inputs trigger rebuilds; editor/VCS metadata never does.
fn source_digest(source: &Path) -> Result<String> {
    fn visit(
        root: &Path,
        path: &Path,
        files: &mut BTreeMap<String, String>,
        bytes: &mut u64,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth <= 16, "local source nesting budget");
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("source filename UTF-8")?;
            if name.starts_with('.') || name.ends_with('~') {
                continue;
            }
            let kind = entry.file_type()?;
            ensure!(!kind.is_symlink(), "local source symlinks forbidden");
            if kind.is_dir() {
                visit(root, &entry.path(), files, bytes, depth + 1)?;
            } else {
                ensure!(kind.is_file(), "local source special files forbidden");
                if name.ends_with(".md") {
                    continue;
                }
                *bytes += entry.metadata()?.len();
                ensure!(
                    *bytes <= 64 * 1024 * 1024 && files.len() < 4096,
                    "local source watch budget"
                );
                files.insert(
                    entry
                        .path()
                        .strip_prefix(root)?
                        .to_string_lossy()
                        .into_owned(),
                    day2::digest(&fs::read(entry.path())?),
                );
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    visit(source, source, &mut files, &mut 0, 0)?;
    Ok(day2::digest(&serde_json::to_vec(&files)?))
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    fn session(root: &Path) -> Result<Session> {
        let source = root.join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("App.roc"), "App :: [].{}\n")?;
        Session::resolve(
            root,
            Options {
                source: source.to_string_lossy().into_owned(),
                directory: root.join("session").to_string_lossy().into_owned(),
                action: "start".into(),
                example: String::new(),
                generated: 0,
                seed: "42".into(),
                actor: "developer".into(),
                port: "0".into(),
                watch: "off".into(),
                reset: false,
                backup: String::new(),
                detach: false,
                data_requested: false,
            },
        )
    }

    struct MemoryCapture {
        bytes: Vec<u8>,
        fail: bool,
        trace: std::rc::Rc<std::cell::RefCell<Vec<Value>>>,
    }

    impl ContractCapture for MemoryCapture {
        fn capture(&mut self, _: &Path) -> Result<Vec<u8>> {
            self.trace.borrow_mut().push(json!("capture"));
            ensure!(!self.fail, "capture failed");
            Ok(self.bytes.clone())
        }
    }

    struct MemoryPublisher {
        file: Option<Vec<u8>>,
        cleanup_fail: bool,
        publish_fail: bool,
        race: bool,
        trace: std::rc::Rc<std::cell::RefCell<Vec<Value>>>,
    }

    impl ContractPublisher for MemoryPublisher {
        fn remove_stale(&mut self, _: &Path) -> Result<()> {
            self.trace.borrow_mut().push(json!("cleanup"));
            ensure!(!self.cleanup_fail, "cleanup failed");
            self.file = None;
            Ok(())
        }

        fn publish(&mut self, _: &Path, bytes: &[u8]) -> Result<()> {
            self.trace.borrow_mut().push(json!({"publish":bytes}));
            if self.race {
                self.file = Some(b"racer".to_vec());
            }
            ensure!(!self.publish_fail, "publish failed");
            ensure!(self.file.is_none(), "output exists");
            self.file = Some(bytes.to_vec());
            Ok(())
        }
    }

    struct PublicationReplayTrace {
        seed: u64,
        records: Vec<Value>,
    }

    impl Drop for PublicationReplayTrace {
        fn drop(&mut self) {
            if std::thread::panicking() {
                let save = (|| -> Result<PathBuf> {
                    let root = tempfile::tempdir()?;
                    fs::write(
                        root.path().join("contract-publication-replay.json"),
                        serde_json::to_vec(&json!({"seed":self.seed,"records":self.records}))?,
                    )?;
                    Ok(root.keep())
                })();
                eprintln!("contract publication failure replay: {save:?}");
            }
        }
    }

    fn replay_publications(seed: u64) -> Result<Vec<u8>> {
        let mut schedule = seed;
        let mut evidence = PublicationReplayTrace {
            seed,
            records: Vec::new(),
        };
        let records = &mut evidence.records;
        for _ in 0..64 {
            schedule = schedule.wrapping_mul(6364136223846793005).wrapping_add(1);
            let case = (schedule >> 32) % 8;
            let bytes = match case {
                3 => br#"{"artifact":"sha256:other"}"#.to_vec(),
                5 => b"not json".to_vec(),
                6 => vec![b' '; 4 * 1024 * 1024 + 1],
                _ => br#"{"artifact":"sha256:served"}"#.to_vec(),
            };
            let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
            let mut capture = MemoryCapture {
                bytes: bytes.clone(),
                fail: case == 2,
                trace: trace.clone(),
            };
            let mut publisher = MemoryPublisher {
                file: Some(b"stale".to_vec()),
                cleanup_fail: case == 1,
                publish_fail: case == 4,
                race: case == 7,
                trace: trace.clone(),
            };
            let path = Path::new("/session/app-contracts.json");
            let status = contract_status_with(
                path,
                Path::new("/artifact"),
                "sha256:served",
                &mut capture,
                &mut publisher,
            );
            let ready = json!({"state":"ready","artifact":"sha256:served","contracts":status});
            let expected_file = match case {
                0 => Some(bytes.clone()),
                1 => Some(b"stale".to_vec()),
                7 => Some(b"racer".to_vec()),
                _ => None,
            };
            let expected_trace = match case {
                1 => json!(["cleanup"]),
                0 | 4 | 7 => json!(["cleanup", "capture", {"publish":bytes}]),
                _ => json!(["cleanup", "capture"]),
            };
            records.push(
                json!({"case":case,"status":ready,"file":publisher.file,"trace":*trace.borrow()}),
            );
            assert_eq!(
                publisher.file, expected_file,
                "seed={seed} trace={records:?}"
            );
            assert_eq!(
                serde_json::to_value(&*trace.borrow())?,
                expected_trace,
                "seed={seed} trace={records:?}"
            );
            assert_eq!(ready["state"], "ready");
            assert_eq!(status["artifact"], "sha256:served");
            if case == 0 {
                let digest = day2::digest(&bytes);
                assert_eq!(
                    status,
                    json!({"artifact":"sha256:served","path":path,"sha256":&digest[7..]})
                );
            } else {
                assert!(status["error"].is_string(), "seed={seed} trace={records:?}");
                assert!(status.get("path").is_none());
                assert!(status.get("sha256").is_none());
                let message = match case {
                    1 => "remove stale app contracts: cleanup failed",
                    2 => "capture failed",
                    3 => "exported app contract artifact differs from served artifact",
                    4 => "write app contracts: publish failed",
                    5 => "expected ident",
                    6 => "app contract export byte budget exceeded",
                    7 => "write app contracts: output exists",
                    _ => unreachable!(),
                };
                assert!(status["error"].as_str().unwrap().contains(message));
            }
        }
        Ok(serde_json::to_vec(&json!({"seed":seed,"records":records}))?)
    }

    #[test]
    fn seeded_contract_status_and_publication_replay_byte_identically() -> Result<()> {
        for seed in [0, 42, 130, u64::MAX] {
            let trace = replay_publications(seed)?;
            assert_eq!(trace, replay_publications(seed)?);
            let root = tempfile::tempdir()?;
            let path = root.path().join("contract-publication-replay.json");
            fs::write(&path, &trace)?;
            let replay: Value = serde_json::from_slice(&fs::read(path)?)?;
            assert_eq!(
                trace,
                replay_publications(replay["seed"].as_u64().unwrap())?
            );
            eprintln!("contract publication replay: {}", root.keep().display());
        }
        Ok(())
    }

    #[test]
    fn out_of_order_contract_observation_fails_closed() {
        let step = ContractStep::Cleanup.advance(
            Path::new("/output"),
            "sha256:served",
            ContractObservation::Published(Ok(())),
        );
        let ContractStep::Done(status) = step else {
            panic!("invalid sequence must finish")
        };
        assert_eq!(status["artifact"], "sha256:served");
        assert!(status["error"].is_string());
        assert!(status.get("path").is_none());
    }

    #[test]
    fn filesystem_contract_publication_is_private_and_no_clobber() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("app-contracts.json");
        let mut publisher = FilesystemContractPublisher;
        publisher.publish(&path, b"current")?;
        assert_eq!(fs::read(&path)?, b"current");
        assert_eq!(
            fs::symlink_metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        assert!(publisher.publish(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path)?, b"current");
        publisher.remove_stale(&path)?;
        let artifact = root.path().join("artifact.json");
        fs::write(&artifact, b"admitted")?;
        fs::hard_link(&artifact, &path)?;
        assert!(publisher.publish(&path, b"replacement").is_err());
        assert_eq!(fs::read(&artifact)?, b"admitted");
        assert_eq!(fs::read(&path)?, b"admitted");
        publisher.remove_stale(&path)?;
        std::os::unix::fs::symlink(&artifact, &path)?;
        assert!(publisher.publish(&path, b"replacement").is_err());
        assert_eq!(fs::read(&artifact)?, b"admitted");
        publisher.remove_stale(&path)?;
        assert_eq!(fs::read(&artifact)?, b"admitted");
        assert_eq!(fs::read_dir(root.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn failed_export_removes_stale_file_and_keeps_ready_status() -> Result<()> {
        let root = tempfile::tempdir()?;
        let session = session(root.path())?;
        let path = session.directory.join("app-contracts.json");
        fs::write(&path, b"stale contract")?;
        let contracts = session.contracts(&root.path().join("missing"), "sha256:served");
        assert_eq!(contracts["artifact"], "sha256:served");
        assert!(contracts["error"].is_string());
        assert!(contracts.get("path").is_none());
        assert!(contracts.get("sha256").is_none());
        assert!(!path.exists());
        session
            .ready(json!({"state":"ready", "artifact":"sha256:served", "contracts":contracts}))?;
        let status = session.status()?;
        assert_eq!(status["state"], "ready");
        assert_eq!(status["contracts"]["artifact"], status["artifact"]);
        Ok(())
    }

    #[test]
    fn failed_export_unlinks_stale_symlink_without_touching_target() -> Result<()> {
        let root = tempfile::tempdir()?;
        let session = session(root.path())?;
        let target = root.path().join("unrelated.json");
        fs::write(&target, b"unrelated")?;
        let path = session.directory.join("app-contracts.json");
        std::os::unix::fs::symlink(&target, &path)?;
        let contracts = session.contracts(&root.path().join("missing"), "sha256:served");
        assert!(contracts["error"].is_string());
        assert!(fs::symlink_metadata(&path).is_err());
        assert_eq!(fs::read(target)?, b"unrelated");
        Ok(())
    }

    #[test]
    fn stale_cleanup_error_does_not_advertise_success() -> Result<()> {
        let root = tempfile::tempdir()?;
        let session = session(root.path())?;
        let path = session.directory.join("app-contracts.json");
        fs::create_dir(&path)?;
        let contracts = session.contracts(&root.path().join("missing"), "sha256:served");
        assert!(
            contracts["error"]
                .as_str()
                .unwrap()
                .contains("remove stale app contracts")
        );
        assert!(contracts.get("path").is_none());
        assert!(contracts.get("sha256").is_none());
        Ok(())
    }

    #[test]
    fn atomic_contract_bytes_replace_with_private_regular_file() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("app-contracts.json");
        fs::write(&path, b"stale")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        atomic_bytes(&path, b"current")?;
        assert_eq!(fs::read(&path)?, b"current");
        let metadata = fs::symlink_metadata(&path)?;
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_dir(root.path())?.count(), 1);
        Ok(())
    }
}
