use crate::{digest, output_schema::Type, worker::Worker};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

const DECLARATION_LIMIT: u64 = 64 * 1024;
const EXECUTABLE_LIMIT: u64 = 64 * 1024 * 1024;
const PIN_LIMIT: usize = 64 * 1024;
const REQUEST_LIMIT: usize = 1024 * 1024 - 1;
const MAX_RENDERERS: usize = 64;
const MAX_TOTAL_SCHEMA_NODES: usize = 1024;

pub type Catalog = BTreeMap<String, Contract>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub input: Type,
    pub output: Type,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Declarations {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    renderers: Catalog,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    abi: u32,
    executable: PathBuf,
    digest: String,
    renderers: Catalog,
}

#[derive(Serialize)]
struct Request<'a> {
    abi: u32,
    renderer: &'a str,
    data: &'a Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    abi: u32,
    renderer: String,
    #[serde(rename = "inputDigest")]
    input_digest: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<String>,
}

pub fn validate_catalog(catalog: &Catalog) -> Result<()> {
    ensure!(
        catalog.len() <= MAX_RENDERERS,
        "presentation_renderer_budget"
    );
    let mut nodes = 0usize;
    for (name, contract) in catalog {
        crate::schema::identifier(name)?;
        for shape in [&contract.input, &contract.output] {
            validate_shape(shape, 0, &mut nodes)?;
        }
    }
    Ok(())
}

fn validate_shape(shape: &Type, depth: usize, nodes: &mut usize) -> Result<()> {
    ensure!(
        depth <= crate::output_schema::MAX_DEPTH,
        "presentation_schema_depth"
    );
    *nodes = nodes.saturating_add(1);
    ensure!(
        *nodes <= MAX_TOTAL_SCHEMA_NODES,
        "presentation_schema_budget"
    );
    match shape {
        Type::String | Type::Integer | Type::Boolean => Ok(()),
        Type::Record(fields) => {
            ensure!(fields.len() <= 64, "presentation_field_budget");
            for (name, field) in fields {
                crate::schema::identifier(name)?;
                validate_shape(field, depth + 1, nodes)?;
            }
            Ok(())
        }
        Type::List(item) => validate_shape(item, depth + 1, nodes),
        _ => anyhow::bail!("unsupported_presentation_shape"),
    }
}

pub fn read_declarations(ui: &Path) -> Result<Catalog> {
    let path = ui.join("presentation.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Catalog::new()),
        Err(error) => return Err(error).context("presentation_declarations_metadata"),
    };
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= DECLARATION_LIMIT,
        "presentation_declarations_file"
    );
    let bytes = read_bounded(&path, DECLARATION_LIMIT)?;
    let declarations: Declarations =
        serde_json::from_slice(&bytes).context("presentation_declarations_json")?;
    ensure!(
        declarations.schema_version == 1,
        "presentation_declarations_version"
    );
    validate_catalog(&declarations.renderers)?;
    Ok(declarations.renderers)
}

pub trait Port: Send + Sync {
    fn render(&self, renderer: &str, data: &Value) -> Result<Value>;
}

pub fn load_environment(required: &Catalog) -> Result<Option<Arc<dyn Port>>> {
    validate_catalog(required)?;
    if required.is_empty() {
        return Ok(None);
    }
    let pin_json = std::env::var("DAY2_PRESENTATION_PIN_JSON")
        .context("presentation_execution_pin_required")?;
    load_from_pin(required, Some(&pin_json))
}

fn validate_pin(required: &Catalog, pin_json: Option<&str>) -> Result<Pin> {
    validate_catalog(required)?;
    let pin_json = pin_json.context("presentation_execution_pin_required")?;
    ensure!(pin_json.len() <= PIN_LIMIT, "presentation_pin_budget");
    let pin: Pin = serde_json::from_str(pin_json).context("presentation_pin_json")?;
    ensure!(
        pin.schema_version == 1 && pin.abi == 1,
        "presentation_pin_version"
    );
    validate_catalog(&pin.renderers)?;
    for (name, contract) in required {
        ensure!(
            pin.renderers.get(name) == Some(contract),
            "presentation_pin_contract_mismatch"
        );
    }
    Ok(pin)
}

fn load_from_pin(required: &Catalog, pin_json: Option<&str>) -> Result<Option<Arc<dyn Port>>> {
    let pin = validate_pin(required, pin_json)?;
    let pinned_digest = crate::assets::hash_part(&pin.digest)?;
    let metadata =
        fs::symlink_metadata(&pin.executable).context("presentation_executable_metadata")?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= EXECUTABLE_LIMIT,
        "presentation_executable_file"
    );
    let (bytes, captured_metadata) = read_regular_nofollow(&pin.executable, EXECUTABLE_LIMIT)?;
    ensure!(
        same_file(&metadata, &captured_metadata)
            && bytes.len() as u64 == captured_metadata.len()
            && digest(&bytes) == format!("sha256:{pinned_digest}"),
        "presentation_executable_digest"
    );
    let directory = tempfile::Builder::new()
        .prefix("day2-presentation-")
        .tempdir()
        .context("presentation_snapshot_directory")?;
    let snapshot = directory.path().join("approved-renderer");
    fs::write(&snapshot, &bytes).context("presentation_snapshot_write")?;
    set_executable_mode(&snapshot)?;
    let snapshot = snapshot
        .canonicalize()
        .context("presentation_snapshot_path")?;
    let starter: Arc<WorkerStarter> =
        Arc::new(|path| Ok(Box::new(Worker::start(path)?) as Box<dyn PresentationExchange>));
    let worker =
        starter(&snapshot).map_err(|_| anyhow::anyhow!("presentation_worker_start_failed"))?;
    Ok(Some(Arc::new(WorkerPort {
        worker: std::sync::Mutex::new(Some(worker)),
        snapshot,
        starter,
        contracts: required.clone(),
        _directory: directory,
    })))
}

trait PresentationExchange: Send {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>>;
}

impl PresentationExchange for Worker {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        Worker::exchange(self, request)
    }
}

type WorkerStarter = dyn Fn(&Path) -> Result<Box<dyn PresentationExchange>> + Send + Sync;

struct WorkerPort {
    worker: std::sync::Mutex<Option<Box<dyn PresentationExchange>>>,
    snapshot: PathBuf,
    starter: Arc<WorkerStarter>,
    contracts: Catalog,
    _directory: tempfile::TempDir,
}

impl WorkerPort {
    fn restart(&self, worker: &mut Option<Box<dyn PresentationExchange>>) {
        drop(worker.take());
        *worker = (self.starter)(&self.snapshot).ok();
    }
}

trait AdmissionWait {
    fn elapsed(&self) -> std::time::Duration;
    fn pause(&self);
}

struct SystemWait(std::time::Instant);

impl SystemWait {
    fn new() -> Self {
        Self(std::time::Instant::now())
    }
}

impl AdmissionWait for SystemWait {
    fn elapsed(&self) -> std::time::Duration {
        self.0.elapsed()
    }

    fn pause(&self) {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

// Admission has its own deadline; it never extends the worker exchange budget.
fn lock_worker<'a, T>(
    worker: &'a std::sync::Mutex<T>,
    wait: &impl AdmissionWait,
) -> Result<std::sync::MutexGuard<'a, T>> {
    loop {
        ensure!(
            wait.elapsed() < std::time::Duration::from_secs(2),
            "presentation_worker_busy"
        );
        match worker.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                anyhow::bail!("presentation_worker_unavailable")
            }
            Err(std::sync::TryLockError::WouldBlock) => wait.pause(),
        }
    }
}

impl Port for WorkerPort {
    fn render(&self, renderer: &str, data: &Value) -> Result<Value> {
        self.render_with_wait(renderer, data, &SystemWait::new())
    }
}

impl WorkerPort {
    fn render_with_wait(
        &self,
        renderer: &str,
        data: &Value,
        wait: &impl AdmissionWait,
    ) -> Result<Value> {
        let contract = self
            .contracts
            .get(renderer)
            .context("presentation_unknown_renderer")?;
        contract
            .input
            .validate_value(data)
            .context("presentation_input_invalid")?;
        let request = serde_json::to_vec(&Request {
            abi: 1,
            renderer,
            data,
        })?;
        ensure!(
            request.len() <= REQUEST_LIMIT,
            "presentation_request_budget"
        );
        let input_digest = digest(&request);
        let mut worker = lock_worker(&self.worker, wait)?;
        if worker.is_none() {
            self.restart(&mut worker);
        }
        let exchange = match worker.as_mut() {
            Some(worker) => worker.exchange(&request),
            None => Err(anyhow::anyhow!("presentation_worker_start_failed")),
        };
        let result = exchange
            .map_err(|_| anyhow::anyhow!("presentation_worker_exchange_failed"))
            .and_then(|bytes| validate_response(contract, renderer, &input_digest, &bytes));
        if result.is_err() {
            self.restart(&mut worker);
        }
        result
    }
}

fn validate_response(
    contract: &Contract,
    renderer: &str,
    input_digest: &str,
    bytes: &[u8],
) -> Result<Value> {
    let response: Response =
        serde_json::from_slice(bytes).context("presentation_response_invalid")?;
    ensure!(response.abi == 1, "presentation_response_abi");
    ensure!(
        response.renderer == renderer,
        "presentation_response_renderer"
    );
    ensure!(
        response.input_digest == input_digest,
        "presentation_response_identity"
    );
    match (response.result, response.error) {
        (Some(result), None) => validate_output(contract, result),
        (None, Some(code)) => {
            ensure!(
                code.len() <= 128
                    && !code.is_empty()
                    && code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    }),
                "presentation_response_error_code"
            );
            anyhow::bail!("presentation_renderer_rejected")
        }
        _ => anyhow::bail!("presentation_response_envelope"),
    }
}

fn validate_output(contract: &Contract, result: Value) -> Result<Value> {
    contract
        .output
        .validate_value(&result)
        .context("presentation_output_invalid")?;
    Ok(result)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    read_regular_nofollow(path, limit).map(|(bytes, _)| bytes)
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.is_file() && right.is_file()
    }
}

fn read_regular_nofollow(path: &Path, limit: u64) -> Result<(Vec<u8>, fs::Metadata)> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32);
    let mut file = options.open(path).context("presentation_file_open")?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= limit,
        "presentation_file_budget_or_type"
    );
    let mut bytes = Vec::new();
    file.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        after.is_file()
            && after.len() == before.len()
            && bytes.len() as u64 == after.len()
            && bytes.len() as u64 <= limit,
        "presentation_file_changed_during_capture"
    );
    Ok((bytes, after))
}

#[cfg(unix)]
fn set_executable_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable_mode(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct VirtualWait<'a> {
        millis: Cell<u64>,
        on_pause: Box<dyn Fn(u64) + 'a>,
    }

    impl VirtualWait<'_> {
        fn new() -> Self {
            Self {
                millis: Cell::new(0),
                on_pause: Box::new(|_| {}),
            }
        }
    }

    impl AdmissionWait for VirtualWait<'_> {
        fn elapsed(&self) -> std::time::Duration {
            std::time::Duration::from_millis(self.millis.get())
        }

        fn pause(&self) {
            let next = self.millis.get() + 2;
            self.millis.set(next);
            (self.on_pause)(next);
        }
    }

    fn contract() -> Contract {
        Contract {
            input: Type::Record(BTreeMap::from([("count".into(), Type::Integer)])),
            output: Type::Record(BTreeMap::from([("label".into(), Type::String)])),
        }
    }

    #[test]
    fn virtual_admission_deadline_is_exclusive_and_poisoning_fails_closed() {
        for release_at in [2, 4, 1_998, 2_000, 2_002] {
            let busy = std::sync::Mutex::new(());
            let held = RefCell::new(Some(busy.lock().unwrap()));
            let wait = VirtualWait {
                millis: Cell::new(0),
                on_pause: Box::new(|time| {
                    if time >= release_at {
                        held.borrow_mut().take();
                    }
                }),
            };
            let result = lock_worker(&busy, &wait);
            assert_eq!(
                result.is_ok(),
                release_at < 2_000,
                "release_at={release_at}"
            );
            if let Err(error) = result {
                assert_eq!(error.to_string(), "presentation_worker_busy");
            }
            assert!(wait.millis.get() <= 2_000);
        }
        let poisoned = std::sync::Mutex::new(());
        let _ = std::panic::catch_unwind(|| {
            let _held = poisoned.lock().unwrap();
            panic!("test poison");
        });
        assert_eq!(
            lock_worker(&poisoned, &VirtualWait::new())
                .unwrap_err()
                .to_string(),
            "presentation_worker_unavailable"
        );
    }

    #[test]
    fn request_identity_hashes_the_exact_frame_without_line_feed() {
        let data = serde_json::json!({"count":3});
        let frame = serde_json::to_vec(&Request {
            abi: 1,
            renderer: "render_v1",
            data: &data,
        })
        .unwrap();
        let expected = br#"{"abi":1,"renderer":"render_v1","data":{"count":3}}"#;
        assert_eq!(frame, expected);
        assert_eq!(digest(&frame), digest(expected));
        assert_ne!(
            digest(&frame),
            digest(b"{\"abi\":1,\"renderer\":\"render_v1\",\"data\":{\"count\":3}}\n")
        );
    }

    struct ScheduledExchange {
        failure: Option<&'static str>,
    }

    impl PresentationExchange for ScheduledExchange {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>> {
            if let Some(failure) = self.failure {
                anyhow::bail!("{failure}")
            }
            let request: Value = serde_json::from_slice(request)?;
            Ok(serde_json::to_vec(&serde_json::json!({
                "abi": 1,
                "renderer": request["renderer"],
                "inputDigest": digest(&serde_json::to_vec(&Request {
                    abi: 1,
                    renderer: request["renderer"].as_str().unwrap(),
                    data: &request["data"],
                })?),
                "result": {"label":"recovered"}
            }))?)
        }
    }

    fn fake_port(start: Arc<WorkerStarter>, directory: tempfile::TempDir) -> WorkerPort {
        WorkerPort {
            worker: std::sync::Mutex::new(None),
            snapshot: directory.path().join("unused-approved-snapshot"),
            starter: start,
            contracts: BTreeMap::from([("render_v1".into(), contract())]),
            _directory: directory,
        }
    }

    #[test]
    fn pin_missing_malformed_version_and_digest_fail_closed_before_worker_start() {
        let required = BTreeMap::from([("render_v1".into(), contract())]);
        assert!(load_from_pin(&required, None).is_err());
        assert!(load_from_pin(&required, Some("{")).is_err());
        assert!(load_from_pin(
            &required,
            Some(r#"{"schemaVersion":2,"abi":1,"executable":"/missing","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","renderers":{}}"#)
        ).is_err());
        assert!(load_from_pin(
            &required,
            Some(r#"{"schemaVersion":1,"abi":2,"executable":"/missing","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","renderers":{}}"#)
        ).is_err());

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("approved");
        fs::write(&executable, b"approved bytes").unwrap();
        let pin = serde_json::json!({
            "schemaVersion":1,
            "abi":1,
            "executable":executable,
            "digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "renderers":{"render_v1": contract()}
        });
        assert!(load_from_pin(&required, Some(&pin.to_string())).is_err());
    }

    #[test]
    fn response_malformed_identity_envelope_and_output_mismatches_reject() {
        let contract = contract();
        let digest = "sha256:input";
        assert!(validate_response(&contract, "render_v1", digest, b"{").is_err());
        for response in [
            serde_json::json!({"abi":2,"renderer":"render_v1","inputDigest":digest,"result":{"label":"x"}}),
            serde_json::json!({"abi":1,"renderer":"other","inputDigest":digest,"result":{"label":"x"}}),
            serde_json::json!({"abi":1,"renderer":"render_v1","inputDigest":"sha256:other","result":{"label":"x"}}),
            serde_json::json!({"abi":1,"renderer":"render_v1","inputDigest":digest,"result":{"label":"x"},"error":"rejected"}),
            serde_json::json!({"abi":1,"renderer":"render_v1","inputDigest":digest,"result":{"unexpected":true}}),
            serde_json::json!({"abi":1,"renderer":"render_v1","inputDigest":digest,"error":"not a bounded code!"}),
            serde_json::json!({"abi":1,"renderer":"render_v1","inputDigest":digest,"result":{"label":"x"},"unknown":true}),
        ] {
            assert!(
                validate_response(
                    &contract,
                    "render_v1",
                    digest,
                    &serde_json::to_vec(&response).unwrap()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn worker_crash_or_timeout_restarts_from_approved_snapshot() {
        for failure in ["worker_crashed", "worker_timeout"] {
            let starts = Arc::new(AtomicUsize::new(0));
            let factory_starts = starts.clone();
            let starter: Arc<WorkerStarter> = Arc::new(move |_| {
                let attempt = factory_starts.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(ScheduledExchange {
                    failure: (attempt == 0).then_some(failure),
                }) as Box<dyn PresentationExchange>)
            });
            let port = fake_port(starter, tempfile::tempdir().unwrap());
            let input = serde_json::json!({"count":1});
            assert!(port.render("render_v1", &input).is_err());
            assert_eq!(starts.load(Ordering::SeqCst), 2);
            assert_eq!(
                port.render("render_v1", &input).unwrap(),
                serde_json::json!({"label":"recovered"})
            );
        }
    }

    #[test]
    fn seeded_restart_and_contention_schedules_replay_without_wall_clock() {
        fn replay(seed: u32) -> Vec<(bool, usize)> {
            let starts = Arc::new(AtomicUsize::new(0));
            let factory_starts = starts.clone();
            let starter: Arc<WorkerStarter> = Arc::new(move |_| {
                let attempt = factory_starts.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(ScheduledExchange {
                    failure: attempt.is_multiple_of(3).then_some("worker_timeout"),
                }) as Box<dyn PresentationExchange>)
            });
            let port = fake_port(starter, tempfile::tempdir().unwrap());
            let mut random = seed;
            let mut transcript = Vec::new();
            let mut expected_starts: usize = 0;
            let mut has_worker = false;
            for step in 0..64 {
                random = random.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let busy = random & 3 == 0;
                let held = busy.then(|| port.worker.lock().unwrap());
                let wait = VirtualWait::new();
                let result =
                    port.render_with_wait("render_v1", &serde_json::json!({"count": step}), &wait);
                let expected_ok = if busy {
                    false
                } else {
                    if !has_worker {
                        expected_starts += 1;
                        has_worker = true;
                    }
                    let failure = (expected_starts - 1).is_multiple_of(3);
                    if failure {
                        expected_starts += 1;
                    }
                    !failure
                };
                assert_eq!(result.is_ok(), expected_ok, "seed={seed} step={step}");
                assert_eq!(
                    starts.load(Ordering::SeqCst),
                    expected_starts,
                    "seed={seed} step={step}: busy admission restarted worker"
                );
                assert_eq!(
                    wait.millis.get(),
                    if busy { 2_000 } else { 0 },
                    "seed={seed} step={step}"
                );
                drop(held);
                transcript.push((result.is_ok(), expected_starts));
            }
            transcript
        }
        for seed in 1..=64 {
            assert_eq!(replay(seed), replay(seed), "seed={seed}");
        }
    }

    #[test]
    fn rejects_non_provider_neutral_shapes() {
        let catalog = BTreeMap::from([(
            "render_v1".into(),
            Contract {
                input: Type::Map(Box::new(Type::String)),
                output: Type::String,
            },
        )]);
        assert!(validate_catalog(&catalog).is_err());
    }
}
