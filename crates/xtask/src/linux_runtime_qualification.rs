//! Disposable native deployment acceptance. Roc owns the order of these effects.

use anyhow::{Context, Result, bail, ensure};
use day2::artifact::{Instance, LoadedArtifact};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    num::NonZeroU16,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const APP: &str = "reports";
const ACTOR: &str = "alice";
const INSTANCE: &str = "/srv/day2/instance.json";
const BODY_LIMIT: u64 = 2 * 1024 * 1024;
/// The runtime image is distroless: no shell or coreutils. Every look inside a
/// running runtime container goes through this fixed, read-only inspector.
const INSPECT: &str = "/usr/local/bin/day2-inspect";
/// The runtime image's online backup, which scheduled GKE backups run beside
/// the serving pod.
const BACKUP: &str = "/usr/local/bin/day2-backup";

struct Company {
    directory: PathBuf,
    desired: Value,
    port: u16,
    volume: String,
    container: Option<String>,
    attempted: bool,
    cookie: String,
    csrf: String,
    commands: Vec<String>,
    current_receipts_from: usize,
}

pub struct RuntimeSession {
    output: PathBuf,
    artifact: PathBuf,
    artifact_id: String,
    artifact_worker: String,
    artifact_evidence: Option<Value>,
    image: String,
    tooling_image: Option<String>,
    companies: Vec<Company>,
    completed: BTreeSet<String>,
    helpers: BTreeSet<String>,
    sequence: u64,
    identity: String,
    binary_hashes: BTreeMap<String, String>,
    strict_receipt: Option<PathBuf>,
}

impl RuntimeSession {
    pub fn new(_root: &Path, output: &Path, artifact: &Path, image: &str) -> Result<Self> {
        day2_assets::hash_part(image)?;
        let artifact = artifact.canonicalize()?;
        // Full artifact loading executes the worker contract. The orchestration
        // host may be macOS, so it only checks addressed bytes independently of
        // the mandatory native admission evidence supplied below.
        let inspected = super::linux_qualification::inspect_artifact(&artifact)?;
        let artifact_id = inspected["artifact"]
            .as_str()
            .context("artifact identity")?
            .to_owned();
        let artifact_worker = inspected["worker"]
            .as_str()
            .context("worker identity")?
            .to_owned();
        let output = output.join("runtime");
        fs::create_dir(&output)?;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(output.join("logs"))?;
        fs::create_dir(output.join("operator-output"))?;
        // Only this empty disposable subdirectory is exposed to UID 10001.
        // Its private host parent and the generated restore directories remain 0700.
        fs::set_permissions(
            output.join("operator-output"),
            fs::Permissions::from_mode(0o777),
        )?;
        let output = output.canonicalize()?;
        let identity = day2::digest(output.as_os_str().as_encoded_bytes());
        Ok(Self {
            output,
            artifact,
            artifact_id,
            artifact_worker,
            artifact_evidence: None,
            image: image.into(),
            tooling_image: None,
            companies: Vec::new(),
            completed: BTreeSet::new(),
            helpers: BTreeSet::new(),
            sequence: 0,
            identity: day2_assets::hash_part(&identity)?[..16].into(),
            binary_hashes: BTreeMap::new(),
            strict_receipt: None,
        })
    }

    pub fn set_tooling_image(&mut self, image: &str) -> Result<()> {
        day2_assets::hash_part(image)?;
        ensure!(self.tooling_image.is_none(), "tooling image already bound");
        self.tooling_image = Some(image.into());
        Ok(())
    }

    pub fn set_artifact_evidence(&mut self, evidence: &Value) -> Result<()> {
        ensure!(
            self.artifact_evidence.is_none(),
            "native artifact evidence already bound"
        );
        ensure!(
            evidence["artifact"] == self.artifact_id && evidence["worker"] == self.artifact_worker,
            "host artifact bytes differ from native admission evidence"
        );
        day2_assets::hash_part(
            evidence["platform_inventory"]
                .as_str()
                .context("native platform inventory")?,
        )?;
        self.artifact_evidence = Some(
            json!({"artifact":self.artifact_id,"worker":self.artifact_worker,
            "platform_inventory":evidence["platform_inventory"]}),
        );
        Ok(())
    }

    pub fn effect(&mut self, action: &str) -> Result<Value> {
        ensure!(
            !self.completed.contains(action),
            "duplicate runtime qualification effect"
        );
        let result = (|| -> Result<Value> {
            Ok(match action {
                "linux-runtime-package" => self.package()?,
                "linux-runtime-start" => {
                    self.require("linux-runtime-package")?;
                    let evidence = self.start(0)?;
                    self.login(0)?;
                    evidence
                }
                "linux-runtime-read-write" => {
                    self.require("linux-runtime-start")?;
                    self.read_write()?
                }
                "linux-runtime-revoke" => {
                    self.require("linux-runtime-read-write")?;
                    self.revoke()?
                }
                "linux-runtime-graceful-restart" => {
                    self.require("linux-runtime-revoke")?;
                    self.restart(false)?
                }
                "linux-runtime-forced-restart" => {
                    self.require("linux-runtime-graceful-restart")?;
                    self.restart(true)?
                }
                "linux-runtime-isolation" => {
                    self.require("linux-runtime-forced-restart")?;
                    self.isolation()?
                }
                "linux-runtime-restore" => {
                    self.require("linux-runtime-isolation")?;
                    self.restore()?
                }
                "linux-runtime-stop" => self.stop()?,
                _ => bail!("unknown Linux runtime qualification effect"),
            })
        })();
        let mut evidence = match result {
            Ok(evidence) => evidence,
            Err(error) => {
                if let Err(snapshot) =
                    self.capture_failure(action, error.downcast_ref::<HttpFailure>())
                {
                    eprintln!("Linux runtime failure snapshot unavailable: {snapshot}");
                }
                return Err(error);
            }
        };
        let object = evidence
            .as_object_mut()
            .context("runtime evidence object")?;
        object.insert("artifact".into(), json!(self.artifact_id));
        object.insert("runtime_image".into(), json!(self.image));
        object.insert("status".into(), json!("passed"));
        self.completed.insert(action.into());
        fs::write(
            self.output.join(format!("{action}.json")),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
        Ok(evidence)
    }

    fn capture_failure(&mut self, action: &str, http: Option<&HttpFailure>) -> Result<()> {
        ensure!(
            !action.is_empty()
                && action.len() <= 80
                && action
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
            "failure snapshot action name"
        );
        let mut companies = Vec::new();
        for index in 0..self.companies.len() {
            let Some(container) = self.companies[index].container.clone() else {
                continue;
            };
            let mut metrics = BTreeMap::new();
            for path in [
                "/sys/fs/cgroup/cpu.stat",
                "/sys/fs/cgroup/memory.events",
                "/sys/fs/cgroup/memory.current",
                "/sys/fs/cgroup/pids.events",
                "/sys/fs/cgroup/pids.current",
            ] {
                let result = self.docker_with_budget(
                    &[
                        "exec".into(),
                        container.clone(),
                        INSPECT.into(),
                        "read".into(),
                        path.into(),
                    ],
                    Duration::from_secs(10),
                );
                metrics.insert(
                    path,
                    match result {
                        Ok(value) => json!({"value":value}),
                        Err(error) => json!({"unavailable":error.to_string()}),
                    },
                );
            }
            let temporary = self.temporary_metadata(&container);
            companies.push(json!({"company_index":index,"container":container,
            "volume":self.companies[index].volume,"metrics":metrics,
            "temporary_filesystem":match temporary {
                Ok(value) => value,
                Err(error) => json!({"unavailable":error.to_string()}),
            }}));
        }
        fs::write(
            self.output.join(format!("{action}-failure.json")),
            serde_json::to_vec_pretty(&json!({
                "status":"failed","action":action,"artifact":self.artifact_id,"runtime_image":self.image,
                "http_error":http.map(|failure|json!({"status":failure.status,"code":failure.code})),
                "companies":companies,"captured_before_cleanup":true,"action_retried":false
            }))?,
        )?;
        Ok(())
    }

    fn temporary_metadata(&mut self, container: &str) -> Result<Value> {
        let bytes = self.docker_with_budget(
            &[
                "exec".into(),
                container.into(),
                INSPECT.into(),
                "tmp-bytes".into(),
            ],
            Duration::from_secs(10),
        )?;
        let inodes = self.docker_with_budget(
            &[
                "exec".into(),
                container.into(),
                INSPECT.into(),
                "tmp-inodes".into(),
            ],
            Duration::from_secs(10),
        )?;
        let listing = self.docker_with_budget(
            &[
                "exec".into(),
                container.into(),
                INSPECT.into(),
                "tmp-files".into(),
            ],
            Duration::from_secs(10),
        )?;
        let mut files = Vec::new();
        let mut file_bytes = 0_u64;
        for line in listing.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            ensure!(
                fields.len() == 3
                    && files.len() < 16_384
                    && fields.iter().all(|field| !field.is_empty()
                        && field.bytes().all(|byte| byte.is_ascii_digit())),
                "bounded numeric temporary file metadata required"
            );
            let size: u64 = fields[0].parse()?;
            let mode = u32::from_str_radix(fields[1], 8)?;
            let uid: u64 = fields[2].parse()?;
            file_bytes = file_bytes
                .checked_add(size)
                .context("temporary byte accounting")?;
            files.push(json!({"bytes":size,"mode":mode,"uid":uid}));
        }
        Ok(
            json!({"value":bytes,"inodes":inodes,"file_count":files.len(),"file_bytes":file_bytes,
            "files":files,"names_and_contents_collected":false,"atomic":false}),
        )
    }

    fn temporary_checkpoint(&mut self, index: usize, checkpoint: &str) -> Result<()> {
        ensure!(
            !checkpoint.is_empty()
                && checkpoint.len() <= 80
                && checkpoint
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
            "temporary checkpoint name"
        );
        let container = self.companies[index]
            .container
            .clone()
            .context("checkpoint runtime container")?;
        let metadata = self.temporary_metadata(&container)?;
        fs::write(
            self.output.join(format!("{checkpoint}.json")),
            serde_json::to_vec_pretty(&json!({
                "checkpoint":checkpoint,"container":container,"runtime_image":self.image,
                "artifact":self.artifact_id,"temporary_filesystem":metadata
            }))?,
        )?;
        Ok(())
    }

    fn require(&self, action: &str) -> Result<()> {
        ensure!(
            self.completed.contains(action),
            "runtime prerequisite missing: {action}"
        );
        Ok(())
    }

    fn package(&mut self) -> Result<Value> {
        ensure!(
            self.companies.is_empty(),
            "runtime packages already created"
        );
        let mut receipts = Vec::new();
        let mut reserved = Vec::new();
        let companies: &[&str] = if self.strict_receipt.is_some() {
            &["alpha"]
        } else {
            &["alpha", "beta"]
        };
        for company in companies {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            reserved.push(listener);
            let installation = format!("linux_qualification_{}_{company}", self.identity);
            let (directory, proof) = self.package_native(company, &installation, port)?;
            let desired = proof["instance"].clone();
            let volume = proof["volume"]
                .as_str()
                .context("native state volume")?
                .to_owned();
            receipts.push(json!({"company":company,"scope":Instance::load(&directory.join("instance.json"))?.scope(APP)?,
                "volume":volume,"port":port,"deployment":directory.join("deployment.json"),
                "native_package":proof}));
            self.companies.push(Company {
                directory,
                desired,
                port,
                volume,
                container: None,
                attempted: false,
                cookie: String::new(),
                csrf: String::new(),
                commands: Vec::new(),
                current_receipts_from: 0,
            });
        }
        ensure!(
            self.companies.len() == 1 || self.companies[0].volume != self.companies[1].volume,
            "company volume collision"
        );
        Ok(json!({"companies":receipts,"database_contents_exported":false}))
    }

    fn package_native(
        &mut self,
        company: &str,
        installation: &str,
        port: u16,
    ) -> Result<(PathBuf, Value)> {
        ensure!(
            ["alpha", "beta", "recovery"].contains(&company),
            "qualification package name"
        );
        let expected = self
            .artifact_evidence
            .clone()
            .context("native artifact admission required before packaging")?;
        let image = self
            .tooling_image
            .clone()
            .context("immutable tooling image required for native packaging")?;
        let hash = day2_assets::hash_part(&self.artifact_id)?;
        let native_artifact = format!("/qualification-artifacts/{hash}");
        let native_output = format!("/evidence/{company}");
        let directory = self.output.join("operator-output").join(company);
        ensure!(!directory.exists(), "native package output must be new");
        let owner = fs::metadata(&self.output)?;
        let name = format!("day2-linux-{}-package-{}", self.identity, self.sequence);
        let mut args = vec![
            "run".into(),
            "--rm".into(),
            "--name".into(),
            name.clone(),
            "--platform".into(),
            super::linux_qualification::native_platform()?.docker.into(),
            "--user".into(),
            format!("{}:{}", owner.uid(), owner.gid()),
            "--network".into(),
            "none".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges:true".into(),
            "--memory".into(),
            "1g".into(),
            "--cpus".into(),
            "1".into(),
            "--pids-limit".into(),
            "64".into(),
            "--cgroupns".into(),
            "private".into(),
            "--mount".into(),
            format!(
                "type=bind,source={},target={native_artifact},readonly",
                self.artifact.display()
            ),
            "--mount".into(),
            format!(
                "type=bind,source={},target=/evidence",
                self.output.join("operator-output").display()
            ),
            "--entrypoint".into(),
            "/workspace/platform/target/debug/xtask".into(),
            image.clone(),
            "linux-runtime-package".into(),
            native_artifact,
            native_output,
            installation.into(),
            port.to_string(),
            self.image.clone(),
        ];
        if let Some(receipt) = &self.strict_receipt {
            let image_index = args
                .iter()
                .position(|value| value == &image)
                .context("tooling image argument")?;
            args.splice(
                image_index..image_index,
                [
                    "--mount".into(),
                    format!(
                        "type=bind,source={},target=/qualification/qualification.json,readonly",
                        receipt.display()
                    ),
                ],
            );
            args.push("/qualification/qualification.json".into());
        }
        self.helpers.insert(name.clone());
        let response = self.docker(&args)?;
        self.helpers.remove(&name);
        let proof: Value = serde_json::from_str(&response).context("native package proof")?;
        for field in ["artifact", "worker", "platform_inventory"] {
            ensure!(
                proof[field] == expected[field],
                "native package admission differs from qualified artifact: {field}"
            );
        }
        ensure!(
            proof["installation"] == installation && proof["port"] == port,
            "native package scope or port changed"
        );
        let instance_path = directory.join("instance.json");
        let instance = Instance::load(&instance_path)?;
        ensure!(
            serde_json::to_value(&instance)? == proof["instance"],
            "native packaged instance changed on export"
        );
        let artifact = directory.join(&instance.apps[APP].artifact);
        let inspected = super::linux_qualification::inspect_artifact(&artifact)?;
        ensure!(
            inspected["artifact"] == expected["artifact"]
                && inspected["worker"] == expected["worker"],
            "packaged artifact bytes differ from native admission"
        );
        let deployment_bytes = fs::read(directory.join("deployment.json"))?;
        ensure!(
            day2::digest(&deployment_bytes) == proof["deployment_digest"],
            "native deployment manifest changed"
        );
        let deployment: Value = serde_json::from_slice(&deployment_bytes)?;
        ensure!(
            deployment["instance_digest"] == day2::digest(&fs::read(instance_path)?)
                && deployment["compose_digest"]
                    == day2::digest(&fs::read(directory.join("compose.json"))?),
            "native deployment inputs changed"
        );
        Ok((directory, proof))
    }

    fn compose(&mut self, index: usize, arguments: &[&str]) -> Result<String> {
        let mut args = vec![
            "compose".into(),
            "-f".into(),
            self.companies[index]
                .directory
                .join("compose.json")
                .display()
                .to_string(),
        ];
        let recovery = self.companies[index]
            .directory
            .join("recovery-compose.json");
        if recovery.exists() {
            args.extend(["-f".into(), recovery.display().to_string()]);
        }
        args.extend(arguments.iter().map(|arg| (*arg).into()));
        self.docker(&args)
    }

    fn start(&mut self, index: usize) -> Result<Value> {
        self.companies[index].attempted = true;
        self.compose(index, &["up", "-d", "--no-build", "--pull", "never"])?;
        let id = self.compose(index, &["ps", "-q", "app"])?;
        let id = id.trim().to_owned();
        ensure!(
            id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()),
            "one runtime container required"
        );
        self.companies[index].container = Some(id.clone());
        let start = Instant::now();
        loop {
            if self
                .request(index, "GET", "/health/ready", &[], "")
                .is_ok_and(|response| response.status == 200 && response.body.is_empty())
            {
                break;
            }
            ensure!(
                start.elapsed() < Duration::from_secs(45),
                "packaged runtime readiness deadline; inspect redacted runtime logs"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let inspect: Value = serde_json::from_str(&self.docker(&["inspect".into(), id.clone()])?)?;
        let inspect = &inspect[0];
        ensure!(
            inspect["Image"] == self.image,
            "container image differs from admitted image"
        );
        ensure!(
            inspect["Config"]["User"] == "10001:10001",
            "runtime user changed"
        );
        ensure!(
            inspect["HostConfig"]["ReadonlyRootfs"] == true,
            "runtime root is writable"
        );
        let mounts = inspect["Mounts"].as_array().context("container mounts")?;
        ensure!(
            mounts
                .iter()
                .any(|mount| mount["Destination"] == "/srv/day2/.state"
                    && mount["Name"] == self.companies[index].volume
                    && mount["RW"] == true),
            "wrong state volume mounted"
        );
        let kernel = self.docker(&["exec".into(), id.clone(), INSPECT.into(), "uname".into()])?;
        let mut files = BTreeMap::new();
        for path in [
            "/proc/self/cgroup",
            "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/cpu.max",
            "/sys/fs/cgroup/pids.max",
            "/proc/self/mountinfo",
        ] {
            files.insert(
                path,
                self.docker(&[
                    "exec".into(),
                    id.clone(),
                    INSPECT.into(),
                    "read".into(),
                    path.into(),
                ])?,
            );
        }
        ensure!(
            files["/proc/self/cgroup"].trim() == "0::/",
            "runtime cgroup namespace mismatch"
        );
        ensure!(
            files["/sys/fs/cgroup/memory.max"].trim() == "536870912",
            "runtime memory limit mismatch"
        );
        ensure!(
            files["/sys/fs/cgroup/pids.max"].trim() == "64",
            "runtime process limit mismatch"
        );
        let live = self.request(index, "GET", "/health/live", &[], "")?;
        ensure!(
            live.status == 200 && live.body.is_empty(),
            "runtime liveness response"
        );
        let native = self.output.join("native");
        fs::create_dir_all(&native)?;
        let mut binaries = BTreeMap::new();
        for (field, filename) in [
            ("runtime_supervisor", "day2-serve"),
            ("runtime_sandbox", "day2-sandbox"),
        ] {
            let copied = native.join(format!("{}-{index}-{filename}", self.sequence));
            self.docker(&[
                "cp".into(),
                format!("{id}:/usr/local/bin/{filename}"),
                copied.display().to_string(),
            ])?;
            let digest = day2::digest(&fs::read(&copied)?);
            if let Some(expected) = self.binary_hashes.get(field) {
                ensure!(
                    expected == &digest,
                    "packaged runtime executable changed between starts"
                );
            } else {
                self.binary_hashes.insert(field.into(), digest.clone());
            }
            binaries.insert(field, digest);
        }
        Ok(
            json!({"container":id,"kernel":kernel.trim(),"kernel_files":files,
            "mounts":mounts,"host_config":inspect["HostConfig"],"health":{"live":200,"ready":200},
            "runtime_supervisor":binaries["runtime_supervisor"],"runtime_sandbox":binaries["runtime_sandbox"],
            "startup_sandbox_probe":"mandatory before HTTP admission"}),
        )
    }

    fn login(&mut self, index: usize) -> Result<()> {
        let id = self.companies[index]
            .container
            .clone()
            .context("running runtime required")?;
        let logs = self.docker(&["logs".into(), id])?;
        let login = logs
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|value| value["login_url"].as_str().map(str::to_owned))
            .next_back()
            .context("runtime startup login grant missing")?;
        let origin = format!("http://127.0.0.1:{}", self.companies[index].port);
        let path = login
            .strip_prefix(&origin)
            .context("login origin mismatch")?;
        let token = path
            .strip_prefix("/login?token=")
            .context("login URL shape")?;
        ensure!(
            token.len() == 43
                && token
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
            "login token shape"
        );
        self.companies[index].cookie.clear();
        let get = self.request(index, "GET", path, &[], "")?;
        ensure!(get.status == 200, "login confirmation GET failed");
        let post = self.request(
            index,
            "POST",
            "/login",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            &format!("token={token}"),
        )?;
        ensure!(post.status == 303, "login confirmation POST failed");
        let cookie = post
            .headers
            .get("set-cookie")
            .and_then(|value| value.split(';').next())
            .context("session cookie missing")?;
        self.companies[index].cookie = cookie.into();
        let response = self.request(index, "GET", "/api/session", &[], "")?;
        ensure!(response.status == 200, "authenticated session unavailable");
        self.companies[index].csrf = response.json()?["csrf_token"]
            .as_str()
            .context("CSRF token missing")?
            .into();
        Ok(())
    }

    fn submit(&mut self, index: usize, key: &str, title: &str) -> Result<String> {
        let input =
            json!({"title":title,"text":"Linux qualification\nDurable second line"}).to_string();
        let csrf = self.companies[index].csrf.clone();
        let response = self.request(
            index,
            "POST",
            "/api/reports.submit",
            &[
                ("Content-Type", "application/json"),
                ("X-CSRF-Token", &csrf),
                ("Idempotency-Key", key),
                ("Prefer", "respond-async"),
            ],
            &input,
        )?;
        ensure!(
            response.status == 202,
            "durable HTTP acceptance returned {}",
            response.status
        );
        let id = response.json()?["invocation_id"]
            .as_str()
            .context("accepted invocation ID")?
            .to_owned();
        ensure!(
            id.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
            "invocation ID shape"
        );
        self.companies[index].commands.push(id.clone());
        Ok(id)
    }

    fn await_command(&self, index: usize, id: &str) -> Result<Value> {
        let started = Instant::now();
        loop {
            let response =
                self.request(index, "GET", &format!("/api/invocations/{id}"), &[], "")?;
            ensure!(
                response.status == 200,
                "invocation status HTTP {}",
                response.status
            );
            let value = response.json()?;
            ensure!(
                !matches!(value["status"].as_str(), Some("failure" | "blocked")),
                "durable command failed"
            );
            if value["status"] == "success" && self.descendants_complete(index, &value, 0)? {
                return Ok(value);
            }
            ensure!(
                started.elapsed() < Duration::from_secs(45),
                "durable command completion deadline"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn descendants_complete(&self, index: usize, value: &Value, depth: u8) -> Result<bool> {
        ensure!(depth < 16, "qualification command depth budget");
        if let Some(children) = value["children"].as_array() {
            ensure!(children.len() <= 32, "qualification child command budget");
            for child in children {
                ensure!(
                    !matches!(child["status"].as_str(), Some("failure" | "blocked")),
                    "child command failed"
                );
                if child["status"] != "success" {
                    return Ok(false);
                }
                let id = child["id"].as_str().context("child invocation ID")?;
                let response =
                    self.request(index, "GET", &format!("/api/invocations/{id}"), &[], "")?;
                ensure!(response.status == 200, "child command status unavailable");
                if !self.descendants_complete(index, &response.json()?, depth + 1)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn list(&self, index: usize) -> Result<Value> {
        let response = self.request(index, "GET", "/api/reports.list?after=&limit=20", &[], "")?;
        if response.status != 200 {
            return Err(anyhow::Error::new(HttpFailure {
                status: response.status,
                code: response.stable_error_code(),
            })
            .context("report list"));
        }
        let value = response.json()?;
        ensure!(value["items"].is_array(), "report list shape");
        Ok(value)
    }

    fn read_write(&mut self) -> Result<Value> {
        self.temporary_checkpoint(0, "read-write-before-empty-list")?;
        ensure!(
            self.list(0)?["items"]
                .as_array()
                .context("items")?
                .is_empty(),
            "fresh runtime contains reports"
        );
        self.temporary_checkpoint(0, "read-write-after-empty-list")?;
        let id = self.submit(0, "same-company-scoped-key", "Alpha Linux report")?;
        let receipt = self.await_command(0, &id)?;
        self.temporary_checkpoint(0, "read-write-after-command-before-populated-list")?;
        let rows = self.list(0)?;
        self.temporary_checkpoint(0, "read-write-after-populated-list")?;
        ensure!(
            rows["items"].as_array().context("items")?.len() == 1,
            "write did not create exactly one report"
        );
        ensure!(
            rows["items"][0]["title"] == "Alpha Linux report",
            "report data mismatch"
        );
        // One write each from submit, analyze and notify's announcement, as
        // the native command-recovery and live-update suites also require.
        ensure!(
            rows["items"][0]["version"] == 3,
            "submitted report did not settle at its expected revision: {}",
            rows["items"][0]["version"]
        );
        let report = rows["items"][0]["id"].as_str().context("report ID")?;
        let page = self.request(0, "GET", &format!("/reports/{report}"), &[], "")?;
        ensure!(
            page.status == 200
                && page.body.contains("Alpha Linux report")
                && page.body.contains("Complete"),
            "admitted HTML data missing"
        );
        let audit = self.request(0, "GET", "/audit", &[], "")?;
        ensure!(
            audit.status == 200 && audit.body.contains("reports.submit"),
            "mandatory audit missing"
        );
        // A rapid sequence used to exhaust the declared tmpfs with deleted
        // per-session executable copies. Keep these requests free of sleeps,
        // metadata probes, and successful retries after failed requests.
        for _ in 0..32 {
            ensure!(
                self.list(0)? == rows,
                "consecutive protected query changed rows"
            );
        }
        self.temporary_checkpoint(0, "read-write-after-consecutive-queries")?;
        Ok(
            json!({"invocation":id,"receipt":receipt,"rows":rows,"html_status":200,"audit_status":200,"consecutive_queries":32}),
        )
    }

    fn write_desired(&self, index: usize, value: &Value) -> Result<()> {
        let path = self.companies[index].directory.join("instance.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let result = fs::write(&path, serde_json::to_vec_pretty(value)?);
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
        result?;
        Ok(())
    }

    fn authority(&mut self, index: usize, instance: &str) -> Result<Value> {
        self.host(
            index,
            "authority-inspect",
            json!({"instance":instance,"app_name":APP}),
        )
    }

    fn apply_desired(&mut self, index: usize, request: &str) -> Result<Value> {
        let current = self.authority(index, INSTANCE)?;
        let stamp = &current["active"]["stamp"];
        ensure!(!stamp.is_null(), "initialized authority missing");
        self.host(index, "authority-apply", json!({"instance":INSTANCE,"app_name":APP,
            "operator":"linux-qualification-operator","expected":stamp.to_string(),"request_id":request}))
    }

    fn revoke(&mut self) -> Result<Value> {
        let before = self.list(0)?;
        let mut denied = self.companies[0].desired.clone();
        denied["apps"][APP]["authority"]["operations"]["reports.submit"]["actors"] = json!([]);
        self.write_desired(0, &denied)?;
        let revoked = self.apply_desired(0, "qualification-revoke-submit")?;
        let csrf = self.companies[0].csrf.clone();
        let response = self.request(
            0,
            "POST",
            "/api/reports.submit",
            &[
                ("Content-Type", "application/json"),
                ("X-CSRF-Token", &csrf),
                ("Idempotency-Key", "must-be-denied"),
                ("Prefer", "respond-async"),
            ],
            &json!({"title":"Forbidden report","text":"Must not commit"}).to_string(),
        )?;
        ensure!(
            response.status == 403,
            "revoked live session returned HTTP {}",
            response.status
        );
        ensure!(
            self.list(0)? == before,
            "revoked command changed domain data"
        );
        self.write_desired(0, &self.companies[0].desired)?;
        let restored = self.apply_desired(0, "qualification-restore-submit")?;
        for id in &self.companies[0].commands {
            let response = self.request(0, "GET", &format!("/api/invocations/{id}"), &[], "")?;
            ensure!(
                response.status == 403 && response.body.contains("receipt_policy_changed"),
                "regrant exposed a receipt from the retired authority revision"
            );
        }
        // Historical domain rows survive the revision change, but its completed
        // receipts must remain inaccessible. Later restart checks only await
        // commands admitted under the current revision.
        self.companies[0].current_receipts_from = self.companies[0].commands.len();
        Ok(
            json!({"denied_http_status":403,"unchanged_rows":true,"revocation":revoked,"fresh_grant":restored,"retired_receipt_http_status":403}),
        )
    }

    fn restart(&mut self, forced: bool) -> Result<Value> {
        let phase = if forced { "forced" } else { "graceful" };
        let id = self.submit(
            0,
            &format!("{phase}-accepted"),
            &format!("Alpha {phase} report"),
        )?;
        let container = self.companies[0]
            .container
            .clone()
            .context("runtime container")?;
        if forced {
            self.docker(&[
                "kill".into(),
                "--signal".into(),
                "KILL".into(),
                container.clone(),
            ])?;
        } else {
            self.docker(&[
                "stop".into(),
                "--time".into(),
                "32".into(),
                container.clone(),
            ])?;
        }
        let stopped: Value =
            serde_json::from_str(&self.docker(&["inspect".into(), container.clone()])?)?;
        let exit = stopped[0]["State"]["ExitCode"]
            .as_i64()
            .context("container exit code")?;
        ensure!(
            if forced { exit == 137 } else { exit == 0 },
            "{phase} restart exit code {exit}"
        );
        let old_cookie = self.companies[0].cookie.clone();
        self.docker(&["start".into(), container])?;
        let startup = self.start(0)?;
        // Retain the pre-restart browser session to prove its SQLite secret survived.
        self.companies[0].cookie = old_cookie;
        let session = self.request(0, "GET", "/api/session", &[], "")?;
        ensure!(
            session.status == 200,
            "browser session did not survive restart"
        );
        self.companies[0].csrf = session.json()?["csrf_token"]
            .as_str()
            .context("restored CSRF")?
            .into();
        let ids = self.companies[0].commands[self.companies[0].current_receipts_from..].to_vec();
        let mut receipts = Vec::new();
        for command in ids {
            receipts.push(self.await_command(0, &command)?);
        }
        let rows = self.list(0)?;
        ensure!(
            rows["items"].as_array().context("rows")?.len() == self.companies[0].commands.len(),
            "restart duplicated or lost reports"
        );
        let audit = self.request(0, "GET", "/audit", &[], "")?;
        ensure!(
            audit.status == 200 && audit.body.contains("reports.submit"),
            "audit did not survive restart"
        );
        Ok(
            json!({"signal":if forced {"SIGKILL"} else {"SIGTERM"},"exit_code":exit,
            "accepted_before_stop":id,"receipts_after_restart":receipts,"rows":rows,
            "pre_restart_session_valid":true,"startup":startup,
            "interruption_point":"after durable HTTP acceptance; completion may precede signal delivery"}),
        )
    }

    fn isolation(&mut self) -> Result<Value> {
        let before = self.list(0)?;
        let startup = self.start(1)?;
        let foreign = self.companies[0].cookie.clone();
        self.companies[1].cookie = foreign;
        let denied = self.request(1, "GET", "/api/session", &[], "")?;
        ensure!(
            denied.status == 401,
            "company A session authenticated to company B"
        );
        self.login(1)?;
        ensure!(
            self.list(1)?["items"]
                .as_array()
                .context("items")?
                .is_empty(),
            "company B inherited company A data"
        );
        let id = self.submit(1, "same-company-scoped-key", "Beta isolated report")?;
        let receipt = self.await_command(1, &id)?;
        let beta = self.list(1)?;
        ensure!(
            beta["items"].as_array().context("items")?.len() == 1
                && beta["items"][0]["title"] == "Beta isolated report",
            "company B independent write failed"
        );
        ensure!(self.list(0)? == before, "company B write changed company A");
        ensure!(
            self.companies[0].commands[0] != id,
            "company command identities collided"
        );
        Ok(
            json!({"startup":startup,"foreign_session_http":401,"same_idempotency_key_is_scoped":true,
            "alpha_unchanged":true,"beta_rows":beta,"beta_receipt":receipt,
            "volumes":[self.companies[0].volume,self.companies[1].volume]}),
        )
    }

    fn restore(&mut self) -> Result<Value> {
        let before = self.native_evidence(0, INSTANCE)?;
        ensure!(
            before["pending"] == 0,
            "backup requires completed qualification commands"
        );
        self.native(
            0,
            "/workspace/platform/cli/day2",
            &["platform", "backup", INSTANCE, APP, "/evidence/backup"],
        )?;
        self.native(
            0,
            "/workspace/platform/cli/day2",
            &[
                "platform",
                "restore",
                "/evidence/backup",
                "/evidence/restored",
            ],
        )?;
        let restored = self.native_evidence(0, "/evidence/restored/instance.json")?;
        ensure!(
            before["domain"] == restored["domain"],
            "restored domain snapshot differs"
        );
        ensure!(
            before["journal"] == restored["journal"],
            "restored execution or audit journal differs"
        );
        verify_restored_delegation_fence(&before, &restored)?;
        ensure!(
            restored["authority"]["document"]["enabled"] == false,
            "restore enabled historical grants"
        );
        ensure!(
            before["authority"]["stamp"]["epoch"] != restored["authority"]["stamp"]["epoch"],
            "restore retained old authority epoch"
        );
        ensure!(
            restored["sessions"] == 0 && restored["session_secrets"] == 0,
            "restore retained browser authority"
        );
        let source_after = self.native_evidence(0, INSTANCE)?;
        ensure!(
            before["authority"]["stamp"] == source_after["authority"]["stamp"]
                && before["delegation_restore_fence"] == source_after["delegation_restore_fence"],
            "backup or restore changed source authority"
        );
        let runtime_backup = self.runtime_backup(0, &before)?;
        let (startup, activation, override_digest) = self.start_restored(&restored)?;
        Ok(
            json!({"coverage":"backup-restore-fencing","domain":before["domain"],"journal":before["journal"],
            "delegation_restore_fence":restored["delegation_restore_fence"],
            "source_epoch":before["authority"]["stamp"]["epoch"],"restored_epoch":restored["authority"]["stamp"]["epoch"],
            "historical_grants_disabled":true,"browser_sessions_rotated":true,
            "restored_server_started":true,"restored_startup":startup,"fresh_policy_activation":activation,
            "recovery_compose_digest":override_digest,"fresh_restored_session":true,"old_session_http":401,
            "runtime_image_backup":runtime_backup,
            "explanation":"Native restore preserves complete domain and journal contents and disables historical grants. Explicit fresh policy activation binds the final read-only artifact path before a separate recovered runtime starts. The recovered read uses a fresh browser session; provider write budgets remain fenced. The runtime image's day2-backup, run beside the serving runtime on its live volume, produces a bundle the tooling restore accepts with the same domain and journal contents."}),
        )
    }

    /// Scheduled GKE backups run the runtime image's day2-backup beside the
    /// serving pod, on its state volume. Run it the same way against the live
    /// company volume (read-only root, no network, no capabilities), then
    /// verify and restore its bundle with the tooling image's own recipe.
    fn runtime_backup(&mut self, index: usize, before: &Value) -> Result<Value> {
        ensure!(
            self.companies[index].container.is_some(),
            "runtime backup requires the serving runtime"
        );
        let name = format!(
            "day2-linux-{}-runtime-backup-{}",
            self.identity, self.sequence
        );
        let mut args: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "--name".into(),
            name.clone(),
            "--platform".into(),
            super::linux_qualification::native_platform()?.docker.into(),
            "--user".into(),
            "10001:10001".into(),
            "--network".into(),
            "none".into(),
            "--read-only".into(),
            // day2 copies the artifact's worker into /tmp and executes it
            // there, as it does in day2-serve. Docker makes a tmpfs noexec
            // unless told otherwise; Kubernetes' memory emptyDir is exec.
            "--tmpfs".into(),
            "/tmp:rw,exec,nosuid,nodev,mode=1777,size=64m".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges:true".into(),
            "--memory".into(),
            "1g".into(),
            "--cpus".into(),
            "1".into(),
            "--pids-limit".into(),
            "64".into(),
            "--cgroupns".into(),
            "private".into(),
            "--entrypoint".into(),
            BACKUP.into(),
        ];
        for mount in self.operator_mounts(index) {
            args.extend(["--mount".into(), mount]);
        }
        args.extend([
            self.image.clone(),
            INSTANCE.into(),
            APP.into(),
            "/evidence/runtime-backup".into(),
        ]);
        self.helpers.insert(name.clone());
        let output = self.docker(&args)?;
        self.helpers.remove(&name);
        let summary: Value =
            serde_json::from_str(output.trim()).context("runtime backup summary")?;
        ensure!(
            summary["verified"] == true
                && summary["app"] == APP
                && summary["artifact"] == self.artifact_id
                && summary["backup"] == "/evidence/runtime-backup",
            "runtime backup summary"
        );
        self.native(
            index,
            "/workspace/platform/cli/day2",
            &[
                "platform",
                "restore",
                "/evidence/runtime-backup",
                "/evidence/runtime-restored",
            ],
        )?;
        let restored = self.native_evidence(index, "/evidence/runtime-restored/instance.json")?;
        ensure!(
            before["domain"] == restored["domain"] && before["journal"] == restored["journal"],
            "runtime image backup restored different domain or journal contents"
        );
        verify_restored_delegation_fence(before, &restored)?;
        ensure!(
            restored["authority"]["document"]["enabled"] == false
                && restored["sessions"] == 0
                && restored["session_secrets"] == 0,
            "runtime image backup restore retained historical authority"
        );
        Ok(
            json!({"executable":BACKUP,"image":self.image,"beside_serving_runtime":true,
            "read_only_root":true,"summary":summary,"tooling_restore_verified":true,
            "domain_and_journal_equal":true}),
        )
    }

    fn start_restored(&mut self, restored: &Value) -> Result<(Value, Value, String)> {
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let installation = self.companies[0].desired["installation"]
            .as_str()
            .context("recovery installation")?
            .to_owned();
        let (directory, proof) = self.package_native("recovery", &installation, port)?;
        let desired = proof["instance"].clone();
        let volume = format!("day2-recovery-state-{}", self.identity);
        // Recovery keeps the database's installation identity. A separately
        // addressed operator override selects a fresh physical volume/project;
        // every runtime security setting and admitted package byte is retained.
        let override_bytes = serde_json::to_vec_pretty(&json!({
            "name":format!("day2-recovery-{}", self.identity),
            "volumes":{"state":{"name":volume}}
        }))?;
        fs::write(directory.join("recovery-compose.json"), &override_bytes)?;
        let index = self.companies.len();
        self.companies.push(Company {
            directory,
            desired,
            port,
            volume,
            container: None,
            attempted: true,
            cookie: String::new(),
            csrf: String::new(),
            commands: Vec::new(),
            current_receipts_from: 0,
        });
        // Creating (without starting) populates the new volume with the image's
        // correctly owned, empty state directory. No restored server runs yet.
        self.compose(index, &["create", "--no-build", "--pull", "never"])?;
        let id = self.compose(index, &["ps", "--all", "-q", "app"])?;
        ensure!(id.trim().len() == 64, "recovery container identity");
        self.companies[index].container = Some(id.trim().into());
        self.native(
            index,
            "/bin/cp",
            &["-a", "/evidence/restored/.state/.", "/srv/day2/.state/"],
        )?;
        let target = format!(
            "/srv/day2/artifacts/{}",
            day2_assets::hash_part(&self.artifact_id)?
        );
        let activation = self.host(
            index,
            "authority-activate",
            json!({
                "instance":INSTANCE,"app_name":APP,"target":target,
                "operator":"linux-qualification-recovery-operator",
                "expected":restored["authority"]["stamp"].to_string(),
                "request_id":"qualification-recovery-fresh-policy"
            }),
        )?;
        let rebound = self.native_evidence(index, INSTANCE)?;
        ensure!(
            rebound["domain"] == restored["domain"]
                && rebound["journal"] == restored["journal"]
                && rebound["delegation_restore_fence"] == restored["delegation_restore_fence"],
            "recovery activation changed domain or execution journals"
        );
        let startup = self.start(index)?;
        self.companies[index].cookie = self.companies[0].cookie.clone();
        ensure!(
            self.request(index, "GET", "/api/session", &[], "")?.status == 401,
            "restored runtime accepted a pre-backup session"
        );
        self.login(index)?;
        let original = self.list(0)?;
        let recovered = self.list(index)?;
        ensure!(original == recovered, "restored runtime HTTP data differs");
        Ok((startup, activation, day2::digest(&override_bytes)))
    }

    fn native_evidence(&mut self, index: usize, instance: &str) -> Result<Value> {
        serde_json::from_str(&self.native(
            index,
            "/workspace/platform/target/debug/xtask",
            &["linux-runtime-evidence", instance],
        )?)
        .context("native runtime evidence")
    }

    fn host(&mut self, index: usize, action: &str, input: Value) -> Result<Value> {
        let (operation, fields): (&str, &[&str]) = match action {
            "authority-inspect" => ("inspect", &["instance", "app_name"]),
            "authority-apply" => (
                "apply",
                &["instance", "app_name", "operator", "expected", "request_id"],
            ),
            "authority-activate" => (
                "activate",
                &[
                    "instance",
                    "app_name",
                    "target",
                    "operator",
                    "expected",
                    "request_id",
                ],
            ),
            _ => bail!("unknown qualification authority workflow"),
        };
        let mut arguments = vec!["authority", operation];
        for field in fields {
            arguments.push(
                input[*field]
                    .as_str()
                    .context("authority workflow argument")?,
            );
        }
        // The private host rejects direct authority capabilities. Execute the
        // existing Authority.roc recipe through its admitted workflow runner.
        let request =
            json!({"protocol":1,"action":"workflow","input":serde_json::to_string(&arguments)?})
                .to_string();
        let output = self.native(index, "/workspace/platform/cli/day2-host", &[&request])?;
        let value: Value = serde_json::from_str(&output).context("native operator response")?;
        ensure!(
            value["ok"] == true,
            "native operator {action} failed: {}",
            value["error"]
        );
        serde_json::from_str(value["result"].as_str().context("native operator result")?)
            .context("native operator result JSON")
    }

    fn native(&mut self, index: usize, executable: &str, arguments: &[&str]) -> Result<String> {
        self.native_with_mounts(index, executable, arguments, &[])
    }

    fn native_with_mounts(
        &mut self,
        index: usize,
        executable: &str,
        arguments: &[&str],
        extra_mounts: &[String],
    ) -> Result<String> {
        let image = self
            .tooling_image
            .clone()
            .context("immutable tooling image required for operator effects")?;
        let name = format!("day2-linux-{}-operator-{}", self.identity, self.sequence);
        let mut args = vec![
            "run".into(),
            "--rm".into(),
            "--name".into(),
            name.clone(),
            "--platform".into(),
            super::linux_qualification::native_platform()?.docker.into(),
            "--user".into(),
            "10001:10001".into(),
            "--network".into(),
            "none".into(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges:true".into(),
            "--memory".into(),
            "1g".into(),
            "--cpus".into(),
            "1".into(),
            "--pids-limit".into(),
            "64".into(),
            "--cgroupns".into(),
            "private".into(),
            "--entrypoint".into(),
            executable.into(),
        ];
        for mount in self.operator_mounts(index) {
            args.extend(["--mount".into(), mount]);
        }
        for mount in extra_mounts {
            args.extend(["--mount".into(), mount.clone()]);
        }
        args.push(image);
        args.extend(arguments.iter().map(|value| (*value).into()));
        self.helpers.insert(name.clone());
        let result = self.docker(&args);
        if result.is_ok() {
            self.helpers.remove(&name);
        }
        result
    }

    /// The serving runtime's instance, artifacts and state volume, at the paths
    /// the runtime sees them, plus the shared operator output directory.
    fn operator_mounts(&self, index: usize) -> [String; 4] {
        let company = &self.companies[index];
        [
            format!(
                "type=bind,source={},target={INSTANCE},readonly",
                company.directory.join("instance.json").display()
            ),
            format!(
                "type=bind,source={},target=/srv/day2/artifacts,readonly",
                company.directory.join("artifacts").display()
            ),
            format!(
                "type=volume,source={},target=/srv/day2/.state",
                company.volume
            ),
            format!(
                "type=bind,source={},target=/evidence",
                self.output.join("operator-output").display()
            ),
        ]
    }

    fn request(
        &self,
        index: usize,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<HttpResponse> {
        let company = &self.companies[index];
        ensure!(
            path.starts_with('/') && !path.contains(['\r', '\n']),
            "HTTP request path"
        );
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, company.port));
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        socket.set_read_timeout(Some(Duration::from_secs(20)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        // HTTP/1.0 makes the bounded response unambiguously delimited by close.
        write!(
            socket,
            "{method} {path} HTTP/1.0\r\nHost: {address}\r\nOrigin: http://{address}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        )?;
        if !company.cookie.is_empty() {
            write!(socket, "Cookie: {}\r\n", company.cookie)?;
        }
        for (name, value) in headers {
            ensure!(
                !name.contains(['\r', '\n']) && !value.contains(['\r', '\n']),
                "HTTP header encoding"
            );
            write!(socket, "{name}: {value}\r\n")?;
        }
        write!(socket, "\r\n{body}")?;
        let mut bytes = Vec::new();
        socket.take(BODY_LIMIT + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= BODY_LIMIT,
            "HTTP qualification response budget"
        );
        let text = String::from_utf8(bytes)?;
        let (head, body) = text
            .split_once("\r\n\r\n")
            .context("HTTP response framing")?;
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .context("HTTP response status")?
            .parse()?;
        let mut headers = BTreeMap::new();
        for line in lines {
            let (name, value) = line.split_once(':').context("HTTP response header")?;
            headers.insert(name.to_ascii_lowercase(), value.trim().into());
        }
        ensure!(
            !headers.contains_key("transfer-encoding"),
            "unexpected HTTP/1.0 transfer encoding"
        );
        Ok(HttpResponse {
            status,
            headers,
            body: body.into(),
        })
    }

    fn docker(&mut self, arguments: &[String]) -> Result<String> {
        self.docker_with_budget(arguments, Duration::from_secs(120))
    }

    fn docker_with_budget(&mut self, arguments: &[String], budget: Duration) -> Result<String> {
        self.sequence += 1;
        let label = format!("{:04}", self.sequence);
        let output = self.output.join("logs");
        let stdout_path = output.join(format!("{label}.stdout.private"));
        let stderr_path = output.join(format!("{label}.stderr.private"));
        let stdout = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&stdout_path)?;
        let stderr = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&stderr_path)?;
        let mut child = Command::new("docker")
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .context("start Docker qualification effect")?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Ok(status);
            }
            if started.elapsed() > budget
                || fs::metadata(&stdout_path)?.len() + fs::metadata(&stderr_path)?.len()
                    > 16 * 1024 * 1024
            {
                let _ = child.kill();
                let _ = child.wait();
                break Err(anyhow::anyhow!(
                    "Docker qualification effect exceeded time or output budget"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let stdout = fs::read_to_string(&stdout_path)?;
        let stderr = fs::read_to_string(&stderr_path)?;
        fs::write(
            output.join(format!("{label}.log")),
            format!("{}{}", redacted(&stdout), redacted(&stderr)),
        )?;
        fs::remove_file(stdout_path)?;
        fs::remove_file(stderr_path)?;
        ensure!(
            status?.success(),
            "Docker qualification effect failed; redacted log {}",
            output.join(format!("{label}.log")).display()
        );
        Ok(stdout)
    }

    fn stop(&mut self) -> Result<Value> {
        let mut volumes = Vec::new();
        let mut failures = Vec::new();
        for index in 0..self.companies.len() {
            if let Some(id) = self.companies[index].container.clone()
                && let Ok(logs) = self.docker(&["logs".into(), id])
            {
                fs::write(
                    self.output.join(format!("company-{index}.log")),
                    redacted(&logs),
                )?;
            }
            if self.companies[index].attempted {
                match self.compose(index, &["down", "--timeout", "32"]) {
                    Ok(_) => {
                        self.companies[index].container = None;
                        self.companies[index].attempted = false;
                    }
                    Err(error) => failures.push(error.to_string()),
                }
            }
            volumes.push(self.companies[index].volume.clone());
        }
        ensure!(
            failures.is_empty(),
            "runtime cleanup failures: {}",
            failures.join("; ")
        );
        Ok(
            json!({"containers_removed":true,"state_volumes_preserved":volumes,
            "operator_output":self.output.join("operator-output"),"logs":"redacted"}),
        )
    }
}

const STRICT_ACTIONS: &[&str] = &[
    "linux-strict-package",
    "linux-strict-activate",
    "linux-strict-start",
    "linux-strict-query",
    "linux-strict-denial",
    "linux-strict-stop",
    "linux-strict-receipt",
];

const PROVISION_ACTIONS: &[&str] = &[
    "linux-provision-package",
    "linux-provision-apply",
    "linux-provision-retry",
    "linux-provision-start",
    "linux-provision-inspect",
    "linux-provision-stop",
    "linux-provision-receipt",
];

pub(super) fn provision_preflight(runner: &Path) -> Result<()> {
    let mut next = 0;
    let result = day2::automation::run(runner, &["provision-linux"], |request| {
        let input: Value = request.decode()?;
        ensure!(
            input == json!({}) && PROVISION_ACTIONS.get(next) == Some(&request.action.as_str()),
            "closed Linux provisioning recipe required"
        );
        next += 1;
        Ok(json!({"provision_recipe_preflight":true}))
    })?;
    ensure!(
        next == PROVISION_ACTIONS.len() && result == json!({"provision_recipe_preflight":true}),
        "Linux provisioning recipe did not complete"
    );
    Ok(())
}

/// Actual packaged credential registration using a fresh synthetic token. This
/// runs only after qualification and makes no external provider request.
pub fn provision(root: &Path, qualified: &Path, output: &Path) -> Result<()> {
    let qualified = qualified.canonicalize()?;
    let receipt_path = qualified.join("qualification.json");
    let metadata = fs::symlink_metadata(&receipt_path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 1_048_576,
        "bounded qualification receipt required"
    );
    let receipt_bytes = fs::read(&receipt_path)?;
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    ensure!(
        receipt["format"] == 1
            && receipt["status"] == "passed"
            && receipt["scope"] == "linux_sqlite_single_v1",
        "completed qualification required for provisioning smoke"
    );
    let field = |key: &str| receipt[key].as_str().context("qualification identity");
    let inputs = day2_control::build::PlatformInputs::capture(root, &root.join("../.toolchains"))?;
    ensure!(
        inputs.digest().as_str() == field("platform")?
            && day2::automation::source_digest() == field("workflow")?,
        "provisioning smoke source differs from qualification"
    );
    let artifact = qualified
        .join("artifacts")
        .join(day2_assets::hash_part(field("artifact")?)?);
    let runner = super::workflows::build(root)?;
    provision_preflight(&runner)?;
    fs::create_dir(output).context("provisioning smoke output must be new")?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    let output = output.canonicalize()?;
    ensure!(
        !output.starts_with(&qualified),
        "preserve original qualification"
    );
    let mut runtime = RuntimeSession::new(root, &output, &artifact, field("runtime_image")?)?;
    runtime.set_tooling_image(field("tooling_image")?)?;
    runtime.set_artifact_evidence(
        &json!({"artifact":receipt["artifact"],"worker":receipt["worker"],
        "platform_inventory":receipt["platform_inventory"]}),
    )?;
    for key in ["runtime_supervisor", "runtime_sandbox"] {
        runtime.binary_hashes.insert(key.into(), field(key)?.into());
    }
    let mut results = BTreeMap::<String, Value>::new();
    let mut next = 0;
    let outcome = day2::automation::run(&runner, &["provision-linux"], |request| {
        let input: Value = request.decode()?;
        let action = request.action.as_str();
        ensure!(
            input == json!({}) && PROVISION_ACTIONS.get(next) == Some(&action),
            "closed provisioning effect sequence required"
        );
        let evidence = match action {
            "linux-provision-package" => {
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
                let port = listener.local_addr()?.port();
                let installation = format!("linux_provisioning_{}", runtime.identity);
                let parent = runtime.output.join("operator-output");
                let fixture = parent.join("provision");
                let helper = format!("day2-linux-{}-provision-package", runtime.identity);
                runtime.helpers.insert(helper.clone());
                let text = runtime.docker(&[
                    "run".into(),
                    "--rm".into(),
                    "--name".into(),
                    helper.clone(),
                    format!(
                        "--platform={}",
                        super::linux_qualification::native_platform()?.docker
                    ),
                    "--user=10001:10001".into(),
                    "--network=none".into(),
                    "--cap-drop=ALL".into(),
                    "--security-opt=no-new-privileges:true".into(),
                    "--memory=1g".into(),
                    "--cpus=1".into(),
                    "--pids-limit=64".into(),
                    "--cgroupns=private".into(),
                    "--mount".into(),
                    format!(
                        "type=bind,source={},target={},readonly",
                        runtime.artifact.display(),
                        runtime.artifact.display()
                    ),
                    "--mount".into(),
                    format!(
                        "type=bind,source={},target={}",
                        parent.display(),
                        parent.display()
                    ),
                    "--entrypoint=/workspace/platform/target/debug/xtask".into(),
                    field("tooling_image")?.into(),
                    "linux-provision-package".into(),
                    runtime.artifact.display().to_string(),
                    fixture.display().to_string(),
                    installation.clone(),
                    port.to_string(),
                    runtime.image.clone(),
                    field("tooling_image")?.into(),
                ])?;
                runtime.helpers.remove(&helper);
                let proof: Value = serde_json::from_str(&text)?;
                for key in ["artifact", "worker", "platform_inventory"] {
                    ensure!(
                        proof[key] == receipt[key],
                        "provisioning native artifact identity mismatch"
                    );
                }
                let directory = fixture.join("deployment");
                ensure!(
                    proof["directory"] == directory.display().to_string()
                        && proof["installation"] == installation
                        && proof["port"] == port
                        && proof["credential_bytes_absent"] == true
                        && proof["provider_qualified"] == false,
                    "provisioning fixture scope mismatch"
                );
                let desired =
                    serde_json::to_value(Instance::load(&directory.join("instance.json"))?)?;
                ensure!(
                    desired == proof["instance"]
                        && day2::digest(&fs::read(directory.join("deployment.json"))?)
                            == proof["deployment_digest"],
                    "provisioning package transport changed"
                );
                let volume = proof["volume"]
                    .as_str()
                    .context("provisioning volume")?
                    .to_owned();
                runtime.companies.push(Company {
                    directory,
                    desired,
                    port,
                    volume,
                    container: None,
                    attempted: false,
                    cookie: String::new(),
                    csrf: String::new(),
                    commands: Vec::new(),
                    current_receipts_from: 0,
                });
                proof
            }
            "linux-provision-apply" | "linux-provision-retry" => {
                runtime.companies[0].attempted = true;
                let response = runtime.compose(
                    0,
                    &[
                        "--profile",
                        "operator",
                        "run",
                        "--rm",
                        "--no-deps",
                        "provision-credentials",
                    ],
                )?;
                let proof: Value = serde_json::from_str(&response)?;
                ensure!(
                    proof["registered"] == 1 && proof["provider_qualified"] == false,
                    "credential provisioning did not complete"
                );
                proof
            }
            "linux-provision-start" => runtime.start(0)?,
            "linux-provision-inspect" => {
                let instance_mount = format!(
                    "{}:{INSTANCE}:ro",
                    runtime.companies[0]
                        .directory
                        .join("instance.json")
                        .display()
                );
                let response = runtime.compose(
                    0,
                    &[
                        "--profile",
                        "operator",
                        "run",
                        "--rm",
                        "--no-deps",
                        "--entrypoint",
                        "/workspace/platform/target/debug/xtask",
                        "--volume",
                        &instance_mount,
                        "provision-credentials",
                        "linux-provision-inspect",
                        INSTANCE,
                    ],
                )?;
                let proof: Value = serde_json::from_str(&response)?;
                let id = runtime.companies[0]
                    .container
                    .clone()
                    .context("provisioned runtime")?;
                let inspected: Value =
                    serde_json::from_str(&runtime.docker(&["inspect".into(), id])?)?;
                let mounts = inspected[0]["Mounts"]
                    .as_array()
                    .context("runtime mounts")?;
                let credentials: Vec<_> = mounts
                    .iter()
                    .filter(|mount| {
                        mount["Destination"]
                            .as_str()
                            .is_some_and(|target| target.starts_with("/run/day2/credentials/"))
                    })
                    .collect();
                ensure!(
                    credentials.len() == 1 && credentials[0]["RW"] == false,
                    "runtime credential mount is not exact and read-only"
                );
                json!({"native":proof,"runtime_credential_mounts":credentials,"provider_calls":0})
            }
            "linux-provision-stop" => runtime.stop()?,
            "linux-provision-receipt" => {
                ensure!(
                    fs::read(&receipt_path)? == receipt_bytes
                        && day2_control::build::PlatformInputs::capture(
                            root,
                            &root.join("../.toolchains")
                        )?
                        .digest()
                            == inputs.digest(),
                    "provisioning smoke source or receipt changed"
                );
                json!({"status":"provisioning-smoke-passed","provider_qualified":false})
            }
            _ => bail!("unknown provisioning effect"),
        };
        next += 1;
        results.insert(action.into(), evidence.clone());
        Ok(evidence)
    });
    fs::write(
        output.join("provisioning-smoke.json"),
        serde_json::to_vec_pretty(&json!({
            "format":1,"status":if outcome.is_ok(){"provisioning-smoke-passed"}else{"provisioning-smoke-failed"},
            "qualification":false,"provider_qualified":false,"provider_calls":0,"synthetic_token":true,
            "qualification_receipt":receipt_path,"qualification_digest":day2::digest(&receipt_bytes),"results":results,
            "error":outcome.as_ref().err().map(|error|format!("{error:#}"))
        }))?,
    )?;
    outcome?;
    ensure!(
        next == PROVISION_ACTIONS.len(),
        "provisioning smoke incomplete"
    );
    println!(
        "{}",
        json!({"status":"provisioning-smoke-passed","evidence":output.join("provisioning-smoke.json")})
    );
    Ok(())
}

pub(super) fn strict_preflight(runner: &Path) -> Result<()> {
    let mut next = 0;
    let result = day2::automation::run(runner, &["strict-linux"], |request| {
        let input: Value = request.decode()?;
        ensure!(
            input == json!({}) && STRICT_ACTIONS.get(next) == Some(&request.action.as_str()),
            "closed strict Linux recipe required"
        );
        next += 1;
        Ok(json!({"strict_recipe_preflight":true}))
    })?;
    ensure!(
        next == STRICT_ACTIONS.len() && result == json!({"strict_recipe_preflight":true}),
        "strict Linux recipe did not complete"
    );
    Ok(())
}

/// Separate acceptance of explicit security requirements from an actual completed
/// qualification. This consumes the receipt unchanged and never creates one.
pub fn strict(root: &Path, qualified: &Path, output: &Path) -> Result<()> {
    let qualified = qualified.canonicalize()?;
    let receipt_path = qualified.join("qualification.json");
    let metadata = fs::symlink_metadata(&receipt_path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 1_048_576,
        "bounded qualification receipt required"
    );
    let receipt_bytes = fs::read(&receipt_path)?;
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    ensure!(
        receipt["format"] == 1
            && receipt["status"] == "passed"
            && receipt["scope"] == "linux_sqlite_single_v1",
        "actual completed Linux qualification required"
    );
    day2::security_admission::require_linux_checks(&serde_json::from_value(
        receipt["checks"].clone(),
    )?)?;
    let field = |name: &str| {
        receipt[name]
            .as_str()
            .context("qualification identity field")
    };
    let artifact = qualified
        .join("artifacts")
        .join(day2_assets::hash_part(field("artifact")?)?);
    let inspected = super::linux_qualification::inspect_artifact(&artifact)?;
    ensure!(
        inspected["artifact"] == receipt["artifact"] && inspected["worker"] == receipt["worker"],
        "strict smoke artifact differs from qualification"
    );
    let current_inputs =
        day2_control::build::PlatformInputs::capture(root, &root.join("../.toolchains"))?;
    let current_app = day2_control::build::PinnedTree::capture(&root.join("examples/reports"))?;
    ensure!(
        current_inputs.digest().as_str() == field("platform")?
            && current_app.digest().as_str() == field("source")?
            && day2::automation::source_digest() == field("workflow")?,
        "strict smoke sources changed since qualification"
    );
    let runner = super::workflows::build(root)?;
    strict_preflight(&runner)?;
    fs::create_dir(output).context("strict smoke output must be new")?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    let output = output.canonicalize()?;
    ensure!(
        !output.starts_with(&qualified),
        "strict smoke must preserve original qualification"
    );
    let input_copy = output.join("qualification-input.json");
    fs::write(&input_copy, &receipt_bytes)?;
    fs::set_permissions(&input_copy, fs::Permissions::from_mode(0o444))?;
    let mut runtime = RuntimeSession::new(root, &output, &artifact, field("runtime_image")?)?;
    runtime.set_tooling_image(field("tooling_image")?)?;
    runtime.set_artifact_evidence(
        &json!({"artifact":receipt["artifact"],"worker":receipt["worker"],
        "platform_inventory":receipt["platform_inventory"]}),
    )?;
    runtime.strict_receipt = Some(input_copy.clone());
    for key in ["runtime_supervisor", "runtime_sandbox"] {
        day2_assets::hash_part(field(key)?)?;
        runtime.binary_hashes.insert(key.into(), field(key)?.into());
    }
    let mut next = 0;
    let mut results = BTreeMap::<String, Value>::new();
    let outcome = day2::automation::run(&runner, &["strict-linux"], |request| {
        let input: Value = request.decode()?;
        let action = request.action.as_str();
        ensure!(
            input == json!({}) && STRICT_ACTIONS.get(next) == Some(&action),
            "closed strict Linux effect sequence required"
        );
        let evidence = match action {
            "linux-strict-package" => {
                let proof = runtime.package()?;
                ensure!(
                    runtime.companies.len() == 1,
                    "one fresh strict fixture required"
                );
                let security = &runtime.companies[0].desired["apps"][APP]["security"];
                ensure!(
                    security["artifact"] == receipt["artifact"]
                        && security["platform_inventory"] == receipt["platform_inventory"]
                        && security["containment"]["evidence"]["receipt_digest"]
                            == day2::digest(&receipt_bytes),
                    "native operator review did not bind original qualification"
                );
                proof
            }
            "linux-strict-activate" => {
                runtime.companies[0].attempted = true;
                runtime.compose(0, &["create", "--no-build", "--pull", "never"])?;
                runtime.native(
                    0,
                    "/workspace/platform/target/debug/day2",
                    &["init", INSTANCE, APP],
                )?;
                let activation = runtime.apply_desired(0, "strict-smoke-explicit-activation")?;
                let active = runtime.authority(0, INSTANCE)?;
                ensure!(
                    active["active"]["document"]["security"]
                        == runtime.companies[0].desired["apps"][APP]["security"],
                    "strict security requirements were not activated"
                );
                json!({"local_operator":"linux-qualification-operator","activation":activation,
                    "security":active["active"]["document"]["security"],"server_started":false})
            }
            "linux-strict-start" => {
                let proof = runtime.start(0)?;
                runtime.login(0)?;
                proof
            }
            "linux-strict-query" => {
                let rows = runtime.list(0)?;
                ensure!(
                    rows["items"]
                        .as_array()
                        .context("strict report rows")?
                        .is_empty(),
                    "fresh strict fixture inherited rows"
                );
                json!({"operation":"reports.list","http_status":200,"rows":rows,
                    "generated_fixture_login":true})
            }
            "linux-strict-denial" => {
                let container = runtime.companies[0]
                    .container
                    .clone()
                    .context("strict runtime")?;
                let sandbox = runtime.output.join("native/strict-day2-sandbox");
                runtime.docker(&[
                    "cp".into(),
                    format!("{container}:/usr/local/bin/day2-sandbox"),
                    sandbox.display().to_string(),
                ])?;
                ensure!(
                    day2::digest(&fs::read(&sandbox)?) == field("runtime_sandbox")?,
                    "strict negative probe launcher differs from qualified launcher"
                );
                let result = runtime.native_with_mounts(0, "/workspace/platform/target/debug/xtask",
                    &["linux-strict-denial", INSTANCE], &[format!(
                        "type=bind,source={},target=/workspace/platform/target/debug/day2-sandbox,readonly", sandbox.display())])?;
                let proof: Value = serde_json::from_str(&result)?;
                ensure!(
                    proof["code"] == "security_runtime_mismatch",
                    "wrong supervisor was not denied"
                );
                proof
            }
            "linux-strict-stop" => runtime.stop()?,
            "linux-strict-receipt" => {
                ensure!(
                    fs::read(&receipt_path)? == receipt_bytes
                        && fs::read(&input_copy)? == receipt_bytes,
                    "original qualification receipt changed"
                );
                ensure!(
                    day2_control::build::PlatformInputs::capture(
                        root,
                        &root.join("../.toolchains")
                    )?
                    .digest()
                        == current_inputs.digest()
                        && day2_control::build::PinnedTree::capture(
                            &root.join("examples/reports")
                        )?
                        .digest()
                            == current_app.digest(),
                    "strict smoke sources changed during execution"
                );
                json!({"status":"strict-admission-passed","qualification":false})
            }
            _ => bail!("unknown strict Linux action"),
        };
        next += 1;
        results.insert(action.into(), evidence.clone());
        Ok(evidence)
    });
    let evidence = json!({"format":1,"status":if outcome.is_ok(){"strict-admission-passed"}else{"strict-admission-failed"},
        "qualification":false,"qualification_receipt":receipt_path,"qualification_digest":day2::digest(&receipt_bytes),
        "artifact":receipt["artifact"],"platform":receipt["platform"],"platform_inventory":receipt["platform_inventory"],
        "runtime_image":receipt["runtime_image"],"tooling_image":receipt["tooling_image"],"results":results,
        "error":outcome.as_ref().err().map(|error|format!("{error:#}")),
        "scope":"disposable explicit operator admission; not production identity or hostile-code certification"});
    fs::write(
        output.join("strict-admission.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    outcome?;
    ensure!(next == STRICT_ACTIONS.len(), "strict smoke incomplete");
    println!(
        "{}",
        json!({"status":"strict-admission-passed","evidence":output.join("strict-admission.json")})
    );
    Ok(())
}

/// Resume only the native diagnostic work using a failed run's retained inputs.
/// The current compiled Roc recipe still owns effect ordering. Retained builds
/// cannot count as a fresh qualification, and this never emits qualification.json.
pub fn diagnose(
    root: &Path,
    failed: &Path,
    output: &Path,
    runtime_override: Option<&str>,
    prior_suites: Option<&Path>,
) -> Result<()> {
    fn read(path: &Path) -> Result<Value> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 8 * 1024 * 1024,
            "bounded regular diagnostic input required"
        );
        Ok(serde_json::from_slice(&fs::read(path)?)?)
    }

    let failed = failed.canonicalize()?;
    let failure = read(&failed.join("failure.json"))?;
    ensure!(
        failure["status"] == "failed",
        "diagnostic requires a retained failed run"
    );
    let former: BTreeSet<String> = serde_json::from_value(failure["completed"].clone())?;
    let original_runtime_image = failure["runtime_image"]
        .as_str()
        .context("retained runtime image")?;
    let image = runtime_override.unwrap_or(original_runtime_image);
    let tooling_image = failure["tooling_image"]
        .as_str()
        .context("retained tooling image")?;
    day2_assets::hash_part(image)?;
    day2_assets::hash_part(original_runtime_image)?;
    day2_assets::hash_part(tooling_image)?;
    day2_assets::hash_part(
        failure["platform"]
            .as_str()
            .context("retained platform identity")?,
    )?;
    let source = day2_control::build::PinnedTree::capture(&failed.join("inputs/examples/reports"))?;
    ensure!(
        failure["source"] == source.digest().as_str(),
        "retained Reports sources changed"
    );
    let admitted = read(&failed.join("artifact-admission.log"))?;
    let probe = read(&failed.join("probe-admission.log"))?;
    let mut artifacts = Vec::new();
    for evidence in [&admitted, &probe] {
        let hash =
            day2_assets::hash_part(evidence["artifact"].as_str().context("retained artifact")?)?;
        let path = failed.join("artifacts").join(hash);
        let inspected = super::linux_qualification::inspect_artifact(&path)?;
        ensure!(
            inspected["artifact"] == evidence["artifact"]
                && inspected["worker"] == evidence["worker"],
            "retained artifact bytes differ from native admission"
        );
        artifacts.push((path, format!("/qualification-artifacts/{hash}")));
    }
    ensure!(
        admitted["artifact"] != probe["artifact"]
            && admitted["platform_inventory"] == probe["platform_inventory"],
        "distinct probe from the same retained platform required"
    );
    let prior_suites = if let Some(path) = prior_suites {
        let path = path.canonicalize()?;
        let evidence = read(&path)?;
        ensure!(
            evidence["qualification"] == false
                && evidence["failed_run"] == failed.display().to_string()
                && evidence["retained"]["linux-build-tooling"]["tooling_image"] == tooling_image
                && evidence["retained"]["linux-build-check"]["admission"] == admitted
                && evidence["retained"]["linux-build-probe"]["admission"] == probe,
            "prior diagnostic native suite identities differ"
        );
        for suite in ["sandbox", "worker", "http", "backup"] {
            let result = &evidence["executed"][format!("test-{suite}")];
            ensure!(
                result["status"] == "passed" && result["suite"] == suite,
                "prior native suite did not pass"
            );
        }
        Some(json!({"file":path,"digest":day2::digest(&fs::read(&path)?),
            "qualification":false,"tooling_image":tooling_image,"artifact":admitted["artifact"],"probe":probe["artifact"]}))
    } else {
        None
    };
    fs::create_dir(output).context("diagnostic output must be new")?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o700))?;
    let output = output.canonicalize()?;
    ensure!(
        !output.starts_with(&failed),
        "diagnostics must preserve the failed run unchanged"
    );
    let runner = super::workflows::build(root)?;
    super::linux_qualification::preflight(&runner)?;
    let mut runtime = RuntimeSession::new(root, &output, &artifacts[0].0, image)?;
    runtime.set_tooling_image(tooling_image)?;
    runtime.set_artifact_evidence(&admitted)?;
    let container = format!("day2-linux-{}-diagnostic", runtime.identity);
    let mut executed = BTreeMap::<String, Value>::new();
    let mut retained = BTreeMap::<String, Value>::new();
    let mut reused_suites = BTreeMap::<String, Value>::new();
    let result = day2::automation::run(&runner, &["qualify-linux"], |request| {
        let input: Value = request.decode()?;
        let action = request.action.as_str();
        let key = if action == "linux-test-suite" {
            format!(
                "test-{}",
                input["suite"].as_str().context("diagnostic suite")?
            )
        } else {
            action.to_owned()
        };
        ensure!(
            !executed.contains_key(&key)
                && !retained.contains_key(&key)
                && !reused_suites.contains_key(&key),
            "duplicate diagnostic effect"
        );
        eprintln!("Linux diagnostic: {key}");
        let evidence = match action {
            "linux-capture" | "linux-build-tooling" | "linux-build-runtime" => {
                ensure!(former.contains(action), "retained build was not completed");
                let evidence = json!({"status":if action == "linux-build-runtime" && runtime_override.is_some() {"diagnostic-runtime-override"} else {"retained-diagnostic-only"},"source_status":"pre-final",
                    "failed_run":failed,"platform":failure["platform"],"source":failure["source"],
                    "runtime_image":image,"original_runtime_image":original_runtime_image,"tooling_image":tooling_image});
                retained.insert(key, evidence.clone());
                return Ok(evidence);
            }
            "linux-start-tooling" => {
                ensure!(retained.len() == 3, "retained diagnostic inputs required");
                let mut arguments = vec![
                    "run".into(),
                    "--detach".into(),
                    "--name".into(),
                    container.clone(),
                    format!(
                        "--platform={}",
                        super::linux_qualification::native_platform()?.docker
                    ),
                    "--memory=6g".into(),
                    "--memory-swap=6g".into(),
                    "--cpus=4".into(),
                    "--pids-limit=512".into(),
                    "--cgroupns=private".into(),
                    "--cap-drop=ALL".into(),
                    "--security-opt=no-new-privileges:true".into(),
                    "--env=CARGO_INCREMENTAL=0".into(),
                ];
                for (host, native) in &artifacts {
                    arguments.extend([
                        "--mount".into(),
                        format!(
                            "type=bind,source={},target={native},readonly",
                            host.display()
                        ),
                    ]);
                }
                arguments.extend([
                    "--mount".into(),
                    format!(
                        "type=bind,source={},target=/workspace/platform/examples/reports,readonly",
                        failed.join("inputs/examples/reports").display()
                    ),
                    tooling_image.into(),
                    "sleep".into(),
                    "infinity".into(),
                ]);
                runtime.helpers.insert(container.clone());
                runtime.docker(&arguments)?;
                let inspected: Value =
                    serde_json::from_str(&runtime.docker(&["inspect".into(), container.clone()])?)?;
                ensure!(
                    inspected[0]["Image"] == tooling_image,
                    "diagnostic tooling image changed"
                );
                json!({"container":container,"image":tooling_image,"source_status":"pre-final"})
            }
            "linux-build-check" | "linux-build-probe" => {
                ensure!(
                    executed.contains_key("linux-start-tooling") && former.contains(action),
                    "retained native build admission required"
                );
                let index = usize::from(action == "linux-build-probe");
                let expected = if index == 0 { &admitted } else { &probe };
                let proof: Value = serde_json::from_str(&runtime.docker(&[
                    "exec".into(),
                    container.clone(),
                    "target/debug/xtask".into(),
                    "linux-artifact-evidence".into(),
                    artifacts[index].1.clone(),
                ])?)?;
                ensure!(
                    proof == *expected,
                    "retained native artifact admission changed"
                );
                let evidence = json!({"status":"retained-build-re-admitted","source_status":"pre-final","admission":proof});
                retained.insert(key, evidence.clone());
                return Ok(evidence);
            }
            "linux-test-suite" => {
                ensure!(
                    retained.contains_key("linux-build-probe"),
                    "both native artifacts required before suites"
                );
                let suite = input["suite"].as_str().context("diagnostic suite")?;
                ensure!(
                    ["sandbox", "worker", "http", "backup"].contains(&suite),
                    "unknown diagnostic suite"
                );
                if let Some(prior) = &prior_suites {
                    let evidence = json!({"status":"prior-diagnostic-evidence","suite":suite,
                        "executed_in_this_run":false,"source":prior});
                    reused_suites.insert(key, evidence.clone());
                    return Ok(evidence);
                }
                runtime.docker_with_budget(
                    &[
                        "exec".into(),
                        "--env=CARGO_INCREMENTAL=0".into(),
                        container.clone(),
                        "target/debug/xtask".into(),
                        "linux-test-suite".into(),
                        suite.into(),
                        artifacts[0].1.clone(),
                        artifacts[1].1.clone(),
                    ],
                    Duration::from_secs(1800),
                )?;
                json!({"suite":suite,"status":"passed","source_status":"pre-final"})
            }
            "linux-runtime-package"
            | "linux-runtime-start"
            | "linux-runtime-read-write"
            | "linux-runtime-revoke"
            | "linux-runtime-graceful-restart"
            | "linux-runtime-forced-restart"
            | "linux-runtime-isolation"
            | "linux-runtime-restore"
            | "linux-runtime-stop" => {
                ensure!(
                    ["sandbox", "worker", "http", "backup"]
                        .iter()
                        .all(|suite| executed.contains_key(&format!("test-{suite}"))
                            || reused_suites.contains_key(&format!("test-{suite}"))),
                    "native diagnostic suites required"
                );
                runtime.effect(action)?
            }
            "linux-stop-tooling" => {
                ensure!(
                    executed.contains_key("linux-runtime-stop"),
                    "runtime diagnostic completion required"
                );
                runtime.docker(&["rm".into(), "--force".into(), container.clone()])?;
                runtime.helpers.remove(&container);
                json!({"stopped":true})
            }
            "linux-receipt" => {
                ensure!(
                    executed.len() + reused_suites.len() == 15
                        && retained.len() == 5
                        && executed.contains_key("linux-stop-tooling"),
                    "diagnostic recipe incomplete"
                );
                return Ok(json!({"status":"diagnostic-passed","qualification":false}));
            }
            _ => bail!("unknown Linux diagnostic capability"),
        };
        executed.insert(key, evidence.clone());
        Ok(evidence)
    });
    let evidence = json!({"format":1,"status":if result.is_ok() {"diagnostic-passed"} else {"diagnostic-failed"},
        "qualification":false,"source_status":if runtime_override.is_some() {"mixed-diagnostic-only"} else {"pre-final-retained"},"failed_run":failed,
        "original_runtime_image":original_runtime_image,"diagnostic_runtime_image":image,"runtime_image_overridden":runtime_override.is_some(),
        "workflow":day2::automation::source_digest(),"retained":retained,"executed":executed,"prior_native_suites":reused_suites,
        "error":result.as_ref().err().map(|error|format!("{error:#}")),
        "explanation":"Diagnostic execution of the current Roc recipe against retained failed-run images and artifacts. This is not a completed captured qualification and cannot be reviewed as security Requirements."});
    fs::write(
        output.join("diagnostic.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    result?;
    println!(
        "{}",
        json!({"status":"diagnostic-passed","qualification":false,"evidence":output.join("diagnostic.json")})
    );
    Ok(())
}

impl Drop for RuntimeSession {
    fn drop(&mut self) {
        // Scope every cleanup to a container created by this qualification run.
        // State volumes and all evidence survive both success and failure.
        let _ = self.stop();
        for name in self.helpers.clone() {
            let _ = self.docker(&["rm".into(), "-f".into(), name]);
        }
    }
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: String,
}

#[derive(Debug)]
struct HttpFailure {
    status: u16,
    code: &'static str,
}

impl std::fmt::Display for HttpFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "HTTP {} ({})", self.status, self.code)
    }
}

impl std::error::Error for HttpFailure {}

impl HttpResponse {
    fn json(&self) -> Result<Value> {
        serde_json::from_str(&self.body).context("HTTP JSON response")
    }

    fn stable_error_code(&self) -> &'static str {
        let value: Value = serde_json::from_str(&self.body).unwrap_or(Value::Null);
        // Never copy free-form bodies, messages, input, or authentication fields
        // into diagnostics. Only these platform-owned error literals are retained.
        match value["error"]["code"].as_str() {
            Some("internal_error") => "internal_error",
            Some("worker_timeout") => "worker_timeout",
            Some("transaction_budget_exceeded") => "transaction_budget_exceeded",
            Some("preparation_deadline") => "preparation_deadline",
            Some("external_outcome_ambiguous") => "external_outcome_ambiguous",
            Some("sign_in_required") => "sign_in_required",
            Some("forbidden") => "forbidden",
            Some("invalid_input") => "invalid_input",
            _ => "unrecognized_error",
        }
    }
}

fn redacted(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.contains("login_url")
                || line.contains("/login?token=")
                || line.contains("csrf_token")
            {
                "[local authentication material redacted]\n".to_owned()
            } else {
                format!("{line}\n")
            }
        })
        .collect()
}

fn admitted_artifact_evidence(artifact: &LoadedArtifact) -> Result<Value> {
    Ok(json!({
        "artifact":artifact.id(),
        "worker":artifact.contract().worker_digest,
        "platform_inventory":day2::security_admission::platform_inventory_digest(artifact)?
    }))
}

/// This tooling-only entrypoint performs admission on the worker's native OS.
/// The macOS orchestrator independently checks addressed JSON and worker bytes.
pub fn native_artifact_evidence(path: &Path) -> Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "native artifact admission requires Linux"
    );
    let artifact = LoadedArtifact::load(path)?;
    artifact.require_current_api()?;
    admitted_artifact_evidence(&artifact)
}

/// Package disposable Reports fixtures inside the trusted Linux tooling image.
/// Package construction stays outside the application runtime image.
pub fn native_package(
    artifact: &Path,
    output: &Path,
    installation: &str,
    port: u16,
    image: &str,
    security_receipt: Option<&Path>,
) -> Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "native runtime packaging requires Linux"
    );
    let artifact = LoadedArtifact::load(artifact)?;
    artifact.require_current_api()?;
    day2_contracts::names::identifier(installation)?;
    let mut policy: day2::authority::Policy = serde_json::from_str(include_str!(
        "../../../fixtures/authority-policies/reports.json"
    ))?;
    policy.admins.insert(ACTOR.into());
    let (resources, resource_policies) =
        day2::development::resource_fixture_for_artifact(APP, &artifact, &policy)?;
    let mut desired = json!({
        "installation":installation,"environment":"disposable","resources":resources,
        "apps":{APP:{
            "artifact":artifact.directory(),"readers":[ACTOR],"writers":[ACTOR],
            "authority":policy,"resource_policies":resource_policies,
            "runtime":{"kind":"linux_sqlite_single_v1","resources":{
                "memory_mib":512,"cpu_millis":1000,"process_limit":64,
                "http_concurrency":4,"shutdown_seconds":30
            }}
        }}
    });
    if let Some(path) = security_receipt {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.len() <= 1_048_576,
            "bounded regular strict qualification receipt required"
        );
        let bytes = fs::read(path)?;
        let receipt: Value = day2::json::decode(&bytes)?;
        ensure!(
            receipt["artifact"] == artifact.id()
                && receipt["worker"] == artifact.contract().worker_digest
                && receipt["runtime_image"] == image,
            "strict package receipt identity mismatch"
        );
        let security = day2::security_admission::review_linux(&artifact, path)?;
        let day2::security_admission::Containment::LinuxQualifiedV1 { evidence } =
            &security.containment
        else {
            bail!("strict package requires native Linux qualification");
        };
        ensure!(
            evidence.receipt_digest == day2::digest(&bytes),
            "strict receipt changed during review"
        );
        desired["apps"][APP]["security"] = serde_json::to_value(security)?;
    }
    let parent = output.parent().context("native package output parent")?;
    let mut input = tempfile::NamedTempFile::new_in(parent)?;
    input.write_all(&serde_json::to_vec_pretty(&desired)?)?;
    input.as_file().sync_all()?;
    day2::packaging::export(
        input.path(),
        APP,
        ACTOR,
        image,
        NonZeroU16::new(port).context("native package port")?,
        output,
    )?;
    // Inputs carry no secrets and remain inside a private host evidence parent.
    // Preserve the orchestrator UID's ownership for explicit desired-policy edits.
    fs::set_permissions(output, fs::Permissions::from_mode(0o755))?;
    let instance = Instance::load(&output.join("instance.json"))?;
    let compose: Value = serde_json::from_slice(&fs::read(output.join("compose.json"))?)?;
    let mut evidence = admitted_artifact_evidence(&artifact)?;
    let proof = evidence
        .as_object_mut()
        .context("native package evidence object")?;
    proof.insert("installation".into(), json!(installation));
    proof.insert("port".into(), json!(port));
    proof.insert("volume".into(), compose["volumes"]["state"]["name"].clone());
    proof.insert("instance".into(), serde_json::to_value(instance)?);
    proof.insert(
        "deployment_digest".into(),
        json!(day2::digest(&fs::read(output.join("deployment.json"))?)),
    );
    Ok(evidence)
}

/// Tooling-only negative admission proof. The qualified launcher is retained,
/// while this explicitly measured operator executable must not act as the app.
pub fn native_strict_denial(instance: &Path) -> Result<Value> {
    ensure!(
        cfg!(target_os = "linux"),
        "strict runtime denial requires Linux"
    );
    let runtime = day2::store::Runtime::load(instance, APP)?;
    let database = rusqlite::Connection::open_with_flags(
        runtime.db(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let active = day2::authority_state::current(&database)?;
    ensure!(
        active.document.enabled && active.artifact_id == runtime.artifact().id(),
        "strict denial requires enabled authority for the admitted artifact"
    );
    let security = active
        .document
        .security
        .as_ref()
        .context("active strict authority required")?;
    security.validate(runtime.artifact())?;
    let day2::security_admission::Containment::LinuxQualifiedV1 { evidence } =
        &security.containment
    else {
        bail!("active native Linux qualification required");
    };
    let executable = std::env::current_exe()?.canonicalize()?;
    let supervisor = day2::digest(&fs::read(&executable)?);
    let sandbox = day2::digest(&fs::read(
        executable
            .parent()
            .context("strict tooling directory")?
            .join("day2-sandbox"),
    )?);
    ensure!(
        supervisor != evidence.runtime_supervisor,
        "negative proof must use a different supervisor"
    );
    ensure!(
        sandbox == evidence.runtime_sandbox,
        "negative proof requires the qualified sandbox"
    );
    const INVOCATION: &str = "linux-strict-runtime-denial";
    let previous: i64 = database.query_row(
        "SELECT (SELECT count(*) FROM day2_invocations WHERE id=?1) + (SELECT count(*) FROM day2_audit_events WHERE identity=?1)",
        [INVOCATION], |row| row.get(0),
    )?;
    ensure!(
        previous == 0,
        "strict denial requires a fresh synthetic invocation"
    );
    drop(database);
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    let result = runtime.invoke(
        "reports.list",
        ACTOR,
        INVOCATION,
        &json!({"after":"","limit":20}),
        now,
        day2::store::Fault::None,
    );
    let error = result
        .err()
        .context("unqualified tooling supervisor unexpectedly admitted protected query")?;
    ensure!(
        error
            .chain()
            .any(|cause| cause.to_string() == "security_runtime_mismatch"),
        "strict query did not fail at the required runtime admission guard"
    );
    Ok(
        json!({"code":"security_runtime_mismatch","artifact":runtime.artifact().id(),
        "actual_supervisor":supervisor,"expected_supervisor":evidence.runtime_supervisor,
        "actual_sandbox":sandbox,"expected_sandbox":evidence.runtime_sandbox}),
    )
}

/// Tooling-only, read-only evidence capability. No worker or operator grants are
/// needed: the explicitly authorized machine operator samples one SQLite read
/// transaction, including every row within a fail-closed qualification budget.
pub fn native_evidence(instance: &Path) -> Result<Value> {
    use rusqlite::{Connection, OpenFlags, OptionalExtension, types::ValueRef};
    ensure!(
        cfg!(target_os = "linux"),
        "native runtime evidence requires Linux"
    );
    let runtime = day2::store::Runtime::load(instance, APP)?;
    let mut connection =
        Connection::open_with_flags(runtime.db(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let transaction = connection.transaction()?;
    let authority = day2::authority_state::current(&transaction)?;
    let tables = transaction
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let excluded = BTreeSet::from([
        "sqlite_sequence",
        "day2_authority",
        "day2_authority_history",
        "day2_authority_blocks",
        "day2_authority_requests",
        "day2_authority_desired_requests",
        "day2_web_sessions",
        "day2_web_secret",
        "day2_budget_meta",
        "day2_selection_cursor_pins",
        "day2_app_restore_fence",
    ]);
    let mut domain = BTreeMap::new();
    let mut journal = BTreeMap::new();
    let mut total = 0_usize;
    for table in &tables {
        if excluded.contains(table.as_str()) {
            continue;
        }
        ensure!(
            table
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_'),
            "evidence table name"
        );
        let mut statement = transaction.prepare(&format!("SELECT * FROM \"{table}\""))?;
        let columns: Vec<_> = statement
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut cursor = statement.query([])?;
        let mut rows = Vec::new();
        while let Some(row) = cursor.next()? {
            let mut cells = Vec::new();
            for index in 0..columns.len() {
                cells.push(match row.get_ref(index)? {
                    ValueRef::Null => json!(["null"]),
                    ValueRef::Integer(value) => json!(["integer", value]),
                    ValueRef::Real(value) => json!(["real", value.to_bits().to_string()]),
                    ValueRef::Text(value) => json!(["text", String::from_utf8(value.to_vec())?]),
                    ValueRef::Blob(value) => json!(["blob", value.len(), day2::digest(value)]),
                });
            }
            let encoded = serde_json::to_string(&cells)?;
            total = total
                .checked_add(encoded.len())
                .context("evidence byte accounting")?;
            ensure!(
                total <= 64 * 1024 * 1024 && rows.len() < 100_000,
                "complete native evidence exceeds qualification budget"
            );
            rows.push(encoded);
        }
        rows.sort_unstable();
        let snapshot = json!({"columns":columns,"rows":rows.len(),"digest":day2::digest(&serde_json::to_vec(&rows)?)});
        if runtime
            .artifact()
            .contract()
            .schema
            .models
            .contains_key(table)
        {
            domain.insert(table.clone(), snapshot);
        } else {
            journal.insert(table.clone(), snapshot);
        }
    }
    let count = |table: &str| -> Result<i64> {
        if !tables.iter().any(|name| name == table) {
            return Ok(0);
        }
        Ok(
            transaction.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?,
        )
    };
    let pending: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM day2_invocations WHERE status='pending'",
        [],
        |row| row.get(0),
    )?;
    let restore_not_before: Option<i64> = transaction
        .query_row(
            "SELECT not_before FROM day2_app_restore_fence WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let sampled_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(
        json!({"artifact":runtime.artifact().id(),"scope":runtime.scope(),
        "domain":domain,"journal":journal,"authority":authority,"pending":pending,
        "sessions":count("day2_web_sessions")?,"session_secrets":count("day2_web_secret")?,
        "sampled_at_unix":sampled_at_unix,
        "delegation_restore_fence":{"not_before":restore_not_before},
        "snapshot":"single SQLite read transaction; complete bounded row digests",
        "restore_mutable_tables_excluded":excluded}),
    )
}

fn verify_restored_delegation_fence(before: &Value, restored: &Value) -> Result<()> {
    let cutoff = restored["delegation_restore_fence"]["not_before"]
        .as_i64()
        .context("restore omitted delegation fence")?;
    let prior = before["delegation_restore_fence"]["not_before"]
        .as_i64()
        .unwrap_or(0);
    let started = before["sampled_at_unix"]
        .as_i64()
        .context("source evidence time missing")?;
    let completed = restored["sampled_at_unix"]
        .as_i64()
        .context("restore evidence time missing")?;
    ensure!(
        cutoff > 0 && cutoff >= prior && cutoff >= started && cutoff <= completed,
        "restore delegation fence is stale or outside the observed interval"
    );
    Ok(())
}

#[cfg(test)]
mod restore_fence_tests {
    use super::*;

    #[test]
    fn restored_fence_requires_fresh_non_decreasing_cutoff() {
        let before = json!({"sampled_at_unix":100,"delegation_restore_fence":{"not_before":90}});
        let after = |cutoff: Value| json!({"sampled_at_unix":102,"delegation_restore_fence":{"not_before":cutoff}});
        assert!(verify_restored_delegation_fence(&before, &after(json!(101))).is_ok());
        for cutoff in [Value::Null, json!(89), json!(99), json!(103)] {
            assert!(verify_restored_delegation_fence(&before, &after(cutoff)).is_err());
        }
        let previously_fenced =
            json!({"sampled_at_unix":100,"delegation_restore_fence":{"not_before":102}});
        assert!(verify_restored_delegation_fence(&previously_fenced, &after(json!(101))).is_err());
    }
}
