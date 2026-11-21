//! OpenTofu runs of an instance's core roots, for `day2 instance plan` and
//! `day2 instance apply`. The CLI renders each root's backend and variables from
//! day2.json and InstanceRoots.roc chooses the step order; this adapter
//! independently validates the request and every engine operation.
//!
//! What it guarantees, and how:
//! - The pinned engine: OpenTofu `ENGINE_VERSION`, admitted by digest, copied into
//!   the output directory and checked again before every operation, with a
//!   private CLI configuration (no ambient provider overrides).
//! - The pinned stacks: each root runs a private copy of
//!   `deploy/gke/stacks/<stack>` read as git objects of the spec's platform
//!   commit (no working tree, replace refs, filters or attributes), and the
//!   CLI's and this host's rendering rules must both be that commit's.
//! - The host's mode: the host action fixes the session's `Mode`, and the request
//!   must name the same one, so a plan can never apply whatever the recipe asks.
//! - Read-only plans: a plan session never takes a state lock. A root whose state
//!   does not exist yet plans against an empty local state, so no state object is
//!   created.
//! - Reviewed applies: an apply session plans each root with the state lock and
//!   applies exactly that saved plan, which OpenTofu refuses if the state changed
//!   in between. It refuses a plan that deletes, replaces or forgets a resource,
//!   and it runs no root until every shared root before it has applied.
//! - Secrets stay out of the output: the DNS token is held in memory and passed
//!   to app-edge plans and applies only; the kubeconfig and its auth-plugin cache
//!   live in a private temporary directory removed with the session; the receipt
//!   step refuses unexpected files in the output.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::Read,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The core stacks a session may run. day2-app is planned by the release
/// controller, which owns its image and artifact inputs.
pub const STACKS: [&str; 4] = ["project", "cluster", "tenancy", "app-edge"];

/// The stacks every later root reads. An apply runs no root until each shared
/// root before it has applied, so one failure stops the rest; an app edge reads
/// only these, so its failure never stops another app's.
pub const SHARED: [&str; 3] = ["project", "cluster", "tenancy"];

/// How long a plan or apply waits for another holder of a root's state lock.
const LOCK_TIMEOUT: &str = "-lock-timeout=300s";

/// The engine every instance session runs, by version and by the digest of the
/// official release binary for each supported host.
pub const ENGINE_VERSION: &str = "1.12.3";
const ENGINE_DIGESTS: [(&str, &str); 2] = [
    (
        "linux_amd64",
        "sha256:d5e3276d613fdc070178ad6b0eb545f79a05e9aeae51f3c20024d21362fe25c6",
    ),
    (
        "darwin_arm64",
        "sha256:fa6b1125152f97f5b355d4a6cc8ef28e3e511efb58a78ad42f794317f738eba0",
    ),
];

/// The Secret Manager secret in the instance project holding the DNS provider
/// token app edges plan with.
pub const DNS_TOKEN_SECRET: &str = "cloudflare-api-token";

/// The rendering rules this host was built with. A plan refuses a platform
/// commit whose copies differ, so a plan always renders with the rules of the
/// commit whose stacks it plans.
const RENDERER: [(&str, &[u8]); 4] = [
    (
        "cli/InstanceSpec.roc",
        include_bytes!("../../../cli/InstanceSpec.roc"),
    ),
    (
        "cli/InstanceRender.roc",
        include_bytes!("../../../cli/InstanceRender.roc"),
    ),
    ("cli/Names.roc", include_bytes!("../../../cli/Names.roc")),
    (
        "cli/JsonValue.roc",
        include_bytes!("../../../cli/JsonValue.roc"),
    ),
];

/// Instance inputs this plan cannot pass through yet; their presence fails closed.
const UNSUPPORTED: [&str; 1] = ["gcp/config/oauth-workloads.json"];

/// The ambient variables planning tools may see: the search path and home, Google
/// credential and account selection (including impersonation), and proxy and CA
/// settings. OpenTofu's own configuration is always the session's private file.
const PASSED: [&str; 13] = [
    "PATH",
    "HOME",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
    "CLOUDSDK_CONFIG",
    "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
];

const GIT: &str = "/usr/bin/git";
const REQUEST_LIMIT: u64 = 1 << 20;
const BLOB_LIMIT: u64 = 16 << 20;
const SHOW_LIMIT: u64 = 64 << 20;

/// What a session may do: `day2 instance plan` never locks state or applies;
/// `day2 instance apply` applies each root's saved plan.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Plan,
    Apply,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Apply => "apply",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub mode: Mode,
    pub instance: PathBuf,
    /// A git repository containing `commit`; only that commit's objects are read.
    pub checkout: PathBuf,
    pub output: PathBuf,
    pub commit: String,
    pub project: String,
    pub zone: String,
    pub cluster: String,
    pub roots: Vec<Root>,
    /// The rendering sources the CLI was built with, compared byte for byte with
    /// this host's and the platform commit's.
    pub renderer: Vec<Source>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub path: String,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub label: String,
    pub stack: String,
    pub app_id: Option<String>,
    pub bucket: String,
    pub prefix: String,
    /// The instance's committed variables for this root, at its fixed path.
    pub inputs: String,
    /// The rendered .tfvars.json document. It is passed after `inputs`, so a
    /// rendered value wins over a committed copy of the same variable.
    pub variables: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Init,
    Plan,
    Show,
    Apply,
}

impl Stage {
    fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "init" => Self::Init,
            "plan" => Self::Plan,
            "show" => Self::Show,
            "apply" => Self::Apply,
            _ => bail!("unknown instance root operation"),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Plan => "plan",
            Self::Show => "show",
            Self::Apply => "apply",
        }
    }

    fn after(self) -> Option<Self> {
        match self {
            Self::Init => None,
            Self::Plan => Some(Self::Init),
            Self::Show => Some(Self::Plan),
            Self::Apply => Some(Self::Show),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Credentials,
    Stage(Stage),
    /// The saved plan deletes, replaces or forgets a resource; nothing was applied.
    Destroys,
}

#[derive(Default)]
struct Progress {
    done: BTreeSet<Stage>,
    failed: Option<Failure>,
    new_root: bool,
    changes: Vec<Value>,
    destroys: Vec<String>,
}

/// Where a root's files live inside the output directory.
pub struct Layout {
    pub config: PathBuf,
    pub stack: PathBuf,
    pub data: PathBuf,
    pub inputs: PathBuf,
    pub rendered: PathBuf,
    pub plan: PathBuf,
}

/// Credentials an engine step receives; only `plan` and `apply` of the roots that
/// need them.
pub struct Credentials<'a> {
    pub kubeconfig: Option<&'a Path>,
    pub dns_token: Option<&'a str>,
}

pub fn expected_inputs(stack: &str, app_id: Option<&str>) -> Result<String> {
    Ok(match (stack, app_id) {
        ("project" | "cluster" | "tenancy", None) => format!("gcp/config/{stack}.tfvars"),
        ("app-edge", Some(app)) => format!("gcp/config/app-edge/{app}.tfvars"),
        _ => bail!("no committed inputs for {stack}"),
    })
}

fn needs_cluster(stack: &str) -> bool {
    stack == "tenancy" || stack == "app-edge"
}

fn needs_dns(stack: &str) -> bool {
    stack == "app-edge"
}

/// The exact engine invocation for one stage of one root: arguments and the
/// variables set on top of the allowlisted ambient ones. `local_state` is a plan
/// session's root that has never been applied.
pub fn invocation(
    mode: Mode,
    stage: Stage,
    root: &Root,
    layout: &Layout,
    local_state: bool,
    credentials: &Credentials,
) -> (Vec<OsString>, Vec<(&'static str, OsString)>) {
    let mut args: Vec<OsString> = vec![format!("-chdir={}", layout.stack.display()).into()];
    let mut env: Vec<(&'static str, OsString)> = vec![
        ("TF_CLI_CONFIG_FILE", layout.config.clone().into()),
        ("TF_DATA_DIR", layout.data.clone().into()),
        ("TF_IN_AUTOMATION", "1".into()),
        ("TF_INPUT", "0".into()),
        ("CHECKPOINT_DISABLE", "1".into()),
    ];
    match stage {
        Stage::Init => {
            args.extend(
                [
                    "init",
                    "-input=false",
                    "-no-color",
                    "-reconfigure",
                    "-lockfile=readonly",
                ]
                .map(OsString::from),
            );
            if !local_state {
                args.push(format!("-backend-config=bucket={}", root.bucket).into());
                args.push(format!("-backend-config=prefix={}", root.prefix).into());
            }
        }
        Stage::Plan => {
            args.extend(["plan", "-input=false", "-no-color"].map(OsString::from));
            args.push(match mode {
                Mode::Plan => "-lock=false".into(),
                Mode::Apply => LOCK_TIMEOUT.into(),
            });
            args.push(format!("-var-file={}", layout.inputs.display()).into());
            args.push(format!("-var-file={}", layout.rendered.display()).into());
            args.push(format!("-out={}", layout.plan.display()).into());
            if needs_cluster(&root.stack)
                && let Some(kubeconfig) = credentials.kubeconfig
            {
                // A -var outranks every var file, so a committed kubeconfig_path can
                // never point the provider at another kubeconfig. A saved plan keeps it.
                args.push(format!("-var=kubeconfig_path={}", kubeconfig.display()).into());
            }
            provider_env(root, credentials, &mut env);
        }
        Stage::Show => {
            args.extend(["show", "-json", "-no-color"].map(OsString::from));
            args.push(layout.plan.clone().into());
        }
        Stage::Apply => {
            // Exactly the saved plan: OpenTofu refuses it if the state changed since.
            args.extend(["apply", "-input=false", "-no-color", LOCK_TIMEOUT].map(OsString::from));
            args.push(layout.plan.clone().into());
            provider_env(root, credentials, &mut env);
        }
    }
    (args, env)
}

/// The cluster and DNS credentials a root's providers read from the environment.
fn provider_env(root: &Root, credentials: &Credentials, env: &mut Vec<(&'static str, OsString)>) {
    if needs_cluster(&root.stack)
        && let Some(kubeconfig) = credentials.kubeconfig
    {
        env.push(("KUBECONFIG", kubeconfig.into()));
        env.push(("KUBE_CONFIG_PATH", kubeconfig.into()));
    }
    if needs_dns(&root.stack)
        && let Some(token) = credentials.dns_token
    {
        env.push(("CLOUDFLARE_API_TOKEN", token.into()));
    }
}

/// Whether `stage` of `label` may run now. Each root runs its stages in order and
/// stops at its first failure; only an apply session applies; and an apply runs no
/// root until every shared root before it has applied, since later roots read
/// their state.
fn admit(
    mode: Mode,
    roots: &[Root],
    progress: &BTreeMap<String, Progress>,
    label: &str,
    stage: Stage,
) -> Result<()> {
    let current = progress.get(label).context("unknown root")?;
    ensure!(current.failed.is_none(), "{label} already failed");
    ensure!(
        !current.done.contains(&stage),
        "duplicate {} for {label}",
        stage.name()
    );
    if let Some(required) = stage.after() {
        ensure!(
            current.done.contains(&required),
            "{} needs {} first",
            stage.name(),
            required.name()
        );
    }
    ensure!(
        stage != Stage::Apply || mode == Mode::Apply,
        "instance plan never applies"
    );
    if mode == Mode::Apply {
        for root in roots.iter().take_while(|root| root.label != label) {
            let earlier = progress.get(&root.label).context("unknown root")?;
            ensure!(
                !SHARED.contains(&root.stack.as_str())
                    || (earlier.failed.is_none() && earlier.done.contains(&Stage::Apply)),
                "{label} runs only after {} has applied",
                root.label
            );
        }
    }
    Ok(())
}

fn text(value: &str, limit: usize, allowed: impl Fn(u8) -> bool) -> bool {
    !value.is_empty() && value.len() <= limit && value.bytes().all(allowed)
}

fn lower(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

fn starts_lower(value: &str) -> bool {
    value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
}

pub fn validate(request: &Request) -> Result<()> {
    ensure!(
        request.commit.len() == 40
            && text(&request.commit, 40, |b| b.is_ascii_hexdigit()
                && !b.is_ascii_uppercase()),
        "platform commit must be a full lowercase commit"
    );
    ensure!(
        text(&request.project, 30, |b| lower(b) || b == b'-')
            && starts_lower(&request.project)
            && !request.project.ends_with('-'),
        "invalid GCP project"
    );
    ensure!(
        text(&request.zone, 32, |b| lower(b) || b == b'-')
            && starts_lower(&request.zone)
            && request.zone.matches('-').count() == 2,
        "invalid GCP zone"
    );
    ensure!(
        text(&request.cluster, 40, |b| lower(b) || b == b'-') && starts_lower(&request.cluster),
        "invalid cluster name"
    );
    ensure!(
        !request.roots.is_empty() && request.roots.len() <= 3 + 128,
        "core root count"
    );
    let mut labels = BTreeSet::new();
    for root in &request.roots {
        ensure!(
            STACKS.contains(&root.stack.as_str()),
            "not a core stack: {}",
            root.stack
        );
        let label = match (root.stack.as_str(), &root.app_id) {
            ("app-edge", Some(app)) => {
                day2_contracts::names::identifier(app)?;
                format!("app-edge/{app}")
            }
            ("app-edge", None) => bail!("app-edge needs its app"),
            (_, Some(_)) => bail!("{} takes no app", root.stack),
            (stack, None) => stack.to_owned(),
        };
        ensure!(root.label == label, "root label must be {label}");
        ensure!(labels.insert(label), "duplicate root {}", root.label);
        ensure!(
            root.inputs == expected_inputs(&root.stack, root.app_id.as_deref())?,
            "{} reads only its fixed committed inputs",
            root.label
        );
        ensure!(
            text(&root.bucket, 63, |b| lower(b)
                || b == b'-'
                || b == b'_'
                || b == b'.')
                && root.bucket.len() >= 3,
            "invalid state bucket"
        );
        ensure!(
            text(&root.prefix, 256, |b| lower(b)
                || b == b'-'
                || b == b'_'
                || b == b'/')
                && !root.prefix.starts_with('/')
                && !root.prefix.ends_with('/')
                && !root.prefix.contains("//"),
            "invalid state prefix"
        );
        ensure!(root.variables.len() <= 65_536, "rendered variables budget");
        let variables: Value =
            day2::json::decode(root.variables.as_bytes()).context("rendered variables")?;
        let fields = variables
            .as_object()
            .context("rendered variables must be an object")?;
        for name in fields.keys() {
            ensure!(
                text(name, 64, |b| lower(b) || b == b'_') && starts_lower(name),
                "invalid variable name {name}"
            );
        }
    }
    Ok(())
}

/// Run a trusted tool and return its bounded stdout bytes. stderr goes to `log`
/// when given and is otherwise discarded, so stdout (a secret, an archive or a
/// plan) never reaches a log.
fn capture(
    mut command: Command,
    log: Option<&Path>,
    timeout: Duration,
    limit: u64,
) -> Result<Vec<u8>> {
    let stderr = match log {
        Some(path) => Stdio::from(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?,
        ),
        None => Stdio::null(),
    };
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(stderr)
        .spawn()
        .context("start platform tool")?;
    let mut stdout = child.stdout.take().context("tool output")?;
    // Drain past the limit so a large output fails as too large, not as a stall.
    let reader = std::thread::spawn(move || -> std::io::Result<(Vec<u8>, bool)> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 65_536];
        let mut overflow = false;
        loop {
            let read = stdout.read(&mut chunk)?;
            if read == 0 {
                return Ok((bytes, overflow));
            }
            if bytes.len() as u64 + read as u64 > limit {
                overflow = true;
            } else {
                bytes.extend_from_slice(&chunk[..read]);
            }
        }
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("tool deadline exceeded");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let (bytes, overflow) = reader
        .join()
        .map_err(|_| anyhow::anyhow!("tool output reader"))??;
    ensure!(!overflow, "tool output exceeds its bound");
    ensure!(status.success(), "tool exited {status}");
    Ok(bytes)
}

fn ambient() -> Vec<(&'static str, OsString)> {
    PASSED
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (*name, value)))
        .collect()
}

/// Read-only git, hardened as day2-control's fixed source reader: no replace
/// objects, system or global configuration, hooks, fsmonitor, optional locks or
/// protocol access.
fn git(repository: &Path, args: &[&str], limit: u64) -> Result<Vec<u8>> {
    let mut command = Command::new(GIT);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("LANG", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(["-c", "protocol.allow=never", "-c", "gc.auto=0"])
        .arg("-C")
        .arg(repository)
        .args(args);
    capture(command, None, Duration::from_secs(60), limit)
}

/// The regular files at or under `path` in `commit`, read as git objects, so no
/// working tree, filter, attribute or export rule can change their bytes. Paths
/// are relative to `path`; links and submodules are refused.
pub fn tree_files(repository: &Path, commit: &str, path: &str) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    let listing = git(
        repository,
        &["ls-tree", "-r", "-z", commit, "--", path],
        BLOB_LIMIT,
    )?;
    let mut files = Vec::new();
    for entry in listing
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        ensure!(files.len() < 4096, "tree file budget");
        let entry = std::str::from_utf8(entry)?;
        let (header, name) = entry.split_once('\t').context("git tree record")?;
        let mut parts = header.split(' ');
        let (mode, kind, oid) = (
            parts.next(),
            parts.next(),
            parts.next().context("git blob id")?,
        );
        ensure!(
            matches!(mode, Some("100644" | "100755"))
                && kind == Some("blob")
                && parts.next().is_none(),
            "{name}: stacks and rendering sources are regular files only"
        );
        let relative = if name == path {
            PathBuf::new()
        } else {
            Path::new(name)
                .strip_prefix(format!("{path}/"))
                .with_context(|| format!("{name} is outside {path}"))?
                .to_path_buf()
        };
        ensure!(
            relative
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
            "unsafe tree path {name}"
        );
        ensure!(
            oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid git blob id"
        );
        files.push((
            relative,
            git(repository, &["cat-file", "blob", oid], BLOB_LIMIT)?,
        ));
    }
    Ok(files)
}

/// The CLI that rendered the request, this host and the platform commit must all
/// carry the same rendering sources.
pub fn renderer_matches(repository: &Path, commit: &str, sent: &[Source]) -> Result<()> {
    ensure!(
        sent.len() == RENDERER.len()
            && sent
                .iter()
                .zip(RENDERER)
                .all(|(source, (path, bytes))| source.path == path
                    && source.text.as_bytes() == bytes),
        "this CLI and its platform host were built from different rendering sources; rebuild them together"
    );
    for (path, bytes) in RENDERER {
        let pinned = tree_files(repository, commit, path)?;
        ensure!(
            !pinned.is_empty(),
            "day2.json's platform commit {commit} predates instance plan and apply: it has no {path}"
        );
        ensure!(
            pinned.len() == 1 && pinned[0].1 == bytes,
            "this CLI renders with {path} from another commit; use a CLI built from {commit}"
        );
    }
    Ok(())
}

/// Whether a listing of exactly `object` found it. The listing repeats the name
/// once per retained version; any other name is refused.
pub fn state_listed(listed: &str, object: &str) -> Result<bool> {
    let names: Vec<&str> = listed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    ensure!(
        names.iter().all(|name| *name == object),
        "unexpected state objects listed for {object}"
    );
    Ok(!names.is_empty())
}

/// The backend a root that has never been applied plans with: an empty local state.
pub fn backend_override(state: &Path) -> Result<String> {
    Ok(format!(
        "terraform {{\n  backend \"local\" {{\n    path = {}\n  }}\n}}\n",
        serde_json::to_string(state)?
    ))
}

fn host() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux_amd64",
        ("macos", "aarch64") => "darwin_arm64",
        _ => "unsupported",
    }
}

pub struct Session {
    request: Request,
    instance: PathBuf,
    instance_commit: String,
    instance_clean: bool,
    platform: PathBuf,
    stacks_tree: String,
    output: PathBuf,
    engine_digest: String,
    layouts: BTreeMap<String, Layout>,
    inputs: BTreeMap<String, String>,
    rendered: BTreeMap<String, String>,
    private: tempfile::TempDir,
    kubeconfig: Option<PathBuf>,
    dns_token: Option<String>,
    credentials_read: bool,
    progress: BTreeMap<String, Progress>,
}

impl Session {
    /// Validate and stage the CLI's request for a session the host started in `mode`.
    pub fn prepare(raw: &Path, mode: Mode) -> Result<Self> {
        let mut bytes = Vec::new();
        fs::File::open(raw)?
            .take(REQUEST_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= REQUEST_LIMIT,
            "instance request budget"
        );
        let request: Request = day2::json::decode(&bytes)?;
        ensure!(
            request.mode == mode,
            "the host started an instance {} but the request is for an instance {}",
            mode.name(),
            request.mode.name()
        );
        validate(&request)?;
        let verb = mode.name();
        // Refuse a reused output directory before running anything; the builder
        // below still refuses one that appears in between.
        ensure!(
            fs::symlink_metadata(&request.output).is_err(),
            "instance {verb} requires a new output directory"
        );
        let instance = request
            .instance
            .canonicalize()
            .context("instance directory")?;
        let platform = request
            .checkout
            .canonicalize()
            .context("platform checkout")?;
        let parent = request
            .output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()
            .context("output parent directory")?;
        // The instance may be a subdirectory of its repository; its whole repository
        // is off limits too.
        let repository = git(&instance, &["rev-parse", "--show-toplevel"], 4096)
            .ok()
            .and_then(|top| String::from_utf8(top).ok())
            .map(|top| PathBuf::from(top.trim()))
            .and_then(|top| top.canonicalize().ok());
        ensure!(
            !parent.starts_with(&instance)
                && !parent.starts_with(&platform)
                && !repository
                    .as_ref()
                    .is_some_and(|top| parent.starts_with(top)),
            "the output directory must be outside the instance and the platform checkout"
        );
        for unsupported in UNSUPPORTED {
            ensure!(
                fs::symlink_metadata(instance.join(unsupported)).is_err(),
                "{unsupported} is not supported by instance plan or apply yet"
            );
        }
        for root in &request.roots {
            let path = instance.join(&root.inputs);
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("{} needs the instance's {}", root.label, root.inputs))?;
            ensure!(
                metadata.is_file() && metadata.len() <= 1_048_576,
                "{} must be a regular file of at most 1 MiB",
                root.inputs
            );
        }
        let commit = &request.commit;
        git(
            &platform,
            &["cat-file", "-e", &format!("{commit}^{{commit}}")],
            4096,
        )
        .context("the platform checkout must contain day2.json's platform commit")?;
        renderer_matches(&platform, commit, &request.renderer)?;
        let stacks_tree = String::from_utf8(git(
            &platform,
            &["rev-parse", &format!("{commit}:deploy/gke/stacks")],
            4096,
        )?)?
        .trim()
        .to_owned();
        let mut stacks = BTreeMap::new();
        for root in &request.roots {
            if !stacks.contains_key(&root.stack) {
                let files = tree_files(
                    &platform,
                    commit,
                    &format!("deploy/gke/stacks/{}", root.stack),
                )?;
                ensure!(
                    files.iter().any(|(path, _)| path == Path::new("main.tf")),
                    "the platform commit has no {} stack",
                    root.stack
                );
                stacks.insert(root.stack.clone(), files);
            }
        }
        let (instance_commit, instance_clean) = match (
            git(&instance, &["rev-parse", "HEAD"], 4096),
            git(&instance, &["status", "--porcelain"], 1 << 20),
        ) {
            (Ok(head), Ok(status)) => (
                String::from_utf8(head)?.trim().to_owned(),
                status.is_empty(),
            ),
            _ => (String::new(), false),
        };
        let found = crate::maintenance::on_path("tofu")?;
        let bytes = fs::read(&found)?;
        let engine_digest = day2::digest(&bytes);
        ensure!(
            ENGINE_DIGESTS.contains(&(host(), engine_digest.as_str())),
            "{} is not the pinned OpenTofu {ENGINE_VERSION} for {}",
            found.display(),
            host()
        );
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&request.output)
            .with_context(|| format!("instance {verb} requires a new output directory"))?;
        let output = request.output.canonicalize()?;
        let engine = output.join("tofu");
        fs::write(&engine, &bytes)?;
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(output.join("plugins"))?;
        let config = output.join("tofurc");
        fs::write(
            &config,
            format!(
                "disable_checkpoint = true\nplugin_cache_dir = {}\nprovider_installation {{\n  direct {{}}\n}}\n",
                serde_json::to_string(&output.join("plugins"))?
            ),
        )?;
        let mut layouts = BTreeMap::new();
        let mut inputs = BTreeMap::new();
        let mut rendered = BTreeMap::new();
        for root in &request.roots {
            let directory = output.join(root.label.replace('/', "-"));
            fs::create_dir(&directory)?;
            let stack = directory.join("stack");
            for (path, bytes) in &stacks[&root.stack] {
                let target = stack.join(path);
                fs::create_dir_all(target.parent().context("stack file")?)?;
                fs::write(&target, bytes)?;
            }
            let mut committed = Vec::new();
            fs::File::open(instance.join(&root.inputs))?
                .take(1_048_577)
                .read_to_end(&mut committed)?;
            ensure!(committed.len() <= 1_048_576, "{} budget", root.inputs);
            let layout = Layout {
                config: config.clone(),
                stack,
                data: directory.join("data"),
                inputs: directory.join("inputs.tfvars"),
                rendered: directory.join("rendered.tfvars.json"),
                plan: directory.join("plan.bin"),
            };
            fs::write(&layout.inputs, &committed)?;
            fs::write(&layout.rendered, &root.variables)?;
            inputs.insert(root.label.clone(), day2::digest(&committed));
            rendered.insert(root.label.clone(), day2::digest(root.variables.as_bytes()));
            layouts.insert(root.label.clone(), layout);
        }
        let progress = request
            .roots
            .iter()
            .map(|root| (root.label.clone(), Progress::default()))
            .collect();
        let session = Self {
            request,
            instance,
            instance_commit,
            instance_clean,
            platform,
            stacks_tree,
            output,
            engine_digest,
            layouts,
            inputs,
            rendered,
            private: tempfile::Builder::new()
                .prefix("day2-instance-")
                .tempdir()?,
            kubeconfig: None,
            dns_token: None,
            credentials_read: false,
            progress,
        };
        let reported: Value = serde_json::from_slice(&capture(
            session.engine(&["version", "-json"])?,
            None,
            Duration::from_secs(60),
            65_536,
        )?)?;
        ensure!(
            reported["terraform_version"] == ENGINE_VERSION,
            "OpenTofu version mismatch"
        );
        Ok(session)
    }

    /// A command for the session's engine copy, admitted again by digest.
    fn engine(&self, args: &[&str]) -> Result<Command> {
        let engine = self.output.join("tofu");
        ensure!(
            day2::digest(&fs::read(&engine)?) == self.engine_digest,
            "pinned engine changed"
        );
        let mut command = self.tool(&engine);
        command
            .env("TF_CLI_CONFIG_FILE", self.output.join("tofurc"))
            .env("CHECKPOINT_DISABLE", "1")
            .args(args);
        Ok(command)
    }

    fn tool(&self, program: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .envs(ambient())
            .env("LANG", "C")
            .env("TMPDIR", "/tmp")
            .env("CLOUDSDK_CORE_PROJECT", &self.request.project)
            .env("USE_GKE_GCLOUD_AUTH_PLUGIN", "True")
            .current_dir(self.private.path());
        command
    }

    /// The roots in apply order, and which of them every later root reads.
    pub fn summary(&self) -> Value {
        json!({"roots": self.request.roots.iter().map(|root| json!({
            "label": root.label,
            "shared": SHARED.contains(&root.stack.as_str()),
        })).collect::<Vec<_>>()})
    }

    /// The cluster kubeconfig (from derived names) and the DNS token, read once.
    /// A failure is recorded against the roots that need it; the others run.
    pub fn credentials(&mut self) -> Result<Value> {
        ensure!(
            !self.credentials_read,
            "credentials are read once per session"
        );
        self.credentials_read = true;
        if self
            .request
            .roots
            .iter()
            .any(|root| needs_cluster(&root.stack))
        {
            let kubeconfig = self.private.path().join("kubeconfig");
            let fetched = crate::maintenance::on_path("gcloud").and_then(|gcloud| {
                let mut command = self.tool(&gcloud);
                command
                    .env("KUBECONFIG", &kubeconfig)
                    .args(["container", "clusters", "get-credentials"])
                    .arg(&self.request.cluster)
                    .args(["--zone", &self.request.zone])
                    .args(["--project", &self.request.project]);
                crate::process::run(
                    &mut command,
                    self.private.path(),
                    &self.output.join("credentials.log"),
                    Duration::from_secs(120),
                )
            });
            match fetched {
                Ok(()) => self.kubeconfig = Some(kubeconfig),
                Err(error) => fs::write(self.output.join("cluster.error"), format!("{error:#}"))?,
            }
        }
        if self.request.roots.iter().any(|root| needs_dns(&root.stack)) {
            let read = crate::maintenance::on_path("gcloud").and_then(|gcloud| {
                let mut command = self.tool(&gcloud);
                command
                    .args(["secrets", "versions", "access", "latest"])
                    .arg(format!("--secret={DNS_TOKEN_SECRET}"))
                    .arg(format!("--project={}", self.request.project));
                let token =
                    String::from_utf8(capture(command, None, Duration::from_secs(60), 4096)?)?;
                ensure!(!token.trim().is_empty(), "empty DNS token");
                Ok(token.trim().to_owned())
            });
            match read {
                Ok(token) => self.dns_token = Some(token),
                Err(error) => fs::write(
                    self.output.join("dns.error"),
                    format!("read the {DNS_TOKEN_SECRET} secret: {error:#}"),
                )?,
            }
        }
        Ok(json!({}))
    }

    /// Whether the root's state object exists, read without touching it. Listing
    /// the exact object needs only object read access: an empty listing is a root
    /// that has never been applied, and any error (a missing bucket, no access)
    /// fails the root instead of passing it off as new.
    fn state_exists(&self, root: &Root, directory: &Path) -> Result<bool> {
        let gcloud = crate::maintenance::on_path("gcloud")?;
        let object = format!("{}/default.tfstate", root.prefix);
        let mut command = self.tool(&gcloud);
        command
            .args(["storage", "objects", "list"])
            .arg(format!("gs://{}/{object}", root.bucket))
            .arg("--format=value(name)");
        let listed = capture(
            command,
            Some(&directory.join("state.log")),
            Duration::from_secs(60),
            1 << 20,
        )
        .with_context(|| format!("list {}'s state in {}", root.label, root.bucket))?;
        state_listed(&String::from_utf8(listed)?, &object)
    }

    fn run_stage(&self, stage: Stage, root: &Root, local_state: bool) -> Result<Option<Vec<u8>>> {
        let directory = self.output.join(root.label.replace('/', "-"));
        let layout = &self.layouts[&root.label];
        let log = directory.join(format!("{}.log", stage.name()));
        let (args, env) = invocation(
            self.request.mode,
            stage,
            root,
            layout,
            local_state,
            &Credentials {
                kubeconfig: self.kubeconfig.as_deref(),
                dns_token: self.dns_token.as_deref(),
            },
        );
        let mut command = self.engine(&[])?;
        command.args(args).envs(env);
        if stage == Stage::Show {
            return Ok(Some(capture(
                command,
                Some(&log),
                Duration::from_secs(300),
                SHOW_LIMIT,
            )?));
        }
        // Creating a cluster takes most of an hour; a plan or init never should.
        let deadline = if stage == Stage::Apply { 3600 } else { 900 };
        crate::process::run(
            &mut command,
            &directory,
            &log,
            Duration::from_secs(deadline),
        )?;
        Ok(None)
    }

    /// One engine operation of one root: init, then plan, then show, then, in an
    /// apply session, apply. A failed operation is recorded for the receipt and
    /// stops that root; `admit` keeps later roots from running after a shared one.
    pub fn operation(&mut self, label: &str, name: &str) -> Result<Value> {
        ensure!(self.credentials_read, "credentials come before any root");
        let stage = Stage::parse(name)?;
        admit(
            self.request.mode,
            &self.request.roots,
            &self.progress,
            label,
            stage,
        )?;
        let root = self
            .request
            .roots
            .iter()
            .find(|root| root.label == label)
            .context("unknown root")?
            .clone();
        let progress = self.progress.get(label).context("unknown root")?;
        let mut new_root = progress.new_root;
        let (planned, destroys) = (progress.changes.is_empty(), progress.destroys.clone());
        let directory = self.output.join(label.replace('/', "-"));
        let missing = (needs_cluster(&root.stack) && self.kubeconfig.is_none())
            || (needs_dns(&root.stack) && self.dns_token.is_none());
        let outcome = if stage == Stage::Init && missing {
            Err(Failure::Credentials)
        } else if stage == Stage::Apply && planned {
            // Nothing to change: the root is complete without running the engine.
            Ok(None)
        } else if stage == Stage::Apply && !destroys.is_empty() {
            let _ = fs::write(
                directory.join("apply.error"),
                format!(
                    "the plan deletes, replaces or forgets {}; instance apply never does",
                    destroys.join(", ")
                ),
            );
            Err(Failure::Destroys)
        } else {
            (|| -> Result<Option<Vec<u8>>> {
                if stage == Stage::Init {
                    new_root = !self.state_exists(&root, &directory)?;
                    if self.request.mode == Mode::Plan && new_root {
                        // Plan against an empty local state: nothing is created remotely.
                        // An apply initializes the real backend, so its apply creates the state.
                        fs::write(
                            self.layouts[label].stack.join("backend_override.tf"),
                            backend_override(&directory.join("new.tfstate"))?,
                        )?;
                    }
                }
                self.run_stage(stage, &root, self.request.mode == Mode::Plan && new_root)
            })()
            .map_err(|error| {
                let _ = fs::write(
                    directory.join(format!("{name}.error")),
                    format!("{error:#}"),
                );
                Failure::Stage(stage)
            })
        };
        let outcome = outcome.and_then(|shown| match shown {
            Some(shown) => {
                fs::write(directory.join("show.json"), &shown)
                    .map_err(|_| Failure::Stage(stage))?;
                changes(&shown)
                    .and_then(|found| Ok((found, destructive(&shown)?)))
                    .map(Some)
                    .map_err(|error| {
                        let _ = fs::write(directory.join("show.error"), format!("{error:#}"));
                        Failure::Stage(stage)
                    })
            }
            None => Ok(None),
        });
        let progress = self.progress.get_mut(label).context("unknown root")?;
        progress.new_root = new_root;
        match outcome {
            Err(failure) => {
                progress.failed = Some(failure);
                Ok(json!({"ok": false}))
            }
            Ok(found) => {
                if let Some((found, destroys)) = found {
                    progress.changes = found;
                    progress.destroys = destroys;
                }
                progress.done.insert(stage);
                Ok(json!({"ok": true}))
            }
        }
    }

    pub fn receipt(&self) -> Result<Value> {
        audit(&self.output, &self.layouts)?;
        let mode = self.request.mode;
        let mut roots = Vec::new();
        let mut ok = true;
        // In an apply, the roots after a failed shared root never run.
        let mut stopped = false;
        for root in &self.request.roots {
            let progress = &self.progress[&root.label];
            let status = match progress.failed {
                Some(failure) => status(failure),
                None if stopped && progress.done.is_empty() => "skipped",
                None => {
                    let last = match mode {
                        Mode::Plan => Stage::Show,
                        Mode::Apply => Stage::Apply,
                    };
                    ensure!(
                        progress.done.contains(&last),
                        "{} did not finish its {}",
                        root.label,
                        mode.name()
                    );
                    match (mode, progress.changes.is_empty()) {
                        (_, true) => "no_changes",
                        (Mode::Plan, false) => "changes",
                        (Mode::Apply, false) => "applied",
                    }
                }
            };
            ok &= progress.failed.is_none();
            stopped |= mode == Mode::Apply
                && progress.failed.is_some()
                && SHARED.contains(&root.stack.as_str());
            let directory = self.output.join(root.label.replace('/', "-"));
            let digest = |name: &str| -> Result<String> {
                let path = directory.join(name);
                Ok(if path.is_file() {
                    day2::digest(&fs::read(path)?)
                } else {
                    String::new()
                })
            };
            roots.push(json!({
                "label": root.label,
                "stack": root.stack,
                "backend": {"bucket": root.bucket, "prefix": root.prefix},
                "new_root": progress.new_root,
                "inputs": {"path": root.inputs, "digest": self.inputs[&root.label]},
                "variables": self.rendered[&root.label],
                "status": status,
                "changes": progress.changes,
                "plan_digest": digest("plan.bin")?,
                "show_digest": digest("show.json")?,
                "logs": directory,
            }));
        }
        let receipt = json!({
            "format": 1,
            "mode": mode.name(),
            "ok": ok,
            "commit": self.request.commit,
            "stacks_tree": self.stacks_tree,
            "checkout": self.platform,
            "instance": self.instance,
            "instance_commit": self.instance_commit,
            "instance_clean": self.instance_clean,
            "engine": {"version": ENGINE_VERSION, "digest": self.engine_digest},
            "roots": roots,
            "directory": self.output,
        });
        fs::write(
            self.output.join("receipt.json"),
            serde_json::to_vec_pretty(&receipt)?,
        )?;
        Ok(receipt)
    }
}

/// A failed root's receipt status.
fn status(failure: Failure) -> &'static str {
    match failure {
        Failure::Credentials => "failed_credentials",
        Failure::Stage(Stage::Init) => "failed_init",
        Failure::Stage(Stage::Plan) => "failed_plan",
        Failure::Stage(Stage::Show) => "failed_show",
        Failure::Stage(Stage::Apply) => "failed_apply",
        Failure::Destroys => "refused_destroy",
    }
}

/// The output holds only the session's own files: no kubeconfig, auth-plugin
/// cache or other credential material may appear in it.
fn audit(output: &Path, layouts: &BTreeMap<String, Layout>) -> Result<()> {
    let roots: BTreeSet<String> = layouts
        .keys()
        .map(|label| label.replace('/', "-"))
        .collect();
    for entry in fs::read_dir(output)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        ensure!(
            [
                "tofu",
                "tofurc",
                "plugins",
                "credentials.log",
                "cluster.error",
                "dns.error"
            ]
            .contains(&name.as_str())
                || roots.contains(&name),
            "unexpected {name} in the instance output"
        );
    }
    let mut pending = vec![output.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            ensure!(
                !name.contains("kubeconfig") && !name.contains("gcloud_auth_plugin"),
                "credential material {name} in the instance output"
            );
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

/// What a saved plan would change, from `tofu show -json`: resource actions other
/// than no-op and read, pending moves, imports and output changes.
pub fn changes(shown: &[u8]) -> Result<Vec<Value>> {
    let plan: Value = serde_json::from_slice(shown).context("plan JSON")?;
    ensure!(
        plan["format_version"]
            .as_str()
            .is_some_and(|version| version.starts_with("1.")),
        "unsupported plan format"
    );
    let resources = plan["resource_changes"]
        .as_array()
        .context("plan has no resource changes")?;
    let mut found = Vec::new();
    for change in resources {
        let actions = change["change"]["actions"]
            .as_array()
            .context("plan actions")?;
        let mut names: Vec<&str> = actions.iter().filter_map(Value::as_str).collect();
        ensure!(
            names.len() == actions.len() && !names.is_empty(),
            "plan actions"
        );
        let address = change["address"].as_str().context("plan address")?;
        let moved = change["previous_address"].as_str();
        let imported = !change["change"]["importing"].is_null();
        if names == ["no-op"] || names == ["read"] {
            names.clear();
        }
        if imported {
            names.push("import");
        }
        if let Some(from) = moved {
            names.push("move");
            found.push(json!({"address": format!("{address} (from {from})"), "actions": names}));
        } else if !names.is_empty() {
            found.push(json!({"address": address, "actions": names}));
        }
    }
    if let Some(outputs) = plan["output_changes"].as_object() {
        for (name, change) in outputs {
            let actions: Vec<&str> = change["actions"]
                .as_array()
                .context("output actions")?
                .iter()
                .filter_map(Value::as_str)
                .collect();
            if actions != ["no-op"] {
                found.push(json!({"address": format!("output.{name}"), "actions": actions}));
            }
        }
    }
    Ok(found)
}

/// The resources a saved plan would delete (a replacement included) or forget,
/// from `tofu show -json`. `day2 instance apply` refuses such a plan; output
/// removals are not resources and never count.
pub fn destructive(shown: &[u8]) -> Result<Vec<String>> {
    let plan: Value = serde_json::from_slice(shown).context("plan JSON")?;
    let mut found = Vec::new();
    for change in plan["resource_changes"]
        .as_array()
        .context("plan has no resource changes")?
    {
        let actions = change["change"]["actions"]
            .as_array()
            .context("plan actions")?;
        if actions
            .iter()
            .any(|action| matches!(action.as_str(), Some("delete" | "forget")))
        {
            found.push(
                change["address"]
                    .as_str()
                    .context("plan address")?
                    .to_owned(),
            );
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            mode: Mode::Plan,
            instance: "instance".into(),
            checkout: "platform".into(),
            output: "plan".into(),
            commit: "9724058033abd6342e118cff56fc3cae7e424a2d".into(),
            project: "exampleco-tools".into(),
            zone: "us-central1-a".into(),
            cluster: "day2".into(),
            roots: vec![
                Root {
                    label: "project".into(),
                    stack: "project".into(),
                    app_id: None,
                    bucket: "exampleco-tools-tofu-state".into(),
                    prefix: "foundation".into(),
                    inputs: "gcp/config/project.tfvars".into(),
                    variables: r#"{"project_id":"exampleco-tools"}"#.into(),
                },
                Root {
                    label: "app-edge/home".into(),
                    stack: "app-edge".into(),
                    app_id: Some("home".into()),
                    bucket: "exampleco-tools-tofu-state".into(),
                    prefix: "platform/app/home".into(),
                    inputs: "gcp/config/app-edge/home.tfvars".into(),
                    variables: r#"{"app_id":"home"}"#.into(),
                },
            ],
            renderer: RENDERER
                .iter()
                .map(|(path, bytes)| Source {
                    path: (*path).to_owned(),
                    text: String::from_utf8(bytes.to_vec()).unwrap(),
                })
                .collect(),
        }
    }

    /// A scratch repository; returns its path and the commit of `files`.
    fn repository(scratch: &Path, files: &[(&str, &[u8])]) -> (PathBuf, String) {
        let root = scratch.join("repo");
        fs::create_dir_all(&root).unwrap();
        let git = |args: &[&str]| {
            let output = Command::new(GIT)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/nonexistent")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.com")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.com")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}: {output:?}");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        git(&["init", "-q"]);
        for (path, bytes) in files {
            let target = root.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, bytes).unwrap();
        }
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "files"]);
        let commit = git(&["rev-parse", "HEAD"]);
        (root, commit)
    }

    fn renderer_files() -> Vec<(&'static str, &'static [u8])> {
        RENDERER.to_vec()
    }

    fn layout() -> Layout {
        Layout {
            config: "/out/tofurc".into(),
            stack: "/out/root/stack".into(),
            data: "/out/root/data".into(),
            inputs: "/out/root/inputs.tfvars".into(),
            rendered: "/out/root/rendered.tfvars.json".into(),
            plan: "/out/root/plan.bin".into(),
        }
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn accepts_core_roots_with_their_fixed_shapes() {
        validate(&request()).unwrap();
    }

    #[test]
    fn rejects_everything_outside_the_core_roots_and_fixed_inputs() {
        let cases: [fn(&mut Request); 15] = [
            |r| r.roots[0].stack = "day2-app".into(),
            |r| r.roots[0].stack = "security-shell".into(),
            |r| r.roots[0].label = "cluster".into(),
            |r| r.roots[1].app_id = None,
            |r| r.roots[0].app_id = Some("home".into()),
            |r| r.roots[1].label = "app-edge/go".into(),
            |r| r.roots[1].inputs = "gcp/config/apps/home.tfvars".into(),
            |r| r.roots[1].inputs = "gcp/config/../../etc/passwd.tfvars".into(),
            |r| r.roots[0].inputs = "gcp/config/cluster.tfvars".into(),
            |r| r.roots[0].variables = "[]".into(),
            |r| r.roots[0].prefix = "foundation/".into(),
            |r| r.commit = "9724058".into(),
            |r| r.zone = "-us-central1-a".into(),
            |r| r.cluster = "-day2".into(),
            |r| r.roots.push(r.roots[0].clone()),
        ];
        for (index, edit) in cases.iter().enumerate() {
            let mut request = request();
            edit(&mut request);
            assert!(validate(&request).is_err(), "case {index}");
        }
    }

    #[test]
    fn plans_never_lock_or_change_providers_and_rendered_variables_win() {
        let request = request();
        let (project, edge) = (&request.roots[0], &request.roots[1]);
        let credentials = Credentials {
            kubeconfig: Some(Path::new("/private/kubeconfig")),
            dns_token: Some("token"),
        };
        let (init, env) = invocation(
            Mode::Plan,
            Stage::Init,
            edge,
            &layout(),
            false,
            &credentials,
        );
        assert_eq!(
            strings(&init),
            [
                "-chdir=/out/root/stack",
                "init",
                "-input=false",
                "-no-color",
                "-reconfigure",
                "-lockfile=readonly",
                "-backend-config=bucket=exampleco-tools-tofu-state",
                "-backend-config=prefix=platform/app/home",
            ]
        );
        // Init never sees cluster or DNS credentials; every stage gets the
        // private configuration and its own data directory.
        let names: Vec<&str> = env.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "TF_CLI_CONFIG_FILE",
                "TF_DATA_DIR",
                "TF_IN_AUTOMATION",
                "TF_INPUT",
                "CHECKPOINT_DISABLE"
            ]
        );
        assert_eq!(env[0].1, OsString::from("/out/tofurc"));
        assert_eq!(env[1].1, OsString::from("/out/root/data"));
        let (new_init, _) =
            invocation(Mode::Plan, Stage::Init, edge, &layout(), true, &credentials);
        assert!(
            !strings(&new_init)
                .iter()
                .any(|arg| arg.starts_with("-backend-config"))
        );
        let (plan, env) = invocation(
            Mode::Plan,
            Stage::Plan,
            edge,
            &layout(),
            false,
            &credentials,
        );
        assert_eq!(
            strings(&plan),
            [
                "-chdir=/out/root/stack",
                "plan",
                "-input=false",
                "-no-color",
                "-lock=false",
                "-var-file=/out/root/inputs.tfvars",
                "-var-file=/out/root/rendered.tfvars.json",
                "-out=/out/root/plan.bin",
                "-var=kubeconfig_path=/private/kubeconfig",
            ]
        );
        let names: Vec<&str> = env.iter().map(|(name, _)| *name).collect();
        assert!(names.contains(&"KUBECONFIG") && names.contains(&"CLOUDFLARE_API_TOKEN"));
        // The project root plans with neither the kubeconfig nor the DNS token.
        let (args, env) = invocation(
            Mode::Plan,
            Stage::Plan,
            project,
            &layout(),
            false,
            &credentials,
        );
        assert!(!strings(&args).iter().any(|arg| arg.starts_with("-var=")));
        assert!(env.iter().all(|(name, _)| {
            !["KUBECONFIG", "KUBE_CONFIG_PATH", "CLOUDFLARE_API_TOKEN"].contains(name)
        }));
        let (show, env) = invocation(
            Mode::Plan,
            Stage::Show,
            edge,
            &layout(),
            false,
            &credentials,
        );
        assert_eq!(
            strings(&show),
            [
                "-chdir=/out/root/stack",
                "show",
                "-json",
                "-no-color",
                "/out/root/plan.bin"
            ]
        );
        assert!(env.iter().all(|(name, _)| *name != "CLOUDFLARE_API_TOKEN"));
        // Ambient OpenTofu configuration never passes through.
        assert!(
            !PASSED.contains(&"TF_CLI_CONFIG_FILE") && !PASSED.contains(&"TF_PLUGIN_CACHE_DIR")
        );
    }

    #[test]
    fn changes_count_actions_moves_imports_and_outputs() {
        let shown = json!({"format_version": "1.2", "resource_changes": [
            {"address": "google_project_service.a", "change": {"actions": ["no-op"]}},
            {"address": "data.google_client_config.c", "change": {"actions": ["read"]}},
            {"address": "google_storage_bucket.b", "change": {"actions": ["update"]}},
            {"address": "google_compute_address.d", "change": {"actions": ["delete", "create"]}},
            {"address": "google_dns.new", "previous_address": "google_dns.old", "change": {"actions": ["no-op"]}},
            {"address": "google_sa.x", "change": {"actions": ["no-op"], "importing": {"id": "x"}}},
        ], "output_changes": {"same": {"actions": ["no-op"]}, "url": {"actions": ["update"]}}});
        assert_eq!(
            changes(&serde_json::to_vec(&shown).unwrap()).unwrap(),
            vec![
                json!({"address": "google_storage_bucket.b", "actions": ["update"]}),
                json!({"address": "google_compute_address.d", "actions": ["delete", "create"]}),
                json!({"address": "google_dns.new (from google_dns.old)", "actions": ["move"]}),
                json!({"address": "google_sa.x", "actions": ["import"]}),
                json!({"address": "output.url", "actions": ["update"]}),
            ]
        );
        let empty = json!({"format_version": "1.2", "resource_changes": []});
        assert!(
            changes(&serde_json::to_vec(&empty).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(changes(br#"{"resource_changes":[]}"#).is_err());
        assert!(changes(br#"{"format_version":"1.2"}"#).is_err());
        assert!(
            changes(
                br#"{"format_version":"1.2","resource_changes":[{"address":"x","change":{"actions":[]}}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn stacks_are_read_as_git_objects_never_through_local_rewrites() {
        let scratch = tempfile::tempdir().unwrap();
        let (root, commit) = repository(
            scratch.path(),
            &[
                ("deploy/gke/stacks/app-edge/main.tf", b"original main"),
                ("deploy/gke/stacks/app-edge/variables.tf", b"variables"),
                ("deploy/gke/stacks/app-edge-x/main.tf", b"look-alike"),
            ],
        );
        let read = || {
            tree_files(&root, &commit, "deploy/gke/stacks/app-edge")
                .unwrap()
                .into_iter()
                .map(|(path, bytes)| {
                    (
                        path.display().to_string(),
                        String::from_utf8(bytes).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let expected = vec![
            ("main.tf".to_owned(), "original main".to_owned()),
            ("variables.tf".to_owned(), "variables".to_owned()),
        ];
        assert_eq!(read(), expected);
        // A replace ref, a smudge filter with its attribute, and an export-ignore rule
        // change nothing: the bytes come from the commit's objects.
        let git = |args: &[&str]| {
            let output = Command::new(GIT)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{args:?}: {output:?}");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let original = git(&[
            "rev-parse",
            &format!("{commit}:deploy/gke/stacks/app-edge/main.tf"),
        ]);
        fs::write(scratch.path().join("forged"), "forged main").unwrap();
        let forged = git(&[
            "hash-object",
            "-w",
            scratch.path().join("forged").to_str().unwrap(),
        ]);
        git(&["replace", &original, &forged]);
        fs::write(
            root.join(".git/info/attributes"),
            "*.tf filter=rewrite\nvariables.tf export-ignore\n",
        )
        .unwrap();
        git(&["config", "filter.rewrite.smudge", "echo rewritten"]);
        assert_eq!(read(), expected);
        // Links are refused.
        let (linked, commit) = {
            let scratch = tempfile::tempdir().unwrap();
            let (root, _) = repository(
                scratch.path(),
                &[("deploy/gke/stacks/project/main.tf", b"main")],
            );
            std::os::unix::fs::symlink("main.tf", root.join("deploy/gke/stacks/project/link.tf"))
                .unwrap();
            let add = |args: &[&str]| {
                Command::new(GIT)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("GIT_AUTHOR_NAME", "t")
                    .env("GIT_AUTHOR_EMAIL", "t@example.com")
                    .env("GIT_COMMITTER_NAME", "t")
                    .env("GIT_COMMITTER_EMAIL", "t@example.com")
                    .arg("-C")
                    .arg(&root)
                    .args(args)
                    .output()
                    .unwrap()
            };
            add(&["add", "-A"]);
            add(&["commit", "-q", "-m", "link"]);
            let head = String::from_utf8(add(&["rev-parse", "HEAD"]).stdout).unwrap();
            (
                tree_files(&root, head.trim(), "deploy/gke/stacks/project").is_err(),
                scratch,
            )
        };
        assert!(linked);
        drop(commit);
    }

    #[test]
    fn the_cli_host_and_platform_commit_must_share_rendering_sources() {
        let scratch = tempfile::tempdir().unwrap();
        let (root, commit) = repository(scratch.path(), &renderer_files());
        let sent = request().renderer;
        renderer_matches(&root, &commit, &sent).unwrap();
        // A CLI built from other sources than its host.
        let mut other = sent.clone();
        other[0].text.push('\n');
        let error = renderer_matches(&root, &commit, &other).unwrap_err();
        assert!(
            format!("{error:#}").contains("different rendering sources"),
            "{error:#}"
        );
        // A commit with other rules, and one from before instance plan.
        let changed: Vec<(&str, &[u8])> = renderer_files()
            .into_iter()
            .map(|(path, bytes)| {
                (
                    path,
                    if path.ends_with("Names.roc") {
                        b"other".as_slice()
                    } else {
                        bytes
                    },
                )
            })
            .collect();
        let scratch = tempfile::tempdir().unwrap();
        let (root, commit) = repository(scratch.path(), &changed);
        let error = renderer_matches(&root, &commit, &sent).unwrap_err();
        assert!(
            format!("{error:#}").contains("from another commit"),
            "{error:#}"
        );
        let scratch = tempfile::tempdir().unwrap();
        let (root, commit) = repository(scratch.path(), &[("README.md", b"old")]);
        let error = renderer_matches(&root, &commit, &sent).unwrap_err();
        assert!(
            format!("{error:#}").contains("predates instance plan"),
            "{error:#}"
        );
    }

    #[test]
    fn only_an_empty_listing_of_this_object_makes_a_new_root() {
        let object = "platform/app/home/default.tfstate";
        assert!(!state_listed("", object).unwrap());
        assert!(!state_listed("\n", object).unwrap());
        // One name per retained version.
        assert!(state_listed(&format!("{object}\n{object}\n"), object).unwrap());
        assert!(state_listed("platform/app/home/default.tfstate.backup\n", object).is_err());
        assert!(
            state_listed(
                &format!("{object}\nplatform/app/go/default.tfstate\n"),
                object
            )
            .is_err()
        );
        assert_eq!(
            backend_override(Path::new("/out/root/new.tfstate")).unwrap(),
            "terraform {\n  backend \"local\" {\n    path = \"/out/root/new.tfstate\"\n  }\n}\n"
        );
    }

    #[test]
    fn the_output_audit_refuses_credential_material() {
        let scratch = tempfile::tempdir().unwrap();
        let mut layouts = BTreeMap::new();
        layouts.insert("app-edge/home".to_owned(), layout());
        fs::create_dir(scratch.path().join("app-edge-home")).unwrap();
        fs::write(scratch.path().join("tofurc"), "").unwrap();
        audit(scratch.path(), &layouts).unwrap();
        fs::write(
            scratch
                .path()
                .join("app-edge-home/gke_gcloud_auth_plugin_cache"),
            "",
        )
        .unwrap();
        assert!(audit(scratch.path(), &layouts).is_err());
        fs::remove_file(
            scratch
                .path()
                .join("app-edge-home/gke_gcloud_auth_plugin_cache"),
        )
        .unwrap();
        fs::write(scratch.path().join("kubeconfig"), "").unwrap();
        assert!(audit(scratch.path(), &layouts).is_err());
    }

    #[test]
    fn prepare_refuses_without_writing_anything() {
        let scratch = tempfile::tempdir().unwrap();
        let instance = scratch.path().join("instance");
        fs::create_dir_all(instance.join("gcp/config/app-edge")).unwrap();
        fs::write(instance.join("gcp/config/project.tfvars"), "").unwrap();
        fs::write(instance.join("gcp/config/app-edge/home.tfvars"), "").unwrap();
        let platform = scratch.path().join("platform");
        fs::create_dir(&platform).unwrap();
        let write = |request: &Request| {
            let path = scratch.path().join("request.json");
            fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
            path
        };
        let mut request = request();
        request.instance = instance.clone();
        request.checkout = platform.clone();
        request.output = scratch.path().join("plan");
        // A request for another mode than the host started is refused first.
        let error = Session::prepare(&write(&request), Mode::Apply)
            .err()
            .unwrap();
        assert!(
            format!("{error:#}")
                .contains("started an instance apply but the request is for an instance plan"),
            "{error:#}"
        );
        assert!(!scratch.path().join("plan").exists());
        // Not a git checkout.
        assert!(Session::prepare(&write(&request), Mode::Plan).is_err());
        assert!(!scratch.path().join("plan").exists());
        // An output directory inside the instance or the checkout.
        for inside in [instance.join("plan"), platform.join("plan")] {
            request.output = inside.clone();
            let error = Session::prepare(&write(&request), Mode::Plan)
                .err()
                .unwrap();
            assert!(
                format!("{error:#}").contains("outside the instance"),
                "{error:#}"
            );
            assert!(!inside.exists());
        }
        // An instance OAuth workload input fails closed, even as a dangling link.
        request.output = scratch.path().join("plan");
        std::os::unix::fs::symlink("missing", instance.join("gcp/config/oauth-workloads.json"))
            .unwrap();
        let error = Session::prepare(&write(&request), Mode::Plan)
            .err()
            .unwrap();
        assert!(
            format!("{error:#}").contains("oauth-workloads.json"),
            "{error:#}"
        );
    }

    #[test]
    fn applies_lock_state_and_apply_exactly_the_saved_plan() {
        let request = request();
        let (project, edge) = (&request.roots[0], &request.roots[1]);
        let credentials = Credentials {
            kubeconfig: Some(Path::new("/private/kubeconfig")),
            dns_token: Some("token"),
        };
        // An apply session's init always uses the real backend: apply creates state.
        let (init, _) = invocation(
            Mode::Apply,
            Stage::Init,
            edge,
            &layout(),
            false,
            &credentials,
        );
        assert!(strings(&init).contains(&"-backend-config=prefix=platform/app/home".to_owned()));
        let (plan, _) = invocation(
            Mode::Apply,
            Stage::Plan,
            edge,
            &layout(),
            false,
            &credentials,
        );
        let plan = strings(&plan);
        assert!(plan.contains(&"-lock-timeout=300s".to_owned()));
        assert!(!plan.iter().any(|arg| arg.starts_with("-lock=")));
        let (apply, env) = invocation(
            Mode::Apply,
            Stage::Apply,
            edge,
            &layout(),
            false,
            &credentials,
        );
        assert_eq!(
            strings(&apply),
            [
                "-chdir=/out/root/stack",
                "apply",
                "-input=false",
                "-no-color",
                "-lock-timeout=300s",
                "/out/root/plan.bin",
            ]
        );
        let names: Vec<&str> = env.iter().map(|(name, _)| *name).collect();
        assert!(
            names.contains(&"KUBECONFIG")
                && names.contains(&"KUBE_CONFIG_PATH")
                && names.contains(&"CLOUDFLARE_API_TOKEN")
        );
        // The project root applies with neither the kubeconfig nor the DNS token.
        let (_, env) = invocation(
            Mode::Apply,
            Stage::Apply,
            project,
            &layout(),
            false,
            &credentials,
        );
        assert!(env.iter().all(|(name, _)| {
            !["KUBECONFIG", "KUBE_CONFIG_PATH", "CLOUDFLARE_API_TOKEN"].contains(name)
        }));
    }

    #[test]
    fn destructive_finds_deletes_replacements_and_forgets_but_not_outputs() {
        let shown = json!({"format_version": "1.2", "resource_changes": [
            {"address": "google_storage_bucket.b", "change": {"actions": ["update"]}},
            {"address": "google_compute_address.d", "change": {"actions": ["delete", "create"]}},
            {"address": "google_compute_address.e", "change": {"actions": ["create", "delete"]}},
            {"address": "google_sa.gone", "change": {"actions": ["delete"]}},
            {"address": "google_sa.kept", "change": {"actions": ["forget"]}},
            {"address": "google_sa.new", "change": {"actions": ["create"]}},
        ], "output_changes": {"url": {"actions": ["delete"]}}});
        assert_eq!(
            destructive(&serde_json::to_vec(&shown).unwrap()).unwrap(),
            [
                "google_compute_address.d",
                "google_compute_address.e",
                "google_sa.gone",
                "google_sa.kept",
            ]
        );
        let additive = json!({"format_version": "1.2", "resource_changes": [
            {"address": "google_sa.new", "change": {"actions": ["create"]}},
        ], "output_changes": {"url": {"actions": ["delete"]}}});
        assert!(
            destructive(&serde_json::to_vec(&additive).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(destructive(br#"{"format_version":"1.2"}"#).is_err());
    }

    #[test]
    fn stages_run_in_order_and_an_apply_waits_for_every_shared_root() {
        let roots = request().roots;
        let fresh = || -> BTreeMap<String, Progress> {
            roots
                .iter()
                .map(|root| (root.label.clone(), Progress::default()))
                .collect()
        };
        let finish = |progress: &mut BTreeMap<String, Progress>, label: &str, stages: &[Stage]| {
            progress
                .get_mut(label)
                .unwrap()
                .done
                .extend(stages.iter().copied());
        };
        let refused = |mode, progress: &BTreeMap<String, Progress>, label, stage| {
            format!(
                "{:#}",
                admit(mode, &roots, progress, label, stage).unwrap_err()
            )
        };
        let mut progress = fresh();
        assert!(
            refused(Mode::Plan, &progress, "project", Stage::Plan)
                .contains("plan needs init first")
        );
        finish(
            &mut progress,
            "project",
            &[Stage::Init, Stage::Plan, Stage::Show],
        );
        assert!(refused(Mode::Plan, &progress, "project", Stage::Show).contains("duplicate show"));
        // A plan session never applies, even after show.
        assert!(refused(Mode::Plan, &progress, "project", Stage::Apply).contains("never applies"));
        // A plan runs every root regardless of the others.
        admit(Mode::Plan, &roots, &fresh(), "app-edge/home", Stage::Init).unwrap();
        // An apply runs an app edge only once the shared root before it has applied.
        assert!(
            refused(Mode::Apply, &progress, "app-edge/home", Stage::Init)
                .contains("runs only after project has applied")
        );
        admit(Mode::Apply, &roots, &progress, "project", Stage::Apply).unwrap();
        finish(&mut progress, "project", &[Stage::Apply]);
        admit(Mode::Apply, &roots, &progress, "app-edge/home", Stage::Init).unwrap();
        // A failed shared root stops every later root.
        let mut failed = fresh();
        failed.get_mut("project").unwrap().failed = Some(Failure::Destroys);
        assert!(
            refused(Mode::Apply, &failed, "app-edge/home", Stage::Init).contains("runs only after")
        );
        assert!(refused(Mode::Apply, &failed, "project", Stage::Init).contains("already failed"));
        assert_eq!(status(Failure::Destroys), "refused_destroy");
        assert_eq!(status(Failure::Stage(Stage::Apply)), "failed_apply");
    }
}
