//! OpenTofu runs of an instance's core roots, for `day2 instance plan` and
//! `day2 instance apply`, and of one app's day2-app root for `day2 instance
//! deploy`. The CLI renders each root's backend and variables from day2.json and
//! InstanceRoots.roc chooses the step order; this adapter independently
//! validates the request and every engine operation.
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
//!   and it runs no root until every shared root before it has applied, nor an
//!   app's day2-app root until that app's edge has.
//! - Release inputs: a day2-app root's image, artifact and native admission come
//!   from the app's durable selection, read and checked in-process
//!   (`release`), and win over every other input. An app with no selection is
//!   `unreleased` and not run; nothing falls back to a committed image.
//! - Selected deploys: a deploy session runs one day2-app root for an explicit
//!   candidate. It may render the instance ConfigMap with a targeted, unlocked
//!   plan that is never applied, and applies only once the app's selection names
//!   exactly that candidate, under its own shorter deadlines.
//! - App CI's forge IDs: with `forge.oidc`, the project root and each app edge
//!   are pinned to their repositories' native IDs, read from the forge once per
//!   session (`app_ci`); a root whose repository cannot be read fails alone.
//! - Secrets stay out of the output: the DNS token is held in memory and passed
//!   to app-edge plans and applies only; the kubeconfig and its auth-plugin cache
//!   live in a private temporary directory removed with the session; the forge
//!   token is held in memory and sent only to the forge; the receipt step
//!   refuses unexpected files in the output.
pub mod app_ci;
pub mod release;

use crate::instance_candidate::record;
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

/// The core stacks a session may run.
pub const STACKS: [&str; 5] = ["project", "cluster", "tenancy", "app-edge", "day2-app"];

/// The stack whose image and artifact inputs come from the app's release selection.
pub const DAY2_APP: &str = "day2-app";

/// The one resource a deploy's targeted render plans: the instance ConfigMap, whose `instance.json` is the target of
/// `day2 platform maintain activate`. The stack's release admission is not in its dependency graph, so it renders
/// while an activation is pending.
pub const TARGET: &str = "kubernetes_config_map_v1.instance";

/// The stacks every later root reads. An apply runs no root until each shared
/// root before it has applied, so one failure stops the rest; an app edge reads
/// only these, so its failure never stops another app's.
pub const SHARED: [&str; 3] = ["project", "cluster", "tenancy"];

/// How long a plan or apply waits for another holder of a root's state lock.
const LOCK_TIMEOUT: &str = "-lock-timeout=300s";

/// How long an engine step may run before it is interrupted, and how long an interrupted step that holds the state
/// lock gets to save state and release it before it is killed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline {
    pub run: Duration,
    pub grace: Duration,
}

/// `instance plan` and `apply`: a plan 15 minutes, an apply two hours (creating a cluster can take most of an hour),
/// then 30 minutes' grace.
pub const ROOTS_PLAN: Deadline = Deadline {
    run: Duration::from_secs(900),
    grace: Duration::from_secs(1800),
};
pub const ROOTS_APPLY: Deadline = Deadline {
    run: Duration::from_secs(7200),
    grace: Duration::from_secs(1800),
};

/// A deploy's one day2-app root, applied while the app is stopped and within its job's budget: a plan 10 minutes, an
/// apply 15 minutes, then one minute's grace. The lock wait is `LOCK_TIMEOUT`, as for every root.
pub const DEPLOY_PLAN: Deadline = Deadline {
    run: Duration::from_secs(600),
    grace: Duration::from_secs(60),
};
pub const DEPLOY_APPLY: Deadline = Deadline {
    run: Duration::from_secs(900),
    grace: Duration::from_secs(60),
};
pub const DEPLOY_SHOW: Duration = Duration::from_secs(60);

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
/// `day2 instance apply` applies each root's saved plan as reviewed; a deploy
/// applies one app's day2-app root for the candidate its selection names.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Plan,
    Apply,
    Deploy,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::Deploy => "deploy",
        }
    }

    /// Whether the session takes state locks and applies.
    fn applies(self) -> bool {
        self != Self::Plan
    }

    /// The deadline of a locked engine step.
    pub fn deadline(self, stage: Stage) -> Deadline {
        match (self, stage) {
            (Self::Deploy, Stage::Apply) => DEPLOY_APPLY,
            (Self::Deploy, _) => DEPLOY_PLAN,
            (_, Stage::Apply) => ROOTS_APPLY,
            _ => ROOTS_PLAN,
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
    /// An apply's reviewed plan: a prior `instance plan` output directory. Each
    /// root applies only a plan whose changes equal the ones reviewed there.
    pub reviewed: Option<PathBuf>,
    /// Where releases are kept and admitted, for the day2-app roots.
    pub releases: Option<release::Releases>,
    /// A deploy's candidate record file: what its root renders and applies.
    pub candidate: Option<PathBuf>,
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
    /// With `forge.oidc`, the forge repository whose IDs this project or
    /// app-edge root's app CI variable is pinned to (`app_ci`).
    pub app_ci_repository: Option<String>,
}

/// One operation on one root. A day2-app root reads its release first; a deploy may render its target after init,
/// and checks its selection before it plans.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Release,
    Init,
    Target,
    Selected,
    Plan,
    Show,
    Apply,
}

impl Stage {
    fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "release" => Self::Release,
            "init" => Self::Init,
            "target" => Self::Target,
            "selected" => Self::Selected,
            "plan" => Self::Plan,
            "show" => Self::Show,
            "apply" => Self::Apply,
            _ => bail!("unknown instance root operation"),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Init => "init",
            Self::Target => "target",
            Self::Selected => "selected",
            Self::Plan => "plan",
            Self::Show => "show",
            Self::Apply => "apply",
        }
    }

    /// The stage that must have run before this one, for a root of `stack` in `mode`.
    fn after(self, mode: Mode, stack: &str) -> Option<Self> {
        match self {
            Self::Release => None,
            Self::Init => (stack == DAY2_APP).then_some(Self::Release),
            Self::Target | Self::Selected => Some(Self::Init),
            Self::Plan if mode == Mode::Deploy => Some(Self::Selected),
            Self::Plan => Some(Self::Init),
            Self::Show => Some(Self::Plan),
            Self::Apply => Some(Self::Show),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Credentials,
    /// The forge could not show the repository this root's app CI trusts.
    Forge,
    /// A committed input sets a variable the platform owns.
    Inputs,
    /// The release could not be read or was refused, or a deploy's selection does not name its candidate.
    Release,
    Stage(Stage),
    /// The saved plan deletes, replaces or forgets a resource; nothing was applied.
    Destroys,
    /// The saved plan's changes differ from the reviewed plan's; nothing was applied.
    Unreviewed,
}

#[derive(Default)]
struct Progress {
    done: BTreeSet<Stage>,
    failed: Option<Failure>,
    /// A day2-app root whose app has no release selection: it runs nothing else.
    unreleased: bool,
    /// A day2-app root's checked release, and the selection it came from.
    release: Option<release::Release>,
    selection: Option<release::Selection>,
    /// A deploy's rendered target `instance.json`.
    target: Option<Value>,
    new_root: bool,
    changes: Vec<Value>,
    destroys: Vec<String>,
    /// The digest of the saved plan's changes (`review_digest`), and of the saved
    /// plan file itself, both taken at show.
    review: String,
    plan_digest: String,
}

/// Where a root's files live inside the output directory.
#[derive(Clone)]
pub struct Layout {
    pub config: PathBuf,
    pub stack: PathBuf,
    pub data: PathBuf,
    pub inputs: PathBuf,
    pub rendered: PathBuf,
    /// An app CI root's `forge.tfvars.json`.
    pub forge: PathBuf,
    /// A day2-app root's `release.tfvars.json`.
    pub release: PathBuf,
    pub plan: PathBuf,
    /// A deploy's targeted plan.
    pub target: PathBuf,
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
        (DAY2_APP, Some(app)) => format!("gcp/config/apps/{app}.tfvars"),
        _ => bail!("no committed inputs for {stack}"),
    })
}

fn needs_cluster(stack: &str) -> bool {
    stack == "tenancy" || stack == "app-edge" || stack == DAY2_APP
}

/// `gcloud container clusters get-credentials <cluster> --zone <zone> --project
/// <project>`: how a private kubeconfig (the caller's `KUBECONFIG`) is built
/// for the cluster, from derived names. A deploy builds its own the same way.
pub fn kubeconfig_args(cluster: &str, zone: &str, project: &str) -> Vec<OsString> {
    [
        "container",
        "clusters",
        "get-credentials",
        cluster,
        "--zone",
        zone,
        "--project",
        project,
    ]
    .map(OsString::from)
    .to_vec()
}

/// Whether a root that has never been applied plans against an empty local state: only in a read-only plan. An apply
/// or a deploy initializes the real backend, so its apply creates the state.
fn plans_locally(mode: Mode, new_root: bool) -> bool {
    mode == Mode::Plan && new_root
}

fn needs_dns(stack: &str) -> bool {
    stack == "app-edge"
}

/// The exact engine invocation for one stage of one root: arguments and the
/// variables set on top of the allowlisted ambient ones. `local_state` is a plan
/// session's root that has never been applied. A day2-app root's release
/// variables come last, so they win; a deploy's `Target` plans only the instance
/// ConfigMap, unlocked, into its own plan file. `Release` and `Selected` run no
/// engine.
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
        Stage::Plan | Stage::Target => {
            args.extend(["plan", "-input=false", "-no-color"].map(OsString::from));
            args.push(if mode.applies() && stage == Stage::Plan {
                LOCK_TIMEOUT.into()
            } else {
                "-lock=false".into()
            });
            if stage == Stage::Target {
                args.push(format!("-target={TARGET}").into());
            }
            args.push(format!("-var-file={}", layout.inputs.display()).into());
            args.push(format!("-var-file={}", layout.rendered.display()).into());
            if root.app_ci_repository.is_some() {
                args.push(format!("-var-file={}", layout.forge.display()).into());
            }
            if root.stack == DAY2_APP {
                args.push(format!("-var-file={}", layout.release.display()).into());
                args.extend(release::PROFILE.map(OsString::from));
            }
            let out = if stage == Stage::Target {
                &layout.target
            } else {
                &layout.plan
            };
            args.push(format!("-out={}", out.display()).into());
            if needs_cluster(&root.stack)
                && let Some(kubeconfig) = credentials.kubeconfig
            {
                // A -var outranks every var file, so a committed kubeconfig_path can
                // never point the provider at another kubeconfig. A saved plan keeps it.
                args.push(format!("-var=kubeconfig_path={}", kubeconfig.display()).into());
            }
            provider_env(root, credentials, &mut env);
        }
        Stage::Release | Stage::Selected => {}
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

/// The roots that must have applied before `root` in an apply: none for a shared
/// root or an app edge (the shared roots gate every later root separately), and
/// its app's edge for a day2-app root, whose platform contract the edge writes.
fn needs(root: &Root) -> Vec<String> {
    match (root.stack.as_str(), &root.app_id) {
        (DAY2_APP, Some(app)) => vec![format!("app-edge/{app}")],
        _ => Vec::new(),
    }
}

/// Whether `stage` of `label` may run now. Each root runs its stages in order and
/// stops at its first failure or once it is unreleased; only an apply or a deploy
/// applies, and only a deploy renders a target or checks its selection; and an
/// apply runs no root until every shared root before it has applied, since later
/// roots read their state, nor a day2-app root until its app's edge has.
fn admit(
    mode: Mode,
    roots: &[Root],
    progress: &BTreeMap<String, Progress>,
    label: &str,
    stage: Stage,
) -> Result<()> {
    let current = progress.get(label).context("unknown root")?;
    let root = roots
        .iter()
        .find(|root| root.label == label)
        .context("unknown root")?;
    ensure!(current.failed.is_none(), "{label} already failed");
    ensure!(!current.unreleased, "{label} has no release selection");
    ensure!(
        !current.done.contains(&stage),
        "duplicate {} for {label}",
        stage.name()
    );
    ensure!(
        stage != Stage::Release || root.stack == DAY2_APP,
        "only a day2-app root reads a release"
    );
    if let Some(required) = stage.after(mode, &root.stack) {
        ensure!(
            current.done.contains(&required),
            "{} needs {} first",
            stage.name(),
            required.name()
        );
    }
    ensure!(
        stage != Stage::Apply || mode.applies(),
        "instance plan never applies"
    );
    ensure!(
        !matches!(stage, Stage::Target | Stage::Selected) || mode == Mode::Deploy,
        "only a deploy renders a target or checks its selection"
    );
    ensure!(
        stage != Stage::Target || !current.done.contains(&Stage::Selected),
        "a deploy renders its target before it checks its selection"
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
        for needed in needs(root) {
            let earlier = progress.get(&needed).context("unknown root")?;
            ensure!(
                earlier.failed.is_none() && earlier.done.contains(&Stage::Apply),
                "{label} runs only after {needed} has applied"
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
        !request.roots.is_empty() && request.roots.len() <= 3 + 2 * 128,
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
                day2_contracts::names::app_id(app)?;
                format!("app-edge/{app}")
            }
            ("app-edge", None) => bail!("app-edge needs its app"),
            (DAY2_APP, Some(app)) => {
                day2_contracts::names::identifier(app)?;
                format!("{DAY2_APP}/{app}")
            }
            (DAY2_APP, None) => bail!("day2-app needs its app"),
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
    // A day2-app root keeps its state in its app's own bucket and prefix, the
    // derived names, so no request can point it at another app's state.
    for root in &request.roots {
        if let (DAY2_APP, Some(app)) = (root.stack.as_str(), &root.app_id) {
            ensure!(
                root.bucket == format!("{}-{app}-state", request.project)
                    && root.prefix == format!("{DAY2_APP}/{app}"),
                "{} keeps its state in <project>-{app}-state, prefix day2-app/{app}",
                root.label
            );
        }
    }
    let day2_apps = request
        .roots
        .iter()
        .filter(|root| root.stack == DAY2_APP)
        .count();
    match (request.mode, &request.reviewed, &request.candidate) {
        (Mode::Plan, None, None) | (Mode::Apply, Some(_), None) => {}
        (Mode::Deploy, None, Some(_)) => ensure!(
            request.roots.len() == 1 && day2_apps == 1,
            "a deploy runs exactly one day2-app root"
        ),
        (Mode::Plan, Some(_), _) => bail!("a plan reviews nothing"),
        (Mode::Apply, None, _) => bail!("an apply needs the plan that was reviewed"),
        (Mode::Deploy, Some(_), _) => {
            bail!("a deploy is bound to its selection, not a reviewed plan")
        }
        (Mode::Deploy, None, None) => bail!("a deploy needs the candidate it deploys"),
        (_, _, Some(_)) => bail!("only a deploy names a candidate"),
    }
    match &request.releases {
        Some(releases) => releases.validate(&request.project)?,
        None => ensure!(
            day2_apps == 0,
            "day2-app roots need the instance's releases"
        ),
    }
    app_ci::validate(request)?;
    if request.mode == Mode::Deploy {
        return Ok(());
    }
    // Apply order is fixed: the shared roots first, then each app's edge by app,
    // then each app's day2-app root by app, so no request can run a root before
    // the state it reads.
    ensure!(
        request
            .roots
            .iter()
            .take(SHARED.len())
            .map(|root| root.stack.as_str())
            .eq(SHARED),
        "the core roots start with project, cluster and tenancy, in that order"
    );
    let rest = &request.roots[SHARED.len()..];
    let edges = rest.len() - day2_apps;
    ensure!(
        rest[..edges].iter().all(|root| root.stack == "app-edge")
            && rest[..edges]
                .windows(2)
                .all(|pair| pair[0].app_id < pair[1].app_id),
        "app edges follow the shared roots, sorted by app"
    );
    ensure!(
        day2_apps == 0
            || rest[..edges]
                .iter()
                .map(|root| &root.app_id)
                .eq(rest[edges..].iter().map(|root| &root.app_id)),
        "each app's day2-app root follows every app edge, in the same app order"
    );
    // Every other core root keeps its state in one bucket, each under its own prefix.
    let bucket = &request.roots[0].bucket;
    let mut prefixes = BTreeSet::new();
    for root in request.roots.iter().filter(|root| root.stack != DAY2_APP) {
        ensure!(
            &root.bucket == bucket,
            "the core roots share one state bucket"
        );
        ensure!(
            prefixes.insert(root.prefix.as_str()),
            "two roots share the state prefix {}",
            root.prefix
        );
    }
    ensure!(
        request
            .releases
            .as_ref()
            .is_none_or(|releases| &releases.bucket == bucket),
        "releases live in the core roots' state bucket"
    );
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

/// An apply reads the instance only as committed: a clean git checkout whose
/// day2.json and every root's committed inputs, as already read into `committed`,
/// equal their bytes at HEAD.
fn committed_at_head(
    instance: &Path,
    commit: &str,
    clean: bool,
    roots: &[Root],
    committed: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    ensure!(
        !commit.is_empty() && clean,
        "instance apply needs a clean git checkout of the instance"
    );
    let prefix = String::from_utf8(git(instance, &["rev-parse", "--show-prefix"], 4096)?)?;
    let prefix = prefix.trim();
    let at_head = |path: &str| {
        git(
            instance,
            &["cat-file", "blob", &format!("{commit}:{prefix}{path}")],
            BLOB_LIMIT,
        )
        .with_context(|| format!("{path} is not committed at the instance's HEAD"))
    };
    ensure!(
        fs::read(instance.join("day2.json"))? == at_head("day2.json")?,
        "day2.json differs from the instance's HEAD"
    );
    for root in roots {
        ensure!(
            committed[&root.label] == at_head(&root.inputs)?,
            "{} differs from the instance's HEAD",
            root.inputs
        );
    }
    Ok(())
}

/// What a reviewed plan reviewed: each root's changes digest, for the roots it
/// could plan, and each day2-app root's release variables digest, `None` for a
/// root that was unreleased.
#[derive(Debug, Default)]
struct Reviewed {
    changes: BTreeMap<String, String>,
    releases: BTreeMap<String, Option<String>>,
}

/// The format of the receipt a session writes, and the only one an apply accepts
/// as its reviewed plan.
pub const RECEIPT_FORMAT: u64 = 2;

/// The reviewed changes of each root, from a prior `instance plan` output for the
/// same platform commit and stacks, the same roots in the same order and the same
/// backends, committed inputs and rendered variables. A root that plan could not
/// plan (before its cluster existed, say) has no reviewed changes, so an apply
/// refuses it if it has any; plan and review again after the roots before it apply.
/// A day2-app root's release is compared root by root when it is read again
/// (`release_reviewed`), so one app's new release never refuses the others.
fn reviewed_changes(
    directory: &Path,
    request: &Request,
    stacks_tree: &str,
    inputs: &BTreeMap<String, String>,
    rendered: &BTreeMap<String, String>,
) -> Result<Reviewed> {
    let mut bytes = Vec::new();
    fs::File::open(directory.join("receipt.json"))
        .context("the reviewed plan directory has no receipt.json")?
        .take(SHOW_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= SHOW_LIMIT, "reviewed receipt budget");
    let receipt: Value = serde_json::from_slice(&bytes).context("reviewed receipt")?;
    ensure!(
        receipt["format"] == RECEIPT_FORMAT
            && receipt["mode"] == "plan"
            && receipt["audit_error"].is_null(),
        "the reviewed directory must hold an instance plan of this platform's receipt format"
    );
    ensure!(
        receipt["commit"] == request.commit.as_str() && receipt["stacks_tree"] == stacks_tree,
        "the reviewed plan used another platform commit; plan and review again"
    );
    let planned = receipt["roots"]
        .as_array()
        .context("reviewed receipt roots")?;
    ensure!(
        planned.len() == request.roots.len(),
        "the reviewed plan has other roots; plan and review again"
    );
    let mut reviewed = Reviewed::default();
    for (root, planned) in request.roots.iter().zip(planned) {
        let label = &root.label;
        ensure!(
            planned["label"] == label.as_str(),
            "the reviewed plan has other roots; plan and review again"
        );
        ensure!(
            planned["backend"] == json!({"bucket": root.bucket, "prefix": root.prefix})
                && planned["inputs"]["path"] == root.inputs.as_str()
                && planned["inputs"]["digest"] == inputs[label].as_str()
                && planned["variables"] == rendered[label].as_str(),
            "{label}'s backend or inputs changed since the reviewed plan; plan and review again"
        );
        let day2_app = root.stack == DAY2_APP;
        match planned["status"].as_str() {
            Some("no_changes" | "changes") => {
                let review = planned["review"]
                    .as_str()
                    .filter(|review| review.starts_with("sha256:"))
                    .context("reviewed receipt review digest")?;
                reviewed.changes.insert(label.clone(), review.to_owned());
                if day2_app {
                    let release = planned["release"]["variables"]
                        .as_str()
                        .filter(|digest| digest.starts_with("sha256:"))
                        .context("reviewed receipt release digest")?;
                    reviewed
                        .releases
                        .insert(label.clone(), Some(release.to_owned()));
                }
            }
            Some("unreleased") if day2_app => {
                reviewed.releases.insert(label.clone(), None);
            }
            Some("failed_inputs" | "failed_release") if day2_app => {}
            Some("failed_credentials" | "failed_init" | "failed_plan" | "failed_show") => {}
            _ => bail!("the reviewed receipt has an unknown status for {label}"),
        }
    }
    Ok(reviewed)
}

/// Whether an apply may run a day2-app root whose release now renders `current`
/// (`None`: unreleased), against what the reviewed plan reviewed for it: an
/// unchanged release, or the root still unreleased. A release that appeared or
/// changed since needs a new plan and review; a root the reviewed plan could not
/// plan is left to the changes gate, which refuses it unless nothing changes.
fn release_reviewed(
    reviewed: &BTreeMap<String, Option<String>>,
    label: &str,
    current: Option<&str>,
) -> Result<(), (Failure, String)> {
    match (reviewed.get(label), current) {
        (None, _) | (Some(None), None) => Ok(()),
        (Some(Some(before)), Some(now)) if before == now => Ok(()),
        (Some(Some(_)), None) => Err((
            Failure::Release,
            "the app's release selection is gone since the reviewed plan".into(),
        )),
        (Some(_), Some(_)) => Err((
            Failure::Unreviewed,
            "the app's release changed since the reviewed plan; plan and review again".into(),
        )),
    }
}

fn host() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux_amd64",
        ("macos", "aarch64") => "darwin_arm64",
        _ => "unsupported",
    }
}

/// What a session reads outside its engine runs: the instance's release state at an exact generation, the
/// release cache's tools and root (`$DAY2_RELEASE_CACHE`, else `~/.cache/day2-platform-releases`), and the forge,
/// for app CI's repository IDs, with the clock its retries wait on.
pub struct Effects {
    pub store: Box<dyn crate::instance_candidate::tools::Store>,
    pub tools: Box<dyn crate::instance_release::Tools>,
    pub cache: Option<PathBuf>,
    pub forge: Box<dyn crate::instance_source::Transport>,
    pub token: Option<String>,
    pub waiting: Box<dyn crate::ci_fetch::Waiting>,
}

impl Effects {
    /// `gcloud storage` with the job's ambient credentials, as `instance candidate` reads release state, and the
    /// forge over HTTPS with `instance source`'s token.
    pub fn native() -> Result<Self> {
        Ok(Self {
            store: Box::new(crate::instance_candidate::tools::Gcloud::native()),
            tools: Box::new(crate::instance_release::Native),
            cache: None,
            forge: Box::new(crate::instance_source::Native::new()?),
            token: crate::instance_source::token()?,
            waiting: Box::new(crate::instance_source::System::new()),
        })
    }
}

pub struct Session {
    request: Request,
    effects: Effects,
    /// Every root's committed inputs, as read once in prepare.
    committed: BTreeMap<String, Vec<u8>>,
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
    /// False once an apply changed the cluster root: the kubeconfig (or its
    /// absence) must be fetched again before the next root that needs it.
    kubeconfig_current: bool,
    /// Whether this apply already read the cluster's credentials again.
    kubeconfig_refreshed: bool,
    dns_token: Option<String>,
    credentials_read: bool,
    /// Roots whose app CI repository could not be read or whose committed inputs set an app CI variable; each fails
    /// at its init.
    app_ci_failed: BTreeMap<String, Failure>,
    /// An apply's reviewed changes and releases per root label.
    reviewed: Reviewed,
    progress: BTreeMap<String, Progress>,
}

impl Session {
    /// Validate and stage the CLI's request for a session the host started in
    /// `mode`, reading release state through `effects`.
    pub fn prepare(raw: &Path, mode: Mode, effects: Effects) -> Result<Self> {
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
        // Every root's committed inputs, read once and bounded, before anything is written.
        let mut committed = BTreeMap::new();
        for root in &request.roots {
            let mut bytes = Vec::new();
            fs::File::open(instance.join(&root.inputs))?
                .take(1_048_577)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 1_048_576, "{} budget", root.inputs);
            committed.insert(root.label.clone(), bytes);
        }
        let inputs: BTreeMap<String, String> = committed
            .iter()
            .map(|(label, bytes)| (label.clone(), day2::digest(bytes)))
            .collect();
        let rendered: BTreeMap<String, String> = request
            .roots
            .iter()
            .map(|root| (root.label.clone(), day2::digest(root.variables.as_bytes())))
            .collect();
        if mode.applies() {
            // An apply or a deploy runs only what is committed.
            committed_at_head(
                &instance,
                &instance_commit,
                instance_clean,
                &request.roots,
                &committed,
            )?;
        }
        let reviewed = match &request.reviewed {
            None => Reviewed::default(),
            // An apply runs only what was reviewed.
            Some(directory) => {
                reviewed_changes(directory, &request, &stacks_tree, &inputs, &rendered)?
            }
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
        for root in &request.roots {
            let directory = output.join(root.label.replace('/', "-"));
            fs::create_dir(&directory)?;
            let stack = directory.join("stack");
            for (path, bytes) in &stacks[&root.stack] {
                let target = stack.join(path);
                fs::create_dir_all(target.parent().context("stack file")?)?;
                fs::write(&target, bytes)?;
            }
            let layout = Layout {
                config: config.clone(),
                stack,
                data: directory.join("data"),
                inputs: directory.join("inputs.tfvars"),
                rendered: directory.join("rendered.tfvars.json"),
                forge: directory.join("forge.tfvars.json"),
                release: directory.join("release.tfvars.json"),
                plan: directory.join("plan.bin"),
                target: directory.join("target.bin"),
            };
            fs::write(&layout.inputs, &committed[&root.label])?;
            fs::write(&layout.rendered, &root.variables)?;
            layouts.insert(root.label.clone(), layout);
        }
        let progress = request
            .roots
            .iter()
            .map(|root| (root.label.clone(), Progress::default()))
            .collect();
        let session = Self {
            request,
            effects,
            committed,
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
            kubeconfig_current: true,
            kubeconfig_refreshed: false,
            dns_token: None,
            credentials_read: false,
            app_ci_failed: BTreeMap::new(),
            reviewed,
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

    /// The roots in apply order: which of them every later root reads, which
    /// roots each needs applied first, and which read a release first.
    pub fn summary(&self) -> Value {
        json!({"roots": self.request.roots.iter().map(|root| json!({
            "label": root.label,
            "shared": SHARED.contains(&root.stack.as_str()),
            "needs": needs(root),
            "release": root.stack == DAY2_APP,
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
            self.fetch_kubeconfig("credentials.log")?;
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
        self.read_app_ci()?;
        Ok(json!({}))
    }

    /// App CI's forge IDs, read once for every root that names a repository and written as its
    /// `forge.tfvars.json`; no project or app-edge root may commit a variable app CI owns. The reads share one
    /// retry budget, the instance workflows' git-oidc wait: a transient failure retries the reads still unanswered.
    /// A failure is recorded in the root's `forge.error` or `inputs.error` and fails that root at its init; the
    /// others run.
    fn read_app_ci(&mut self) -> Result<()> {
        let mut wanted = Vec::new();
        for root in &self.request.roots {
            if !app_ci::stack(&root.stack) {
                continue;
            }
            let restated = app_ci::restated(&self.committed[&root.label]);
            if !restated.is_empty() {
                fs::write(
                    self.output
                        .join(root.label.replace('/', "-"))
                        .join("inputs.error"),
                    format!(
                        "{} sets {}, which app CI owns",
                        root.inputs,
                        restated.join(", ")
                    ),
                )?;
                self.app_ci_failed
                    .insert(root.label.clone(), Failure::Inputs);
            } else if let Some(repository) = &root.app_ci_repository {
                wanted.push((root.label.clone(), root.stack.clone(), repository.clone()));
            }
        }
        if wanted.is_empty() {
            return Ok(());
        }
        let forge = self.request.releases.clone().context("releases")?.forge;
        let Effects {
            forge: transport,
            token,
            waiting,
            ..
        } = &mut self.effects;
        let mut answers: BTreeMap<String, Result<Vec<u8>, String>> = BTreeMap::new();
        let finished = crate::ci_fetch::retrying(waiting.as_mut(), "app CI's forge reads", |_| {
            let mut unanswered = None;
            for (label, stack, repository) in &wanted {
                if answers.contains_key(label) {
                    continue;
                }
                let read = app_ci::read(
                    &mut crate::instance_source::Forge::new(
                        transport.as_mut(),
                        token.as_deref(),
                        &forge.server,
                        repository,
                    ),
                    repository,
                    &forge.org,
                )
                .and_then(|ids| app_ci::variables(stack, ids));
                match read {
                    Err(error) if crate::ci_fetch::transient(&error) => unanswered = Some(error),
                    read => {
                        answers.insert(label.clone(), read.map_err(|error| format!("{error:#}")));
                    }
                }
            }
            unanswered.map_or(Ok(()), Err)
        });
        let exhausted = finished.err().map(|error| format!("{error:#}"));
        // A job's own token reads only its repository; say so when there is none at all.
        let tokenless = if token.is_none() {
            "; no forge token was set (AUTODEPLOY_SOURCE_TOKEN, else GITEA_TOKEN)"
        } else {
            ""
        };
        for (label, _, repository) in &wanted {
            let answer = answers
                .remove(label)
                .unwrap_or_else(|| Err(exhausted.clone().unwrap_or_default()));
            match answer {
                Ok(variables) => fs::write(&self.layouts[label].forge, variables)?,
                Err(reason) => {
                    fs::write(
                        self.output
                            .join(label.replace('/', "-"))
                            .join("forge.error"),
                        format!("read {repository} on {}: {reason}{tokenless}", forge.server),
                    )?;
                    self.app_ci_failed.insert(label.clone(), Failure::Forge);
                }
            }
        }
        Ok(())
    }

    /// The cluster's kubeconfig, from derived names, into the private directory.
    /// A failure is recorded in `cluster.error` and leaves no kubeconfig.
    fn fetch_kubeconfig(&mut self, log: &str) -> Result<()> {
        let kubeconfig = self.private.path().join("kubeconfig");
        let _ = fs::remove_file(&kubeconfig);
        let fetched = crate::maintenance::on_path("gcloud").and_then(|gcloud| {
            let mut command = self.tool(&gcloud);
            command.env("KUBECONFIG", &kubeconfig).args(kubeconfig_args(
                &self.request.cluster,
                &self.request.zone,
                &self.request.project,
            ));
            crate::process::run(
                &mut command,
                self.private.path(),
                &self.output.join(log),
                Duration::from_secs(120),
            )
        });
        self.kubeconfig_current = true;
        match fetched {
            Ok(()) => {
                let _ = fs::remove_file(self.output.join("cluster.error"));
                self.kubeconfig = Some(kubeconfig);
            }
            Err(error) => {
                self.kubeconfig = None;
                fs::write(self.output.join("cluster.error"), format!("{error:#}"))?;
            }
        }
        Ok(())
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
        command.args(args.clone()).envs(env.clone());
        if stage == Stage::Show {
            let timeout = if self.request.mode == Mode::Deploy {
                DEPLOY_SHOW
            } else {
                Duration::from_secs(300)
            };
            let shown = capture(command, Some(&log), timeout, SHOW_LIMIT)?;
            // The same plan as text, which is what an operator reviews before an
            // apply; OpenTofu masks sensitive values in it.
            let mut text = self.engine(&[])?;
            text.args(args.iter().filter(|arg| arg.as_os_str() != "-json"))
                .envs(env);
            let readable = capture(
                text,
                Some(&directory.join("plan-text.log")),
                timeout,
                SHOW_LIMIT,
            )?;
            fs::write(directory.join("plan.txt"), readable)?;
            return Ok(Some(shown));
        }
        // A step that holds the state lock (an apply or a deploy session's plan and
        // apply) is interrupted when it overruns, so OpenTofu saves state and
        // releases the lock, and is killed only after its mode's grace period.
        let mode = self.request.mode;
        let deadline = mode.deadline(stage);
        if mode.applies() && matches!(stage, Stage::Plan | Stage::Apply) {
            crate::process::run_interruptible(
                &mut command,
                &directory,
                &log,
                deadline.run,
                deadline.grace,
            )?;
        } else {
            crate::process::run(&mut command, &directory, &log, deadline.run)?;
        }
        Ok(None)
    }

    /// One operation of one root: a day2-app root's release first; init, then
    /// plan, then show, then, in an apply or a deploy, apply; and in a deploy its
    /// target render and selection check. A failed operation is recorded for the
    /// receipt and stops that root; `admit` keeps later roots from running after a
    /// shared one, or after their own app's edge.
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
        match stage {
            Stage::Release => return self.release(&root),
            Stage::Selected => return self.selected(&root),
            Stage::Target => return self.target(&root),
            Stage::Init | Stage::Plan | Stage::Show | Stage::Apply => {}
        }
        if self.request.mode == Mode::Apply
            && stage == Stage::Init
            && needs_cluster(&root.stack)
            && !self.kubeconfig_refreshed
        {
            // The first root that needs the cluster runs only after the cluster root
            // has applied. Read the credentials again if that apply changed the
            // cluster (it may have created it) or if the first read failed.
            self.kubeconfig_refreshed = true;
            if !self.kubeconfig_current || self.kubeconfig.is_none() {
                self.fetch_kubeconfig("credentials-refresh.log")?;
            }
        }
        let progress = self.progress.get(label).context("unknown root")?;
        let mut new_root = progress.new_root;
        let plan_digest = progress.plan_digest.clone();
        let gate = apply_gate(
            self.request.mode,
            &progress.changes,
            &progress.destroys,
            &progress.review,
            self.reviewed.changes.get(label),
        );
        let directory = self.output.join(label.replace('/', "-"));
        let plan_file = self.layouts[label].plan.clone();
        let missing = (needs_cluster(&root.stack) && self.kubeconfig.is_none())
            || (needs_dns(&root.stack) && self.dns_token.is_none());
        let app_ci_failed = self.app_ci_failed.get(label).copied();
        let outcome = if stage == Stage::Init
            && let Some(failure) = app_ci_failed
        {
            Err(failure)
        } else if stage == Stage::Init && missing {
            Err(Failure::Credentials)
        } else if stage == Stage::Apply && gate != Ok(true) {
            // Nothing to change completes the root without the engine; a refusal fails it.
            gate.clone().map(|_| None).map_err(|(failure, message)| {
                let _ = fs::write(directory.join("apply.error"), message);
                failure
            })
        } else {
            (|| -> Result<Option<(Vec<u8>, String)>> {
                match stage {
                    Stage::Init => {
                        new_root = !self.state_exists(&root, &directory)?;
                        if plans_locally(self.request.mode, new_root) {
                            // Plan against an empty local state: nothing is created
                            // remotely. An apply or a deploy initializes the real
                            // backend, so its apply creates the state.
                            fs::write(
                                self.layouts[label].stack.join("backend_override.tf"),
                                backend_override(&directory.join("new.tfstate"))?,
                            )?;
                        }
                    }
                    Stage::Apply => ensure!(
                        day2::digest(&fs::read(&plan_file)?) == plan_digest,
                        "the saved plan changed after it was shown"
                    ),
                    Stage::Plan | Stage::Show => {}
                    Stage::Release | Stage::Target | Stage::Selected => {
                        bail!("{name} runs no engine step")
                    }
                }
                // Show reads the plan file; its digest must be the same before and after.
                let before = if stage == Stage::Show {
                    day2::digest(&fs::read(&plan_file)?)
                } else {
                    String::new()
                };
                let shown =
                    self.run_stage(stage, &root, plans_locally(self.request.mode, new_root))?;
                Ok(shown.map(|shown| (shown, before)))
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
            Some((shown, plan)) => {
                fs::write(directory.join("show.json"), &shown)
                    .map_err(|_| Failure::Stage(stage))?;
                (|| -> Result<_> {
                    ensure!(
                        day2::digest(&fs::read(&plan_file)?) == plan,
                        "the saved plan changed while it was shown"
                    );
                    Ok((
                        changes(&shown)?,
                        destructive(&shown)?,
                        review_digest(&shown)?,
                        plan,
                    ))
                })()
                .map(Some)
                .map_err(|error| {
                    let _ = fs::write(directory.join("show.error"), format!("{error:#}"));
                    Failure::Stage(stage)
                })
            }
            None => Ok(None),
        });
        if stage == Stage::Apply && root.stack == "cluster" && gate == Ok(true) && outcome.is_ok() {
            self.kubeconfig_current = false;
        }
        let progress = self.progress.get_mut(label).context("unknown root")?;
        progress.new_root = new_root;
        match outcome {
            Err(failure) => {
                progress.failed = Some(failure);
                Ok(json!({"ok": false}))
            }
            Ok(found) => {
                if let Some((found, destroys, review, plan)) = found {
                    progress.changes = found;
                    progress.destroys = destroys;
                    progress.review = review;
                    progress.plan_digest = plan;
                }
                progress.done.insert(stage);
                Ok(json!({"ok": true}))
            }
        }
    }

    /// Record a root's failure: its message in `<stage>.error` in the root's
    /// directory, and the failure for the receipt.
    fn fail(&mut self, label: &str, stage: Stage, failure: Failure, message: &str) -> Result<()> {
        let directory = self.output.join(label.replace('/', "-"));
        let _ = fs::write(directory.join(format!("{}.error", stage.name())), message);
        self.progress.get_mut(label).context("unknown root")?.failed = Some(failure);
        Ok(())
    }

    /// A day2-app root's release. Its committed inputs may not set a variable the
    /// platform owns. Then, in a plan or an apply, the app's selection, read at its
    /// exact generation (absent: the root is unreleased and runs nothing else),
    /// and its candidate, checked; an apply compares the release with the reviewed
    /// plan's. In a deploy, the request's candidate, checked the same way. The
    /// release variables are written for the root's plans.
    fn release(&mut self, root: &Root) -> Result<Value> {
        let label = root.label.as_str();
        let failed = json!({"ok": false, "released": false, "release": null});
        let app = root.app_id.clone().context("day2-app needs its app")?;
        let releases = self.request.releases.clone().context("releases")?;
        let rendered: Value = day2::json::decode(root.variables.as_bytes())?;
        let mut owned: Vec<&str> = rendered
            .as_object()
            .context("rendered variables must be an object")?
            .keys()
            .map(String::as_str)
            .collect();
        owned.extend(release::OWNED);
        let restated = release::restated(&self.committed[label], &owned);
        if !restated.is_empty() {
            let message = format!(
                "{} sets {}, which the platform owns for day2-app; delete them there",
                root.inputs,
                restated.join(", ")
            );
            self.fail(label, Stage::Release, Failure::Inputs, &message)?;
            return Ok(failed);
        }
        let read = (|| -> Result<Option<(release::Release, Option<release::Selection>)>> {
            let root_path = match &self.effects.cache {
                Some(path) => path.clone(),
                None => crate::instance_release::cache_root()?,
            };
            let cache = crate::instance_release::Cache::open(&root_path, &releases.objects())?;
            let tools = self.effects.tools.as_mut();
            if self.request.mode == Mode::Deploy {
                let path = self
                    .request
                    .candidate
                    .as_ref()
                    .context("deploy candidate")?;
                let candidate = record::decode(&crate::instance_candidate::read_bounded(
                    path,
                    record::RECORD_LIMIT,
                )?)?;
                let checked = release::check(&candidate, &app, &releases, &cache, tools)?;
                return Ok(Some((checked, None)));
            }
            let Some(selection) =
                release::read_selection(self.effects.store.as_mut(), &releases, &app)?
            else {
                return Ok(None);
            };
            ensure!(
                self.request.mode != Mode::Apply || selection.status == release::Status::Ready,
                "the app's release is still activating; finish it through the deployment controller before applying"
            );
            let checked = release::check(&selection.candidate, &app, &releases, &cache, tools)?;
            Ok(Some((checked, Some(selection))))
        })();
        let (checked, selection) = match read {
            Err(error) => {
                self.fail(
                    label,
                    Stage::Release,
                    Failure::Release,
                    &format!("{error:#}"),
                )?;
                return Ok(failed);
            }
            Ok(found) => found.unzip(),
        };
        let variables = checked
            .as_ref()
            .map(|release| day2::digest(&release.variables));
        if let Err((failure, message)) =
            release_reviewed(&self.reviewed.releases, label, variables.as_deref())
        {
            self.fail(label, Stage::Release, failure, &message)?;
            return Ok(failed);
        }
        let selection = selection.flatten();
        let Some(checked) = checked else {
            let progress = self.progress.get_mut(label).context("unknown root")?;
            progress.unreleased = true;
            progress.done.insert(Stage::Release);
            return Ok(json!({"ok": true, "released": false, "release": null}));
        };
        fs::write(&self.layouts[label].release, &checked.variables)?;
        let reported = json!({
            "candidate": checked.digest,
            "commit": checked.commit,
            "image": checked.image,
            "artifact_id": checked.artifact_id,
            "tooling_image": checked.tooling_image,
        });
        let progress = self.progress.get_mut(label).context("unknown root")?;
        progress.release = Some(checked);
        progress.selection = selection;
        progress.done.insert(Stage::Release);
        Ok(json!({"ok": true, "released": true, "release": reported}))
    }

    /// A deploy's selection check, just before its locked plan: the app's
    /// selection, read again at its exact generation, must name exactly the
    /// candidate the root renders.
    fn selected(&mut self, root: &Root) -> Result<Value> {
        let label = root.label.as_str();
        let app = root.app_id.clone().context("day2-app needs its app")?;
        let releases = self.request.releases.clone().context("releases")?;
        let candidate = self.progress[label]
            .release
            .as_ref()
            .context("a deploy checks its selection after its release")?
            .candidate
            .clone();
        match release::selection(self.effects.store.as_mut(), &releases, &app, &candidate) {
            Ok(selection) => {
                let progress = self.progress.get_mut(label).context("unknown root")?;
                progress.selection = Some(selection);
                progress.done.insert(Stage::Selected);
                Ok(json!({"ok": true}))
            }
            Err(error) => {
                self.fail(
                    label,
                    Stage::Selected,
                    Failure::Release,
                    &format!("{error:#}"),
                )?;
                Ok(json!({"ok": false}))
            }
        }
    }

    /// A deploy's target: the `instance.json` the root's plan would publish, from
    /// a plan of only the instance ConfigMap, without the state lock, into its own
    /// plan file that is never applied. It is written to `instance.json` (0600) in
    /// the root's directory, with the plan as `target.json` and `target.txt`.
    fn target(&mut self, root: &Root) -> Result<Value> {
        let label = root.label.as_str();
        let directory = self.output.join(label.replace('/', "-"));
        let layout = self.layouts[label].clone();
        let rendered = (|| -> Result<Value> {
            let credentials = Credentials {
                kubeconfig: self.kubeconfig.as_deref(),
                dns_token: None,
            };
            let (args, env) = invocation(
                Mode::Deploy,
                Stage::Target,
                root,
                &layout,
                false,
                &credentials,
            );
            let mut command = self.engine(&[])?;
            command.args(args).envs(env);
            crate::process::run(
                &mut command,
                &directory,
                &directory.join("target.log"),
                DEPLOY_PLAN.run,
            )?;
            let before = day2::digest(&fs::read(&layout.target)?);
            let shown_layout = Layout {
                plan: layout.target.clone(),
                ..layout.clone()
            };
            let (args, env) = invocation(
                Mode::Deploy,
                Stage::Show,
                root,
                &shown_layout,
                false,
                &credentials,
            );
            let mut command = self.engine(&[])?;
            command.args(args.clone()).envs(env.clone());
            let shown = capture(
                command,
                Some(&directory.join("target-show.log")),
                DEPLOY_SHOW,
                SHOW_LIMIT,
            )?;
            let mut text = self.engine(&[])?;
            text.args(args.iter().filter(|arg| arg.as_os_str() != "-json"))
                .envs(env);
            let readable = capture(
                text,
                Some(&directory.join("target-text.log")),
                DEPLOY_SHOW,
                SHOW_LIMIT,
            )?;
            ensure!(
                day2::digest(&fs::read(&layout.target)?) == before,
                "the targeted plan changed while it was shown"
            );
            fs::write(directory.join("target.json"), &shown)?;
            fs::write(directory.join("target.txt"), readable)?;
            let instance = target_instance(&shown)?;
            let path = directory.join("instance.json");
            crate::instance_candidate::tools::write_private(&path, &instance)?;
            Ok(json!({"path": path, "digest": day2::digest(&instance), "bytes": instance.len()}))
        })();
        match rendered {
            Ok(file) => {
                let progress = self.progress.get_mut(label).context("unknown root")?;
                progress.target = Some(file.clone());
                progress.done.insert(Stage::Target);
                Ok(json!({"ok": true, "instance": file}))
            }
            Err(error) => {
                self.fail(
                    label,
                    Stage::Target,
                    Failure::Stage(Stage::Target),
                    &format!("{error:#}"),
                )?;
                Ok(json!({"ok": false, "instance": null}))
            }
        }
    }

    /// The session's receipt. It is written even when the output audit fails, so
    /// an apply that changed infrastructure always leaves one, then marked failed.
    pub fn receipt(&self) -> Result<Value> {
        let audited = audit(&self.output, &self.layouts);
        let mode = self.request.mode;
        let mut roots = Vec::new();
        let mut ok = true;
        // In an apply, the roots after a failed shared root never run, nor a
        // day2-app root whose app's edge did not apply.
        let mut stopped = false;
        let mut unapplied = BTreeSet::new();
        for root in &self.request.roots {
            let progress = &self.progress[&root.label];
            let blocked = needs(root).iter().any(|needed| unapplied.contains(needed));
            let status = match progress.failed {
                Some(failure) => status(failure),
                None if progress.unreleased => "unreleased",
                None if mode == Mode::Apply && (stopped || blocked) && progress.done.is_empty() => {
                    "skipped"
                }
                // A deploy that stopped before its apply (its own step failed) leaves the
                // root prepared and not applied.
                None if mode == Mode::Deploy && !progress.done.contains(&Stage::Apply) => {
                    "not_applied"
                }
                None => {
                    let last = match mode {
                        Mode::Plan => Stage::Show,
                        Mode::Apply | Mode::Deploy => Stage::Apply,
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
                        (Mode::Apply | Mode::Deploy, false) => "applied",
                    }
                }
            };
            ok &= progress.failed.is_none();
            if status.starts_with("failed_")
                || status.starts_with("refused_")
                || status == "skipped"
            {
                unapplied.insert(root.label.clone());
            }
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
                "review": progress.review,
                "plan_digest": digest("plan.bin")?,
                "show_digest": digest("show.json")?,
                "logs": directory,
                "release": progress.release.as_ref().map(|release| {
                    let record = match (&progress.selection, &self.request.candidate) {
                        (_, Some(path)) if mode == Mode::Deploy => path.display().to_string(),
                        (Some(selection), _) => selection.uri.clone(),
                        _ => String::new(),
                    };
                    release::summary(
                        release,
                        if mode == Mode::Deploy { "candidate" } else { "selection" },
                        &record,
                        progress.selection.as_ref(),
                    )
                }),
                "target": progress.target,
            }));
        }
        let mut receipt = json!({
            "format": RECEIPT_FORMAT,
            "mode": mode.name(),
            "ok": ok && audited.is_ok(),
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
        if let Err(error) = &audited {
            receipt["audit_error"] = json!(format!("{error:#}"));
        }
        fs::write(
            self.output.join("receipt.json"),
            serde_json::to_vec_pretty(&receipt)?,
        )?;
        audited?;
        Ok(receipt)
    }
}

/// What an apply does at a root's apply stage, from its shown plan: complete the
/// root without the engine when nothing changes (`Ok(false)`), refuse a plan that
/// destroys or, in an apply, differs from the reviewed one, and otherwise run it
/// (`Ok(true)`). A deploy has no reviewed plan: its selection binds it.
fn apply_gate(
    mode: Mode,
    changes: &[Value],
    destroys: &[String],
    review: &str,
    reviewed: Option<&String>,
) -> Result<bool, (Failure, String)> {
    if changes.is_empty() {
        Ok(false)
    } else if !destroys.is_empty() {
        Err((
            Failure::Destroys,
            format!(
                "the plan deletes, replaces or forgets {}; instance apply never does",
                destroys.join(", ")
            ),
        ))
    } else if mode != Mode::Deploy && reviewed.map(String::as_str) != Some(review) {
        Err((
            Failure::Unreviewed,
            "the plan's changes differ from the reviewed plan's, or the reviewed plan could \
             not plan this root; plan and review again"
                .into(),
        ))
    } else {
        Ok(true)
    }
}

/// A failed root's receipt status.
fn status(failure: Failure) -> &'static str {
    match failure {
        Failure::Credentials => "failed_credentials",
        Failure::Forge => "failed_forge",
        Failure::Inputs => "failed_inputs",
        Failure::Release => "failed_release",
        Failure::Stage(Stage::Target) => "failed_target",
        Failure::Stage(Stage::Release | Stage::Selected) => "failed_release",
        Failure::Stage(Stage::Init) => "failed_init",
        Failure::Stage(Stage::Plan) => "failed_plan",
        Failure::Stage(Stage::Show) => "failed_show",
        Failure::Stage(Stage::Apply) => "failed_apply",
        Failure::Destroys => "refused_destroy",
        Failure::Unreviewed => "refused_unreviewed",
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
                "credentials-refresh.log",
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

/// The `instance.json` a deploy's targeted plan would publish, from its
/// `tofu show -json`: the one instance ConfigMap change's known
/// `data["instance.json"]`, byte for byte as OpenTofu holds it.
pub fn target_instance(shown: &[u8]) -> Result<Vec<u8>> {
    let plan: Value = serde_json::from_slice(shown).context("plan JSON")?;
    let found: Vec<&Value> = plan["resource_changes"]
        .as_array()
        .context("plan has no resource changes")?
        .iter()
        .filter(|change| change["address"] == TARGET)
        .collect();
    let [change] = found.as_slice() else {
        bail!("the targeted plan has no single {TARGET}");
    };
    let unknown = &change["change"]["after_unknown"]["data"];
    ensure!(
        *unknown != json!(true) && unknown["instance.json"] != json!(true),
        "the targeted plan does not know the instance's instance.json"
    );
    let instance = change["change"]["after"]["data"]["instance.json"]
        .as_str()
        .context("the targeted plan does not render the instance's instance.json")?;
    Ok(instance.as_bytes().to_vec())
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

/// A digest of exactly what a saved plan would change, from `tofu show -json`:
/// every resource change other than an unmoved, unimported no-op or read, with
/// its actions and its values before, after and known only after apply, and
/// every output change. An apply applies a root only when its new plan has the
/// digest of the plan that was reviewed.
pub fn review_digest(shown: &[u8]) -> Result<String> {
    let plan: Value = serde_json::from_slice(shown).context("plan JSON")?;
    let mut resources = Vec::new();
    for change in plan["resource_changes"]
        .as_array()
        .context("plan has no resource changes")?
    {
        let detail = &change["change"];
        let quiet = detail["actions"] == json!(["no-op"]) || detail["actions"] == json!(["read"]);
        if quiet && change["previous_address"].is_null() && detail["importing"].is_null() {
            continue;
        }
        resources.push(json!({
            "address": change["address"],
            "deposed": change["deposed"],
            "previous_address": change["previous_address"],
            "actions": detail["actions"],
            "before": detail["before"],
            "after": detail["after"],
            "after_unknown": detail["after_unknown"],
            "before_sensitive": detail["before_sensitive"],
            "after_sensitive": detail["after_sensitive"],
            "replace_paths": detail["replace_paths"],
            "importing": detail["importing"],
        }));
    }
    let mut outputs = Vec::new();
    if let Some(changes) = plan["output_changes"].as_object() {
        for (name, change) in changes {
            if change["actions"] != json!(["no-op"]) {
                outputs.push(json!({
                    "name": name,
                    "actions": change["actions"],
                    "before": change["before"],
                    "after": change["after"],
                    "after_unknown": change["after_unknown"],
                    "before_sensitive": change["before_sensitive"],
                    "after_sensitive": change["after_sensitive"],
                }));
            }
        }
    }
    let mut bytes = Vec::new();
    canonical(
        &json!({"resources": resources, "outputs": outputs}),
        &mut bytes,
    )?;
    Ok(day2::digest(&bytes))
}

/// JSON with object keys sorted at every level, so equal values hash equally.
fn canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Object(fields) => {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            out.push(b'{');
            for (index, name) in names.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(name)?);
                out.push(b':');
                canonical(&fields[name], out)?;
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                canonical(item, out)?;
            }
            out.push(b']');
        }
        scalar => out.extend(serde_json::to_vec(scalar)?),
    }
    Ok(())
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
                    app_ci_repository: None,
                },
                Root {
                    label: "cluster".into(),
                    stack: "cluster".into(),
                    app_id: None,
                    bucket: "exampleco-tools-tofu-state".into(),
                    prefix: "platform/cluster".into(),
                    inputs: "gcp/config/cluster.tfvars".into(),
                    variables: r#"{"cluster_name":"day2"}"#.into(),
                    app_ci_repository: None,
                },
                Root {
                    label: "tenancy".into(),
                    stack: "tenancy".into(),
                    app_id: None,
                    bucket: "exampleco-tools-tofu-state".into(),
                    prefix: "platform/tenancy".into(),
                    inputs: "gcp/config/tenancy.tfvars".into(),
                    variables: r#"{"app_namespace_prefix":"app-"}"#.into(),
                    app_ci_repository: None,
                },
                Root {
                    label: "app-edge/home".into(),
                    stack: "app-edge".into(),
                    app_id: Some("home".into()),
                    bucket: "exampleco-tools-tofu-state".into(),
                    prefix: "platform/app/home".into(),
                    inputs: "gcp/config/app-edge/home.tfvars".into(),
                    variables: r#"{"app_id":"home"}"#.into(),
                    app_ci_repository: None,
                },
            ],
            renderer: RENDERER
                .iter()
                .map(|(path, bytes)| Source {
                    path: (*path).to_owned(),
                    text: String::from_utf8(bytes.to_vec()).unwrap(),
                })
                .collect(),
            reviewed: None,
            releases: None,
            candidate: None,
        }
    }

    /// The synthetic `links` app's edge and day2-app roots after the shared roots, as `instance plan` renders them.
    fn app_request(mode: Mode) -> Request {
        let mut request = request();
        request.mode = mode;
        request.roots.truncate(3);
        request.roots.push(Root {
            label: "app-edge/links".into(),
            stack: "app-edge".into(),
            app_id: Some("links".into()),
            bucket: "exampleco-tools-tofu-state".into(),
            prefix: "platform/app/links".into(),
            inputs: "gcp/config/app-edge/links.tfvars".into(),
            variables: r#"{"app_id":"links"}"#.into(),
            app_ci_repository: None,
        });
        request.roots.push(Root {
            label: "day2-app/links".into(),
            stack: DAY2_APP.into(),
            app_id: Some("links".into()),
            bucket: "exampleco-tools-links-state".into(),
            prefix: "day2-app/links".into(),
            inputs: "gcp/config/apps/links.tfvars".into(),
            variables: r#"{"app_id":"links","namespace":"app-links"}"#.into(),
            app_ci_repository: None,
        });
        request.releases = Some(release::tests::releases());
        match mode {
            Mode::Plan => {}
            Mode::Apply => request.reviewed = Some("reviewed".into()),
            Mode::Deploy => {
                request.roots.drain(..4);
                request.candidate = Some("candidate.json".into());
            }
        }
        request
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
            forge: "/out/root/forge.tfvars.json".into(),
            release: "/out/root/release.tfvars.json".into(),
            plan: "/out/root/plan.bin".into(),
            target: "/out/root/target.bin".into(),
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
        let cases: [fn(&mut Request); 23] = [
            |r| r.roots[0].stack = "day2-app".into(),
            |r| r.roots[0].stack = "security-shell".into(),
            |r| r.roots[0].label = "cluster".into(),
            |r| r.roots[3].app_id = None,
            |r| r.roots[0].app_id = Some("home".into()),
            |r| r.roots[3].label = "app-edge/go".into(),
            |r| r.roots[3].inputs = "gcp/config/apps/home.tfvars".into(),
            |r| r.roots[3].inputs = "gcp/config/../../etc/passwd.tfvars".into(),
            |r| r.roots[0].inputs = "gcp/config/cluster.tfvars".into(),
            |r| r.roots[0].variables = "[]".into(),
            |r| r.roots[0].prefix = "foundation/".into(),
            |r| r.commit = "9724058".into(),
            |r| r.zone = "-us-central1-a".into(),
            |r| r.cluster = "-day2".into(),
            |r| r.roots.push(r.roots[0].clone()),
            // Apply order, backends and the reviewed plan are fixed.
            |r| r.roots.swap(0, 3),
            |r| r.roots.swap(1, 2),
            |r| {
                r.roots.remove(2);
            },
            |r| {
                let mut go = r.roots[3].clone();
                go.label = "app-edge/go".into();
                go.app_id = Some("go".into());
                go.inputs = "gcp/config/app-edge/go.tfvars".into();
                go.prefix = "platform/app/go".into();
                r.roots.push(go);
            },
            |r| r.roots[3].bucket = "exampleco-tools-home-state".into(),
            |r| r.roots[2].prefix = "platform/cluster".into(),
            |r| r.reviewed = Some("plan".into()),
            |r| r.mode = Mode::Apply,
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
        let (project, edge) = (&request.roots[0], &request.roots[3]);
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
        for inputs in ["project", "cluster", "tenancy", "app-edge/home"] {
            fs::write(instance.join(format!("gcp/config/{inputs}.tfvars")), "").unwrap();
        }
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
        let error = Session::prepare(&write(&request), Mode::Apply, Effects::native().unwrap())
            .err()
            .unwrap();
        assert!(
            format!("{error:#}")
                .contains("started an instance apply but the request is for an instance plan"),
            "{error:#}"
        );
        assert!(!scratch.path().join("plan").exists());
        // Not a git checkout.
        assert!(
            Session::prepare(&write(&request), Mode::Plan, Effects::native().unwrap()).is_err()
        );
        assert!(!scratch.path().join("plan").exists());
        // An output directory inside the instance or the checkout.
        for inside in [instance.join("plan"), platform.join("plan")] {
            request.output = inside.clone();
            let error = Session::prepare(&write(&request), Mode::Plan, Effects::native().unwrap())
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
        let error = Session::prepare(&write(&request), Mode::Plan, Effects::native().unwrap())
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
        let (project, edge) = (&request.roots[0], &request.roots[3]);
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
        assert!(
            refused(Mode::Apply, &progress, "app-edge/home", Stage::Init)
                .contains("runs only after cluster has applied")
        );
        for shared in ["cluster", "tenancy"] {
            finish(
                &mut progress,
                shared,
                &[Stage::Init, Stage::Plan, Stage::Show, Stage::Apply],
            );
        }
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
        assert_eq!(status(Failure::Unreviewed), "refused_unreviewed");
    }

    #[test]
    fn a_review_digest_covers_every_changed_value_and_ignores_quiet_resources() {
        let digest = |shown: Value| review_digest(&serde_json::to_vec(&shown).unwrap()).unwrap();
        let plan = |members: &str| {
            json!({"format_version": "1.2", "resource_changes": [
                {"address": "google_project_service.a", "change": {"actions": ["no-op"], "before": {"x": 1}, "after": {"x": 1}}},
                {"address": "data.google_client_config.c", "change": {"actions": ["read"], "after": {"access_token": "t"}}},
                {"address": "google_project_iam_member.m", "change": {"actions": ["update"],
                    "before": {"member": "user:a@example.com"}, "after": {"member": members}, "after_unknown": {}}},
            ], "output_changes": {"same": {"actions": ["no-op"]}}})
        };
        let reviewed = digest(plan("user:b@example.com"));
        assert!(reviewed.starts_with("sha256:"));
        // Key order and quiet resources do not matter; every changed value does.
        let mut reordered = plan("user:b@example.com");
        reordered["resource_changes"][0]["change"]["after"] = json!({"x": 2});
        reordered["resource_changes"][1]["change"]["after"] = json!({"access_token": "u"});
        assert_eq!(digest(reordered), reviewed);
        assert_ne!(digest(plan("user:c@example.com")), reviewed);
        let mut output = plan("user:b@example.com");
        output["output_changes"]["url"] =
            json!({"actions": ["update"], "before": "a", "after": "b"});
        assert_ne!(digest(output), reviewed);
        // A moved or imported no-op is a change to review.
        let mut moved = plan("user:b@example.com");
        moved["resource_changes"][0]["previous_address"] = json!("google_project_service.old");
        assert_ne!(digest(moved), reviewed);
        assert!(review_digest(br#"{"format_version":"1.2"}"#).is_err());
    }

    #[test]
    fn an_apply_accepts_only_a_successful_plan_of_the_same_roots_and_inputs() {
        let scratch = tempfile::tempdir().unwrap();
        let request = request();
        let inputs: BTreeMap<String, String> = request
            .roots
            .iter()
            .map(|root| (root.label.clone(), format!("sha256:i-{}", root.label)))
            .collect();
        let rendered: BTreeMap<String, String> = request
            .roots
            .iter()
            .map(|root| (root.label.clone(), format!("sha256:v-{}", root.label)))
            .collect();
        let receipt = || {
            json!({"format": 2, "mode": "plan", "ok": true, "commit": request.commit,
                "stacks_tree": "tree", "roots": request.roots.iter().map(|root| json!({
                    "label": root.label,
                    "backend": {"bucket": root.bucket, "prefix": root.prefix},
                    "inputs": {"path": root.inputs, "digest": inputs[&root.label]},
                    "variables": rendered[&root.label],
                    "status": "changes",
                    "review": format!("sha256:r-{}", root.label),
                })).collect::<Vec<_>>()})
        };
        let check = |receipt: &Value| {
            fs::write(
                scratch.path().join("receipt.json"),
                serde_json::to_vec(receipt).unwrap(),
            )
            .unwrap();
            reviewed_changes(scratch.path(), &request, "tree", &inputs, &rendered)
        };
        let reviewed = check(&receipt()).unwrap();
        assert_eq!(reviewed.changes["app-edge/home"], "sha256:r-app-edge/home");
        type Refusal = (fn(&mut Value), &'static str);
        let refusals: [Refusal; 8] = [
            (|r| r["mode"] = json!("apply"), "must hold an instance plan"),
            (|r| r["format"] = json!(1), "this platform's receipt format"),
            (
                |r| r["audit_error"] = json!("unexpected file"),
                "must hold an instance plan",
            ),
            (
                |r| r["stacks_tree"] = json!("other"),
                "another platform commit",
            ),
            (
                |r| r["roots"].as_array_mut().unwrap().truncate(3),
                "other roots",
            ),
            (
                |r| r["roots"][3]["variables"] = json!("sha256:other"),
                "inputs changed",
            ),
            (
                |r| r["roots"][1]["backend"]["prefix"] = json!("platform/other"),
                "backend or inputs changed",
            ),
            (
                |r| r["roots"][2]["status"] = json!("planned"),
                "unknown status for tenancy",
            ),
        ];
        for (edit, message) in refusals {
            let mut changed = receipt();
            edit(&mut changed);
            let error = format!("{:#}", check(&changed).unwrap_err());
            assert!(error.contains(message), "{error}");
        }
        // A plan where a root could not plan is accepted; that root has no reviewed
        // changes, so an apply refuses it unless it has nothing to change.
        let mut partial = receipt();
        partial["ok"] = json!(false);
        partial["roots"][2]["status"] = json!("failed_credentials");
        let reviewed = check(&partial).unwrap();
        assert!(
            reviewed.changes.contains_key("cluster") && !reviewed.changes.contains_key("tenancy")
        );
    }

    #[test]
    fn an_apply_reads_the_instance_only_as_committed() {
        let scratch = tempfile::tempdir().unwrap();
        let files: Vec<(String, &[u8])> = ["day2.json"]
            .into_iter()
            .map(str::to_owned)
            .chain(request().roots.iter().map(|root| root.inputs.clone()))
            .map(|path| (path, b"x = 1\n".as_slice()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, bytes)| (path.as_str(), *bytes))
            .collect();
        let (instance, commit) = repository(scratch.path(), &borrowed);
        let roots = request().roots;
        let read = |roots: &[Root]| -> BTreeMap<String, Vec<u8>> {
            roots
                .iter()
                .map(|root| {
                    (
                        root.label.clone(),
                        fs::read(instance.join(&root.inputs)).unwrap(),
                    )
                })
                .collect()
        };
        let committed = read(&roots);
        committed_at_head(&instance, &commit, true, &roots, &committed).unwrap();
        assert!(committed_at_head(&instance, &commit, false, &roots, &committed).is_err());
        assert!(committed_at_head(&instance, "", true, &roots, &committed).is_err());
        // The bytes actually read are compared, not a later read of the file.
        let mut edited = committed.clone();
        edited.insert("tenancy".into(), b"x = 2\n".to_vec());
        let error = format!(
            "{:#}",
            committed_at_head(&instance, &commit, true, &roots, &edited).unwrap_err()
        );
        assert!(error.contains("tenancy.tfvars differs"), "{error}");
        fs::write(instance.join("day2.json"), "{}").unwrap();
        let error = format!(
            "{:#}",
            committed_at_head(&instance, &commit, true, &roots, &committed).unwrap_err()
        );
        assert!(error.contains("day2.json differs"), "{error}");
    }

    #[test]
    fn an_apply_runs_only_an_unrefused_plan_with_changes() {
        let reviewed = "sha256:r".to_owned();
        let change = [json!({"address": "google_sa.new", "actions": ["create"]})];
        assert_eq!(
            apply_gate(Mode::Apply, &[], &[], "sha256:other", None),
            Ok(false)
        );
        assert_eq!(
            apply_gate(Mode::Apply, &change, &[], "sha256:r", Some(&reviewed)),
            Ok(true)
        );
        let refused = |destroys: &[String], review, reviewed| {
            apply_gate(Mode::Apply, &change, destroys, review, reviewed)
                .unwrap_err()
                .0
        };
        // A deploy has no reviewed plan; its selection binds it, and it still never destroys.
        assert_eq!(
            apply_gate(Mode::Deploy, &change, &[], "sha256:r", None),
            Ok(true)
        );
        assert_eq!(
            apply_gate(
                Mode::Deploy,
                &change,
                &["google_sa.old".into()],
                "sha256:r",
                None
            )
            .unwrap_err()
            .0,
            Failure::Destroys
        );
        assert_eq!(
            refused(&["google_sa.old".into()], "sha256:r", Some(&reviewed)),
            Failure::Destroys
        );
        assert_eq!(
            refused(&[], "sha256:other", Some(&reviewed)),
            Failure::Unreviewed
        );
        assert_eq!(refused(&[], "sha256:r", None), Failure::Unreviewed);
    }

    #[test]
    fn day2_app_roots_follow_every_edge_with_their_own_state_and_releases() {
        validate(&app_request(Mode::Plan)).unwrap();
        validate(&app_request(Mode::Apply)).unwrap();
        validate(&app_request(Mode::Deploy)).unwrap();
        let cases: [fn(&mut Request); 12] = [
            |r| r.roots[4].bucket = "exampleco-tools-tofu-state".into(),
            |r| r.roots[4].bucket = "exampleco-tools-home-state".into(),
            |r| r.roots[4].prefix = "day2-app/home".into(),
            |r| r.roots[4].inputs = "gcp/config/app-edge/links.tfvars".into(),
            |r| r.roots[4].app_id = None,
            |r| r.releases = None,
            |r| r.roots.swap(3, 4),
            |r| {
                r.roots.remove(3);
            },
            |r| r.candidate = Some("candidate.json".into()),
            |r| r.releases.as_mut().unwrap().bucket = "other-tofu-state".into(),
            |r| r.releases.as_mut().unwrap().forge.org = "Tools".into(),
            |r| r.roots[4].label = "day2-app/home".into(),
        ];
        for (index, edit) in cases.iter().enumerate() {
            let mut request = app_request(Mode::Plan);
            edit(&mut request);
            assert!(validate(&request).is_err(), "case {index}");
        }
        // A deploy runs exactly one day2-app root, for a candidate, with no reviewed plan.
        let deploys: [fn(&mut Request); 5] = [
            |r| r.candidate = None,
            |r| r.reviewed = Some("reviewed".into()),
            |r| r.roots.push(r.roots[0].clone()),
            |r| r.roots = request().roots[..1].to_vec(),
            |r| r.releases = None,
        ];
        for (index, edit) in deploys.iter().enumerate() {
            let mut request = app_request(Mode::Deploy);
            edit(&mut request);
            assert!(validate(&request).is_err(), "deploy case {index}");
        }
    }

    #[test]
    fn a_day2_app_root_plans_with_its_release_last_and_a_deploy_renders_only_its_target() {
        let request = app_request(Mode::Plan);
        let root = &request.roots[4];
        let credentials = Credentials {
            kubeconfig: Some(Path::new("/private/kubeconfig")),
            dns_token: Some("token"),
        };
        let (plan, env) = invocation(
            Mode::Plan,
            Stage::Plan,
            root,
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
                "-var-file=/out/root/release.tfvars.json",
                "-var=release_managed=false",
                "-var=rolling_deploys=false",
                "-var=workload_name=",
                "-var=security_shell_contract=null",
                "-out=/out/root/plan.bin",
                "-var=kubeconfig_path=/private/kubeconfig",
            ]
        );
        // The cluster, never the DNS token.
        let names: Vec<&str> = env.iter().map(|(name, _)| *name).collect();
        assert!(names.contains(&"KUBECONFIG") && !names.contains(&"CLOUDFLARE_API_TOKEN"));
        // A deploy's plan takes the lock; its target never does, and plans only the ConfigMap into its own file.
        let (plan, _) = invocation(
            Mode::Deploy,
            Stage::Plan,
            root,
            &layout(),
            false,
            &credentials,
        );
        assert!(strings(&plan).contains(&"-lock-timeout=300s".to_owned()));
        let (target, _) = invocation(
            Mode::Deploy,
            Stage::Target,
            root,
            &layout(),
            false,
            &credentials,
        );
        assert_eq!(
            strings(&target),
            [
                "-chdir=/out/root/stack",
                "plan",
                "-input=false",
                "-no-color",
                "-lock=false",
                "-target=kubernetes_config_map_v1.instance",
                "-var-file=/out/root/inputs.tfvars",
                "-var-file=/out/root/rendered.tfvars.json",
                "-var-file=/out/root/release.tfvars.json",
                "-var=release_managed=false",
                "-var=rolling_deploys=false",
                "-var=workload_name=",
                "-var=security_shell_contract=null",
                "-out=/out/root/target.bin",
                "-var=kubeconfig_path=/private/kubeconfig",
            ]
        );
        // An app edge has no release file.
        let (edge, _) = invocation(
            Mode::Plan,
            Stage::Plan,
            &request.roots[3],
            &layout(),
            false,
            &credentials,
        );
        assert!(
            !strings(&edge)
                .iter()
                .any(|arg| arg.contains("release.tfvars.json"))
        );
    }

    #[test]
    fn a_deploy_on_a_new_root_initializes_the_real_backend_so_its_apply_creates_state() {
        let request = app_request(Mode::Deploy);
        let root = &request.roots[0];
        assert!(plans_locally(Mode::Plan, true));
        assert!(!plans_locally(Mode::Deploy, true) && !plans_locally(Mode::Apply, true));
        let (init, _) = invocation(
            Mode::Deploy,
            Stage::Init,
            root,
            &layout(),
            plans_locally(Mode::Deploy, true),
            &Credentials {
                kubeconfig: None,
                dns_token: None,
            },
        );
        assert!(
            strings(&init)
                .contains(&"-backend-config=bucket=exampleco-tools-links-state".to_owned())
                && strings(&init).contains(&"-backend-config=prefix=day2-app/links".to_owned())
        );
        // A deploy builds its own private kubeconfig exactly as the session does.
        assert_eq!(
            strings(&kubeconfig_args("day2", "us-central1-a", "exampleco-tools")),
            [
                "container",
                "clusters",
                "get-credentials",
                "day2",
                "--zone",
                "us-central1-a",
                "--project",
                "exampleco-tools"
            ]
        );
        // A first install skips the target: release, init, selected, plan, show and apply are admitted in order.
        let mut progress: BTreeMap<String, Progress> =
            [(root.label.clone(), Progress::default())].into();
        for stage in [
            Stage::Release,
            Stage::Init,
            Stage::Selected,
            Stage::Plan,
            Stage::Show,
            Stage::Apply,
        ] {
            admit(Mode::Deploy, &request.roots, &progress, &root.label, stage).unwrap();
            progress.get_mut(&root.label).unwrap().done.insert(stage);
        }
    }

    #[test]
    fn deploy_deadlines_are_shorter_than_an_apply_s() {
        assert_eq!(
            Mode::Deploy.deadline(Stage::Apply),
            Deadline {
                run: Duration::from_secs(900),
                grace: Duration::from_secs(60)
            }
        );
        assert_eq!(
            Mode::Deploy.deadline(Stage::Plan),
            Deadline {
                run: Duration::from_secs(600),
                grace: Duration::from_secs(60)
            }
        );
        assert_eq!(Mode::Apply.deadline(Stage::Apply), ROOTS_APPLY);
        assert_eq!(Mode::Apply.deadline(Stage::Plan), ROOTS_PLAN);
        assert_eq!(ROOTS_APPLY.run, Duration::from_secs(7200));
        assert_eq!(ROOTS_APPLY.grace, Duration::from_secs(1800));
        assert_eq!(DEPLOY_SHOW, Duration::from_secs(60));
        assert_eq!(LOCK_TIMEOUT, "-lock-timeout=300s");
    }

    #[test]
    fn a_day2_app_root_reads_its_release_first_and_waits_for_its_own_edge() {
        let request = app_request(Mode::Apply);
        let roots = &request.roots;
        let fresh = || -> BTreeMap<String, Progress> {
            roots
                .iter()
                .map(|root| (root.label.clone(), Progress::default()))
                .collect()
        };
        let refused = |mode, progress: &BTreeMap<String, Progress>, label, stage| {
            format!(
                "{:#}",
                admit(mode, roots, progress, label, stage).unwrap_err()
            )
        };
        let mut progress = fresh();
        // A plan reads the release before init; no other root reads one.
        assert!(
            refused(Mode::Plan, &progress, "day2-app/links", Stage::Init).contains("needs release")
        );
        assert!(
            refused(Mode::Plan, &progress, "app-edge/links", Stage::Release)
                .contains("only a day2-app root")
        );
        admit(
            Mode::Plan,
            roots,
            &progress,
            "day2-app/links",
            Stage::Release,
        )
        .unwrap();
        // Only a deploy renders a target or checks its selection.
        for stage in [Stage::Target, Stage::Selected] {
            progress.get_mut("day2-app/links").unwrap().done = [Stage::Release, Stage::Init].into();
            assert!(
                refused(Mode::Plan, &progress, "day2-app/links", stage).contains("only a deploy")
            );
        }
        // An unreleased root runs nothing else.
        progress.get_mut("day2-app/links").unwrap().done = [Stage::Release].into();
        progress.get_mut("day2-app/links").unwrap().unreleased = true;
        assert!(
            refused(Mode::Plan, &progress, "day2-app/links", Stage::Init)
                .contains("no release selection")
        );
        // An apply runs a day2-app root only once the shared roots and its own app's edge have applied.
        let mut progress = fresh();
        for shared in ["project", "cluster", "tenancy"] {
            progress.get_mut(shared).unwrap().done =
                [Stage::Init, Stage::Plan, Stage::Show, Stage::Apply].into();
        }
        assert!(
            refused(Mode::Apply, &progress, "day2-app/links", Stage::Release)
                .contains("runs only after app-edge/links has applied")
        );
        progress.get_mut("app-edge/links").unwrap().failed = Some(Failure::Destroys);
        assert!(
            refused(Mode::Apply, &progress, "day2-app/links", Stage::Release)
                .contains("app-edge/links")
        );
        progress.get_mut("app-edge/links").unwrap().failed = None;
        progress.get_mut("app-edge/links").unwrap().done =
            [Stage::Init, Stage::Plan, Stage::Show, Stage::Apply].into();
        admit(
            Mode::Apply,
            roots,
            &progress,
            "day2-app/links",
            Stage::Release,
        )
        .unwrap();
        // A deploy renders its target after init and before its selection, and plans only after the selection.
        let deploy = app_request(Mode::Deploy);
        let mut progress: BTreeMap<String, Progress> =
            [("day2-app/links".to_owned(), Progress::default())].into();
        let refused = |progress: &BTreeMap<String, Progress>, stage| {
            format!(
                "{:#}",
                admit(
                    Mode::Deploy,
                    &deploy.roots,
                    progress,
                    "day2-app/links",
                    stage
                )
                .unwrap_err()
            )
        };
        progress.get_mut("day2-app/links").unwrap().done = [Stage::Release, Stage::Init].into();
        assert!(refused(&progress, Stage::Plan).contains("plan needs selected first"));
        admit(
            Mode::Deploy,
            &deploy.roots,
            &progress,
            "day2-app/links",
            Stage::Target,
        )
        .unwrap();
        progress.get_mut("day2-app/links").unwrap().done =
            [Stage::Release, Stage::Init, Stage::Target].into();
        assert!(refused(&progress, Stage::Target).contains("duplicate target"));
        assert!(refused(&progress, Stage::Apply).contains("apply needs show first"));
        progress.get_mut("day2-app/links").unwrap().done =
            [Stage::Release, Stage::Init, Stage::Selected].into();
        assert!(refused(&progress, Stage::Target).contains("before it checks its selection"));
        assert_eq!(status(Failure::Inputs), "failed_inputs");
        assert_eq!(status(Failure::Release), "failed_release");
        assert_eq!(status(Failure::Stage(Stage::Target)), "failed_target");
    }

    #[test]
    fn an_apply_runs_a_day2_app_root_only_with_its_reviewed_release() {
        let reviewed: BTreeMap<String, Option<String>> = [
            ("day2-app/go".to_owned(), Some("sha256:a".to_owned())),
            ("day2-app/home".to_owned(), None),
        ]
        .into();
        assert!(release_reviewed(&reviewed, "day2-app/go", Some("sha256:a")).is_ok());
        assert!(release_reviewed(&reviewed, "day2-app/home", None).is_ok());
        // A root the reviewed plan could not plan is left to the changes gate.
        assert!(release_reviewed(&reviewed, "day2-app/links", Some("sha256:x")).is_ok());
        assert_eq!(
            release_reviewed(&reviewed, "day2-app/go", Some("sha256:b"))
                .unwrap_err()
                .0,
            Failure::Unreviewed
        );
        assert_eq!(
            release_reviewed(&reviewed, "day2-app/home", Some("sha256:a"))
                .unwrap_err()
                .0,
            Failure::Unreviewed
        );
        assert_eq!(
            release_reviewed(&reviewed, "day2-app/go", None)
                .unwrap_err()
                .0,
            Failure::Release
        );
    }

    #[test]
    fn a_reviewed_plan_records_each_day2_app_root_s_release() {
        let scratch = tempfile::tempdir().unwrap();
        let request = app_request(Mode::Apply);
        let digests = |prefix: &str| -> BTreeMap<String, String> {
            request
                .roots
                .iter()
                .map(|root| {
                    (
                        root.label.clone(),
                        format!("sha256:{prefix}-{}", root.label),
                    )
                })
                .collect()
        };
        let (inputs, rendered) = (digests("i"), digests("v"));
        let receipt = |status: &str, release: Value| {
            json!({"format": 2, "mode": "plan", "ok": true, "commit": request.commit,
                "stacks_tree": "tree", "roots": request.roots.iter().map(|root| json!({
                    "label": root.label,
                    "backend": {"bucket": root.bucket, "prefix": root.prefix},
                    "inputs": {"path": root.inputs, "digest": inputs[&root.label]},
                    "variables": rendered[&root.label],
                    "status": if root.stack == DAY2_APP { status } else { "no_changes" },
                    "review": "sha256:r",
                    "release": if root.stack == DAY2_APP { release.clone() } else { Value::Null },
                })).collect::<Vec<_>>()})
        };
        let check = |receipt: &Value| {
            fs::write(
                scratch.path().join("receipt.json"),
                serde_json::to_vec(receipt).unwrap(),
            )
            .unwrap();
            reviewed_changes(scratch.path(), &request, "tree", &inputs, &rendered)
        };
        let reviewed = check(&receipt("changes", json!({"variables": "sha256:release"}))).unwrap();
        assert_eq!(
            reviewed.releases["day2-app/links"],
            Some("sha256:release".to_owned())
        );
        let reviewed = check(&receipt("unreleased", Value::Null)).unwrap();
        assert_eq!(reviewed.releases["day2-app/links"], None);
        assert!(!reviewed.changes.contains_key("day2-app/links"));
        let reviewed = check(&receipt("failed_release", Value::Null)).unwrap();
        assert!(!reviewed.releases.contains_key("day2-app/links"));
        // A planned day2-app root must say which release it planned.
        assert!(check(&receipt("changes", Value::Null)).is_err());
    }

    #[test]
    fn a_target_is_the_known_instance_json_of_the_one_instance_config_map() {
        let shown = |change: Value| {
            serde_json::to_vec(&json!({"format_version": "1.2", "resource_changes": [
                {"address": "terraform_data.native_admission", "change": {"actions": ["no-op"]}},
                change,
            ]}))
            .unwrap()
        };
        let instance = "{\"apps\":{\"links\":{\"artifact\":\"artifacts/ab\"}},\"name\":\"é\"}";
        let config_map = |after: Value, unknown: Value| {
            json!({"address": TARGET, "change": {"actions": ["no-op"], "after": after,
                "after_unknown": unknown}})
        };
        assert_eq!(
            target_instance(&shown(config_map(
                json!({"data": {"instance.json": instance}}),
                json!({"data": {}})
            )))
            .unwrap(),
            instance.as_bytes()
        );
        for (after, unknown) in [
            (
                json!({"data": {"instance.json": instance}}),
                json!({"data": true}),
            ),
            (
                json!({"data": {}}),
                json!({"data": {"instance.json": true}}),
            ),
            (json!({"data": {}}), json!({})),
            (json!({"data": {"instance.json": 1}}), json!({})),
        ] {
            assert!(target_instance(&shown(config_map(after, unknown))).is_err());
        }
        let twice = serde_json::to_vec(&json!({"format_version": "1.2", "resource_changes": [
            config_map(json!({"data": {"instance.json": instance}}), json!({})),
            config_map(json!({"data": {"instance.json": instance}}), json!({})),
        ]}))
        .unwrap();
        assert!(target_instance(&twice).is_err());
        assert!(target_instance(br#"{"format_version":"1.2","resource_changes":[]}"#).is_err());
    }

    /// A session staged by hand for `request`, with release state in `objects`, the release bucket holding
    /// `manifest`, and each root's committed inputs (empty unless given).
    fn staged(
        request: Request,
        objects: release::tests::Objects,
        manifest: &[u8],
        committed: &[(&str, &[u8])],
    ) -> (tempfile::TempDir, Session) {
        let scratch = tempfile::tempdir().unwrap();
        let output = scratch.path().join("out");
        fs::create_dir(&output).unwrap();
        let bucket = crate::instance_source::tests::Fake::default();
        let identity = day2::sdk_release::BlobIdentity::of(manifest);
        bucket.0.borrow_mut().objects.insert(
            format!(
                "{}/{}",
                release::tests::releases().objects(),
                &identity.digest[7..]
            ),
            manifest.to_vec(),
        );
        let mut layouts = BTreeMap::new();
        for root in &request.roots {
            let directory = output.join(root.label.replace('/', "-"));
            fs::create_dir(&directory).unwrap();
            layouts.insert(
                root.label.clone(),
                Layout {
                    config: output.join("tofurc"),
                    stack: directory.join("stack"),
                    data: directory.join("data"),
                    inputs: directory.join("inputs.tfvars"),
                    rendered: directory.join("rendered.tfvars.json"),
                    forge: directory.join("forge.tfvars.json"),
                    release: directory.join("release.tfvars.json"),
                    plan: directory.join("plan.bin"),
                    target: directory.join("target.bin"),
                },
            );
        }
        let committed = request
            .roots
            .iter()
            .map(|root| {
                let bytes = committed
                    .iter()
                    .find(|(label, _)| *label == root.label)
                    .map_or(Vec::new(), |(_, bytes)| bytes.to_vec());
                (root.label.clone(), bytes)
            })
            .collect();
        let labels = |value: &str| -> BTreeMap<String, String> {
            request
                .roots
                .iter()
                .map(|root| (root.label.clone(), value.to_owned()))
                .collect()
        };
        let session = Session {
            effects: Effects {
                store: Box::new(objects),
                tools: Box::new(bucket.clone()),
                cache: Some(scratch.path().join("cache")),
                forge: Box::new(bucket.clone()),
                token: Some(crate::instance_source::tests::TOKEN.into()),
                waiting: Box::new(bucket),
            },
            committed,
            instance: scratch.path().join("instance"),
            instance_commit: String::new(),
            instance_clean: false,
            platform: scratch.path().join("platform"),
            stacks_tree: "tree".into(),
            output,
            engine_digest: "sha256:e".into(),
            layouts,
            inputs: labels("sha256:i"),
            rendered: labels("sha256:v"),
            private: tempfile::tempdir().unwrap(),
            kubeconfig: None,
            kubeconfig_current: true,
            kubeconfig_refreshed: false,
            dns_token: None,
            credentials_read: true,
            app_ci_failed: BTreeMap::new(),
            reviewed: Reviewed::default(),
            progress: request
                .roots
                .iter()
                .map(|root| (root.label.clone(), Progress::default()))
                .collect(),
            request,
        };
        (scratch, session)
    }

    fn selection(candidate: &Value) -> release::tests::Objects {
        release::tests::stored(&json!({"version": 1, "status": "ready", "candidate": candidate}))
    }

    #[test]
    fn a_plan_reads_each_app_s_selection_and_renders_its_release() {
        let (candidate, manifest) = crate::instance_candidate::tests::selected_candidate();
        let (_scratch, mut session) = staged(
            app_request(Mode::Plan),
            selection(&candidate),
            &manifest,
            &[],
        );
        let result = session.operation("day2-app/links", "release").unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["released"], true);
        assert_eq!(result["release"]["image"], candidate["image"]);
        assert_eq!(
            result["release"]["candidate"],
            release::candidate_digest(&candidate).unwrap()
        );
        let written = fs::read(&session.layouts["day2-app/links"].release).unwrap();
        assert_eq!(written, release::variables(&candidate).unwrap());
        assert!(
            session.progress["day2-app/links"]
                .done
                .contains(&Stage::Release)
        );
        // An app with no selection is unreleased and runs nothing else.
        let (_scratch, mut session) = staged(
            app_request(Mode::Plan),
            release::tests::Objects::default(),
            &manifest,
            &[],
        );
        let result = session.operation("day2-app/links", "release").unwrap();
        assert_eq!(
            result,
            json!({"ok": true, "released": false, "release": null})
        );
        assert!(session.operation("day2-app/links", "init").is_err());
        assert!(!session.layouts["day2-app/links"].release.exists());
    }

    #[test]
    fn a_release_that_cannot_be_read_or_restates_an_owned_input_fails_only_its_root() {
        let (candidate, manifest) = crate::instance_candidate::tests::selected_candidate();
        let mut failing = release::tests::Objects::default();
        failing.0.insert(release::tests::URI.into(), None);
        let (_scratch, mut session) = staged(app_request(Mode::Plan), failing, &manifest, &[]);
        let result = session.operation("day2-app/links", "release").unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(
            session.progress["day2-app/links"].failed,
            Some(Failure::Release)
        );
        let error =
            fs::read_to_string(session.output.join("day2-app-links/release.error")).unwrap();
        assert!(error.contains("not absence"), "{error}");
        // The rest still run.
        admit(
            Mode::Plan,
            &session.request.roots,
            &session.progress,
            "app-edge/links",
            Stage::Init,
        )
        .unwrap();
        // A committed copy of a rendered or platform-owned variable fails the root before anything is read.
        for committed in [
            b"namespace = \"app-other\"\n".as_slice(),
            b"workload_name = \"x\"\n",
            b"security_shell_contract = {\n  namespace = \"s\"\n  name = \"c\"\n}\n",
        ] {
            let (_scratch, mut session) = staged(
                app_request(Mode::Plan),
                selection(&candidate),
                &manifest,
                &[("day2-app/links", committed)],
            );
            session.operation("day2-app/links", "release").unwrap();
            assert_eq!(
                session.progress["day2-app/links"].failed,
                Some(Failure::Inputs)
            );
            let error =
                fs::read_to_string(session.output.join("day2-app-links/release.error")).unwrap();
            assert!(
                error.starts_with("gcp/config/apps/links.tfvars sets "),
                "{error}"
            );
        }
        // The bootstrap image and artifact may stay committed: the release wins over them.
        let (_scratch, mut session) = staged(
            app_request(Mode::Plan),
            selection(&candidate),
            &manifest,
            &[(
                "day2-app/links",
                b"image = \"r/links/links@sha256:00\"\nartifact_id = \"00\"\n",
            )],
        );
        assert_eq!(
            session.operation("day2-app/links", "release").unwrap()["ok"],
            true
        );
    }

    #[test]
    fn an_apply_refuses_a_release_that_changed_since_the_reviewed_plan() {
        let (candidate, manifest) = crate::instance_candidate::tests::selected_candidate();
        let applied = |objects| {
            let (scratch, mut session) = staged(app_request(Mode::Apply), objects, &manifest, &[]);
            for label in ["project", "cluster", "tenancy", "app-edge/links"] {
                session.progress.get_mut(label).unwrap().done =
                    [Stage::Init, Stage::Plan, Stage::Show, Stage::Apply].into();
            }
            (scratch, session)
        };
        let variables = day2::digest(&release::variables(&candidate).unwrap());
        let (_scratch, mut session) = applied(selection(&candidate));
        session.reviewed.releases = [("day2-app/links".to_owned(), Some(variables.clone()))].into();
        assert_eq!(
            session.operation("day2-app/links", "release").unwrap()["ok"],
            true
        );
        let (_scratch, mut session) = applied(selection(&candidate));
        session.reviewed.releases = [("day2-app/links".to_owned(), None)].into();
        session.operation("day2-app/links", "release").unwrap();
        assert_eq!(
            session.progress["day2-app/links"].failed,
            Some(Failure::Unreviewed)
        );
        // A matching reviewed plan cannot substitute for activation or a guarded first install.
        let activating = release::tests::stored(
            &json!({"version": 1, "status": "activating", "candidate": candidate}),
        );
        let (_scratch, mut session) = applied(activating);
        session.reviewed.releases = [("day2-app/links".to_owned(), Some(variables))].into();
        assert_eq!(
            session.operation("day2-app/links", "release").unwrap()["ok"],
            false
        );
        assert_eq!(
            session.progress["day2-app/links"].failed,
            Some(Failure::Release)
        );
        assert!(session.operation("day2-app/links", "init").is_err());
    }

    #[test]
    fn a_deploy_renders_its_candidate_and_applies_only_once_the_selection_names_it() {
        let (candidate, manifest) = crate::instance_candidate::tests::selected_candidate();
        let deploy = |objects: release::tests::Objects, file: &[u8]| {
            let (scratch, mut session) = staged(app_request(Mode::Deploy), objects, &manifest, &[]);
            let path = scratch.path().join("candidate.json");
            fs::write(&path, file).unwrap();
            session.request.candidate = Some(path);
            (scratch, session)
        };
        let record = crate::instance_candidate::record::encode(&candidate).unwrap();
        // Not selected yet: the candidate still renders, so a target can be planned before the selection is written.
        let (_scratch, mut session) = deploy(release::tests::Objects::default(), &record);
        let result = session.operation("day2-app/links", "release").unwrap();
        assert_eq!(result["released"], true);
        assert_eq!(
            result["release"]["tooling_image"],
            candidate["binding"]["tooling_image"]
        );
        session
            .progress
            .get_mut("day2-app/links")
            .unwrap()
            .done
            .insert(Stage::Init);
        assert_eq!(
            session.operation("day2-app/links", "selected").unwrap(),
            json!({"ok": false})
        );
        assert_eq!(
            session.progress["day2-app/links"].failed,
            Some(Failure::Release)
        );
        // Selected: the check passes and the receipt records the selection it checked.
        let (_scratch, mut session) = deploy(selection(&candidate), &record);
        session.operation("day2-app/links", "release").unwrap();
        session
            .progress
            .get_mut("day2-app/links")
            .unwrap()
            .done
            .insert(Stage::Init);
        assert_eq!(
            session.operation("day2-app/links", "selected").unwrap(),
            json!({"ok": true})
        );
        let receipt = session.receipt().unwrap();
        let root = &receipt["roots"][0];
        assert_eq!(receipt["format"], RECEIPT_FORMAT);
        assert_eq!(receipt["mode"], "deploy");
        assert_eq!(root["status"], "not_applied");
        assert_eq!(root["release"]["source"], "candidate");
        assert_eq!(root["release"]["status"], "ready");
        assert_eq!(root["release"]["generation"], "1700000000000001");
        assert_eq!(root["target"], Value::Null);
        // Another candidate in the selection is refused.
        let mut other = candidate.clone();
        other["source_commit"] = json!("89abcdef0123456789abcdef0123456789abcdef");
        let (_scratch, mut session) = deploy(selection(&other), &record);
        session.operation("day2-app/links", "release").unwrap();
        session
            .progress
            .get_mut("day2-app/links")
            .unwrap()
            .done
            .insert(Stage::Init);
        assert_eq!(
            session.operation("day2-app/links", "selected").unwrap()["ok"],
            false
        );
        // A candidate for another app, or a file that is not a record, fails the release.
        let mut notes = candidate.clone();
        notes["binding"]["app"] = json!("notes");
        for file in [
            crate::instance_candidate::record::encode(&notes).unwrap(),
            b"not json".to_vec(),
        ] {
            let (_scratch, mut session) = deploy(selection(&candidate), &file);
            assert_eq!(
                session.operation("day2-app/links", "release").unwrap()["ok"],
                false
            );
            assert_eq!(
                session.progress["day2-app/links"].failed,
                Some(Failure::Release)
            );
        }
    }

    #[test]
    fn a_receipt_reports_unreleased_and_skipped_day2_app_roots() {
        let (candidate, manifest) = crate::instance_candidate::tests::selected_candidate();
        let (_scratch, mut session) = staged(
            app_request(Mode::Apply),
            selection(&candidate),
            &manifest,
            &[],
        );
        for label in ["project", "cluster", "tenancy"] {
            session.progress.get_mut(label).unwrap().done =
                [Stage::Init, Stage::Plan, Stage::Show, Stage::Apply].into();
        }
        // The app's edge failed, so its day2-app root never ran.
        session.progress.get_mut("app-edge/links").unwrap().failed = Some(Failure::Destroys);
        let receipt = session.receipt().unwrap();
        let statuses: Vec<&str> = receipt["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|root| root["status"].as_str().unwrap())
            .collect();
        assert_eq!(
            statuses,
            [
                "no_changes",
                "no_changes",
                "no_changes",
                "refused_destroy",
                "skipped"
            ]
        );
        assert_eq!(receipt["ok"], false);
        fs::remove_file(session.output.join("receipt.json")).unwrap();
        // An unreleased root is not a failure.
        session.progress.get_mut("app-edge/links").unwrap().failed = None;
        session.progress.get_mut("app-edge/links").unwrap().done =
            [Stage::Init, Stage::Plan, Stage::Show, Stage::Apply].into();
        session
            .progress
            .get_mut("day2-app/links")
            .unwrap()
            .unreleased = true;
        let receipt = session.receipt().unwrap();
        assert_eq!(receipt["roots"][4]["status"], "unreleased");
        assert_eq!(receipt["roots"][4]["release"], Value::Null);
        assert_eq!(receipt["ok"], true);
    }

    /// `app_request` as the CLI renders it with forge.oidc: the project root and the edge trust their repositories.
    fn ci_request(mode: Mode) -> Request {
        let mut request = app_request(mode);
        for root in &mut request.roots {
            let (repository, app_ci) = match root.stack.as_str() {
                "project" => (
                    "tools/day2-ci",
                    json!({"issuer_uri": "https://oidc.example.com", "repository": "tools/day2-ci"}),
                ),
                "app-edge" => (
                    "tools/links",
                    json!({"bucket": "exampleco-tools-links-ci",
                           "reader": "serviceAccount:tools-infra@exampleco-tools.iam.gserviceaccount.com"}),
                ),
                _ => continue,
            };
            let mut variables: Value = serde_json::from_str(&root.variables).unwrap();
            variables["app_ci"] = app_ci;
            root.variables = variables.to_string();
            root.app_ci_repository = Some(repository.into());
        }
        request
    }

    fn repository_record(
        id: u64,
        full_name: &str,
        owner: &str,
    ) -> Option<crate::instance_source::Response> {
        crate::instance_source::tests::ok(json!({
            "id": id, "full_name": full_name, "owner": {"id": 74, "login": owner},
        }))
    }

    const DAY2_CI: &str = "https://git.example.com/api/v1/repos/tools/day2-ci";
    const LINKS: &str = "https://git.example.com/api/v1/repos/tools/links";

    #[test]
    fn app_ci_is_all_or_nothing_and_trusts_only_derived_repositories() {
        validate(&app_request(Mode::Plan)).unwrap();
        validate(&ci_request(Mode::Plan)).unwrap();
        validate(&ci_request(Mode::Apply)).unwrap();
        let cases: [fn(&mut Request); 9] = [
            // The project root and every edge, or none.
            |r| r.roots[0].app_ci_repository = None,
            |r| r.roots[3].app_ci_repository = None,
            // Only the derived repositories, in the instance's org.
            |r| r.roots[0].app_ci_repository = Some("tools/day2-instance".into()),
            |r| r.roots[3].app_ci_repository = Some("tools/other".into()),
            |r| r.roots[3].app_ci_repository = Some("Tools/links".into()),
            // No other root, and never without the rendered variable or with the forge IDs rendered.
            |r| r.roots[1].app_ci_repository = Some("tools/day2-ci".into()),
            |r| r.roots[0].variables = r#"{"project_id":"exampleco-tools"}"#.into(),
            |r| {
                r.roots[3].variables =
                    r#"{"app_id":"links","app_ci":{},"app_ci_forge":{"repository_id":"1"}}"#.into()
            },
            |r| r.releases = None,
        ];
        for (index, edit) in cases.iter().enumerate() {
            let mut request = ci_request(Mode::Plan);
            edit(&mut request);
            assert!(validate(&request).is_err(), "case {index}");
        }
        // Without forge.oidc no root may render app CI.
        let mut request = app_request(Mode::Plan);
        request.roots[3].variables = r#"{"app_id":"links","app_ci":{}}"#.into();
        assert!(validate(&request).is_err());
    }

    #[test]
    fn app_ci_roots_plan_with_their_forge_ids_after_the_rendered_variables() {
        let request = ci_request(Mode::Plan);
        let credentials = Credentials {
            kubeconfig: Some(Path::new("/private/kubeconfig")),
            dns_token: Some("token"),
        };
        for root in [&request.roots[0], &request.roots[3]] {
            let (plan, _) = invocation(
                Mode::Plan,
                Stage::Plan,
                root,
                &layout(),
                false,
                &credentials,
            );
            assert_eq!(
                strings(&plan)[5..8],
                [
                    "-var-file=/out/root/inputs.tfvars",
                    "-var-file=/out/root/rendered.tfvars.json",
                    "-var-file=/out/root/forge.tfvars.json",
                ],
                "{}",
                root.label
            );
            assert_eq!(strings(&plan)[8], "-out=/out/root/plan.bin");
        }
        // Every other root, and every root without forge.oidc, plans as before.
        for root in request.roots[1..3]
            .iter()
            .chain(&app_request(Mode::Plan).roots)
        {
            let (plan, _) = invocation(
                Mode::Plan,
                Stage::Plan,
                root,
                &layout(),
                false,
                &credentials,
            );
            assert!(
                !strings(&plan).iter().any(|arg| arg.contains("forge")),
                "{}",
                root.label
            );
        }
    }

    #[test]
    fn app_ci_reads_each_repository_s_forge_ids_once() {
        let (_scratch, mut session) = staged(
            ci_request(Mode::Plan),
            release::tests::Objects::default(),
            b"manifest",
            &[],
        );
        let forge = crate::instance_source::tests::Fake::default();
        forge.route(
            DAY2_CI,
            vec![repository_record(412, "tools/day2-ci", "tools")],
        );
        forge.route(LINKS, vec![repository_record(245, "tools/links", "tools")]);
        session.effects.forge = Box::new(forge.clone());
        session.read_app_ci().unwrap();
        assert_eq!(
            forge.calls(),
            [(DAY2_CI.to_owned(), true), (LINKS.to_owned(), true)]
        );
        let written = |label: &str| -> Value {
            serde_json::from_slice(&fs::read(&session.layouts[label].forge).unwrap()).unwrap()
        };
        assert_eq!(
            written("project"),
            json!({"app_ci_forge": {"repository_id": "412", "owner_id": "74"}})
        );
        assert_eq!(
            written("app-edge/links"),
            json!({"app_ci_forge": {"repository_id": "245"}})
        );
        assert!(session.app_ci_failed.is_empty());
        for label in ["cluster", "tenancy", "day2-app/links"] {
            assert!(!session.layouts[label].forge.exists(), "{label}");
        }
    }

    #[test]
    fn an_unreadable_app_ci_repository_fails_only_its_root() {
        for (answer, reason) in [
            (
                crate::instance_source::tests::status(404),
                "forge_repository_missing",
            ),
            (
                crate::instance_source::tests::status(301),
                "forge_repository_http_301",
            ),
            (
                repository_record(412, "Tools/day2-ci", "tools"),
                "forge_repository_mismatch",
            ),
            (
                repository_record(412, "tools/day2-ci", "other"),
                "forge_repository_mismatch",
            ),
            (
                repository_record(0, "tools/day2-ci", "tools"),
                "forge_repository_id_invalid",
            ),
        ] {
            let (_scratch, mut session) = staged(
                ci_request(Mode::Plan),
                release::tests::Objects::default(),
                b"manifest",
                &[],
            );
            let forge = crate::instance_source::tests::Fake::default();
            forge.route(DAY2_CI, vec![answer]);
            forge.route(LINKS, vec![repository_record(245, "tools/links", "tools")]);
            session.effects.forge = Box::new(forge);
            session.read_app_ci().unwrap();
            let error = fs::read_to_string(session.output.join("project/forge.error")).unwrap();
            assert_eq!(
                error,
                format!("read tools/day2-ci on https://git.example.com: {reason}")
            );
            assert!(!session.layouts["project"].forge.exists());
            // The root fails at its init, before the engine runs; the edge still has its IDs.
            assert_eq!(
                session.operation("project", "init").unwrap(),
                json!({"ok": false})
            );
            assert_eq!(session.progress["project"].failed, Some(Failure::Forge));
            assert_eq!(status(Failure::Forge), "failed_forge");
            assert!(session.layouts["app-edge/links"].forge.exists());
            assert!(!session.app_ci_failed.contains_key("app-edge/links"));
        }
    }

    #[test]
    fn app_ci_reads_retry_only_unanswered_repositories_within_one_budget() {
        let (_scratch, mut session) = staged(
            ci_request(Mode::Plan),
            release::tests::Objects::default(),
            b"manifest",
            &[],
        );
        // A failed connection, then a 503, then the record: only day2-ci is read again.
        let forge = crate::instance_source::tests::Fake::default();
        forge.route(
            DAY2_CI,
            vec![
                None,
                crate::instance_source::tests::status(503),
                repository_record(412, "tools/day2-ci", "tools"),
            ],
        );
        forge.route(LINKS, vec![repository_record(245, "tools/links", "tools")]);
        session.effects.forge = Box::new(forge.clone());
        session.read_app_ci().unwrap();
        assert_eq!(
            forge
                .calls()
                .iter()
                .map(|(url, _)| url.as_str())
                .collect::<Vec<_>>(),
            [DAY2_CI, LINKS, DAY2_CI, DAY2_CI]
        );
        assert!(session.app_ci_failed.is_empty());
        assert!(session.layouts["project"].forge.exists());
        // A forge that stays down fails each unanswered root once the budget is spent; without a token the
        // message says so.
        let (_scratch, mut session) = staged(
            ci_request(Mode::Plan),
            release::tests::Objects::default(),
            b"manifest",
            &[],
        );
        let forge = crate::instance_source::tests::Fake::default();
        forge.route(DAY2_CI, vec![None]);
        forge.route(LINKS, vec![crate::instance_source::tests::status(404)]);
        session.effects.forge = Box::new(forge.clone());
        session.effects.token = None;
        session.read_app_ci().unwrap();
        let error = fs::read_to_string(session.output.join("project/forge.error")).unwrap();
        assert!(
            error.starts_with("read tools/day2-ci on https://git.example.com: app CI's forge reads did not succeed within 120s")
                && error.ends_with("; no forge token was set (AUTODEPLOY_SOURCE_TOKEN, else GITEA_TOKEN)"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(session.output.join("app-edge-links/forge.error")).unwrap(),
            "read tools/links on https://git.example.com: forge_repository_missing; \
             no forge token was set (AUTODEPLOY_SOURCE_TOKEN, else GITEA_TOKEN)"
        );
        // The 404 is permanent: links was read once, day2-ci until the budget ran out.
        let calls = forge.calls();
        assert_eq!(calls.iter().filter(|(url, _)| url == LINKS).count(), 1);
        assert!(calls.iter().filter(|(url, _)| url == DAY2_CI).count() > 1);
        assert!(calls.iter().all(|(_, authenticated)| !authenticated));
        assert_eq!(session.app_ci_failed.len(), 2);
    }

    #[test]
    fn app_ci_variables_are_never_committed_and_nothing_is_read_without_forge_oidc() {
        // Without forge.oidc nothing is read (the fake refuses any request) and no IDs are written.
        let (_scratch, mut session) = staged(
            app_request(Mode::Plan),
            release::tests::Objects::default(),
            b"manifest",
            &[],
        );
        let forge = crate::instance_source::tests::Fake::default();
        session.effects.forge = Box::new(forge.clone());
        session.read_app_ci().unwrap();
        assert!(forge.calls().is_empty());
        assert!(session.app_ci_failed.is_empty());
        assert!(
            session
                .layouts
                .values()
                .all(|layout| !layout.forge.exists())
        );
        // A committed app CI variable fails its root, indented or not, with or without forge.oidc.
        for request in [app_request(Mode::Plan), ci_request(Mode::Plan)] {
            let (_scratch, mut session) = staged(
                request,
                release::tests::Objects::default(),
                b"manifest",
                &[
                    (
                        "project",
                        b"\t app_ci_forge = {\n  repository_id = \"1\"\n}\n".as_slice(),
                    ),
                    ("app-edge/links", b"\"app_ci\" = null\n"),
                ],
            );
            let forge = crate::instance_source::tests::Fake::default();
            session.effects.forge = Box::new(forge.clone());
            session.read_app_ci().unwrap();
            assert!(forge.calls().is_empty());
            assert_eq!(
                fs::read_to_string(session.output.join("project/inputs.error")).unwrap(),
                "gcp/config/project.tfvars sets app_ci_forge, which app CI owns"
            );
            assert_eq!(session.app_ci_failed["app-edge/links"], Failure::Inputs);
            assert_eq!(
                session.operation("app-edge/links", "init").unwrap(),
                json!({"ok": false})
            );
            assert_eq!(
                session.progress["app-edge/links"].failed,
                Some(Failure::Inputs)
            );
        }
    }
}
