//! `day2 instance deploy`: the non-rolling deploy of an app's checked,
//! preflighted candidate, which the instance's earlier controller ran as
//! `Deployer.deploy` (`maintain.sh backup`, the archive, `maintain.sh
//! activate`, the day2-app apply, the rollout wait and the readback).
//!
//! - **Maintenance** runs the candidate's own SDK operator as a child process
//!   (`day2 platform maintain backup|activate`), so the session's in-pod
//!   protocol always matches the app's tooling image. The operator comes from
//!   the release cache and runs from a private copy whose bytes were checked.
//! - **The request** carries the earlier `maintain.sh`'s values (`request`).
//! - **Backups** are archived where the controller archived them, never
//!   replaced and checked against a local manifest (`archive`).
//! - **The migration fence** decides the path a run takes and what a failure
//!   means (`fence`): before the fence the operator restores the app on its
//!   image (exit 6); after it the old image never restarts and only a rerun of
//!   the same candidate rolls forward (exit 8, `deploy_fenced`). A transient
//!   read before anything stopped is retryable (exit 7).
//!
//! InstanceDeploy.roc orders the steps; this session validates the request
//! first, refuses a step out of order or outside the path its own observation
//! chose, and always ends with the archive of whatever the operator left and a
//! classification of any failure from the cluster as it is afterwards.
pub mod archive;
pub mod fence;
pub mod request;
pub mod tools;

#[cfg(test)]
mod tests;

use crate::instance_candidate::{
    read_bounded, record,
    tools::{Gcloud, Store, write_private},
};
use crate::instance_release;
use crate::instance_roots::{self, release};
use crate::instance_source::{self, App, File};
use anyhow::{Context, Result, anyhow, bail, ensure};
use archive::Totals;
use day2::sdk_release::{self, BlobIdentity, DISTRIBUTION_LIMIT, Distribution, FILE_LIMIT};
use fence::{Claim, Class, Observed, Path as Route, Stage, Workload};
use request::{Attempt, Live, Names, Operation, Target};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const REQUEST_LIMIT: u64 = 65_536;
/// The most a desired instance may hold, as the operator reads it.
const INSTANCE_LIMIT: u64 = 1 << 20;
/// The operator CLI's files, which run from the session's private copy.
pub const CLI_FILES: [&str; 4] = [
    "cli/day2",
    "cli/day2-host",
    "cli/day2-workflows",
    "cli/day2-workflows.json",
];
/// The cluster every app runs on.
pub const CLUSTER: &str = "day2";

/// The instance names the CLI derived from day2.json.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    pub project: String,
    pub zone: String,
    pub cluster: String,
    /// `<region>-docker.pkg.dev/<project>`.
    pub registry: String,
    /// `<project>-tofu-state`.
    pub bucket: String,
    pub server: String,
    pub org: String,
    /// `<org>-infra@<project>.iam.gserviceaccount.com`.
    pub apply_identity: String,
    pub apps: Vec<App>,
}

impl Instance {
    fn releases(&self) -> release::Releases {
        release::Releases {
            bucket: self.bucket.clone(),
            registry: self.registry.clone(),
            forge: release::Forge {
                server: self.server.clone(),
                org: self.org.clone(),
            },
        }
    }

    fn validate(&self) -> Result<()> {
        let lower = |value: &str| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        self.releases().validate(&self.project)?;
        ensure!(
            lower(&self.zone) && self.zone.matches('-').count() == 2,
            "the instance zone must be <region>-<zone>"
        );
        ensure!(
            self.cluster == CLUSTER,
            "the instance's cluster must be {CLUSTER}"
        );
        ensure!(
            self.apply_identity
                == format!(
                    "{}-infra@{}.iam.gserviceaccount.com",
                    self.org, self.project
                ),
            "the apply identity must be the instance's <org>-infra@<project>.iam.gserviceaccount.com"
        );
        ensure!(
            !self.apps.is_empty()
                && self
                    .apps
                    .iter()
                    .all(|app| instance_source::identifier(&app.id)),
            "invalid deployment app ID"
        );
        Ok(())
    }
}

/// The CLI's rendered request.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub instance: Instance,
    /// The instance directory and the platform checkout, which the new output
    /// directory must be outside.
    pub directory: PathBuf,
    pub checkout: PathBuf,
    pub app_id: String,
    /// The checked candidate record's exact bytes.
    pub candidate: PathBuf,
    /// The new private output directory.
    pub output: PathBuf,
    /// Unix seconds the job may run until; none means no deadline.
    pub deadline: Option<u64>,
}

/// The operator the session ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operator {
    /// The qualified release manifest's digest.
    pub release: String,
    /// The digest of the operator's `cli/day2`, as it ran.
    pub cli: String,
}

/// The activation this run started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub request_digest: String,
    pub target_instance_digest: String,
    /// The saved request, when one was kept.
    pub record: Option<String>,
}

/// Where the backups went.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub uri: String,
    pub before: Option<Copied>,
    pub after: Option<Copied>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Copied {
    pub objects: u64,
    pub bytes: u64,
}

impl From<Totals> for Copied {
    fn from(totals: Totals) -> Self {
        Self {
            objects: totals.objects,
            bytes: totals.bytes,
        }
    }
}

/// The day2-app apply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apply {
    /// The roots receipt of the day2-app apply.
    pub roots: Option<File>,
}

/// What the readback saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readback {
    pub generation: u64,
    pub revision: String,
    pub image_id: String,
    pub instance_digest: String,
}

/// What a deploy reports. The host owns this shape; the CLI decodes only it and
/// passes it through verbatim, and cli/fixtures/deploy-receipt.json pins it for
/// both sides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub format: u32,
    pub mode: String,
    pub app_id: String,
    pub commit: String,
    pub image: String,
    pub artifact_id: String,
    pub tooling_image: String,
    pub request_id: String,
    /// `fresh`, `activated`, `serving` or `install`.
    pub path: String,
    pub operator: Operator,
    pub activation: Option<Activation>,
    pub archive: Option<Archive>,
    pub apply: Apply,
    pub readback: Readback,
}

/// What a session reaches outside itself.
pub struct Effects {
    pub tools: Box<dyn tools::Tools>,
    /// The app's selected candidate, read at its exact generation.
    pub store: Box<dyn Store>,
    /// The release cache's bucket reads, for the operator.
    pub release: Box<dyn instance_release::Tools>,
    /// The release cache; else `$DAY2_RELEASE_CACHE` or the home cache.
    pub cache: Option<PathBuf>,
}

impl Effects {
    pub fn native() -> Result<Self> {
        Ok(Self {
            tools: Box::new(tools::Native::new(crate::maintenance::interrupt_flag())),
            store: Box::new(Gcloud::native()),
            release: Box::new(instance_release::Native),
            cache: None,
        })
    }
}

/// A deploy session.
pub struct Session {
    tools: Box<dyn tools::Tools>,
    store: Box<dyn Store>,
    release: Box<dyn instance_release::Tools>,
    cache: Option<PathBuf>,
    instance: Instance,
    deadline: Option<u64>,
    output: PathBuf,
    directory: PathBuf,
    platform: PathBuf,
    candidate_path: PathBuf,
    candidate: Value,
    app: String,
    commit: String,
    image: String,
    artifact_id: String,
    tooling: String,
    request_id: String,
    /// The steps from here, and how many are done.
    plan: Vec<&'static str>,
    done: usize,
    /// The step that ran last, and what a failure in it means.
    stage: Stage,
    retryable: bool,
    refusal: Option<Class>,
    mutated: bool,
    activated: bool,
    verified: bool,
    archived: bool,
    finished: bool,
    archive_error: Option<String>,
    route: Option<Route>,
    live: Option<Live>,
    attempt: Option<Attempt>,
    target_digest: Option<String>,
    activation: Option<Activation>,
    prefix: Option<String>,
    before: Option<Copied>,
    after: Option<Copied>,
    operator: Option<(PathBuf, Operator)>,
    applied: bool,
    readback: Option<Readback>,
}

/// A new private directory, mode 0700, never through a link; an existing path
/// is refused.
fn private_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("create the private directory {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o777 == 0o700,
        "{} must be a private directory",
        path.display()
    );
    Ok(())
}

/// `path` lies in `root` (both resolved).
fn within(path: &Path, root: &Path) -> bool {
    match (path.canonicalize(), root.canonicalize()) {
        (Ok(path), Ok(root)) => path.starts_with(root),
        _ => false,
    }
}

impl Session {
    /// Validate the CLI's request, the candidate and the new output directory
    /// before anything outside this machine is read.
    pub fn prepare(raw: &Path, effects: Effects) -> Result<Self> {
        let request: Request = day2::json::decode(&read_bounded(raw, REQUEST_LIMIT)?)?;
        request.instance.validate()?;
        let app = request.app_id.clone();
        ensure!(
            request.instance.apps.iter().any(|entry| entry.id == app),
            "the app {app} is not in day2.json"
        );
        ensure!(
            request.deadline.is_none_or(|deadline| deadline > 0),
            "the deadline must be unix seconds"
        );
        let output = std::path::absolute(&request.output)?;
        ensure!(
            fs::symlink_metadata(&output).is_err(),
            "instance deploy requires a new output directory: {}",
            output.display()
        );
        let parent = output
            .parent()
            .filter(|parent| parent.is_dir())
            .with_context(|| {
                format!(
                    "the new output directory's parent must exist: {}",
                    output.display()
                )
            })?;
        ensure!(
            !within(parent, &request.directory) && !within(parent, &request.checkout),
            "the output directory must be outside the instance and the platform checkout"
        );
        let candidate_path = std::path::absolute(&request.candidate)?;
        let candidate = record::decode(&read_bounded(&candidate_path, record::RECORD_LIMIT)?)?;
        record::check(&candidate, &app, &request.instance.releases().scope())?;
        let text = |field: &str| -> Result<String> {
            candidate[field]
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("the candidate has no {field}"))
        };
        let commit = text("source_commit")?;
        let image = text("image")?;
        let artifact_id = text("artifact_id")?;
        let tooling = candidate["binding"]["tooling_image"]
            .as_str()
            .context("the candidate has no tooling image")?
            .to_owned();
        let request_id = request::request_id(&commit, &image)?;
        private_directory(&output)?;
        private_directory(&output.join("kube"))?;
        let Effects {
            mut tools,
            store,
            release,
            cache,
        } = effects;
        let kubeconfig = output.join("kube/config");
        tools.configure(tools::Config {
            env: tools::environment(
                &|name| std::env::var_os(name),
                &kubeconfig,
                &request.instance.project,
            ),
            kubeconfig,
            project: request.instance.project.clone(),
            zone: request.instance.zone.clone(),
            cluster: request.instance.cluster.clone(),
        });
        Ok(Self {
            tools,
            store,
            release,
            cache,
            instance: request.instance,
            deadline: request.deadline,
            output,
            directory: std::path::absolute(request.directory)?,
            platform: std::path::absolute(request.checkout)?,
            candidate_path,
            candidate,
            app,
            commit,
            image,
            artifact_id,
            tooling,
            request_id,
            plan: vec!["operator", "credentials", "observe"],
            done: 0,
            stage: Stage::Prepare,
            retryable: false,
            refusal: None,
            mutated: false,
            activated: false,
            verified: false,
            archived: false,
            finished: false,
            archive_error: None,
            route: None,
            live: None,
            attempt: None,
            target_digest: None,
            activation: None,
            prefix: None,
            before: None,
            after: None,
            operator: None,
            applied: false,
            readback: None,
        })
    }

    /// The coordinated root must be the one app and paths this deployment admitted.
    pub fn check_roots_request(&self, raw: &Path) -> Result<()> {
        let request: instance_roots::Request = day2::json::decode(&read_bounded(raw, 1 << 20)?)?;
        ensure!(
            request.mode == instance_roots::Mode::Deploy
                && std::path::absolute(&request.instance)? == self.directory
                && std::path::absolute(&request.checkout)? == self.platform
                && std::path::absolute(&request.output)? == self.output.join("roots")
                && std::path::absolute(request.candidate.context("deploy root candidate")?)?
                    == self.candidate_path
                && request.project == self.instance.project
                && request.zone == self.instance.zone
                && request.cluster == self.instance.cluster
                && request.releases.as_ref() == Some(&self.instance.releases())
                && request.roots.len() == 1
                && request.roots[0].app_id.as_deref() == Some(&self.app),
            "the day2-app root uses different deploy inputs"
        );
        Ok(())
    }

    /// A root may apply only from the deploy's authorized apply phase.
    pub fn check_roots_operation(&self, operation: &str) -> Result<()> {
        let next = self.plan.get(self.done).copied();
        let expected = match operation {
            "release" | "init" => "observe",
            "target" => "target",
            "selected" | "plan" | "show" | "apply" => "applied",
            _ => bail!("unknown deploy root operation"),
        };
        ensure!(
            !self.finished && !self.archived && next == Some(expected),
            "the deploy is not ready to {operation} its day2-app root"
        );
        Ok(())
    }

    /// Run the next step, which must be `name`. `detail` carries what the
    /// recipe learned from the day2-app root: the rendered target, the apply's
    /// outcome, or the error that ended the run.
    pub fn step(&mut self, name: &str, detail: &Value) -> Result<Value> {
        ensure!(!self.finished, "the deploy session has finished");
        match name {
            "archive-after" => return self.archive_after(),
            "finish" => return self.finish(detail),
            _ => {}
        }
        ensure!(!self.archived, "only finish follows the final archive");
        let expected = self.plan.get(self.done).copied();
        let Some(next) = expected.filter(|next| *next == name) else {
            bail!(
                "instance deploy runs {} next, not {name}",
                expected.unwrap_or("nothing more")
            );
        };
        self.retryable = false;
        let value = match next {
            "operator" => self.operator(),
            "credentials" => self.credentials(),
            "observe" => self.observe(detail),
            "target" => self.target(detail),
            "deadline" => self.check_deadline(),
            "backup" => self.backup(),
            "archive-before" => self.archive_before(),
            "activate" => self.activate(),
            "apply" => self.apply(),
            "applied" => self.applied(detail),
            "rollout" => self.rollout(),
            _ => self.read_back(),
        }?;
        self.done += 1;
        Ok(value)
    }

    fn enter(&mut self, stage: Stage) {
        self.stage = stage;
    }

    /// The candidate's qualified release through the release cache, bound as
    /// a fetch binds it and to the candidate's native admission, then its
    /// operator's CLI files copied into the private output directory and
    /// checked again on the copied bytes. The copy is what runs.
    fn operator(&mut self) -> Result<Value> {
        self.enter(Stage::Operator);
        let reference: BlobIdentity =
            serde_json::from_value(self.candidate["binding"]["qualified_release"].clone())
                .context("the candidate names no qualified release")?;
        let root = match &self.cache {
            Some(root) => root.clone(),
            None => instance_release::cache_root()?,
        };
        let objects = format!(
            "gs://{}/{}",
            self.instance.bucket,
            instance_release::OBJECTS
        );
        let verified = instance_release::verified(
            instance_release::Cache::open(&root, &objects)?,
            &self.instance.registry,
            &reference,
            self.release.as_mut(),
        )?;
        ensure!(
            self.candidate["security_requirements"]["containment"]["evidence"]["receipt_digest"]
                == verified.release.evidence.native.digest.as_str(),
            "candidate uses another platform qualification"
        );
        let cache = instance_release::Cache::open(&root, &objects)?;
        let distribution_path = cache.fetch(
            &verified.release.distribution,
            DISTRIBUTION_LIMIT,
            self.release.as_mut(),
        )?;
        let distribution: Distribution = day2::json::decode(&sdk_release::verify(
            &distribution_path,
            &verified.release.distribution,
            DISTRIBUTION_LIMIT,
        )?)?;
        distribution.bind(&verified.release)?;
        let cached = cache.operator(&verified.release, &distribution, self.release.as_mut())?;
        let source = cached.parent().context("the operator's cli directory")?;
        let copy = self.output.join("operator");
        private_directory(&copy)?;
        private_directory(&copy.join("cli"))?;
        for name in CLI_FILES {
            let expected = distribution
                .operator_files
                .get(name)
                .with_context(|| format!("the distribution names no {name}"))?;
            let file = name.trim_start_matches("cli/");
            let bytes = sdk_release::verify(&source.join(file), expected, FILE_LIMIT)
                .context("cached operator executable changed")?;
            let path = copy.join(name);
            write_private(&path, &bytes)?;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(sdk_release::operator_mode(name)),
            )?;
            ensure!(
                sdk_release::identity(&path, FILE_LIMIT).ok().as_ref() == Some(expected),
                "the operator's private copy differs from its qualified bytes: {name}"
            );
        }
        fs::set_permissions(copy.join("cli"), fs::Permissions::from_mode(0o500))?;
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o500))?;
        let operator = Operator {
            release: reference.digest.clone(),
            cli: distribution.operator_files["cli/day2"].digest.clone(),
        };
        self.operator = Some((copy.join("cli/day2"), operator.clone()));
        Ok(serde_json::to_value(operator)?)
    }

    /// The cluster's credentials, from derived names, into the private
    /// kubeconfig. A failure here changed nothing and is retryable.
    fn credentials(&mut self) -> Result<Value> {
        self.enter(Stage::Credentials);
        self.retryable = true;
        self.tools.credentials()?;
        self.retryable = false;
        Ok(json!({}))
    }

    fn namespace(&self) -> String {
        request::namespace(&self.app)
    }

    /// The live workload (and the state claim, when there is no workload).
    fn observed(&mut self) -> Result<Observed> {
        let namespace = self.namespace();
        let statefulset = self.tools.get(
            &namespace,
            tools::Kind::StatefulSet,
            &request::workload(&self.app),
        )?;
        let workload = statefulset.as_ref().map(Workload::read).transpose()?;
        let claim = match workload {
            Some(_) => Claim::Bound,
            None => Claim::read(
                self.tools
                    .get(&namespace, tools::Kind::Claim, request::PVC)?
                    .as_ref(),
            ),
        };
        Ok(Observed { workload, claim })
    }

    /// Read the live workload and choose the path before anything changes.
    fn observe(&mut self, root: &Value) -> Result<Value> {
        self.enter(Stage::Observe);
        ensure!(
            root["candidate"] == release::candidate_digest(&self.candidate)?
                && root["commit"] == self.commit
                && root["image"] == self.image
                && root["artifact_id"] == self.artifact_id
                && root["tooling_image"] == self.tooling,
            "the day2-app root checked a different candidate"
        );
        self.retryable = true;
        let namespace = self.namespace();
        let statefulset = self.tools.get(
            &namespace,
            tools::Kind::StatefulSet,
            &request::workload(&self.app),
        )?;
        self.retryable = false;
        let workload = match statefulset.as_ref().map(Workload::read).transpose() {
            Ok(workload) => workload,
            Err(error) => {
                // A checkpoint this CLI cannot read may be past the fence.
                self.refusal = Some(Class::Fenced);
                return Err(error);
            }
        };
        let claim = match &workload {
            Some(_) => Claim::Bound,
            None => {
                self.retryable = true;
                let pvc = self
                    .tools
                    .get(&namespace, tools::Kind::Claim, request::PVC)?;
                self.retryable = false;
                Claim::read(pvc.as_ref())
            }
        };
        let observed = Observed { workload, claim };
        let route = match fence::choose(&observed, &self.image) {
            Ok(route) => route,
            Err(refusal) => {
                self.refusal = Some(refusal.class);
                return Err(anyhow!(refusal.message));
            }
        };
        self.route = Some(route);
        self.check_selection()?;
        if route == Route::Fresh {
            let workload = observed.workload.as_ref().context("workload")?;
            self.retryable = true;
            let configmap = self.tools.get(
                &namespace,
                tools::Kind::ConfigMap,
                &request::configmap(&self.app),
            )?;
            self.retryable = false;
            let configmap = configmap.context("the workload has no instance ConfigMap")?;
            self.live = Some(Live {
                app_image: workload.image.clone(),
                artifact_id: self.live_artifact(&configmap)?,
            });
        }
        self.plan.extend(match route {
            Route::Fresh => &[
                "target",
                "deadline",
                "backup",
                "archive-before",
                "activate",
                "apply",
                "applied",
                "rollout",
                "readback",
            ][..],
            _ => &["deadline", "apply", "applied", "rollout", "readback"][..],
        });
        Ok(json!({"path": route.name()}))
    }

    fn check_selection(&mut self) -> Result<()> {
        release::selection(
            self.store.as_mut(),
            &self.instance.releases(),
            &self.app,
            &self.candidate,
        )?;
        Ok(())
    }

    /// The artifact the live ConfigMap binds the app to: exactly one app, this
    /// one, at `artifacts/<64 hex>`.
    fn live_artifact(&self, configmap: &Value) -> Result<String> {
        let text = configmap["data"]["instance.json"]
            .as_str()
            .context("the instance ConfigMap has no instance.json")?;
        let instance: Value =
            serde_json::from_str(text).context("the live instance.json is not JSON")?;
        let apps = instance["apps"]
            .as_object()
            .filter(|apps| apps.len() == 1 && apps.contains_key(&self.app))
            .context("the live instance must bind exactly this app")?;
        apps[&self.app]["artifact"]
            .as_str()
            .and_then(|artifact| artifact.strip_prefix("artifacts/"))
            .filter(|id| instance_source::lower_hex(id, 64))
            .map(str::to_owned)
            .context("the live instance binds no artifact")
    }

    /// The desired instance the day2-app root rendered for the candidate: its
    /// file must be the digest and size the recipe reports and bind the app to
    /// the candidate's artifact. It is copied into a new attempt's private
    /// activation directory.
    fn target(&mut self, detail: &Value) -> Result<Value> {
        self.enter(Stage::Target);
        let file: File =
            serde_json::from_value(detail.clone()).context("the target names no rendered file")?;
        let bytes = read_bounded(Path::new(&file.path), INSTANCE_LIMIT)?;
        ensure!(
            BlobIdentity::of(&bytes)
                == BlobIdentity {
                    digest: file.digest.clone(),
                    bytes: file.bytes,
                },
            "the rendered target changed"
        );
        let instance: Value =
            serde_json::from_slice(&bytes).context("the rendered target is not JSON")?;
        ensure!(
            instance["apps"][&self.app]["artifact"]
                == format!("artifacts/{}", self.artifact_id).as_str(),
            "the rendered target does not bind {} to the candidate's artifact",
            self.app
        );
        let attempt = Attempt::new(&self.app, &request::suffix_from(self.tools.random()?))?;
        private_directory(&attempt.activation_dir())?;
        write_private(&attempt.target_instance(), &bytes)?;
        self.attempt = Some(attempt);
        self.target_digest = Some(file.digest.clone());
        Ok(json!({"target": file.digest}))
    }

    /// Refuse to start what cannot finish before the job's deadline.
    fn check_deadline(&mut self) -> Result<Value> {
        self.enter(Stage::Deadline);
        self.check_selection()?;
        let route = self.route.context("path")?;
        let now = self.tools.now()?;
        if let Err(error) = fence::within(now, self.deadline, route) {
            self.retryable = true;
            return Err(error);
        }
        Ok(json!({"remaining": fence::remaining(route)}))
    }

    fn operator_path(&self) -> Result<PathBuf> {
        Ok(self.operator.as_ref().context("operator")?.0.clone())
    }

    fn names(&self) -> Names {
        Names {
            app: self.app.clone(),
            apply_identity: self.instance.apply_identity.clone(),
            tooling_image: self.tooling.clone(),
        }
    }

    fn target_request(&self) -> Target {
        Target {
            app_image: self.image.clone(),
            artifact_id: self.artifact_id.clone(),
            request_id: self.request_id.clone(),
        }
    }

    /// Run one maintenance operation from the private operator copy with a
    /// request file in the output directory.
    fn maintain(&mut self, operation: Operation, bytes: &[u8], deadline: u64) -> Result<Value> {
        let path = self
            .output
            .join(format!("maintain-{}.json", operation.name()));
        write_private(&path, bytes)?;
        let operator = self.operator_path()?;
        let ran =
            self.tools
                .maintain(&operator, operation, &path, Duration::from_secs(deadline))?;
        write_private(
            &self
                .output
                .join(format!("maintain-{}.out", operation.name())),
            &ran.stdout,
        )?;
        tools::finished(&ran, operation)
    }

    /// The earlier controller's off-site backup before the migration fence:
    /// `maintain backup` (which stops the app, backs it up and restores it)
    /// into the attempt's new private backup directory.
    fn backup(&mut self) -> Result<Value> {
        self.enter(Stage::Backup);
        let attempt = self.attempt.clone().context("attempt")?;
        let live = self.live.clone().context("live workload")?;
        private_directory(&attempt.backup_dir())?;
        let value = request::value(Operation::Backup, &self.names(), &live, &attempt, None)?;
        let bytes = request::encode(Operation::Backup, &value)?;
        self.mutated = true;
        self.maintain(Operation::Backup, &bytes, fence::budget::BACKUP)?;
        ensure!(
            archive::nonempty(&attempt.backup_dir())?,
            "maintenance produced no private backup"
        );
        Ok(json!({"backup": attempt.backup_dir()}))
    }

    /// `gs://<project>-<app>-backups/deployments/<commit>/<uuid>/`, once per run.
    fn prefix(&mut self) -> Result<String> {
        if self.prefix.is_none() {
            let bucket = request::backup_bucket(&self.instance.project, &self.app);
            let uuid = archive::uuid4(self.tools.random()?);
            self.prefix = Some(archive::prefix(&bucket, &self.commit, &uuid)?);
        }
        self.prefix.clone().context("archive prefix")
    }

    /// Copy the backup directory under `phase`, never replacing an object, and
    /// require the listing to be exactly the local manifest.
    fn copy(&mut self, phase: &str) -> Result<Copied> {
        let directory = self.attempt.as_ref().context("attempt")?.backup_dir();
        let prefix = self.prefix()?;
        let entries = archive::manifest(&directory)?;
        let expected = archive::expected(
            &prefix,
            phase,
            &archive::directory_name(&directory)?,
            &entries,
        )?;
        self.tools.upload(&directory, &prefix, phase)?;
        let listing = self.tools.list(&prefix, phase)?;
        Ok(archive::verify(&listing, &expected)?.into())
    }

    fn archive_before(&mut self) -> Result<Value> {
        self.enter(Stage::ArchiveBefore);
        let copied = self.copy(archive::BEFORE)?;
        self.before = Some(copied);
        Ok(json!({"uri": archive::phase_uri(&self.prefix()?, archive::BEFORE)}))
    }

    /// The migration: `maintain activate` for the candidate with the
    /// rendered target. Past its fence the old image never restarts.
    fn activate(&mut self) -> Result<Value> {
        self.enter(Stage::Activate);
        self.check_selection()?;
        let attempt = self.attempt.clone().context("attempt")?;
        let live = self.live.clone().context("live workload")?;
        let value = request::value(
            Operation::Activate,
            &self.names(),
            &live,
            &attempt,
            Some(&self.target_request()),
        )?;
        let bytes = request::encode(Operation::Activate, &value)?;
        self.activation = Some(Activation {
            request_digest: day2::digest(&bytes),
            target_instance_digest: self.target_digest.clone().context("target")?,
            record: None,
        });
        self.maintain(Operation::Activate, &bytes, fence::budget::ACTIVATE)?;
        self.activated = true;
        Ok(json!({"activated": self.image}))
    }

    /// The day2-app apply is next: from here the app rolls.
    fn apply(&mut self) -> Result<Value> {
        self.enter(Stage::Apply);
        if self.route == Some(Route::Install) {
            let observed = self.observed()?;
            ensure!(
                observed.workload.is_none() && observed.claim == Claim::Unbound,
                "the first install requires the app's claim to remain unbound and its workload absent"
            );
        }
        self.mutated = true;
        Ok(json!({}))
    }

    /// What the day2-app root's deploy apply reported.
    fn applied(&mut self, detail: &Value) -> Result<Value> {
        ensure!(
            detail["ok"] == true,
            "the day2-app apply did not apply this candidate; its roots receipt says why"
        );
        self.applied = true;
        Ok(json!({}))
    }

    fn rollout(&mut self) -> Result<Value> {
        self.enter(Stage::Rollout);
        let namespace = self.namespace();
        self.tools
            .rollout(&namespace, &request::workload(&self.app))?;
        Ok(json!({}))
    }

    /// The earlier controller's readback, and the stricter checks that name
    /// themselves when they fail.
    fn read_back(&mut self) -> Result<Value> {
        self.enter(Stage::Readback);
        let namespace = self.namespace();
        let workload_name = request::workload(&self.app);
        let digest = self
            .image
            .rsplit_once('@')
            .map(|(_, digest)| digest.to_owned())
            .context("the candidate image is not pinned")?;
        let statefulset = self
            .tools
            .get(&namespace, tools::Kind::StatefulSet, &workload_name)?
            .context("readback workload: the StatefulSet is gone")?;
        let status = &statefulset["status"];
        ensure!(
            status["readyReplicas"].as_u64() == Some(1),
            "readback replicas: the workload is not ready at one replica"
        );
        let generation = statefulset["metadata"]["generation"]
            .as_u64()
            .context("readback generation: the workload has no generation")?;
        ensure!(
            status["observedGeneration"].as_u64().unwrap_or(0) >= generation,
            "readback generation: the workload has not observed its current generation"
        );
        let revision = status["updateRevision"]
            .as_str()
            .filter(|revision| !revision.is_empty())
            .context("readback revision: the workload has no update revision")?
            .to_owned();
        ensure!(
            status["currentRevision"].as_str() == Some(revision.as_str()),
            "readback revision: the workload is not at its update revision"
        );
        let workload = Workload::read(&statefulset).context("readback image")?;
        ensure!(
            workload.image == self.image,
            "readback image: the workload's template runs another image"
        );
        ensure!(
            workload
                .stamp
                .as_ref()
                .is_none_or(|stamp| *stamp == self.image),
            "readback stamp: the workload is stamped activated for another image"
        );
        if self.activation.is_some() {
            ensure!(
                workload
                    .checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| checkpoint.phase == fence::Phase::Activated),
                "readback checkpoint: the workload's activation checkpoint is not activated"
            );
        }
        let pod = self
            .tools
            .get(&namespace, tools::Kind::Pod, &request::pod(&self.app))?
            .context("readback pod: the workload has no pod")?;
        ensure!(
            pod["metadata"]["deletionTimestamp"].is_null(),
            "readback pod deletion: the pod is being deleted"
        );
        ensure!(
            pod["metadata"]["labels"]["controller-revision-hash"] == revision.as_str(),
            "readback pod revision: the pod is not at the workload's update revision"
        );
        let container = pod["status"]["containerStatuses"]
            .as_array()
            .and_then(|statuses| statuses.iter().find(|status| status["name"] == "day2"))
            .context("readback pod image: the pod has no day2 container")?;
        let image_id = container["imageID"].as_str().unwrap_or_default().to_owned();
        ensure!(
            container["ready"] == true && image_id.ends_with(&format!("@{digest}")),
            "readback pod image: the ready pod does not run the selected immutable image"
        );
        let configmap = self
            .tools
            .get(
                &namespace,
                tools::Kind::ConfigMap,
                &request::configmap(&self.app),
            )?
            .context("readback artifact: the workload has no instance ConfigMap")?;
        let installed = configmap["data"]["instance.json"]
            .as_str()
            .context("readback artifact: the ConfigMap has no instance.json")?;
        let instance: Value = serde_json::from_str(installed)
            .context("readback artifact: the installed instance is not JSON")?;
        ensure!(
            instance["apps"][&self.app]["artifact"]
                == format!("artifacts/{}", self.artifact_id).as_str(),
            "readback artifact: the installed instance selects another artifact"
        );
        let instance_digest = day2::digest(installed.as_bytes());
        if let Some(target) = &self.target_digest {
            ensure!(
                instance_digest == *target,
                "readback instance: the installed instance differs from the activated target"
            );
        }
        let cronjob = self
            .tools
            .get(
                &namespace,
                tools::Kind::CronJob,
                &request::cronjob(&self.app),
            )?
            .context("readback backup job: the app has no scheduled backup")?;
        let backup = &cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"];
        ensure!(
            backup["containers"][0]["image"] == self.image.as_str()
                && backup["volumes"]
                    .as_array()
                    .and_then(|volumes| volumes.iter().find(|volume| volume["name"] == "instance"))
                    .is_some_and(|volume| {
                        volume["configMap"]["name"] == request::configmap(&self.app).as_str()
                    }),
            "readback backup job: the scheduled backup has not adopted the release"
        );
        self.verified = true;
        let readback = Readback {
            generation,
            revision,
            image_id,
            instance_digest,
        };
        self.readback = Some(readback.clone());
        Ok(serde_json::to_value(readback)?)
    }

    /// Whatever the operator left in the attempt's backup directory, archived
    /// under `after-activation` whether the run succeeded or not, as the earlier
    /// controller's `finally` did. A failure is kept for `finish`.
    fn archive_after(&mut self) -> Result<Value> {
        ensure!(!self.archived, "the final archive runs once");
        self.archived = true;
        let Some(directory) = self.attempt.as_ref().map(Attempt::backup_dir) else {
            return Ok(json!({"after": null}));
        };
        let archived = (|| -> Result<Value> {
            match fs::symlink_metadata(&directory) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(json!({"after": null}));
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
            if !archive::nonempty(&directory)? {
                return Ok(json!({"after": null}));
            }
            self.after = Some(self.copy(archive::AFTER)?);
            Ok(json!({"uri": archive::phase_uri(&self.prefix()?, archive::AFTER)}))
        })();
        if let Err(error) = &archived {
            self.archive_error = Some(format!("{error:#}"));
        }
        archived
    }

    /// The receipt, or the failure classified from the cluster as it is now:
    /// `retryable: ` (exit 7), `fenced: ` (exit 8) or the plain message (exit 6).
    fn finish(&mut self, detail: &Value) -> Result<Value> {
        self.finished = true;
        let mut error = detail["error"].as_str().map(str::to_owned);
        let complete = self.done == self.plan.len() && self.route.is_some();
        if error.is_none() && complete && self.archive_error.is_none() {
            match self.receipt() {
                Ok(receipt) => return Ok(receipt),
                Err(failure) => error = Some(format!("{failure:#}")),
            }
        }
        let (message, stage) = match (&error, &self.archive_error) {
            (Some(error), _) => (error.clone(), self.stage),
            (None, Some(archived)) if complete => (
                format!("the final archive failed: {archived}"),
                Stage::ArchiveAfter,
            ),
            _ => (
                "the deploy did not run all of its steps".to_owned(),
                self.stage,
            ),
        };
        let (class, note) = match self.refusal {
            Some(class) => (class, ""),
            None => {
                let after = if self.mutated {
                    self.observed().ok()
                } else {
                    None
                };
                fence::classify(&fence::Failure {
                    stage,
                    retryable: self.retryable && error.is_some(),
                    path: self.route,
                    mutated: self.mutated,
                    activated: self.activated,
                    verified: self.verified,
                    original: self.live.as_ref().map(|live| live.app_image.as_str()),
                    target: &self.image,
                    after: after.as_ref(),
                })
            }
        };
        let mut text = message;
        if !note.is_empty() {
            text.push_str("; ");
            text.push_str(note);
        }
        if let (Some(archived), Some(_)) = (&self.archive_error, &error) {
            text.push_str(&format!("; the final archive also failed: {archived}"));
        }
        if let Some(prefix) = &self.prefix {
            text.push_str(&format!("; evidence: {prefix}"));
        }
        Err(anyhow!(match class {
            Class::Unavailable => format!("{}{text}", instance_source::RETRYABLE),
            Class::Fenced => format!("{FENCED}{text}"),
            Class::Failed => text,
        }))
    }

    fn receipt(&mut self) -> Result<Value> {
        let route = self.route.context("path")?;
        let roots = self.output.join("roots/receipt.json");
        let bytes = read_bounded(&roots, 1 << 20).context("read the deploy's day2-app receipt")?;
        let result: Value = day2::json::decode(&bytes)?;
        ensure!(
            result["mode"] == "deploy"
                && result["ok"] == true
                && result["roots"][0]["label"] == format!("day2-app/{}", self.app)
                && result["roots"][0]["release"]["candidate"]
                    == release::candidate_digest(&self.candidate)?
                && matches!(
                    result["roots"][0]["status"].as_str(),
                    Some("applied" | "no_changes")
                ),
            "the day2-app receipt does not prove this candidate was applied"
        );
        let identity = BlobIdentity::of(&bytes);
        let roots = Some(File {
            path: roots.to_string_lossy().into_owned(),
            digest: identity.digest,
            bytes: identity.bytes,
        });
        let receipt = Receipt {
            format: 1,
            mode: "deploy".into(),
            app_id: self.app.clone(),
            commit: self.commit.clone(),
            image: self.image.clone(),
            artifact_id: self.artifact_id.clone(),
            tooling_image: self.tooling.clone(),
            request_id: self.request_id.clone(),
            path: route.name().into(),
            operator: self.operator.as_ref().context("operator")?.1.clone(),
            activation: self.activation.clone(),
            archive: self.prefix.clone().map(|uri| Archive {
                uri,
                before: self.before,
                after: self.after,
            }),
            apply: Apply { roots },
            readback: self.readback.clone().context("readback")?,
        };
        let value = serde_json::to_value(&receipt)?;
        let mut bytes = serde_json::to_vec_pretty(&value)?;
        bytes.push(b'\n');
        write_private(&self.output.join("receipt.json"), &bytes)?;
        Ok(value)
    }
}

/// What the host prefixes a failure after the migration fence with.
pub const FENCED: &str = "fenced: ";
