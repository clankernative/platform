//! `day2 instance ci-workflow`: the two inputs app CI's rendered workflow
//! needs that day2.json cannot spell. The renderer (cli/InstanceCiWorkflow.roc)
//! is pure; this session reads, for it:
//!
//! - the project's number, which the workload identity provider's audience
//!   names (`gcloud projects describe`, with the ambient credentials); and
//! - each app's tooling image, the digest-pinned image of its selected SDK
//!   release manifest (`apps.<id>.sdk`), and that release's tooling
//!   distribution digest, read through the release cache
//!   (`instance_release::manifest`) and pinned under the instance's registry. The manifest's size is the published object's;
//!   its digest is the spec's, checked on every read.
//!
//! InstanceCiWorkflow.roc owns the order; the session refuses a step out of
//! order.
use crate::{instance_release, instance_source};
use anyhow::{Context, Result, bail, ensure};
use day2::sdk_release::{BlobIdentity, MANIFEST_LIMIT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

const REQUEST_LIMIT: u64 = 65_536;

/// One app as the CLI derived it from day2.json.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct App {
    pub id: String,
    /// The selected SDK release manifest, `sha256:<hex>`.
    pub sdk: String,
}

/// What the CLI hands the host: the instance's names, derived from day2.json.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub project: String,
    /// `<region>-docker.pkg.dev/<project>`.
    pub registry: String,
    /// `<project>-tofu-state`, where the release manifests are published.
    pub bucket: String,
    pub apps: Vec<App>,
}

impl Request {
    fn validate(&self) -> Result<()> {
        let project = &self.project;
        ensure!(
            (6..=30).contains(&project.len())
                && project.starts_with(|c: char| c.is_ascii_lowercase())
                && !project.ends_with('-')
                && project
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "the project must be a GCP project ID"
        );
        ensure!(
            self.bucket == format!("{project}-tofu-state"),
            "the release bucket must be the instance's <project>-tofu-state"
        );
        ensure!(
            self.registry.split_once("-docker.pkg.dev/").is_some_and(
                |(region, registry_project)| { !region.is_empty() && registry_project == project }
            ),
            "the registry must be the instance's <region>-docker.pkg.dev/<project>"
        );
        ensure!(
            !self.apps.is_empty()
                && self.apps.windows(2).all(|pair| pair[0].id < pair[1].id)
                && self.apps.iter().all(|app| {
                    crate::ci_fetch::app_id(&app.id) && instance_source::hash(&app.sdk)
                }),
            "the instance apps must be sorted app IDs, each with an sdk digest"
        );
        Ok(())
    }
}

/// One app's tooling image.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tooling {
    pub id: String,
    pub tooling_image: String,
    /// The release's precompiled tooling distribution digest: the SDK identity
    /// a receipt checked on that image records.
    pub distribution: String,
}

/// What the host returns to the renderer. cli/fixtures/ci-workflow-inputs.json
/// pins the shape for the host and the CLI.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub format: u32,
    pub project_number: String,
    pub apps: Vec<Tooling>,
}

/// What the session reaches outside itself.
pub struct Effects {
    /// gcloud.
    pub tools: Box<dyn instance_release::Tools>,
    /// The release cache, else `instance_release::cache_root()`.
    pub cache: Option<PathBuf>,
}

impl Effects {
    pub fn native() -> Self {
        Self {
            tools: Box::new(instance_release::Native),
            cache: None,
        }
    }
}

pub struct Session {
    request: Request,
    effects: Effects,
    number: Option<String>,
    done: usize,
}

impl Session {
    /// Validate the request; nothing is read yet.
    pub fn prepare(path: &Path, effects: Effects) -> Result<Self> {
        let request: Request =
            day2::json::decode(&day2_assets::read_regular(path, REQUEST_LIMIT)?)?;
        request.validate()?;
        Ok(Self {
            request,
            effects,
            number: None,
            done: 0,
        })
    }

    /// Run the next step, which must be `name`: project, then releases.
    pub fn step(&mut self, name: &str) -> Result<Value> {
        let expected = ["project", "releases"].get(self.done).copied();
        let Some(step) = expected.filter(|step| *step == name) else {
            bail!(
                "instance ci-workflow runs {} next, not {name}",
                expected.unwrap_or("nothing more")
            );
        };
        let value = if step == "project" {
            self.project()?
        } else {
            self.releases()?
        };
        self.done += 1;
        Ok(value)
    }

    /// The project's number: decimal digits, as the provider's audience names it.
    fn project(&mut self) -> Result<Value> {
        let number = self
            .effects
            .tools
            .project_number(&self.request.project)?
            .trim()
            .to_owned();
        ensure!(
            (1..=20).contains(&number.len()) && number.bytes().all(|b| b.is_ascii_digit()),
            "gcloud returned no project number"
        );
        self.number = Some(number.clone());
        Ok(json!({"project_number": number}))
    }

    /// Each app's selected release manifest, through the release cache: its
    /// tooling image, pinned under the instance's registry.
    fn releases(&mut self) -> Result<Value> {
        let number = self.number.clone().context("the project number")?;
        let root = match &self.effects.cache {
            Some(root) => root.clone(),
            None => instance_release::cache_root()?,
        };
        let objects = format!("gs://{}/{}", self.request.bucket, instance_release::OBJECTS);
        let cache = instance_release::Cache::open(&root, &objects)?;
        let mut apps = Vec::new();
        for app in &self.request.apps {
            let hex = &app.sdk["sha256:".len()..];
            let uri = format!("{objects}/{hex}");
            let metadata: Value =
                day2::json::decode(self.effects.tools.describe(&uri)?.as_bytes())?;
            let bytes = match &metadata["size"] {
                Value::String(size) => size.parse::<u64>().ok(),
                Value::Number(size) => size.as_u64(),
                _ => None,
            }
            .filter(|bytes| (1..=MANIFEST_LIMIT).contains(bytes))
            .with_context(|| {
                format!("the release {} of {} has no manifest size", app.sdk, app.id)
            })?;
            let reference = BlobIdentity {
                digest: app.sdk.clone(),
                bytes,
            };
            let release = instance_release::manifest(
                &cache,
                &self.request.registry,
                &reference,
                self.effects.tools.as_mut(),
            )?;
            apps.push(Tooling {
                id: app.id.clone(),
                tooling_image: release.tooling.image,
                distribution: release.distribution.digest,
            });
        }
        Ok(serde_json::to_value(Report {
            format: 1,
            project_number: number,
            apps,
        })?)
    }
}
