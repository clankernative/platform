//! Provider-free installation contracts. This crate has no runtime or effect APIs.
#![forbid(unsafe_code)]

pub mod integrations;
pub mod registry;
pub mod resources;
pub mod runtime;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);
impl Digest {
    pub fn new(bytes: &[u8]) -> Self {
        Self(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
    pub fn of<T: Serialize>(value: &T) -> Result<Self> {
        Ok(Self::new(&serde_json::to_vec(value)?))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for Digest {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        ensure!(
            value
                .strip_prefix("sha256:")
                .is_some_and(|hex| hex.len() == 64
                    && hex
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "expected canonical SHA-256 digest"
        );
        Ok(Self(value))
    }
}
impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);
impl Name {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for Name {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        ensure!(
            !value.is_empty()
                && value.len() <= 80
                && value.as_bytes()[0].is_ascii_alphanumeric()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid bounded identifier"
        );
        Ok(Self(value))
    }
}
impl From<Name> for String {
    fn from(value: Name) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitOid(String);
impl GitOid {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for GitOid {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        ensure!(
            value.len() == 40
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "expected immutable Git SHA-1 object id; refs and abbreviations forbidden"
        );
        Ok(Self(value))
    }
}
impl From<GitOid> for String {
    fn from(value: GitOid) -> Self {
        value.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRef {
    pub id: Name,
    pub revision: Digest,
}
impl BindingRef {
    pub fn pin<T: Serialize>(id: Name, configuration: &T) -> Result<Self> {
        Ok(Self {
            id,
            revision: Digest::of(configuration)?,
        })
    }
    pub fn verify<T: Serialize>(&self, configuration: &T) -> Result<()> {
        ensure!(
            self.revision == Digest::of(configuration)?,
            "binding configuration changed"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildProfile {
    pub source: BindingRef,
    pub builder: BindingRef,
    pub durability: BindingRef,
    pub platform: Digest,
    pub recipe: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlScope {
    pub installation: Name,
    pub environment: Name,
}
impl ControlScope {
    /// Existing build executions have one tenant identity; hash the full scope without ambiguous concatenation.
    pub fn company(&self) -> Result<Name> {
        Name::try_from(Digest::of(&("day2-control-scope-v1", self))?.as_str()[7..].to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceProvider {
    LocalGit { repository: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BuildProvider {
    LocalMacos {
        platform_root: String,
        toolchains: String,
        xtask: String,
        rust: String,
        registry: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DurabilityProvider {
    TemporalLocal {
        endpoint: String,
        namespace: String,
        task_queue: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretProvider {
    GcpVersion {
        project_number: std::num::NonZeroU64,
        secret: Name,
        version: std::num::NonZeroU64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppControl {
    pub source: Name,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildProfile>,
    /// Provider-only logical references. These do not grant secret access to Roc code.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_secrets: BTreeMap<Name, Name>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationControl {
    pub version: u32,
    pub state_directory: String,
    pub operators: BTreeSet<String>,
    pub sources: BTreeMap<Name, SourceProvider>,
    pub apps: BTreeMap<Name, AppControl>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub builders: BTreeMap<Name, BuildProvider>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub runtimes: BTreeMap<Name, DurabilityProvider>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<Name, SecretProvider>,
}

impl InstallationControl {
    pub fn validate<'a>(&self, installed_apps: impl IntoIterator<Item = &'a str>) -> Result<()> {
        ensure!(self.version == 1, "unsupported control contract version");
        absolute_directory(&self.state_directory)?;
        ensure!(
            !self.operators.is_empty() && self.operators.len() <= 1024,
            "control operator budget"
        );
        ensure!(
            self.operators.iter().all(|actor| !actor.trim().is_empty()
                && actor.len() <= 254
                && !actor.chars().any(char::is_control)),
            "invalid control operator"
        );
        ensure!(
            self.apps.len() <= 1024
                && self.sources.len() <= 1024
                && self.builders.len() <= 64
                && self.runtimes.len() <= 64,
            "control binding budget"
        );
        // A separate operator tooling instance may administer resources without
        // source/build/secret authority. Empty app bindings cannot conceal unused
        // provider authority in this restricted projection.
        ensure!(
            !self.apps.is_empty()
                || (self.sources.is_empty()
                    && self.builders.is_empty()
                    && self.runtimes.is_empty()
                    && self.secrets.is_empty()),
            "operator_only_control_cannot_have_provider_bindings"
        );
        for provider in self.builders.values() {
            let BuildProvider::LocalMacos {
                platform_root,
                toolchains,
                xtask,
                rust,
                registry,
            } = provider;
            for directory in [platform_root, toolchains, xtask, rust, registry] {
                absolute_directory(directory)?;
            }
        }
        for provider in self.runtimes.values() {
            let DurabilityProvider::TemporalLocal {
                endpoint,
                namespace,
                task_queue,
            } = provider;
            let address: std::net::SocketAddr = endpoint.parse()?;
            ensure!(
                address.ip().is_loopback() && address.port() != 0,
                "only explicit local Temporal endpoints supported"
            );
            Name::try_from(namespace.clone())?;
            Name::try_from(task_queue.clone())?;
        }
        let installed: BTreeSet<_> = installed_apps.into_iter().collect();
        ensure!(self.secrets.len() <= 1024, "secret binding budget");
        let mut used_sources = BTreeSet::new();
        let mut repositories = BTreeSet::new();
        let mut build_queues = BTreeSet::new();
        for (name, app) in &self.apps {
            ensure!(
                installed.contains(name.as_str()),
                "control app is not installed"
            );
            ensure!(
                app.provider_secrets.len() <= 128
                    && app
                        .provider_secrets
                        .values()
                        .all(|secret| self.secrets.contains_key(secret)),
                "unknown or excessive app provider secret bindings"
            );
            ensure!(
                used_sources.insert(&app.source),
                "repository binding cannot grant authority to multiple apps"
            );
            let provider = self
                .sources
                .get(&app.source)
                .ok_or_else(|| anyhow::anyhow!("unknown source binding"))?;
            match provider {
                SourceProvider::LocalGit { repository } => {
                    absolute_directory(repository)?;
                    ensure!(
                        repositories.insert(repository),
                        "duplicate repository authority"
                    );
                    ensure!(
                        repository != &self.state_directory,
                        "repository and control state must be distinct"
                    );
                }
            }
            if let Some(profile) = &app.build {
                ensure!(
                    profile.source == BindingRef::pin(app.source.clone(), provider)?,
                    "build source binding differs from app source authority"
                );
                ensure!(
                    profile.source.id != profile.builder.id
                        && profile.source.id != profile.durability.id
                        && profile.builder.id != profile.durability.id,
                    "duplicate capability binding identity"
                );
                ensure!(
                    self.builders.contains_key(&profile.builder.id)
                        && self.runtimes.contains_key(&profile.durability.id),
                    "build provider or durable runtime binding is missing"
                );
                let runtime = self
                    .runtimes
                    .get(&profile.durability.id)
                    .ok_or_else(|| anyhow::anyhow!("missing build runtime"))?;
                ensure!(
                    build_queues.insert(serde_json::to_string(runtime)?),
                    "local build workers require an app-exclusive Temporal task queue"
                );
            }
        }
        ensure!(
            used_sources.len() == self.sources.len(),
            "unused source binding"
        );
        Ok(())
    }
}

fn absolute_directory(value: &str) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        path.is_absolute()
            && path.components().count() > 1
            && value.len() <= 4096
            && !value.contains('\0')
            && !value.contains("//")
            && !value.split('/').any(|part| part == "." || part == "..")
            && !value.ends_with('/'),
        "expected normalized absolute operator directory"
    );
    Ok(())
}
