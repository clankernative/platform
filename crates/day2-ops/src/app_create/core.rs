//! Mandatory creation guards over bounded evidence. No recipe or native I/O lives here.
use super::{Options, SourceFile, relative, sha};
use anyhow::{Context, Result, ensure};
use day2::host_inputs::Entropy;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug)]
pub(crate) enum Node {
    Directory,
    File(Vec<u8>),
    Link,
    Special,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Snapshot(pub BTreeMap<String, Node>);

impl Snapshot {
    pub fn digest(&self) -> Result<String> {
        ensure!(self.0.len() <= 8192, "scaffold tree entry budget");
        let mut total = 0usize;
        let mut hash = Sha256::new();
        for (path, node) in &self.0 {
            ensure!(relative(path), "scaffold tree path/depth");
            let mut ancestor = path.as_str();
            while let Some((parent, _)) = ancestor.rsplit_once('/') {
                ensure!(
                    matches!(self.0.get(parent), Some(Node::Directory)),
                    "inconsistent scaffold ancestor"
                );
                ancestor = parent;
            }
            match node {
                Node::Directory => {
                    hash.update(path.as_bytes());
                    hash.update(b"\0directory\0");
                }
                Node::File(bytes) => {
                    ensure!(bytes.len() <= 1_048_576, "scaffold member byte budget");
                    total = total
                        .checked_add(bytes.len())
                        .context("scaffold tree bytes")?;
                    ensure!(total <= 64 * 1024 * 1024, "scaffold tree byte budget");
                    hash.update(path.as_bytes());
                    hash.update([0]);
                    hash.update(sha(bytes).as_bytes());
                    hash.update([0]);
                }
                Node::Link => anyhow::bail!("scaffold tree symlink"),
                Node::Special => anyhow::bail!("scaffold tree special file"),
            }
        }
        Ok(format!("sha256:{:x}", hash.finalize()))
    }

    pub fn bytes(&self, path: &str) -> Result<&[u8]> {
        match self.0.get(path) {
            Some(Node::File(bytes)) => Ok(bytes),
            _ => anyhow::bail!("required captured regular file: {path}"),
        }
    }

    fn with_writes(mut self, writes: &BTreeMap<String, Vec<u8>>) -> Result<Self> {
        for (path, bytes) in writes {
            ensure!(
                relative(path) && !self.0.contains_key(path),
                "captured write collision"
            );
            let mut prefix = String::new();
            let parts: Vec<_> = path.split('/').collect();
            for part in &parts[..parts.len() - 1] {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                if let Some(node) = self.0.get(&prefix) {
                    ensure!(matches!(node, Node::Directory), "captured write ancestor");
                } else {
                    self.0.insert(prefix.clone(), Node::Directory);
                }
            }
            self.0.insert(path.clone(), Node::File(bytes.clone()));
        }
        self.digest()?;
        Ok(self)
    }

    fn namespace(&self) -> Result<String> {
        day2::app_inference::namespace(std::str::from_utf8(self.bytes("App.roc")?)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admission {
    pub artifact: PathBuf,
    pub identity: String,
    pub namespace: String,
}

/// Host-private bounded capabilities, not app callbacks or a second operational SDK.
/// Admission must load the ordinary verified artifact; publication must be NOREPLACE.
pub(crate) trait Ports {
    fn snapshot(&self) -> Result<Snapshot>;
    fn resolve_source(&self, source: &Path) -> Result<PathBuf>;
    fn write(&mut self, files: &BTreeMap<String, Vec<u8>>) -> Result<()>;
    fn admit(&self, artifact: &Path) -> Result<Admission>;
    fn publish(&mut self, artifact: &Path) -> Result<serde_json::Value>;
}

pub(crate) fn validate_options(options: &Options) -> Result<()> {
    day2::schema::identifier(&options.name)?;
    ensure!(options.name.len() <= 48, "app name budget");
    ensure!(
        ["none", "html", "clanker"].contains(&options.ui.as_str()),
        "unsupported UI choice"
    );
    ensure!(
        (options.ui == "clanker")
            == (!options.bundle.is_empty() && !options.bundle_sha256.is_empty())
            && (options.ui == "clanker"
                || (options.bundle.is_empty() && options.bundle_sha256.is_empty())),
        "bundle approval is required only for Clanker"
    );
    ensure!(
        !options
            .destination
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            && !options.destination.as_os_str().is_empty(),
        "unsafe destination path"
    );
    Ok(())
}

#[derive(Clone, Debug)]
enum Phase {
    Captured(String),
    Written(String),
    Identified(String),
    Building(String),
    Built(String, Admission),
    Published,
    Failed,
}

pub(crate) struct Creation<P> {
    pub port: P,
    name: String,
    source: PathBuf,
    phase: Phase,
}

impl<P: Ports> Creation<P> {
    pub fn new(name: String, source: PathBuf, port: P) -> Result<Self> {
        let digest = port.snapshot()?.digest()?;
        Ok(Self {
            port,
            name,
            source,
            phase: Phase::Captured(digest),
        })
    }

    // Any rejected phase/evidence or failed native operation terminally closes this
    // attempt. Roc determines which capability to request, never this guard.
    fn attempt<T>(&mut self, call: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = call(self);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn current(&self, expected: &str) -> Result<Snapshot> {
        let snapshot = self.port.snapshot()?;
        ensure!(snapshot.digest()? == expected, "captured scaffold changed");
        Ok(snapshot)
    }

    pub fn write_files(&mut self, files: Vec<SourceFile>) -> Result<()> {
        self.attempt(|this| {
            let Phase::Captured(expected) = &this.phase else {
                anyhow::bail!("scaffold write state/budget")
            };
            let captured = this.current(expected)?;
            ensure!(
                !files.is_empty() && files.len() <= 32,
                "scaffold write state/budget"
            );
            let mut names = BTreeSet::new();
            let mut writes = BTreeMap::new();
            for file in files {
                ensure!(
                    relative(&file.path)
                        && names.insert(file.path.to_ascii_lowercase())
                        && file.content.len() <= 128_000
                        && ["roc", "md", "html", "css"].contains(
                            &Path::new(&file.path)
                                .extension()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                        )
                        && !file.path.starts_with(".ui-dependencies/")
                        && file.path != "model-identities.json",
                    "unsafe scaffold file or budget"
                );
                writes.insert(file.path, file.content.into_bytes());
            }
            let expected = captured.with_writes(&writes)?.digest()?;
            this.port.write(&writes)?;
            this.current(&expected)?;
            this.phase = Phase::Written(expected);
            Ok(())
        })
    }

    pub fn identity(&mut self, table: &str, roc_type: &str, entropy: &dyn Entropy) -> Result<()> {
        self.attempt(|this| {
            let Phase::Written(expected) = &this.phase else {
                anyhow::bail!("identity authoring state")
            };
            let snapshot = this.current(expected)?;
            ensure!(
                snapshot.namespace()? == this.name,
                "created source namespace mismatch"
            );
            ensure!(
                !snapshot.0.contains_key(day2::identity::REGISTRY_FILE),
                "fresh model registry required"
            );
            let mut registry = day2::identity::Registry::default();
            registry.register_model(table, roc_type, entropy)?;
            let bytes = serde_json::to_vec_pretty(&registry)?;
            ensure!(bytes.len() <= 128_000, "model_registry_budget");
            let writes = BTreeMap::from([(day2::identity::REGISTRY_FILE.into(), bytes)]);
            let expected = snapshot.with_writes(&writes)?.digest()?;
            this.port.write(&writes)?;
            this.current(&expected)?;
            this.phase = Phase::Identified(expected);
            Ok(())
        })
    }

    pub fn check_build_source(&mut self, source: &Path) -> Result<()> {
        self.attempt(|this| {
            let Phase::Identified(expected) = &this.phase else {
                anyhow::bail!("build must use identified captured app exactly once")
            };
            ensure!(
                this.port.resolve_source(source)? == this.source,
                "build source mismatch"
            );
            let snapshot = this.current(expected)?;
            ensure!(
                snapshot.namespace()? == this.name,
                "created source namespace mismatch"
            );
            this.phase = Phase::Building(expected.clone());
            Ok(())
        })
    }

    pub fn built(&mut self, artifact: &Path) -> Result<()> {
        self.attempt(|this| {
            let Phase::Building(expected) = &this.phase else {
                anyhow::bail!("ordinary verified build required")
            };
            let snapshot = this.current(expected)?;
            ensure!(
                snapshot.namespace()? == this.name,
                "created source namespace mismatch"
            );
            let admission = this.port.admit(artifact)?;
            ensure!(
                admission.artifact == artifact
                    && admission.namespace == this.name
                    && !admission.identity.is_empty(),
                "created artifact identity/namespace mismatch"
            );
            this.phase = Phase::Built(expected.clone(), admission);
            Ok(())
        })
    }

    #[cfg(test)]
    pub fn test_built(&mut self, admission: Admission) -> Result<()> {
        self.phase = Phase::Built(self.port.snapshot()?.digest()?, admission);
        Ok(())
    }

    pub fn publish(&mut self, artifact: &Path) -> Result<serde_json::Value> {
        self.attempt(|this| {
            let Phase::Built(expected, admitted) = &this.phase else {
                anyhow::bail!("ordinary verified build required before publication")
            };
            ensure!(
                admitted.artifact == artifact,
                "publication artifact mismatch"
            );
            let snapshot = this.current(expected)?;
            ensure!(
                snapshot.namespace()? == this.name,
                "created source namespace mismatch"
            );
            ensure!(
                this.port.admit(artifact)? == *admitted,
                "admitted artifact changed after build"
            );
            let receipt = this.port.publish(artifact)?;
            this.phase = Phase::Published;
            Ok(receipt)
        })
    }
}
