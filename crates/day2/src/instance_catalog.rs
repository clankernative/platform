//! Candidate operation discovery from one instance's selected, verified artifacts.
//!
//! This is build-time data, not a serving or permission decision. A caller lock
//! pins only consumed operations, so an unrelated export can change this catalog
//! without changing that caller's compiled contract closure.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

use crate::operation_contract::{ImportPin, Manifest, Package, TypePin, resolve_type_closure};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedApp {
    pub artifact: String,
    pub manifest: Manifest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCatalog {
    pub installation: String,
    pub environment: String,
    pub digest: String,
    pub apps: BTreeMap<String, SelectedApp>,
}

/// The key is the selected logical target app. No artifact or catalog digest is
/// stored here; a new unrelated export need not change a caller's lock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportLock {
    pub installation: String,
    pub environment: String,
    pub apps: BTreeMap<String, Vec<ImportPin>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedImports {
    pub operations: BTreeMap<String, Package>,
    pub types: BTreeMap<String, TypePin>,
}

impl CandidateCatalog {
    pub fn derive(
        installation: String,
        environment: String,
        apps: BTreeMap<String, SelectedApp>,
    ) -> Result<Self> {
        crate::schema::identifier(&installation)?;
        crate::schema::identifier(&environment)?;
        ensure!((1..=1024).contains(&apps.len()), "candidate app budget");
        let mut identities = BTreeMap::new();
        for (name, selected) in &apps {
            crate::schema::identifier(name)?;
            ensure!(
                selected.manifest.app == *name,
                "selected export belongs to another app: {name}"
            );
            ensure!(
                selected.artifact.starts_with("sha256:")
                    && selected.artifact.len() == 71
                    && selected.artifact[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit()),
                "invalid selected artifact identity"
            );
            selected.manifest.verify()?;
            identities.insert(name, (&selected.artifact, &selected.manifest.digest));
        }
        let digest = crate::digest(&serde_json::to_vec(&(
            &installation,
            &environment,
            identities,
        ))?);
        Ok(Self {
            installation,
            environment,
            digest,
            apps,
        })
    }

    /// Read the instance's candidate selections. This deliberately does not
    /// inspect active authority databases or claim any target is serving.
    pub fn from_instance_file(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let instance = crate::artifact::Instance::load(&path)?;
        let parent = path.parent().context("instance directory")?;
        let mut apps = BTreeMap::new();
        for (name, binding) in &instance.apps {
            let artifact = crate::artifact::LoadedArtifact::load(&parent.join(&binding.artifact))
                .with_context(|| format!("selected artifact for {name}"))?;
            ensure!(
                artifact.contract().namespace == *name,
                "selected artifact namespace mismatch: {name}"
            );
            let manifest = match &artifact.contract().export_manifest {
                Some(manifest) => manifest.clone(),
                None => Manifest::derive(name.clone(), [], &BTreeMap::new())?,
            };
            apps.insert(
                name.clone(),
                SelectedApp {
                    artifact: artifact.id().to_owned(),
                    manifest,
                },
            );
        }
        Self::derive(instance.installation, instance.environment, apps)
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            self == &Self::derive(
                self.installation.clone(),
                self.environment.clone(),
                self.apps.clone(),
            )?,
            "candidate catalog digest mismatch"
        );
        Ok(())
    }

    /// The tooling-generated lock records exact operation contracts without
    /// asking an app author to copy digests out of a manifest.
    pub fn pin(&self, operations: &[String]) -> Result<ImportLock> {
        self.verify()?;
        ensure!(
            !operations.is_empty() && operations.len() <= 1024,
            "import operation budget"
        );
        let mut apps: BTreeMap<String, Vec<ImportPin>> = BTreeMap::new();
        for operation in operations {
            let (app, _) = operation
                .split_once('.')
                .context("import operation needs its app namespace")?;
            let selected = self
                .apps
                .get(app)
                .with_context(|| format!("import target not selected: {app}"))?;
            let package = selected
                .manifest
                .exports
                .get(operation)
                .with_context(|| format!("operation not exported: {operation}"))?;
            let pins = apps.entry(app.to_owned()).or_default();
            ensure!(
                !pins.iter().any(|pin| pin.operation == *operation),
                "duplicate imported operation"
            );
            pins.push(ImportPin {
                operation: operation.clone(),
                version: package.operation.version,
                digest: package.digest.clone(),
            });
        }
        for pins in apps.values_mut() {
            pins.sort_by(|a, b| a.operation.cmp(&b.operation));
        }
        ensure!(apps.len() <= 64, "import app budget");
        let lock = ImportLock {
            installation: self.installation.clone(),
            environment: self.environment.clone(),
            apps,
        };
        self.resolve(&lock)?;
        Ok(lock)
    }

    pub fn resolve(&self, lock: &ImportLock) -> Result<ResolvedImports> {
        self.verify()?;
        ensure!(
            self.installation == lock.installation && self.environment == lock.environment,
            "import lock belongs to another instance scope"
        );
        ensure!(
            !lock.apps.is_empty() && lock.apps.len() <= 64,
            "import app budget"
        );
        let mut operations = BTreeMap::new();
        for (app, pins) in &lock.apps {
            ensure!(
                !pins.is_empty() && pins.len() <= 128,
                "import operation budget"
            );
            let selected = self
                .apps
                .get(app)
                .with_context(|| format!("import target not selected: {app}"))?;
            for package in selected.manifest.resolve(pins)? {
                ensure!(
                    operations
                        .insert(package.operation.id.clone(), package.clone())
                        .is_none(),
                    "duplicate imported operation"
                );
            }
        }
        let types = resolve_type_closure(operations.values())?;
        Ok(ResolvedImports { operations, types })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation_contract::{Codec, Kind, OperationSpec, TypeObject};
    use serde_json::json;
    use std::collections::BTreeSet;

    fn manifest(app: &str, exports: &[(&str, &str, i64)]) -> Manifest {
        let mut types = BTreeMap::new();
        let operations = exports
            .iter()
            .map(|(name, type_id, shape)| {
                types.insert(
                    (*type_id).to_owned(),
                    TypeObject {
                        id: (*type_id).to_owned(),
                        codec: Codec::RocJsonV1,
                        schema: json!({"shape":shape}),
                        dependencies: BTreeSet::new(),
                    },
                );
                OperationSpec {
                    id: format!("{app}.{name}"),
                    version: 1,
                    kind: Kind::Query,
                    input: (*type_id).to_owned(),
                    output: (*type_id).to_owned(),
                    error: (*type_id).to_owned(),
                    semantics: json!({}),
                }
            })
            .collect::<Vec<_>>();
        Manifest::derive(app.to_owned(), operations, &types).unwrap()
    }

    fn selected(manifest: Manifest) -> SelectedApp {
        SelectedApp {
            artifact: format!("sha256:{}", "a".repeat(64)),
            manifest,
        }
    }

    fn catalog(apps: BTreeMap<String, SelectedApp>) -> CandidateCatalog {
        CandidateCatalog::derive("acme".into(), "dev".into(), apps).unwrap()
    }

    fn lock(app: &str, manifest: &Manifest, operation: &str) -> ImportLock {
        let package = &manifest.exports[&format!("{app}.{operation}")];
        ImportLock {
            installation: "acme".into(),
            environment: "dev".into(),
            apps: BTreeMap::from([(
                app.into(),
                vec![ImportPin {
                    operation: package.operation.id.clone(),
                    version: package.operation.version,
                    digest: package.digest.clone(),
                }],
            )]),
        }
    }

    #[test]
    fn unrelated_export_changes_candidate_but_not_a_consumed_lock() {
        let before = manifest("directory", &[("lookup", "directory.type.Person", 1)]);
        let after = manifest(
            "directory",
            &[
                ("lookup", "directory.type.Person", 1),
                ("manager", "directory.type.Manager", 2),
            ],
        );
        let old = catalog(BTreeMap::from([(
            "directory".into(),
            selected(before.clone()),
        )]));
        let new = catalog(BTreeMap::from([("directory".into(), selected(after))]));
        let imported = old.pin(&["directory.lookup".into()]).unwrap();
        assert_ne!(old.digest, new.digest);
        assert_eq!(
            old.resolve(&imported).unwrap(),
            new.resolve(&imported).unwrap()
        );
        assert_eq!(new.resolve(&imported).unwrap().operations.len(), 1);
        assert_eq!(new.pin(&["directory.lookup".into()]).unwrap(), imported);
        assert!(new.pin(&["directory.internal".into()]).is_err());
        assert!(
            new.pin(&["directory.lookup".into(), "directory.lookup".into()])
                .is_err()
        );
    }

    #[test]
    fn stale_scope_selection_and_contract_are_refused() {
        let original = manifest("directory", &[("lookup", "directory.type.Person", 1)]);
        let candidate = catalog(BTreeMap::from([(
            "directory".into(),
            selected(original.clone()),
        )]));
        let mut import = lock("directory", &original, "lookup");
        import.environment = "production".into();
        assert!(candidate.resolve(&import).is_err());
        import.environment = "dev".into();
        import.apps.get_mut("directory").unwrap()[0].digest = "sha256:stale".into();
        assert!(candidate.resolve(&import).is_err());
        let different = catalog(BTreeMap::from([(
            "other".into(),
            selected(manifest("other", &[("lookup", "other.type.Person", 1)])),
        )]));
        assert!(
            different
                .resolve(&lock("directory", &original, "lookup"))
                .is_err()
        );
        assert!(
            CandidateCatalog::derive(
                "acme".into(),
                "dev".into(),
                BTreeMap::from([("wrong".into(), selected(original))]),
            )
            .is_err()
        );
    }

    #[test]
    fn mixed_nominal_shapes_fail_at_import_resolution() {
        let first = manifest("directory", &[("lookup", "shared.type.Person", 1)]);
        let second = manifest("notices", &[("send", "shared.type.Person", 2)]);
        let candidate = catalog(BTreeMap::from([
            ("directory".into(), selected(first.clone())),
            ("notices".into(), selected(second.clone())),
        ]));
        let mut import = lock("directory", &first, "lookup");
        import.apps.extend(lock("notices", &second, "send").apps);
        assert!(candidate.resolve(&import).is_err());
        assert!(
            candidate
                .resolve(&lock("directory", &first, "lookup"))
                .is_ok()
        );
    }
}
