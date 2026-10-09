//! Candidate operation discovery from one instance's selected, verified artifacts.
//!
//! This is build-time data, not a serving or permission decision. A caller lock
//! pins only consumed operations, so an unrelated export can change this catalog
//! without changing that caller's compiled contract closure.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

use crate::operation_contract::{ImportPin, Manifest, Package, TypePin, resolve_type_closure};
use day2_capabilities::{
    Digest,
    credentials::{self, ManifestFamily, QualificationReceipt},
    oauth::{AuthorityAction, AuthorityNode},
};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedImports {
    pub operations: BTreeMap<String, Package>,
    pub types: BTreeMap<String, TypePin>,
}

/// Portable build input: only the consumed operation packages and their exact
/// type closure. Instance scope, selected artifact IDs and the catalog digest
/// stay in build/qualification evidence, outside the compiled app artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedContracts {
    pub operations: BTreeMap<String, Package>,
    pub types: BTreeMap<String, TypePin>,
}

impl ImportedContracts {
    pub fn from_resolved(resolved: ResolvedImports) -> Result<Self> {
        let imports = Self {
            operations: resolved.operations,
            types: resolved.types,
        };
        imports.verify()?;
        Ok(imports)
    }

    pub fn verify(&self) -> Result<()> {
        ensure!(
            !self.operations.is_empty() && self.operations.len() <= 1024,
            "imported operation budget"
        );
        for (id, package) in &self.operations {
            ensure!(
                id == &package.operation.id,
                "imported operation key mismatch"
            );
            package.verify()?;
        }
        ensure!(
            self.types == resolve_type_closure(self.operations.values())?,
            "imported type closure mismatch"
        );
        Ok(())
    }
}

/// Contract checks for the supplied callers only. Release readiness still
/// requires complete dependency evidence, serving bindings and current policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckedConsumers {
    pub catalog_digest: String,
    pub dependencies: BTreeMap<String, Vec<String>>,
    pub imports: BTreeMap<String, ResolvedImports>,
}

/// A selected composition whose callers' embedded imports all resolve to the
/// selected exporters. This is qualification evidence, not invocation authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QualifiedCatalog {
    pub catalog: CandidateCatalog,
    pub consumers: CheckedConsumers,
}

/// Resolve every selected family's app-local binding against the same instance
/// resource catalog used by the release candidate. The receipt pins both the
/// selected artifact composition and the instance definitions; it is evidence
/// for activation, never permission to issue or verify a credential.
pub fn qualify_credentials(
    catalog: &CandidateCatalog,
    instance: &crate::artifact::Instance,
    families: &BTreeMap<String, Vec<ManifestFamily>>,
) -> Result<BTreeMap<String, Vec<QualificationReceipt>>> {
    catalog.verify()?;
    ensure!(
        catalog.installation == instance.installation
            && catalog.environment == instance.environment,
        "credential qualification instance scope mismatch"
    );
    let composition = Digest::of(&(
        "credential-selected-composition-v1",
        &catalog.digest,
        Digest::of(instance)?,
    ))?;
    let mut receipts = BTreeMap::new();
    for (app, selected) in families {
        ensure!(
            catalog.apps.contains_key(app),
            "credential family app not selected: {app}"
        );
        let app_binding = instance
            .apps
            .get(app)
            .context("credential app binding missing")?;
        let definitions = instance.resources.as_ref();
        let mut qualified = Vec::new();
        for family in selected {
            for root in family.roots.values() {
                ensure!(
                    local_credential_closure(&root.closure),
                    "unsupported credential provider or resource authority: {app}/{}",
                    family.id.as_str()
                );
            }
            let binding = app_binding
                .credential_families
                .get(family.id.as_str())
                .with_context(|| {
                    format!(
                        "{}:{}: CREDENTIAL_FAMILY_UNBOUND ({app}/{})",
                        family.source.file,
                        family.source.line,
                        family.id.as_str()
                    )
                })?;
            ensure!(
                binding.namespace.installation.as_str() == instance.installation
                    && binding.namespace.environment.as_str() == instance.environment
                    && binding.namespace.app.as_str() == app
                    && binding.family == family.id,
                "credential binding scope mismatch: {app}/{}",
                family.id.as_str()
            );
            let definitions = definitions.context("credential resource catalog missing")?;
            let policy = definitions
                .credentials
                .management
                .get(binding.management.id.as_str())
                .context("credential management policy missing")?;
            let approved = definitions
                .credentials
                .approved_authority
                .get(binding.approved_authority.id.as_str())
                .context("credential approved authority missing")?;
            qualified.push(credentials::qualify(
                family,
                Some(binding),
                policy,
                approved,
                composition.clone(),
            )?);
        }
        if !qualified.is_empty() {
            receipts.insert(app.clone(), qualified);
        }
    }
    Ok(receipts)
}

fn local_credential_closure(node: &AuthorityNode) -> bool {
    node.actions
        .iter()
        .all(|action| matches!(action, AuthorityAction::LocalData { .. }))
        && node.children.values().all(local_credential_closure)
}

pub fn qualify_artifacts(
    installation: String,
    environment: String,
    paths: &BTreeMap<String, std::path::PathBuf>,
) -> Result<QualifiedCatalog> {
    let mut apps = BTreeMap::new();
    let mut embedded = BTreeMap::new();
    for (name, path) in paths {
        let artifact = crate::artifact::LoadedArtifact::load(path)
            .with_context(|| format!("selected artifact for {name}"))?;
        ensure!(
            artifact.contract().namespace == *name,
            "selected artifact namespace mismatch: {name}"
        );
        let manifest = match &artifact.contract().export_manifest {
            Some(manifest) => manifest.clone(),
            None => Manifest::derive(name.clone(), [], &BTreeMap::new())?,
        };
        if let Some(imports) = &artifact.contract().imports {
            embedded.insert(name.clone(), imports.clone());
        }
        apps.insert(
            name.clone(),
            SelectedApp {
                artifact: artifact.id().to_owned(),
                manifest,
            },
        );
    }
    let catalog = CandidateCatalog::derive(installation, environment, apps)?;
    let consumers = catalog.check_embedded_consumers(&embedded)?;
    Ok(QualifiedCatalog { catalog, consumers })
}

impl CandidateCatalog {
    pub fn derive(
        installation: String,
        environment: String,
        apps: BTreeMap<String, SelectedApp>,
    ) -> Result<Self> {
        day2_contracts::names::identifier(&installation)?;
        day2_contracts::names::identifier(&environment)?;
        ensure!((1..=1024).contains(&apps.len()), "candidate app budget");
        let mut identities = BTreeMap::new();
        for (name, selected) in &apps {
            day2_contracts::names::identifier(name)?;
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

    pub fn check_consumers(
        &self,
        locks: &BTreeMap<String, ImportLock>,
    ) -> Result<CheckedConsumers> {
        self.verify()?;
        ensure!(locks.len() <= self.apps.len(), "consumer lock budget");
        let mut dependencies: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut imports = BTreeMap::new();
        for (caller, lock) in locks {
            ensure!(
                self.apps.contains_key(caller),
                "consumer app not selected: {caller}"
            );
            ensure!(!lock.apps.contains_key(caller), "self app import: {caller}");
            let resolved = self.resolve(lock)?;
            dependencies.insert(caller.clone(), lock.apps.keys().cloned().collect());
            imports.insert(caller.clone(), resolved);
        }
        let mut remaining = dependencies.clone();
        while !remaining.is_empty() {
            let ready = remaining
                .iter()
                .filter(|(_, targets)| targets.iter().all(|target| !remaining.contains_key(target)))
                .map(|(caller, _)| caller.clone())
                .collect::<Vec<_>>();
            ensure!(!ready.is_empty(), "cyclic app contract-build dependency");
            for caller in ready {
                remaining.remove(&caller);
            }
        }
        Ok(CheckedConsumers {
            catalog_digest: self.digest.clone(),
            dependencies,
            imports,
        })
    }

    /// Check every selected caller's portable import closure against the
    /// selected exporter, without asking an operator to maintain a lock list.
    pub fn check_embedded_consumers(
        &self,
        embedded: &BTreeMap<String, ImportedContracts>,
    ) -> Result<CheckedConsumers> {
        let mut locks = BTreeMap::new();
        for (caller, imports) in embedded {
            imports.verify()?;
            let mut apps: BTreeMap<String, Vec<ImportPin>> = BTreeMap::new();
            for (operation, package) in &imports.operations {
                let (app, _) = operation
                    .split_once('.')
                    .context("import operation needs its app namespace")?;
                apps.entry(app.to_owned()).or_default().push(ImportPin {
                    operation: operation.clone(),
                    version: package.operation.version,
                    digest: package.digest.clone(),
                });
            }
            locks.insert(
                caller.clone(),
                ImportLock {
                    installation: self.installation.clone(),
                    environment: self.environment.clone(),
                    apps,
                },
            );
        }
        let checked = self.check_consumers(&locks)?;
        for (caller, imports) in embedded {
            let resolved = &checked.imports[caller];
            ensure!(
                imports.operations == resolved.operations && imports.types == resolved.types,
                "selected caller import closure changed: {caller}"
            );
        }
        Ok(checked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation_contract::{Codec, Kind, OperationSpec, TypeObject};
    use day2_capabilities::{
        BindingRef, Name,
        credentials::{
            CredentialFamilyBinding, CredentialRoot, DeliveryProfile, FamilyDeclaration, GrantMode,
            ManagedProfile, ManagementPolicy, ManagementPredicate, Namespace, RotationProfile,
            SourceLocation,
        },
        oauth::{
            OperationAuthorityContract, OperationKind, ResourceAudienceRef, SecurityOriginRef,
        },
    };
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

    #[test]
    fn selected_credential_binding_pins_policy_and_child_authority() -> Result<()> {
        let name = |value: &str| -> Name { value.to_owned().try_into().unwrap() };
        let pin = |value: &str| BindingRef::pin(name(value), &value).unwrap();
        let root = |child: bool, provider: bool| -> Result<OperationAuthorityContract> {
            let mut actions = BTreeSet::from([AuthorityAction::LocalData {
                category: "records".into(),
                policy: Digest::new(b"records policy"),
                write: true,
            }]);
            if provider {
                actions.insert(AuthorityAction::Provider {
                    requirement: Digest::new(b"provider requirement"),
                    action: "send".into(),
                    permission: Digest::new(b"provider permission"),
                    write: true,
                });
            }
            OperationAuthorityContract::derive(
                "submit".into(),
                1,
                Digest::new(b"submit contract"),
                OperationKind::Command,
                AuthorityNode {
                    actions,
                    children: if child {
                        BTreeMap::from([(
                            "followup".into(),
                            AuthorityNode {
                                actions: BTreeSet::from([AuthorityAction::LocalData {
                                    category: "private".into(),
                                    policy: Digest::new(b"private policy"),
                                    write: false,
                                }]),
                                children: BTreeMap::new(),
                            },
                        )])
                    } else {
                        BTreeMap::new()
                    },
                },
            )
        };
        let make_family = |authority: OperationAuthorityContract| -> Result<ManifestFamily> {
            ManifestFamily::derive(
                FamilyDeclaration {
                    registration: name("client"),
                    id: name("keys"),
                    profile: ManagedProfile::Client,
                    grant: GrantMode::Fixed,
                    roots: vec!["submit".into()],
                    lifetime_seconds: 3600,
                    source: SourceLocation {
                        file: "Keys.roc".into(),
                        line: 7,
                    },
                },
                &BTreeMap::from([(
                    "submit".into(),
                    CredentialRoot {
                        authority,
                        direct_ingress: true,
                        interactive_security: false,
                        single_resource_model: None,
                    },
                )]),
            )
        };
        let approved: BTreeMap<String, OperationAuthorityContract> =
            BTreeMap::from([("submit".into(), root(false, false)?)]);
        let policy = ManagementPolicy {
            identity_authority: pin("directory"),
            issue: ManagementPredicate::Creator,
            read_metadata: ManagementPredicate::Creator,
            rotate: ManagementPredicate::Creator,
            revoke: ManagementPredicate::Creator,
        };
        let binding = CredentialFamilyBinding {
            namespace: Namespace {
                installation: name("acme"),
                environment: name("dev"),
                app: name("reports"),
                binding_generation: 1,
            },
            family: name("keys"),
            approved_authority: BindingRef {
                id: name("approved"),
                revision: Digest::of(&("credential-approved-authority-v1", &approved))?,
            },
            management: BindingRef::pin(name("managers"), &policy)?,
            rotation: RotationProfile::AtomicReplace,
            delivery: DeliveryProfile::AuthenticatedCreatorReveal,
            verifier: pin("verifier"),
            custody: pin("custody"),
            security_shell: SecurityOriginRef(pin("security")),
            audience: ResourceAudienceRef(pin("audience")),
            epoch_store: pin("epoch"),
            quota: pin("quota"),
            max_lifetime_seconds: 86400,
            reveal_window_seconds: 300,
        };
        let instance = |binding: Option<&CredentialFamilyBinding>,
                        policy: &ManagementPolicy|
         -> Result<crate::artifact::Instance> {
            let bindings = binding
                .map(|value| BTreeMap::from([("keys", value)]))
                .unwrap_or_default();
            let bytes = serde_json::to_vec(&json!({
                "installation": "acme", "environment": "dev",
                "apps": {"reports": {"artifact": "unused", "readers": [], "writers": [],
                    "credential_families": bindings}},
                "resources": {"version": 1, "connections": {}, "resources": {}, "policies": {},
                    "credentials": {"management": {"managers": policy},
                        "approved_authority": {"approved": approved}}}
            }))?;
            if binding.is_some() {
                // Deliberately incomplete DATA for pure composition, not CURRENT.
                let error = crate::artifact::Instance::from_bytes(&bytes).unwrap_err();
                assert!(error.to_string().contains("credential_runtime_missing"));
                crate::json::decode(&bytes)
            } else {
                crate::artifact::Instance::from_bytes(&bytes)
            }
        };
        let selected = catalog(BTreeMap::from([(
            "reports".into(),
            selected(manifest("reports", &[])),
        )]));
        let family = make_family(root(false, false)?)?;
        let families = |value: ManifestFamily| BTreeMap::from([("reports".into(), vec![value])]);
        let qualified = qualify_credentials(
            &selected,
            &instance(Some(&binding), &policy)?,
            &families(family.clone()),
        )?;
        assert_eq!(qualified["reports"][0].family_contract, family.contract);
        assert!(
            qualify_credentials(
                &selected,
                &instance(None, &policy)?,
                &families(family.clone())
            )
            .unwrap_err()
            .to_string()
            .contains("CREDENTIAL_FAMILY_UNBOUND")
        );
        let mut changed_policy = policy.clone();
        changed_policy.issue = ManagementPredicate::MemberOf {
            group: name("operators"),
        };
        assert!(
            qualify_credentials(
                &selected,
                &instance(Some(&binding), &changed_policy)?,
                &families(family.clone())
            )
            .unwrap_err()
            .to_string()
            .contains("management policy revision mismatch")
        );
        assert!(
            qualify_credentials(
                &selected,
                &instance(Some(&binding), &policy)?,
                &families(make_family(root(true, false)?)?)
            )
            .unwrap_err()
            .to_string()
            .contains("root exceeds approved authority")
        );
        assert!(
            qualify_credentials(
                &selected,
                &instance(Some(&binding), &policy)?,
                &families(make_family(root(false, true)?)?)
            )
            .unwrap_err()
            .to_string()
            .contains("unsupported credential provider")
        );
        Ok(())
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

    fn embedded(manifest: &Manifest, operation: &str) -> ImportedContracts {
        let package = manifest.exports[operation].clone();
        ImportedContracts::from_resolved(ResolvedImports {
            operations: BTreeMap::from([(operation.into(), package.clone())]),
            types: package.types,
        })
        .unwrap()
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

    #[test]
    fn candidate_checks_consumed_contracts_and_conservative_app_cycles() {
        let directory = manifest("directory", &[("lookup", "directory.type.Person", 1)]);
        let onboarding = manifest("onboarding", &[("start", "onboarding.type.Start", 1)]);
        let selected_apps = BTreeMap::from([
            ("directory".into(), selected(directory.clone())),
            ("onboarding".into(), selected(onboarding.clone())),
        ]);
        let candidate = catalog(selected_apps.clone());
        let callers =
            BTreeMap::from([("onboarding".into(), lock("directory", &directory, "lookup"))]);
        let checked = candidate.check_consumers(&callers).unwrap();
        assert_eq!(checked.dependencies["onboarding"], ["directory"]);
        assert_eq!(checked.imports["onboarding"].operations.len(), 1);

        let mut unrelated = selected_apps.clone();
        unrelated.insert(
            "directory".into(),
            selected(manifest(
                "directory",
                &[
                    ("lookup", "directory.type.Person", 1),
                    ("manager", "directory.type.Manager", 2),
                ],
            )),
        );
        assert!(catalog(unrelated).check_consumers(&callers).is_ok());

        let mut changed = selected_apps;
        changed.insert(
            "directory".into(),
            selected(manifest(
                "directory",
                &[("lookup", "directory.type.Person", 2)],
            )),
        );
        assert!(catalog(changed).check_consumers(&callers).is_err());

        let mut cycle = callers;
        cycle.insert("directory".into(), lock("onboarding", &onboarding, "start"));
        assert!(candidate.check_consumers(&cycle).is_err());
        cycle.remove("onboarding");
        assert!(candidate.check_consumers(&cycle).is_ok());
    }

    #[test]
    fn selected_callers_pin_exact_exports_without_a_separate_lock_inventory() {
        let directory = manifest("directory", &[("lookup", "directory.type.Person", 1)]);
        let caller = manifest("caller", &[("who", "caller.type.Person", 1)]);
        let imports = BTreeMap::from([("caller".into(), embedded(&directory, "directory.lookup"))]);
        let selected_apps = BTreeMap::from([
            ("directory".into(), selected(directory.clone())),
            ("caller".into(), selected(caller.clone())),
        ]);
        let qualified = catalog(selected_apps.clone())
            .check_embedded_consumers(&imports)
            .unwrap();
        assert_eq!(qualified.dependencies["caller"], ["directory"]);

        let mut unrelated = selected_apps.clone();
        unrelated.insert(
            "directory".into(),
            selected(manifest(
                "directory",
                &[
                    ("lookup", "directory.type.Person", 1),
                    ("manager", "directory.type.Manager", 2),
                ],
            )),
        );
        assert!(
            catalog(unrelated)
                .check_embedded_consumers(&imports)
                .is_ok()
        );

        let mut changed = selected_apps;
        changed.insert(
            "directory".into(),
            selected(manifest(
                "directory",
                &[("lookup", "directory.type.Person", 2)],
            )),
        );
        assert!(catalog(changed).check_embedded_consumers(&imports).is_err());

        let mut cycle = imports.clone();
        cycle.insert("directory".into(), embedded(&caller, "caller.who"));
        assert!(
            catalog(BTreeMap::from([
                ("directory".into(), selected(directory)),
                ("caller".into(), selected(caller)),
            ]))
            .check_embedded_consumers(&cycle)
            .is_err()
        );
    }
}
