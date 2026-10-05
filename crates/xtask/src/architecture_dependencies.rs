//! Reviewed workspace dependency boundaries. Cargo resolves dependency aliases,
//! target clauses and feature declarations; this gate never updates its policy.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

const POLICY: &str = "architecture-boundaries.json";
const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum Role {
    Abi,
    Tool,
    Runtime,
    Adapter,
    Contracts,
    Kernel,
}

impl Role {
    fn strict(&self) -> bool {
        matches!(self, Self::Contracts | Self::Kernel)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dependency {
    name: String,
    kind: String,
    target: Option<String>,
    rename: Option<String>,
    features: Vec<String>,
    default_features: bool,
    optional: bool,
    local_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    name: String,
    manifest: String,
    role: Role,
    production_targets: Vec<Target>,
    dependencies: Vec<Dependency>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    name: String,
    kind: Vec<String>,
    source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: String,
    dependencies: Vec<CargoDependency>,
    targets: Vec<CargoTarget>,
}

#[derive(Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
    src_path: String,
}

#[derive(Deserialize)]
struct CargoDependency {
    name: String,
    kind: Option<String>,
    target: Option<String>,
    rename: Option<String>,
    features: Vec<String>,
    uses_default_features: bool,
    optional: bool,
    path: Option<String>,
}

fn relative(root: &Path, value: &str) -> Result<String> {
    let path = Path::new(value).canonicalize()?;
    Ok(path
        .strip_prefix(root)
        .context("dependency boundary leaves platform root")?
        .to_str()
        .context("dependency boundary path must be UTF-8")?
        .to_owned())
}

fn metadata(root: &Path) -> Result<Vec<Package>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ])
        .output()
        .context("read Cargo dependency boundaries")?;
    ensure!(output.status.success(), "Cargo dependency inventory failed");
    ensure!(
        output.stdout.len() <= MAX_BYTES,
        "dependency inventory budget"
    );
    let metadata: Metadata = serde_json::from_slice(&output.stdout)?;
    let mut packages = Vec::new();
    for package in metadata.packages {
        if !metadata.workspace_members.contains(&package.id) {
            continue;
        }
        let manifest = relative(root, &package.manifest_path)?;
        validate_manifest(&manifest)?;
        let package_root = Path::new(&manifest).parent().context("package root")?;
        let mut production_targets = Vec::new();
        for target in &package.targets {
            let source = relative(root, &target.src_path)?;
            ensure!(
                Path::new(&source).starts_with(package_root),
                "Cargo target leaves inventoried package root"
            );
            if !target
                .kind
                .iter()
                .any(|kind| ["test", "bench", "example"].contains(&kind.as_str()))
            {
                ensure!(
                    !Path::new(&source)
                        .strip_prefix(package_root)?
                        .starts_with("tests")
                        && !Path::new(&source)
                            .strip_prefix(package_root)?
                            .starts_with("generated"),
                    "production Cargo target cannot use an exempt source directory"
                );
                production_targets.push(Target {
                    name: target.name.clone(),
                    kind: target.kind.clone(),
                    source,
                });
            }
        }
        production_targets.sort();
        let mut dependencies = Vec::new();
        for dependency in package.dependencies {
            let mut features = dependency.features;
            features.sort();
            features.dedup();
            dependencies.push(Dependency {
                name: dependency.name,
                kind: dependency.kind.unwrap_or_else(|| "normal".into()),
                target: dependency.target,
                rename: dependency.rename,
                features,
                default_features: dependency.uses_default_features,
                optional: dependency.optional,
                local_path: dependency
                    .path
                    .map(|path| relative(root, &path))
                    .transpose()?,
            });
        }
        dependencies.sort();
        packages.push(Package {
            name: package.name,
            manifest,
            // Inventory is a fact report. Only the reviewed policy assigns roles.
            role: Role::Runtime,
            production_targets,
            dependencies,
        });
    }
    packages.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(packages)
}

fn validate_manifest(manifest: &str) -> Result<()> {
    let path = Path::new(manifest);
    ensure!(
        manifest == "cli/checks/Cargo.toml"
            || (path.starts_with("crates")
                && path.components().count() == 3
                && path.file_name().is_some_and(|name| name == "Cargo.toml")),
        "workspace package outside supported source inventory: {manifest}"
    );
    Ok(())
}

fn read_policy(root: &Path) -> Result<Policy> {
    let path = root.join(POLICY);
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "regular boundary policy required"
    );
    ensure!(metadata.len() <= MAX_BYTES as u64, "boundary policy budget");
    let policy: Policy = day2::json::decode(&fs::read(path)?)?;
    validate_policy(&policy)?;
    Ok(policy)
}

fn validate_policy(policy: &Policy) -> Result<()> {
    ensure!(policy.version == 1, "unsupported dependency policy version");
    ensure!(
        !policy.packages.is_empty() && policy.packages.len() <= 128,
        "workspace package budget"
    );
    ensure!(
        policy
            .packages
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name),
        "package policy must be unique and sorted"
    );
    for package in &policy.packages {
        validate_manifest(&package.manifest)?;
        let path = Path::new(&package.manifest);
        ensure!(
            !path.is_absolute()
                && path
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
                && path.file_name().is_some_and(|name| name == "Cargo.toml"),
            "invalid package policy path"
        );
        ensure!(
            package.dependencies.len() <= 256,
            "package dependency budget"
        );
        ensure!(
            !package.production_targets.is_empty() && package.production_targets.len() <= 64,
            "production target budget"
        );
        ensure!(
            package
                .production_targets
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "production targets must be unique and sorted"
        );
        ensure!(
            package
                .dependencies
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "dependency policy must be unique and sorted"
        );
        for dependency in &package.dependencies {
            ensure!(
                ["normal", "dev", "build"].contains(&dependency.kind.as_str()),
                "unknown dependency kind"
            );
            ensure!(
                dependency.features.windows(2).all(|pair| pair[0] < pair[1]),
                "dependency features must be unique and sorted"
            );
        }
    }
    Ok(())
}

fn compare(policy: &Policy, actual: &[Package]) -> Result<()> {
    validate_policy(policy)?;
    ensure!(
        policy.packages.len() == actual.len(),
        "workspace package inventory changed"
    );
    let by_path: BTreeMap<_, _> = policy
        .packages
        .iter()
        .map(|package| {
            (
                Path::new(&package.manifest)
                    .parent()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                package,
            )
        })
        .collect();
    ensure!(
        by_path.len() == policy.packages.len(),
        "duplicate package manifest in policy"
    );
    for (expected, actual) in policy.packages.iter().zip(actual) {
        ensure!(
            expected.name == actual.name && expected.manifest == actual.manifest,
            "unreviewed workspace package or manifest: {}",
            actual.name
        );
        ensure!(
            expected.dependencies == actual.dependencies,
            "unreviewed dependency, target, alias or feature change in {}",
            actual.name
        );
        ensure!(
            expected.production_targets == actual.production_targets,
            "unreviewed production target/source change in {}",
            actual.name
        );
        if expected.role.strict() {
            for dependency in expected
                .dependencies
                .iter()
                .filter(|dependency| dependency.kind != "dev")
            {
                if let Some(path) = &dependency.local_path {
                    let target = by_path
                        .get(path.as_str())
                        .context("unclassified local dependency")?;
                    ensure!(
                        target.role.strict(),
                        "strict {} cannot depend on {:?} {}",
                        expected.name,
                        target.role,
                        target.name
                    );
                }
            }
        }
    }
    Ok(())
}

pub fn check(root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    let policy = read_policy(&root)?;
    compare(&policy, &metadata(&root)?)?;
    let effects = super::architecture::inventory(&root)?;
    for package in &policy.packages {
        if package.role.strict() {
            let prefix = format!(
                "{}/",
                Path::new(&package.manifest).parent().unwrap().display()
            );
            ensure!(
                effects
                    .findings
                    .iter()
                    .all(|finding| !finding.source.starts_with(&prefix)),
                "strict {} cannot contain ambient effects or lint suppressions",
                package.name
            );
        }
    }
    let strict = strict_libraries(&policy)?;
    super::architecture_kernel::check(&root, &strict)?;
    println!(
        "Workspace dependency boundaries checked: {} packages",
        policy.packages.len()
    );
    Ok(())
}

fn strict_libraries(policy: &Policy) -> Result<Vec<super::architecture_kernel::StrictCrate<'_>>> {
    policy
        .packages
        .iter()
        .filter(|package| package.role.strict())
        .map(|package| {
            // `compare` established that these are Cargo's actual sources. A
            // strict package is library-only; adding a bin or build script must
            // first establish a separate reviewed enforcement boundary.
            ensure!(
                package.production_targets.len() == 1
                    && package.production_targets[0].kind == ["lib"],
                "strict {} must have one production library target",
                package.name
            );
            Ok(super::architecture_kernel::StrictCrate {
                name: &package.name,
                source: &package.production_targets[0].source,
                kernel: package.role == Role::Kernel,
            })
        })
        .collect()
}

pub fn inventory(root: &Path) -> Result<serde_json::Value> {
    let root = root.canonicalize()?;
    Ok(serde_json::to_value(Policy {
        version: 1,
        packages: metadata(&root)?,
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_libraries_use_verified_targets_and_reject_uncovered_production_targets() -> Result<()>
    {
        let mut kernel = package("kernel", Role::Kernel);
        kernel.production_targets[0].source = "crates/kernel/decision.rs".into();
        let mut policy = Policy {
            version: 1,
            packages: vec![kernel],
        };
        let selected = strict_libraries(&policy)?;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].source, "crates/kernel/decision.rs");
        assert!(selected[0].kernel);
        for kind in ["bin", "custom-build", "proc-macro"] {
            policy.packages[0].production_targets[0].kind = vec![kind.into()];
            assert!(strict_libraries(&policy).is_err());
        }
        policy.packages[0].production_targets[0].kind = vec!["lib".into()];
        policy.packages[0].production_targets.push(Target {
            name: "extra".into(),
            kind: vec!["bin".into()],
            source: "crates/kernel/main.rs".into(),
        });
        assert!(strict_libraries(&policy).is_err());
        Ok(())
    }

    fn package(name: &str, role: Role) -> Package {
        Package {
            name: name.into(),
            manifest: format!("crates/{name}/Cargo.toml"),
            role,
            production_targets: vec![Target {
                name: name.into(),
                kind: vec!["lib".into()],
                source: format!("crates/{name}/src/lib.rs"),
            }],
            dependencies: Vec::new(),
        }
    }

    fn dependency(name: &str) -> Dependency {
        Dependency {
            name: name.into(),
            kind: "normal".into(),
            target: None,
            rename: None,
            features: Vec::new(),
            default_features: false,
            optional: false,
            local_path: None,
        }
    }

    #[test]
    fn rejects_new_removed_renamed_and_target_specific_dependencies() -> Result<()> {
        let mut approved = package("contracts", Role::Contracts);
        approved.dependencies.push(dependency("serde"));
        let policy = Policy {
            version: 1,
            packages: vec![approved.clone()],
        };
        compare(&policy, &[approved.clone()])?;
        for changed in [
            Dependency {
                target: Some("cfg(target_os = \"linux\")".into()),
                ..dependency("serde")
            },
            Dependency {
                rename: Some("innocent".into()),
                ..dependency("serde")
            },
            Dependency {
                features: vec!["std".into()],
                ..dependency("serde")
            },
            Dependency {
                default_features: true,
                ..dependency("serde")
            },
            Dependency {
                kind: "build".into(),
                ..dependency("serde")
            },
            Dependency {
                optional: true,
                ..dependency("serde")
            },
            dependency("reqwest"),
        ] {
            let mut actual = approved.clone();
            actual.dependencies = vec![changed];
            assert!(compare(&policy, &[actual]).is_err());
        }
        approved.dependencies.clear();
        assert!(compare(&policy, &[approved]).is_err());
        Ok(())
    }

    #[test]
    fn strict_packages_cannot_depend_on_runtime_even_when_allowlisted() {
        let mut contracts = package("contracts", Role::Contracts);
        contracts.dependencies.push(Dependency {
            local_path: Some("crates/runtime".into()),
            ..dependency("runtime")
        });
        let actual = vec![contracts, package("runtime", Role::Runtime)];
        let policy = Policy {
            version: 1,
            packages: actual.clone(),
        };
        assert!(compare(&policy, &actual).is_err());
    }

    #[test]
    fn rejects_unknown_packages_and_duplicate_or_unsorted_policy() {
        let actual = vec![package("contracts", Role::Contracts)];
        let mut policy = Policy {
            version: 1,
            packages: actual.clone(),
        };
        assert!(compare(&policy, &[package("another", Role::Tool)]).is_err());
        assert!(compare(&policy, &[]).is_err());
        policy.packages.push(actual[0].clone());
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn policy_unknown_fields_and_versions_fail_closed() {
        assert!(
            serde_json::from_str::<Policy>(r#"{"version":1,"packages":[],"disable":true}"#)
                .is_err()
        );
        assert!(
            validate_policy(&Policy {
                version: 99,
                packages: vec![package("contracts", Role::Contracts)]
            })
            .is_err()
        );
    }

    #[test]
    fn package_sources_cannot_escape_the_checked_roots() {
        for path in [
            "outside/Cargo.toml",
            "crates/a/nested/Cargo.toml",
            "../crates/a/Cargo.toml",
            "/crates/a/Cargo.toml",
        ] {
            assert!(validate_manifest(path).is_err(), "{path}");
        }
        assert!(validate_manifest("crates/kernel/Cargo.toml").is_ok());
        assert!(validate_manifest("cli/checks/Cargo.toml").is_ok());
    }

    #[test]
    fn changing_a_library_target_to_an_existing_test_file_requires_review() {
        let approved = package("contracts", Role::Contracts);
        let policy = Policy {
            version: 1,
            packages: vec![approved.clone()],
        };
        let mut actual = approved;
        actual.production_targets[0].source = "crates/contracts/tests/previously_exempt.rs".into();
        assert!(compare(&policy, &[actual]).is_err());
    }
}
