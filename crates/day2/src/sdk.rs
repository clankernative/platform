//! Explicit assembly of the Roc SDK source tree into its flat compiler package.
//!
//! Repository folders describe ownership, not Roc namespaces. Keeping published
//! module names stable preserves application imports and nominal type identities.

use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

struct Module {
    file: &'static str,
    source: &'static str,
    app_export: bool,
}

// This is the only source-to-package mapping. New files are never exported or
// admitted merely because their basename happens to match an existing module.
const MODULES: &[Module] = &[
    Module {
        file: "Snowflake.roc",
        source: "contracts/Snowflake.roc",
        app_export: true,
    },
    Module {
        file: "Slack.roc",
        source: "contracts/Slack.roc",
        app_export: true,
    },
    Module {
        file: "OpenAi.roc",
        source: "contracts/OpenAi.roc",
        app_export: true,
    },
    Module {
        file: "GoogleDirectory.roc",
        source: "contracts/GoogleDirectory.roc",
        app_export: true,
    },
    Module {
        file: "Linear.roc",
        source: "contracts/Linear.roc",
        app_export: true,
    },
    Module {
        file: "OperatorAlerts.roc",
        source: "contracts/OperatorAlerts.roc",
        app_export: true,
    },
    Module {
        file: "Resource.roc",
        source: "contracts/Resource.roc",
        app_export: true,
    },
    Module {
        file: "Carta.roc",
        source: "contracts/Carta.roc",
        app_export: true,
    },
    Module {
        file: "Effects.roc",
        source: "contracts/Effects.roc",
        app_export: true,
    },
    Module {
        file: "Notifications.roc",
        source: "contracts/Notifications.roc",
        app_export: true,
    },
    Module {
        file: "Handler.roc",
        source: "contracts/Handler.roc",
        app_export: true,
    },
    Module {
        file: "Delegate.roc",
        source: "contracts/Delegate.roc",
        app_export: true,
    },
    Module {
        file: "ObjectStore.roc",
        source: "contracts/ObjectStore.roc",
        app_export: true,
    },
    Module {
        file: "GitHubActions.roc",
        source: "contracts/GitHubActions.roc",
        app_export: true,
    },
    Module {
        file: "LinearWork.roc",
        source: "contracts/LinearWork.roc",
        app_export: true,
    },
    Module {
        file: "Observe.roc",
        source: "data/Observe.roc",
        app_export: true,
    },
    Module {
        file: "Failure.roc",
        source: "contracts/Failure.roc",
        app_export: true,
    },
    Module {
        file: "Text.roc",
        source: "domain/Text.roc",
        app_export: true,
    },
    Module {
        file: "TextSpec.roc",
        source: "domain/TextSpec.roc",
        app_export: true,
    },
    Module {
        file: "Path.roc",
        source: "contracts/Path.roc",
        app_export: true,
    },
    Module {
        file: "Api.roc",
        source: "contracts/Api.roc",
        app_export: true,
    },
    Module {
        file: "Doc.roc",
        source: "web/Doc.roc",
        app_export: true,
    },
    Module {
        file: "Example.roc",
        source: "testing/Example.roc",
        app_export: true,
    },
    Module {
        file: "Generator.roc",
        source: "testing/Generator.roc",
        app_export: true,
    },
    Module {
        file: "Asset.roc",
        source: "web/Asset.roc",
        app_export: true,
    },
    Module {
        file: "Attribute.roc",
        source: "web/markup/Attribute.roc",
        app_export: true,
    },
    Module {
        file: "Button.roc",
        source: "web/markup/Button.roc",
        app_export: true,
    },
    Module {
        file: "CollectionPage.roc",
        source: "data/pagination/CollectionPage.roc",
        app_export: true,
    },
    Module {
        file: "CommandBinding.roc",
        source: "runtime/CommandBinding.roc",
        app_export: true,
    },
    Module {
        file: "Context.roc",
        source: "contracts/Context.roc",
        app_export: true,
    },
    Module {
        file: "Control.roc",
        source: "web/Control.roc",
        app_export: true,
    },
    Module {
        file: "Cursor.roc",
        source: "data/pagination/Cursor.roc",
        app_export: true,
    },
    Module {
        file: "Declaration.roc",
        source: "contracts/Declaration.roc",
        app_export: true,
    },
    Module {
        file: "Field.roc",
        source: "web/Field.roc",
        app_export: true,
    },
    Module {
        file: "Form.roc",
        source: "web/markup/Form.roc",
        app_export: true,
    },
    Module {
        file: "Html.roc",
        source: "web/markup/Html.roc",
        app_export: true,
    },
    Module {
        file: "Ingress.roc",
        source: "contracts/Ingress.roc",
        app_export: true,
    },
    Module {
        file: "IngressBinding.roc",
        source: "contracts/IngressBinding.roc",
        app_export: true,
    },
    Module {
        file: "Input.roc",
        source: "contracts/Input.roc",
        app_export: true,
    },
    Module {
        file: "Model.roc",
        source: "data/Model.roc",
        app_export: true,
    },
    Module {
        file: "Operation.roc",
        source: "runtime/Operation.roc",
        app_export: false,
    },
    Module {
        file: "Output.roc",
        source: "contracts/Output.roc",
        app_export: true,
    },
    Module {
        file: "Page.roc",
        source: "web/Page.roc",
        app_export: true,
    },
    Module {
        file: "PageBinding.roc",
        source: "web/PageBinding.roc",
        app_export: true,
    },
    Module {
        file: "PageSize.roc",
        source: "data/pagination/PageSize.roc",
        app_export: true,
    },
    Module {
        file: "RowVersion.roc",
        source: "data/RowVersion.roc",
        app_export: true,
    },
    Module {
        file: "Product.roc",
        source: "runtime/Product.roc",
        app_export: true,
    },
    Module {
        file: "Property.roc",
        source: "testing/Property.roc",
        app_export: true,
    },
    Module {
        file: "Query.roc",
        source: "data/Query.roc",
        app_export: true,
    },
    Module {
        file: "QueryBinding.roc",
        source: "runtime/QueryBinding.roc",
        app_export: true,
    },
    Module {
        file: "Read.roc",
        source: "contracts/Read.roc",
        app_export: true,
    },
    Module {
        file: "Ref.roc",
        source: "data/Ref.roc",
        app_export: true,
    },
    Module {
        file: "TextMap.roc",
        source: "data/TextMap.roc",
        app_export: true,
    },
    Module {
        file: "TextSet.roc",
        source: "data/TextSet.roc",
        app_export: true,
    },
    Module {
        file: "Schedule.roc",
        source: "contracts/Schedule.roc",
        app_export: true,
    },
    Module {
        file: "ScheduleBinding.roc",
        source: "contracts/ScheduleBinding.roc",
        app_export: true,
    },
    Module {
        file: "Selection.roc",
        source: "data/Selection.roc",
        app_export: true,
    },
    Module {
        file: "Predicate.roc",
        source: "data/Predicate.roc",
        app_export: true,
    },
    Module {
        file: "Order.roc",
        source: "data/Order.roc",
        app_export: true,
    },
    Module {
        file: "Table.roc",
        source: "data/Table.roc",
        app_export: true,
    },
    Module {
        file: "Template.roc",
        source: "web/Template.roc",
        app_export: true,
    },
    Module {
        file: "Tx.roc",
        source: "data/Tx.roc",
        app_export: true,
    },
    Module {
        file: "WebUrl.roc",
        source: "domain/WebUrl.roc",
        app_export: true,
    },
    Module {
        file: "Wire.roc",
        source: "runtime/Wire.roc",
        app_export: false,
    },
    Module {
        file: "Write.roc",
        source: "contracts/Write.roc",
        app_export: true,
    },
    Module {
        file: "main.roc",
        source: "main.roc",
        app_export: false,
    },
    Module {
        file: "types.roc",
        source: "types.roc",
        app_export: false,
    },
];

/// All package module filenames, including modules unavailable to app imports.
pub fn module_files() -> impl Iterator<Item = &'static str> {
    MODULES.iter().map(|module| module.file)
}

pub fn reserved_module(file: &str) -> bool {
    module_files().any(|name| name == file)
}

/// Resolve a published filename through the catalog, never through path guessing.
pub fn source_path(root: &Path, file: &str) -> Result<PathBuf> {
    let module = MODULES
        .iter()
        .find(|module| module.file == file)
        .context("unknown SDK module")?;
    Ok(root.join(module.source))
}

fn inventory(root: &Path, relative: &Path, found: &mut BTreeSet<PathBuf>) -> Result<()> {
    ensure!(
        relative.components().count() <= 8,
        "SDK directory depth budget"
    );
    let path = root.join(relative);
    ensure!(
        fs::symlink_metadata(&path)?.is_dir(),
        "SDK root must be a real directory"
    );
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "SDK source symlink forbidden");
        let relative = relative.join(entry.file_name());
        if kind.is_dir() {
            // Native linker inputs have their own digest verification in xtask.
            if relative != Path::new("targets") {
                inventory(root, &relative, found)?;
            }
        } else {
            ensure!(kind.is_file(), "SDK special source file forbidden");
            if relative
                .extension()
                .is_some_and(|extension| extension == "roc")
            {
                ensure!(found.len() < 128, "SDK module count budget");
                found.insert(relative);
            } else {
                ensure!(
                    relative
                        .extension()
                        .is_some_and(|extension| extension == "md"),
                    "unexpected SDK source file: {}",
                    relative.display()
                );
            }
        }
    }
    Ok(())
}

fn validate_catalog(modules: &[Module]) -> Result<BTreeSet<PathBuf>> {
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for module in modules {
        ensure!(
            names.insert(module.file),
            "duplicate SDK published module: {}",
            module.file
        );
        ensure!(
            paths.insert(PathBuf::from(module.source)),
            "duplicate SDK source path: {}",
            module.source
        );
        ensure!(
            Path::new(module.file).components().count() == 1 && module.file.ends_with(".roc"),
            "invalid SDK module filename"
        );
        ensure!(
            Path::new(module.source)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
            "SDK source path must be relative"
        );
    }
    Ok(paths)
}

/// No SDK module an application can import may name a destroying capability.
///
/// The registry declares which actions destroy data; this is what stops one of
/// them growing a way back into app reach. A contract module is the only place
/// `Effects.capability` can be called, so checking the modules is checking every
/// path an application has. It runs at stage time rather than in a test because
/// it guards what gets compiled into an artifact, not what a test happened to
/// look at. See docs/DELETION.md.
fn reaches_no_destroying_capability(module: &Module, source: &[u8]) -> Result<()> {
    if !module.app_export {
        return Ok(());
    }
    let text = std::str::from_utf8(source).context("SDK module is not UTF-8")?;
    for action in day2_capabilities::resources::Action::ALL {
        ensure!(
            !action.destroys_data() || !text.contains(action.capability()),
            "SDK module {} names the destroying capability {}; removal is an \
             operator decision and cannot be reachable from application code",
            module.file,
            action.capability()
        );
    }
    Ok(())
}

/// Validate the closed inventory before writing a fresh, flat compiler package.
/// An existing empty directory is accepted; stale or shadowing files are not.
/// Hash keys retain repository paths so artifact provenance locates actual sources.
pub fn stage(root: &Path, target: &Path) -> Result<BTreeMap<String, String>> {
    let expected = validate_catalog(MODULES)?;
    let mut found = BTreeSet::new();
    inventory(root, Path::new(""), &mut found)?;
    ensure!(
        found == expected,
        "SDK source inventory differs from explicit catalog: missing {:?}, unregistered {:?}",
        expected.difference(&found).collect::<Vec<_>>(),
        found.difference(&expected).collect::<Vec<_>>()
    );
    let sources = MODULES
        .iter()
        .map(|module| {
            let path = root.join(module.source);
            ensure!(
                fs::metadata(&path)?.len() <= 256_000,
                "SDK module byte budget"
            );
            Ok((module, fs::read(path)?))
        })
        .collect::<Result<Vec<_>>>()?;
    for (module, bytes) in &sources {
        reaches_no_destroying_capability(module, bytes)?;
    }
    if target.exists() {
        ensure!(
            fs::symlink_metadata(target)?.is_dir(),
            "SDK stage must be a real directory"
        );
        ensure!(
            fs::read_dir(target)?.next().is_none(),
            "SDK stage must be empty"
        );
    } else {
        fs::create_dir_all(target)?;
    }
    let mut hashes = BTreeMap::new();
    for (module, bytes) in sources {
        hashes.insert(format!("sdk/{}", module.source), crate::digest(&bytes));
        fs::write(target.join(module.file), bytes)?;
    }
    Ok(hashes)
}

/// App exports and internal imports are distinct. Sealed constructors on exported
/// types still require the separate dual-profile compiler admission checks.
pub fn reflection_package() -> String {
    let names = MODULES
        .iter()
        .filter(|module| module.app_export)
        .map(|module| module.file.trim_end_matches(".roc"))
        .collect::<Vec<_>>();
    format!("package [{}] {{}}\n", names.join(", "))
}

pub fn app_platform() -> String {
    let names = MODULES
        .iter()
        .filter(|module| module.app_export)
        .map(|module| module.file.trim_end_matches(".roc"))
        .collect::<Vec<_>>();
    let mut source = format!(
        r#"platform "day2-pure"
    requires {{ step : Str -> Str }}
    exposes [{}]
    packages {{}}
    provides {{ "day2_step": step_for_host }}
    targets: {{
        inputs_dir: "targets/",
        arm64mac: {{ inputs: ["libhost.a", app] }},
        arm64glibc: {{ inputs: ["Scrt1.o", "crti.o", "libhost.a", app, "crtn.o", "libc.so.6", "libm.so.6", "libgcc_s.so.1"] }},
        x64glibc: {{ inputs: ["Scrt1.o", "crti.o", "libhost.a", app, "crtn.o", "libc.so.6", "libm.so.6", "libgcc_s.so.1"] }},
    }}
"#,
        names.join(", ")
    );
    for name in names {
        source.push_str(&format!("import {name}\n"));
    }
    source.push_str("step_for_host : Str -> Str\nstep_for_host = |raw| step(raw)\n");
    source
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_tree() -> tempfile::TempDir {
        let tree = tempfile::tempdir().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk");
        for module in MODULES {
            let path = tree.path().join(module.source);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::copy(root.join(module.source), path).unwrap();
        }
        tree
    }

    #[test]
    fn grouped_sources_stage_without_changing_compiler_names_or_bytes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk");
        let target = tempfile::tempdir().unwrap();
        let hashes = stage(&root, target.path()).unwrap();
        assert_eq!(hashes.len(), MODULES.len());
        for module in MODULES {
            let bytes = fs::read(source_path(&root, module.file).unwrap()).unwrap();
            assert_eq!(fs::read(target.path().join(module.file)).unwrap(), bytes);
            assert_eq!(
                hashes[&format!("sdk/{}", module.source)],
                crate::digest(&bytes)
            );
            assert!(reserved_module(module.file));
        }
        assert!(source_path(&root, "../../Wire.roc").is_err());
        assert!(!reserved_module("Application.roc"));
    }

    #[test]
    fn missing_and_unregistered_sources_fail_before_writing() {
        let tree = source_tree();
        let target = tempfile::tempdir().unwrap();
        fs::write(tree.path().join("data/Surprise.roc"), "Surprise :: [].{}\n").unwrap();
        assert!(stage(tree.path(), target.path()).is_err());
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
        fs::remove_file(tree.path().join("data/Surprise.roc")).unwrap();
        fs::remove_file(tree.path().join("data/Query.roc")).unwrap();
        assert!(stage(tree.path(), target.path()).is_err());
        assert_eq!(fs::read_dir(target.path()).unwrap().count(), 0);
    }

    /// No SDK module an application can import may reach a destroying capability.
    ///
    /// The real tree is checked, and then the gate is checked against a module
    /// that does reach one — a gate that only ever sees clean input is a gate
    /// nobody has watched fail. Staging refuses rather than warning, because a
    /// warning here would ship an artifact whose application can destroy data.
    #[test]
    fn staging_refuses_a_module_that_names_a_destroying_capability() {
        use day2_capabilities::resources::Action;
        let destroying = Action::ALL
            .iter()
            .find(|action| action.destroys_data())
            .expect("the registry declares at least one destroying action");

        let tree = source_tree();
        let target = tempfile::tempdir().unwrap();
        stage(tree.path(), target.path()).expect("the real SDK reaches no destroying capability");

        // An app-exported contract that calls it does not stage at all.
        let contract = MODULES
            .iter()
            .find(|module| module.app_export && module.source.starts_with("contracts/"))
            .expect("an app-exported contract exists");
        let poisoned = source_tree();
        let path = poisoned.path().join(contract.source);
        let source = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            format!(
                "{source}\n# Effects.capability(\"{}\")\n",
                destroying.capability()
            ),
        )
        .unwrap();
        let second = tempfile::tempdir().unwrap();
        let failure = stage(poisoned.path(), second.path())
            .unwrap_err()
            .to_string();
        assert!(
            failure.contains(destroying.capability()) && failure.contains(contract.file),
            "unexpected staging failure: {failure}"
        );
        assert_eq!(
            fs::read_dir(second.path()).unwrap().count(),
            0,
            "a refused stage still wrote the package"
        );
    }

    #[test]
    fn duplicate_names_and_paths_are_rejected() {
        for second in [
            Module {
                file: "Query.roc",
                source: "other/Query.roc",
                app_export: true,
            },
            Module {
                file: "Other.roc",
                source: "data/Query.roc",
                app_export: true,
            },
        ] {
            let first = Module {
                file: "Query.roc",
                source: "data/Query.roc",
                app_export: true,
            };
            assert!(validate_catalog(&[first, second]).is_err());
        }
    }

    #[test]
    fn stale_stage_is_not_overwritten() {
        let tree = source_tree();
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("Query.roc"), "stale").unwrap();
        assert!(stage(tree.path(), target.path()).is_err());
        assert_eq!(
            fs::read_to_string(target.path().join("Query.roc")).unwrap(),
            "stale"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_and_stage_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let tree = source_tree();
        let target = tempfile::tempdir().unwrap();
        let original = tree.path().join("data/Query.roc");
        let alias = tree.path().join("data/Alias.roc");
        symlink(&original, &alias).unwrap();
        assert!(stage(tree.path(), target.path()).is_err());
        fs::remove_file(alias).unwrap();
        let linked = target.path().join("linked");
        let empty = tempfile::tempdir().unwrap();
        symlink(empty.path(), &linked).unwrap();
        assert!(stage(tree.path(), &linked).is_err());
    }

    #[test]
    fn private_transport_is_not_an_app_export() {
        let source = app_platform();
        for private in ["Wire", "Operation"] {
            assert!(!source.contains(&format!("import {private}\n")));
            assert!(
                !MODULES
                    .iter()
                    .find(|module| module.file == format!("{private}.roc"))
                    .unwrap()
                    .app_export
            );
        }
        for public in [
            "Context",
            "Query",
            "Tx",
            "Declaration",
            "CollectionPage",
            "PageSize",
        ] {
            assert!(source.contains(&format!("import {public}\n")));
        }
    }
}
