//! Resolve authored folders into one Roc package without changing nominal identity.
//! A module's declaration supplies its identity; directories are organization,
//! never operation registration. App.definition alone supplies the catalog.
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Copy each declared module exactly once into the compiler package. The caller
/// retains the original captured tree and its path-keyed hashes for provenance.
/// Resolve and validate the entire map before writing anything.
pub fn stage(source: &Path, target: &Path) -> Result<BTreeMap<String, PathBuf>> {
    let mut modules = BTreeMap::new();
    discover(source, source, 0, &mut modules)?;
    ensure!(
        modules
            .get("app")
            .is_some_and(|(name, path)| name == "App" && path == Path::new("App.roc")),
        "application requires App.roc at its root"
    );
    fs::create_dir_all(target)?;
    let mut paths = BTreeMap::new();
    for (name, path) in modules.values() {
        let destination = target.join(format!("{name}.roc"));
        ensure!(
            !destination.exists(),
            "compiler module already exists: {name}"
        );
        fs::copy(source.join(path), destination)?;
        paths.insert(name.clone(), path.clone());
    }
    Ok(paths)
}

fn discover(
    root: &Path,
    directory: &Path,
    depth: usize,
    modules: &mut BTreeMap<String, (String, PathBuf)>,
) -> Result<()> {
    ensure!(depth <= 16, "app module nesting budget exceeded");
    ensure!(
        !fs::symlink_metadata(directory)?.file_type().is_symlink(),
        "app module symlink forbidden"
    );
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(entries.len() <= 256, "app module directory budget exceeded");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if [".git", "ui", "assets"]
            .iter()
            .any(|name| entry.file_name() == *name)
        {
            continue;
        }
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "app module symlink forbidden");
        if kind.is_dir() {
            discover(root, &entry.path(), depth + 1, modules)?;
        } else if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "roc")
        {
            ensure!(kind.is_file(), "special app module forbidden");
            let path = entry.path().strip_prefix(root)?.to_owned();
            let source = fs::read_to_string(entry.path())?;
            let name = crate::app_inference::module_name(&source)
                .with_context(|| format!("invalid app module {}", path.display()))?;
            ensure!(
                entry.file_name() == format!("{name}.roc").as_str(),
                "{} must be named {name}.roc to match its module declaration",
                path.display()
            );
            ensure!(modules.len() < 512, "app module count budget exceeded");
            if let Some((_, previous)) = modules.get(&name.to_ascii_lowercase()) {
                anyhow::bail!(
                    "duplicate app module {name}: {} and {}; module names are unique across folders",
                    previous.display(),
                    path.display()
                );
            }
            modules.insert(name.to_ascii_lowercase(), (name, path));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folders_preserve_modules_and_reject_ambiguous_names() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        fs::create_dir_all(source.join("commands"))?;
        fs::create_dir_all(source.join("storage"))?;
        fs::create_dir_all(source.join("domain"))?;
        fs::write(
            source.join("domain/Title.roc"),
            "Title := { marker : Bool }.{ rules = {} }\n",
        )?;
        fs::write(
            source.join("App.roc"),
            "import Submit\nApp :: [].{ definition = {} }\n",
        )?;
        let model = "# A fake Fake :: [] in a comment\nModels :: [].{ Report := {title: Str} }\n";
        fs::write(source.join("storage/Models.roc"), model)?;
        fs::write(
            source.join("commands/Submit.roc"),
            "Submit :: [].{ purpose = \"Fake :: []\" }\n",
        )?;
        let target = temporary.path().join("compiled");
        let paths = stage(&source, &target)?;
        assert_eq!(paths["Models"], Path::new("storage/Models.roc"));
        assert_eq!(paths["Title"], Path::new("domain/Title.roc"));
        assert_eq!(fs::read_to_string(target.join("Models.roc"))?, model);
        assert!(!target.join("storage").exists());
        fs::write(source.join("commands/Models.roc"), model)?;
        let rejected = temporary.path().join("rejected");
        let error = stage(&source, &rejected).unwrap_err().to_string();
        assert!(error.contains("duplicate app module Models"), "{error}");
        assert!(error.contains("commands/Models.roc") && error.contains("storage/Models.roc"));
        assert!(!rejected.exists());
        fs::remove_file(source.join("commands/Models.roc"))?;
        fs::write(source.join("commands/Submit.roc"), "Different :: [].{}")?;
        assert!(
            stage(&source, &rejected)
                .unwrap_err()
                .to_string()
                .contains("must be named Different.roc")
        );
        Ok(())
    }
}
