//! Maintainer configuration and distribution metadata, never app capabilities.
use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn public_files(root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()?;
    ensure!(output.status.success(), "Git source inventory failed");
    let mut files = Vec::new();
    for name in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let path = PathBuf::from(std::str::from_utf8(name)?);
        ensure!(
            !path.is_absolute()
                && !path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir)),
            "source path leaves repository"
        );
        files.push(path);
    }
    files.sort();
    files.dedup();
    Ok(files)
}

pub fn source_check(root: &Path) -> Result<Vec<PathBuf>> {
    let root = root.canonicalize()?;
    let files = public_files(&root)?;
    let inventory: std::collections::BTreeSet<_> = files.iter().cloned().collect();
    for path in &files {
        ensure!(
            !path
                .components()
                .any(|part| day2_control::build::local_platform_input(Path::new(part.as_os_str()))),
            "local/private file in public export: {}",
            path.display()
        );
        let file = root.join(path);
        ensure!(
            fs::symlink_metadata(&file)?.is_file(),
            "public sources must be regular files: {}",
            path.display()
        );
        let bytes = fs::read(&file)?;
        ensure!(
            !bytes.contains(&0),
            "binary in public source export: {}",
            path.display()
        );
        let name = path
            .file_name()
            .context("source filename")?
            .to_string_lossy();
        ensure!(
            ![
                "instance.json",
                "credentials.json",
                "secrets.json",
                "plan.bin"
            ]
            .contains(&name.as_ref()),
            "private configuration in public export: {}",
            path.display()
        );
        let text = std::str::from_utf8(&bytes).context("public source must be UTF-8")?;
        if path.extension().is_some_and(|ext| ext == "rs") {
            for marker in [concat!("include_", "str!("), concat!("include_", "bytes!(")] {
                for tail in text.split(marker).skip(1) {
                    if let Some(tail) = tail.trim_start().strip_prefix('"') {
                        let target = tail.split('"').next().context("include path")?;
                        check_source_target(&root, &inventory, &file, target)?;
                    }
                }
            }
        }
        if path.extension().is_some_and(|ext| ext == "md") {
            for tail in text.split("](").skip(1) {
                let target = tail
                    .split(')')
                    .next()
                    .unwrap_or_default()
                    .split('#')
                    .next()
                    .unwrap_or_default();
                if target.is_empty()
                    || target.starts_with("https://")
                    || target.starts_with("http://")
                    || target.starts_with("mailto:")
                {
                    continue;
                }
                check_source_target(&root, &inventory, &file, target)?;
            }
        }
    }
    println!("Public source boundary checked: {} files", files.len());
    Ok(files)
}

fn check_source_target(
    root: &Path,
    inventory: &std::collections::BTreeSet<PathBuf>,
    source: &Path,
    target: &str,
) -> Result<()> {
    let destination = source
        .parent()
        .context("source parent")?
        .join(target)
        .canonicalize()
        .with_context(|| {
            format!(
                "missing public source/link {target} in {}",
                source.display()
            )
        })?;
    ensure!(
        destination.starts_with(root),
        "source/link leaves public repository: {target} in {}",
        source.display()
    );
    let relative = destination.strip_prefix(root)?;
    ensure!(
        inventory.contains(relative)
            || (destination.is_dir() && inventory.iter().any(|file| file.starts_with(relative))),
        "source/link targets an ignored or unpublished file: {target} in {}",
        source.display()
    );
    Ok(())
}

pub fn source_export(root: &Path, destination: &Path) -> Result<()> {
    let files = source_check(root)?;
    ensure!(
        !destination.exists(),
        "public export requires a new directory"
    );
    fs::create_dir_all(destination)?;
    for file in files {
        let output = destination.join(&file);
        fs::create_dir_all(output.parent().context("export parent")?)?;
        fs::copy(root.join(file), output)?;
    }
    Ok(())
}

pub fn configure_tofu(root: &Path, requested: Option<PathBuf>) -> Result<PathBuf> {
    let binary = requested
        .or_else(|| {
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|directory| directory.join("tofu"))
                    .find(|path| path.is_file())
            })
        })
        .context("OpenTofu missing: install 1.11.5, then run xtask configure-tofu [BINARY]")?
        .canonicalize()?;
    let version = Command::new(&binary).args(["version", "-json"]).output()?;
    ensure!(version.status.success(), "OpenTofu version failed");
    let version: serde_json::Value = serde_json::from_slice(&version.stdout)?;
    ensure!(
        version["terraform_version"] == "1.11.5",
        "OpenTofu 1.11.5 is required"
    );
    let directory = root.join(".cache");
    fs::create_dir_all(&directory)?;
    let path = directory.join("tofu.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "format":1,"installation":"exampleco","environment":"sandbox","apps":["reports"],
            "engine":{"path":binary,"version":"1.11.5","sha256":digest(&fs::read(&binary)?).trim_start_matches("sha256:")}
        }))?,
    )?;
    println!("Configured local OpenTofu pin: {}", path.display());
    Ok(path)
}

/// Generate notices from the exact locked registry inputs. Run after cargo fetch;
/// this includes target-specific dependencies so one notice bundle serves every
/// supported binary. It deliberately includes more than a single target links.
pub fn notices(root: &Path) -> Result<()> {
    let result = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--locked", "--offline", "--format-version=1"])
        .output()?;
    ensure!(
        result.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    let mut packages: Vec<_> = metadata["packages"]
        .as_array()
        .context("Cargo packages")?
        .iter()
        .filter(|package| !package["source"].is_null())
        .collect();
    packages.sort_by_key(|package| (package["name"].as_str(), package["version"].as_str()));
    let mut notice = String::from(
        "Third-party notices for the locked platform distribution\n\nGenerated by xtask notices. Includes all Cargo targets, not only linked crates.\nIndividual notices govern their respective components.\n",
    );
    for path in [
        "LICENSE",
        "vendor/ROC-LICENSE",
        "assets/datastar-LICENSE",
        "assets/lucide-LICENSE",
    ] {
        notice.push_str(&format!(
            "\n===== {path} =====\n{}\n",
            fs::read_to_string(root.join(path))?
        ));
    }
    let mut inventory = Vec::new();
    for package in packages {
        let name = package["name"].as_str().context("package name")?;
        let version = package["version"].as_str().context("package version")?;
        let directory = Path::new(package["manifest_path"].as_str().context("manifest path")?)
            .parent()
            .context("package directory")?;
        let mut files = Vec::new();
        license_files(directory, directory, 0, &mut files)?;
        if let Some(file) = package["license_file"].as_str() {
            let file = directory.join(file);
            ensure!(
                file.canonicalize()?.starts_with(directory.canonicalize()?),
                "license path leaves package"
            );
            files.push(file);
        }
        if files.is_empty() {
            let supplied = root
                .join("vendor/licenses")
                .join(format!("{name}-{version}.txt"));
            let provenance: serde_json::Value =
                serde_json::from_slice(&fs::read(root.join("vendor/licenses/provenance.json"))?)?;
            let reviewed = provenance
                .as_array()
                .context("notice provenance")?
                .iter()
                .find(|entry| entry["name"] == name && entry["version"] == version)
                .with_context(|| format!("missing reviewed notice for {name} {version}"))?;
            ensure!(
                digest(&fs::read(&supplied)?).trim_start_matches("sha256:")
                    == reviewed["sha256"].as_str().context("notice digest")?,
                "third-party notice digest mismatch"
            );
            files.push(supplied);
        }
        files.sort();
        files.dedup();
        ensure!(
            !files.is_empty(),
            "no license/notice text found for {name} {version}; review before distribution"
        );
        notice.push_str(&format!(
            "\n===== {name} {version} =====\nLicense: {}\nSource: {}\n",
            package["license"]
                .as_str()
                .unwrap_or("see supplied license file"),
            package["source"].as_str().unwrap_or_default()
        ));
        notice.push_str(&format!(
            "Unmodified source: https://crates.io/api/v1/crates/{name}/{version}/download\n"
        ));
        for file in &files {
            let label = file
                .strip_prefix(directory)
                .or_else(|_| file.strip_prefix(root))?;
            notice.push_str(&format!(
                "\n--- {} ---\n{}\n",
                label.display(),
                fs::read_to_string(file)?
            ));
        }
        inventory.push(serde_json::json!({"name":name,"version":version,"license":package["license"],"source":package["source"],"repository":package["repository"],"notices":files.iter().map(|file| file.strip_prefix(directory).or_else(|_| file.strip_prefix(root)).unwrap().to_string_lossy()).collect::<Vec<_>>() }));
    }
    fs::write(root.join("THIRD-PARTY-NOTICES.txt"), notice)?;
    fs::write(
        root.join("dependency-inventory.json"),
        serde_json::to_vec_pretty(&inventory)?,
    )?;
    Ok(())
}

fn license_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    ensure!(depth <= 16, "license directory depth");
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if kind.is_dir()
            && ![".git", "target", "tests", "test", "examples"].contains(&name.as_str())
        {
            license_files(root, &entry.path(), depth + 1, files)?;
        } else if kind.is_file()
            && (name.starts_with("license")
                || name.starts_with("licence")
                || name.starts_with("notice")
                || name.starts_with("copying"))
        {
            ensure!(
                entry.metadata()?.len() <= 2_000_000,
                "oversized license file"
            );
            // Code implementing a license API is not a notice.
            if !["rs", "c", "h", "go", "py", "json"]
                .iter()
                .any(|ext| entry.path().extension().is_some_and(|value| value == *ext))
            {
                files.push(root.join(entry.path().strip_prefix(root)?));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository() -> Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        let output = Command::new("git")
            .args(["init", "--quiet"])
            .arg(directory.path())
            .output()?;
        ensure!(output.status.success(), "test repository init");
        Ok(directory)
    }

    #[test]
    fn export_excludes_ignored_state_and_checks_links() -> Result<()> {
        let directory = repository()?;
        let root = directory.path();
        fs::write(root.join(".gitignore"), ".state/\n")?;
        fs::create_dir(root.join(".state"))?;
        fs::write(root.join(".state/private.txt"), "private")?;
        fs::write(root.join("README.md"), "[Guide](guide.md)\n")?;
        fs::write(root.join("guide.md"), "public")?;
        let parent = tempfile::tempdir()?;
        let output = parent.path().join("export");
        source_export(root, &output)?;
        assert!(output.join("guide.md").is_file());
        assert!(!output.join(".state").exists());
        fs::write(root.join("README.md"), "[Private](.state/private.txt)\n")?;
        assert!(source_check(root).is_err());
        Ok(())
    }

    #[test]
    fn export_rejects_credentials_binaries_and_outside_links() -> Result<()> {
        let directory = repository()?;
        let root = directory.path();
        fs::write(root.join("credentials.json"), "{}")?;
        assert!(source_check(root).is_err());
        fs::remove_file(root.join("credentials.json"))?;
        fs::write(root.join("native"), b"binary\0bytes")?;
        assert!(source_check(root).is_err());
        fs::remove_file(root.join("native"))?;
        let external = tempfile::NamedTempFile::new()?;
        fs::write(
            root.join("README.md"),
            format!("[Outside]({})", external.path().display()),
        )?;
        assert!(source_check(root).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn export_rejects_symlinks() -> Result<()> {
        let directory = repository()?;
        fs::write(directory.path().join("source"), "public")?;
        std::os::unix::fs::symlink("source", directory.path().join("alias"))?;
        assert!(source_check(directory.path()).is_err());
        Ok(())
    }
}
