//! Explicit operator-approved Bazel repositories, staged before the private
//! builder loses network and operator-cache access. No runtime outputs enter it.
use super::{MAX_BYTES, MAX_FILE_BYTES, MAX_FILES, PinnedTree};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

/// Prepare operator-selected dependency inputs before private admission. Bazel's
/// generated output-base bridge is never captured. Only aliases whose resolved
/// bytes stay inside this same vendor tree become regular files/directories.
/// The private loader below still refuses every alias, credential and VCS entry.
pub fn prepare_bazel_repositories(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(source)?.file_type().is_dir(),
        "Bazel vendor source must be a real directory"
    );
    let root = source.canonicalize()?;
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow::anyhow!("vendor destination parent"))?;
    ensure!(
        !parent.canonicalize()?.starts_with(&root),
        "prepared vendor destination must be outside its source"
    );
    let mut preparation = RepositoryPreparation {
        root,
        entries: 0,
        bytes: 0,
    };
    preparation.copy(source, destination, 0, &mut BTreeSet::new())?;
    validate_sources(destination)?;
    // Pin exactly these prepared repositories: marker files alone assume the
    // vendor tree still has Bazel's original alias topology. No repository rule
    // or network fallback is admitted in the subsequent private build.
    let mut repositories = BTreeSet::new();
    for entry in fs::read_dir(destination)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("vendor repository name"))?;
        if entry.file_type()?.is_dir() && name != "_registries" {
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._+~-".contains(&byte)),
                "invalid canonical vendor repository name"
            );
            repositories.insert(name);
        }
    }
    ensure!(!repositories.is_empty(), "no prepared Bazel repositories");
    let mut pins = String::new();
    for name in repositories {
        pins.push_str("pin(\"@@");
        pins.push_str(&name);
        pins.push_str("\")\n");
    }
    ensure!(pins.len() <= 64 * 1024, "prepared vendor directives budget");
    fs::write(destination.join("VENDOR.bazel"), pins)?;
    // Enforce the same complete file/byte/depth bounds used for final admission.
    PinnedTree::capture(destination)?;
    Ok(())
}

struct RepositoryPreparation {
    root: PathBuf,
    entries: usize,
    bytes: u64,
}

impl RepositoryPreparation {
    fn copy(
        &mut self,
        source: &Path,
        destination: &Path,
        depth: usize,
        ancestors: &mut BTreeSet<PathBuf>,
    ) -> Result<()> {
        ensure!(
            depth <= 32 && self.entries < MAX_FILES,
            "prepared vendor nesting/entry budget"
        );
        self.entries += 1;
        let resolved = source.canonicalize()?;
        let relative = resolved
            .strip_prefix(&self.root)
            .map_err(|_| anyhow::anyhow!("vendor alias leaves approved repositories"))?;
        ensure!(
            relative
                .components()
                .all(|part| !forbidden_name(part.as_os_str().to_str().unwrap_or("credentials"))),
            "vendor alias reaches VCS metadata or credentials"
        );
        let metadata = fs::symlink_metadata(&resolved)?;
        if metadata.file_type().is_dir() {
            ensure!(
                ancestors.insert(resolved.clone()),
                "vendor directory alias cycle"
            );
            fs::create_dir(destination)?;
            for entry in fs::read_dir(&resolved)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("vendor source filename"))?;
                ensure!(
                    !forbidden_name(&name),
                    "vendored VCS metadata or credentials forbidden"
                );
                if depth == 0 && name == "bazel-external" {
                    ensure!(
                        entry.file_type()?.is_symlink(),
                        "Bazel output bridge must be an alias"
                    );
                    continue;
                }
                if depth == 0 && name == "VENDOR.bazel" {
                    let path = entry.path();
                    ensure!(
                        fs::symlink_metadata(&path)?.file_type().is_file(),
                        "vendor directives must be regular"
                    );
                    let mut bytes = Vec::new();
                    fs::File::open(path)?
                        .take(64 * 1024 + 1)
                        .read_to_end(&mut bytes)?;
                    ensure!(bytes.len() <= 64 * 1024, "vendor directives budget");
                    let text = std::str::from_utf8(&bytes)?;
                    ensure!(
                        text.lines().all(
                            |line| line.trim().is_empty() || line.trim_start().starts_with('#')
                        ),
                        "pre-existing vendor override directives forbidden"
                    );
                    continue;
                }
                self.copy(&entry.path(), &destination.join(name), depth + 1, ancestors)?;
            }
            ancestors.remove(&resolved);
        } else {
            ensure!(
                metadata.file_type().is_file() && metadata.len() <= MAX_FILE_BYTES,
                "vendor source type/file budget"
            );
            ensure!(
                self.bytes
                    .checked_add(metadata.len())
                    .is_some_and(|bytes| bytes <= MAX_BYTES),
                "prepared vendor byte budget"
            );
            let mut bytes = Vec::new();
            fs::File::open(&resolved)?
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_FILE_BYTES
                    && self
                        .bytes
                        .checked_add(bytes.len() as u64)
                        .is_some_and(|total| total <= MAX_BYTES),
                "prepared vendor byte budget"
            );
            self.bytes += bytes.len() as u64;
            fs::write(destination, bytes)?;
            fs::set_permissions(destination, metadata.permissions())?;
        }
        Ok(())
    }
}

fn forbidden_name(name: &str) -> bool {
    [".git", ".hg", ".svn", "credentials", "credentials.toml"].contains(&name)
}

#[derive(Clone, Debug)]
pub(super) struct OfflineBazelSources {
    sources: PinnedTree,
}

impl OfflineBazelSources {
    pub(super) fn capture(root: &Path) -> Result<Self> {
        validate_sources(root)?;
        Ok(Self {
            sources: PinnedTree::capture(root)?,
        })
    }

    pub(super) fn identity(&self) -> Value {
        json!({"repositories":self.sources.digest()})
    }

    pub(super) fn manifest(&self) -> Value {
        json!({"files":self.sources.files()})
    }

    pub(super) fn materialize(&self, destination: &Path) -> Result<()> {
        self.sources.materialize(destination)
    }
}

fn validate_sources(root: &Path) -> Result<()> {
    fn visit(directory: &Path, depth: usize) -> Result<()> {
        ensure!(
            depth <= 32 && fs::symlink_metadata(directory)?.file_type().is_dir(),
            "vendored source directory type/budget"
        );
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("vendored source filename"))?;
            ensure!(
                ![".git", ".hg", ".svn", "credentials", "credentials.toml"]
                    .contains(&name.as_str()),
                "vendored VCS metadata or credentials forbidden"
            );
            let kind = entry.file_type()?;
            ensure!(
                kind.is_file() || kind.is_dir(),
                "vendored symlink or special file forbidden"
            );
            if kind.is_dir() {
                visit(&entry.path(), depth + 1)?;
            }
        }
        Ok(())
    }
    visit(root, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn prepared_vendor_materializes_contained_aliases_and_omits_only_the_output_bridge()
    -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        fs::create_dir(source.path().join("repo+"))?;
        fs::create_dir(source.path().join("repo+/nested"))?;
        fs::write(source.path().join("repo+/nested/tool"), b"reviewed bytes")?;
        fs::set_permissions(
            source.path().join("repo+/nested/tool"),
            fs::Permissions::from_mode(0o755),
        )?;
        fs::write(source.path().join("@repo+.marker"), b"original marker")?;
        fs::write(
            source.path().join("VENDOR.bazel"),
            b"# Bazel generated source\n",
        )?;
        symlink("nested/tool", source.path().join("repo+/file-alias"))?;
        symlink("nested", source.path().join("repo+/directory-alias"))?;
        // This generated bridge may point to private output-base state. It is
        // deliberately never followed or included in the admitted snapshot.
        symlink(output.path(), source.path().join("bazel-external"))?;
        let destination = output.path().join("prepared");
        prepare_bazel_repositories(source.path(), &destination)?;
        assert!(!destination.join("bazel-external").exists());
        assert!(
            fs::symlink_metadata(destination.join("repo+/file-alias"))?
                .file_type()
                .is_file()
        );
        assert_eq!(
            fs::read(destination.join("repo+/directory-alias/tool"))?,
            b"reviewed bytes"
        );
        assert_eq!(
            fs::metadata(destination.join("repo+/file-alias"))?
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::read_to_string(destination.join("VENDOR.bazel"))?,
            "pin(\"@@repo+\")\n"
        );
        assert_eq!(
            fs::read(destination.join("@repo+.marker"))?,
            b"original marker"
        );
        let captured = OfflineBazelSources::capture(&destination)?;
        captured.materialize(&output.path().join("relocated"))?;
        assert_eq!(
            fs::read(output.path().join("relocated/repo+/file-alias"))?,
            b"reviewed bytes"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn prepared_vendor_refuses_external_aliases_cycles_credentials_and_existing_overrides()
    -> Result<()> {
        use std::os::unix::fs::symlink;
        let source = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        fs::create_dir(source.path().join("repo+"))?;
        fs::write(source.path().join("repo+/safe"), b"reviewed")?;
        fs::write(outside.path().join("private"), b"never adopted")?;
        symlink(
            outside.path().join("private"),
            source.path().join("repo+/alias"),
        )?;
        assert!(prepare_bazel_repositories(source.path(), &outside.path().join("escape")).is_err());
        fs::remove_file(source.path().join("repo+/alias"))?;
        symlink(".", source.path().join("repo+/cycle"))?;
        assert!(prepare_bazel_repositories(source.path(), &outside.path().join("cycle")).is_err());
        fs::remove_file(source.path().join("repo+/cycle"))?;
        fs::write(source.path().join("repo+/credentials.toml"), b"private")?;
        assert!(
            prepare_bazel_repositories(source.path(), &outside.path().join("credentials")).is_err()
        );
        fs::remove_file(source.path().join("repo+/credentials.toml"))?;
        fs::write(source.path().join("VENDOR.bazel"), b"ignore(\"@@repo+\")")?;
        assert!(
            prepare_bazel_repositories(source.path(), &outside.path().join("override")).is_err()
        );
        fs::remove_file(source.path().join("VENDOR.bazel"))?;
        fs::create_dir(source.path().join("bazel-external"))?;
        assert!(prepare_bazel_repositories(source.path(), &outside.path().join("bridge")).is_err());
        Ok(())
    }

    #[test]
    fn prepared_vendor_keeps_original_file_and_aggregate_limits() -> Result<()> {
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        let file = source.path().join("large");
        fs::File::create(&file)?.set_len(MAX_FILE_BYTES + 1)?;
        let mut preparation = RepositoryPreparation {
            root: source.path().canonicalize()?,
            entries: 0,
            bytes: 0,
        };
        assert!(
            preparation
                .copy(
                    &file,
                    &output.path().join("oversized"),
                    0,
                    &mut BTreeSet::new()
                )
                .is_err()
        );
        fs::write(&file, b"1234")?;
        preparation.bytes = MAX_BYTES - 3;
        assert!(
            preparation
                .copy(
                    &file,
                    &output.path().join("aggregate"),
                    0,
                    &mut BTreeSet::new()
                )
                .is_err()
        );
        preparation.bytes = 0;
        preparation.entries = MAX_FILES;
        assert!(
            preparation
                .copy(
                    &file,
                    &output.path().join("entries"),
                    0,
                    &mut BTreeSet::new()
                )
                .is_err()
        );
        assert!(
            preparation
                .copy(
                    &file,
                    &output.path().join("depth"),
                    33,
                    &mut BTreeSet::new()
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn offline_repositories_refuse_credentials_vcs_metadata_and_aliases() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().join("approved");
        fs::create_dir(&package)?;
        fs::write(package.join("BUILD.bazel"), b"# approved source")?;
        validate_sources(directory.path())?;
        for forbidden in ["credentials", "credentials.toml"] {
            fs::write(package.join(forbidden), b"private")?;
            assert!(validate_sources(directory.path()).is_err());
            fs::remove_file(package.join(forbidden))?;
        }
        fs::create_dir(package.join(".git"))?;
        fs::write(package.join(".git/config"), b"private")?;
        assert!(validate_sources(directory.path()).is_err());
        fs::remove_dir_all(package.join(".git"))?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("BUILD.bazel", package.join("alias"))?;
            assert!(validate_sources(directory.path()).is_err());
        }
        Ok(())
    }

    #[test]
    fn prepared_repository_bytes_and_modes_are_bound_and_rechecked() -> Result<()> {
        let source = tempfile::tempdir()?;
        fs::write(source.path().join("BUILD.bazel"), b"approved dependency")?;
        let approved = OfflineBazelSources::capture(source.path())?;
        let job = tempfile::tempdir()?;
        let destination = job.path().join("repositories");
        approved.materialize(&destination)?;
        assert_eq!(
            fs::read(destination.join("BUILD.bazel"))?,
            b"approved dependency"
        );
        assert!(!destination.join("credentials.toml").exists());
        fs::write(source.path().join("BUILD.bazel"), b"changed after approval")?;
        assert_ne!(
            approved.identity(),
            OfflineBazelSources::capture(source.path())?.identity()
        );
        assert!(approved.materialize(&job.path().join("changed")).is_err());
        Ok(())
    }
}
