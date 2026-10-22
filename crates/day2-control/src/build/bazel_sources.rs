//! Explicit operator-approved Bazel repositories, staged before the private
//! builder loses network and operator-cache access. No runtime outputs enter it.
use super::PinnedTree;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};

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
