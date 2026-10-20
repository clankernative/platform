//! Prepare locked registry and Git packages before the build loses network and
//! operator Cargo-home access. Only Cargo-vendored source bytes enter the job.

use super::{MAX_LOG_BYTES, PinnedTree, private_directory, read_regular, run_bounded};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

const DIRECTORY_MARKER: &str = "@DAY2_APPROVED_CARGO_SOURCES@";

#[derive(Clone, Debug)]
pub(super) struct OfflineCargoSources {
    _temporary: Arc<tempfile::TempDir>,
    sources: PinnedTree,
    configuration: String,
}

impl OfflineCargoSources {
    pub(super) fn capture(cargo: &Path, registry: &Path, platform: &Path) -> Result<Self> {
        let temporary = Arc::new(
            tempfile::Builder::new()
                .prefix("day2-cargo-sources-")
                .tempdir()?,
        );
        let vendor = temporary.path().join("vendor");
        let output = temporary.path().join("sources.toml");
        let log = temporary.path().join("vendor.log");
        let mut command = Command::new(cargo);
        command
            .args(["vendor", "--locked", "--offline", "--versioned-dirs"])
            .arg(&vendor)
            .current_dir(platform)
            .env_clear()
            .env(
                "CARGO_HOME",
                registry.parent().context("Cargo registry parent")?,
            )
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TERM_COLOR", "never")
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin",
                    cargo.parent().context("Cargo binary parent")?.display()
                ),
            )
            .stdin(Stdio::null())
            .stdout(fs::File::create(&output)?)
            .stderr(fs::File::create(&log)?);
        ensure!(
            run_bounded(&mut command, &log)?,
            "locked offline Cargo source preparation failed: {}",
            String::from_utf8_lossy(&read_regular(&log)?)
        );
        ensure!(
            fs::metadata(&output)?.len() <= MAX_LOG_BYTES,
            "Cargo source configuration budget"
        );
        let configuration = String::from_utf8(read_regular(&output)?)?;
        let directory = format!(
            "directory = {}",
            serde_json::to_string(&vendor.to_str().context("Cargo source path")?)?
        );
        ensure!(
            configuration.matches(&directory).count() == 1,
            "Cargo source configuration requires one exact vendored directory"
        );
        let configuration =
            configuration.replace(&directory, &format!("directory = \"{DIRECTORY_MARKER}\""));
        validate_sources(&vendor)?;
        let sources = PinnedTree::capture(&vendor)?;
        Ok(Self {
            _temporary: temporary,
            sources,
            configuration,
        })
    }

    pub(super) fn identity(&self) -> Value {
        json!({"configuration": self.configuration, "sources": self.sources.digest()})
    }

    pub(super) fn manifest(&self) -> Value {
        json!({"configuration": self.configuration, "files": self.sources.files()})
    }

    pub(super) fn materialize(&self, cargo_home: &Path) -> Result<()> {
        private_directory(cargo_home)?;
        let vendor = cargo_home.join("vendor");
        self.sources.materialize(&vendor)?;
        let configuration = self.configuration.replace(
            &format!("\"{DIRECTORY_MARKER}\""),
            &serde_json::to_string(&vendor.to_str().context("private Cargo source path")?)?,
        );
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(cargo_home.join("config.toml"))?;
        use std::io::Write;
        file.write_all(configuration.as_bytes())?;
        Ok(())
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
    fn vendored_inputs_refuse_credentials_vcs_metadata_and_aliases() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().join("approved-1.0.0");
        fs::create_dir(&package)?;
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname='approved'\nversion='1.0.0'\n",
        )?;
        validate_sources(directory.path())?;
        for forbidden in ["credentials", "credentials.toml"] {
            fs::write(package.join(forbidden), "secret fixture")?;
            assert!(validate_sources(directory.path()).is_err());
            fs::remove_file(package.join(forbidden))?;
        }
        fs::create_dir(package.join(".git"))?;
        fs::write(package.join(".git/config"), "must not enter the build")?;
        assert!(validate_sources(directory.path()).is_err());
        fs::remove_dir_all(package.join(".git"))?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("Cargo.toml", package.join("alias"))?;
            assert!(validate_sources(directory.path()).is_err());
        }
        Ok(())
    }

    #[test]
    fn prepared_bytes_and_source_mapping_are_bound_and_rechecked() -> Result<()> {
        let temporary = Arc::new(tempfile::tempdir()?);
        let vendor = temporary.path().join("vendor");
        fs::create_dir(&vendor)?;
        fs::write(vendor.join("approved.rs"), "approved dependency")?;
        let mut approved = OfflineCargoSources {
            sources: PinnedTree::capture(&vendor)?,
            configuration: format!(
                "[source.vendored-sources]\ndirectory = \"{DIRECTORY_MARKER}\"\n"
            ),
            _temporary: temporary,
        };
        let identity = approved.identity();
        approved.configuration.push_str("# changed mapping\n");
        assert_ne!(identity, approved.identity());
        let job = tempfile::tempdir()?;
        let cargo = job.path().join("cargo");
        approved.materialize(&cargo)?;
        let configuration = fs::read_to_string(cargo.join("config.toml"))?;
        assert!(!configuration.contains(DIRECTORY_MARKER));
        assert!(configuration.contains(cargo.join("vendor").to_str().unwrap()));
        assert!(!cargo.join("git").exists());
        assert!(!cargo.join("credentials.toml").exists());
        fs::write(vendor.join("approved.rs"), "changed after approval")?;
        let changed = tempfile::tempdir()?;
        assert!(approved.materialize(&changed.path().join("cargo")).is_err());
        Ok(())
    }
}
