//! Fixed compiler inputs, prepared before verification and admitted offline at
//! every receiving boundary. This never stores a check, test or runtime result.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const DIRECTORY: &str = "cli/.cache/roc-packages";
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pins {
    format: u32,
    packages: Vec<Package>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    name: String,
    version: String,
    archive: String,
    bytes: u64,
    sha256: String,
    tree_sha256: String,
    files: usize,
    expanded_bytes: u64,
}

impl Package {
    fn hash(&self) -> &str {
        self.archive.strip_suffix(".tar.zst").unwrap()
    }

    fn url(&self) -> String {
        format!(
            "https://github.com/roc-lang/{}/releases/download/{}/{}",
            self.name, self.version, self.archive
        )
    }
}

fn pins() -> Result<Vec<Package>> {
    let pins: Pins = serde_json::from_str(include_str!("../../../build/bazel/roc-packages.json"))?;
    ensure!(
        pins.format == 1 && pins.packages.len() == 2,
        "complete Roc package input catalog required"
    );
    ensure!(
        pins.packages
            .iter()
            .map(|p| p.name.as_str())
            .eq(["basic-cli", "http"]),
        "fixed CLI dependency closure required"
    );
    for p in &pins.packages {
        ensure!(
            p.bytes <= 32 * 1024 * 1024 && p.expanded_bytes <= MAX_BYTES && p.files <= MAX_ENTRIES,
            "Roc package size limits"
        );
        ensure!(
            p.archive.ends_with(".tar.zst")
                && p.hash().len() == 44
                && p.hash().bytes().all(|b| b.is_ascii_alphanumeric()),
            "fixed package content address required"
        );
        ensure!(
            p.version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)),
            "fixed package version required"
        );
        for hash in [&p.sha256, &p.tree_sha256] {
            ensure!(
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "source-owned SHA256 required"
            );
        }
    }
    Ok(pins.packages)
}

fn real_directory(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.is_dir() && path.canonicalize()? == path,
        "real package input directory required"
    );
    Ok(())
}

fn directory(root: &Path) -> Result<PathBuf> {
    for path in [
        root.to_path_buf(),
        root.join("cli"),
        root.join("cli/.cache"),
        root.join(DIRECTORY),
    ] {
        real_directory(&path)?;
    }
    Ok(root.join(DIRECTORY))
}

fn file_hash(path: &Path, max: u64) -> Result<(String, u64)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o7777 == 0o644,
        "regular unaliased package input mode required"
    );
    let mut input = fs::File::open(path)?.take(max + 1);
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    let mut bytes = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        ensure!(bytes <= max, "package input byte limit");
        hash.update(&buffer[..count]);
    }
    let hash = hash
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok((hash, bytes))
}

fn tree(path: &Path) -> Result<(String, usize, u64)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fn visit(
        base: &Path,
        path: &Path,
        entries: &mut BTreeMap<String, String>,
        files: &mut usize,
        bytes: &mut u64,
        depth: usize,
    ) -> Result<()> {
        ensure!(
            depth <= 32 && entries.len() < MAX_ENTRIES,
            "package tree limits"
        );
        let metadata = fs::symlink_metadata(path)?;
        let relative = path
            .strip_prefix(base)?
            .to_str()
            .context("package UTF8 path")?
            .to_owned();
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.is_dir() {
            ensure!(
                mode == 0o755 && path.canonicalize()? == path,
                "package directory mode or alias changed"
            );
            if !relative.is_empty() {
                entries.insert(relative, "directory:0755".into());
            }
            for entry in fs::read_dir(path)? {
                visit(base, &entry?.path(), entries, files, bytes, depth + 1)?;
            }
        } else {
            ensure!(
                metadata.is_file() && mode == 0o644 && metadata.nlink() == 1,
                "package file metadata changed: regular {}, mode {mode:o}, links {}",
                metadata.is_file(),
                metadata.nlink()
            );
            let (hash, length) = file_hash(path, MAX_BYTES.saturating_sub(*bytes))?;
            *bytes += length;
            *files += 1;
            entries.insert(relative, format!("file:0644:sha256:{hash}"));
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    let (mut files, mut bytes) = (0, 0);
    visit(path, path, &mut entries, &mut files, &mut bytes, 0)?;
    Ok((day2::digest(&serde_json::to_vec(&entries)?), files, bytes))
}

fn admit_package(base: &Path, p: &Package) -> Result<()> {
    let (hash, bytes) = file_hash(&base.join(&p.archive), p.bytes)?;
    ensure!(
        hash == p.sha256 && bytes == p.bytes,
        "pinned Roc archive bytes changed"
    );
    let (hash, files, bytes) = tree(&base.join(p.hash()))?;
    ensure!(
        hash == format!("sha256:{}", p.tree_sha256)
            && files == p.files
            && bytes == p.expanded_bytes,
        "pinned Roc package tree changed"
    );
    Ok(())
}

pub(crate) fn admit(root: &Path) -> Result<()> {
    let base = directory(root)?;
    let packages = pins()?;
    let expected = packages
        .iter()
        .flat_map(|p| [p.archive.clone(), p.hash().to_owned()])
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(&base)? {
        ensure!(
            actual.len() < expected.len(),
            "unexpected package input entry"
        );
        actual.insert(
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("package input name"))?,
        );
    }
    ensure!(actual == expected, "exact package input set required");
    for p in packages {
        admit_package(&base, &p)?;
    }
    Ok(())
}

/// Add complete URL-to-local replacements only after actual input admission.
/// A missing local input refuses before a compiler can consult its URL cache.
pub(crate) fn configure(root: &Path, command: &mut Command) -> Result<()> {
    admit(root)?;
    for p in pins()? {
        command
            .arg("--replace-dep")
            .arg(p.url())
            .arg(root.join(DIRECTORY).join(p.hash()).join("main.roc"));
    }
    Ok(())
}

fn execute(root: &Path, command: &mut Command, seconds: u64, phase: &str) -> Result<()> {
    let status = super::command_status_with_budget(root, command, Duration::from_secs(seconds))
        .map_err(|error| match error {
            super::CommandStatusError::Spawn(error) | super::CommandStatusError::Wait(error) => {
                anyhow::Error::from(error).context("Roc package input child failed")
            }
            super::CommandStatusError::Timeout => {
                anyhow::anyhow!("Roc package input child exhausted its original budget")
            }
        })?;
    ensure!(
        status.success(),
        "Roc package {phase} failed, numeric exit {:?}",
        status.code()
    );
    Ok(())
}

// The pinned extractor intentionally uses private0600/0700. Normalize only
// fresh, checksum-verified public inputs; never repair a receiving/cache tree.
fn publish_modes(path: &Path, depth: usize, entries: &mut usize) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    *entries += 1;
    ensure!(
        depth <= 32 && *entries <= MAX_ENTRIES,
        "package publication tree limits"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() || metadata.is_file() && metadata.nlink() == 1,
        "package publication aliases forbidden"
    );
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if metadata.is_dir() { 0o755 } else { 0o644 }),
    )?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            publish_modes(&entry?.path(), depth + 1, entries)?;
        }
    }
    Ok(())
}

pub(crate) fn prepare(root: &Path, roc: &Path) -> Result<()> {
    for path in [
        root.join("cli"),
        root.join("cli/.cache"),
        root.join(DIRECTORY),
    ] {
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        real_directory(&path)?;
    }
    let base = directory(root)?;
    for p in pins()? {
        if base.join(p.hash()).exists() {
            admit_package(&base, &p)?;
            continue;
        }
        let stage = tempfile::tempdir_in(&base)?;
        let archive = stage.path().join(&p.archive);
        if let Some(bytes) = crate::release_inputs::cached(root, &p.sha256, p.bytes)? {
            fs::write(&archive, bytes)?;
        } else {
            execute(
                root,
                Command::new("/usr/bin/curl")
                    .args([
                        "--fail",
                        "--silent",
                        "--show-error",
                        "--location",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "--retry",
                        "4",
                        "--retry-delay",
                        "5",
                        "--retry-max-time",
                        "120",
                        "--connect-timeout",
                        "15",
                        "--max-time",
                        "60",
                        "--max-filesize",
                        "33554432",
                        "--output",
                    ])
                    .arg(&archive)
                    .arg(p.url()),
                180,
                "download",
            )?;
        }
        let (hash, bytes) = file_hash(&archive, p.bytes)?;
        ensure!(
            hash == p.sha256 && bytes == p.bytes,
            "pinned Roc archive download mismatch"
        );
        execute(
            stage.path(),
            Command::new(roc).arg("unbundle").arg(&archive),
            60,
            "unbundle",
        )?;
        publish_modes(&stage.path().join(p.hash()), 0, &mut 0)?;
        admit_package(stage.path(), &p)?;
        fs::rename(&archive, base.join(&p.archive))?;
        fs::rename(stage.path().join(p.hash()), base.join(p.hash()))?;
    }
    admit(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(base: &Path) -> Result<Package> {
        let mut p = Package {
            name: "http".into(),
            version: "1.0.0".into(),
            archive: format!("{}.tar.zst", "a".repeat(44)),
            bytes: 7,
            sha256: day2::digest(b"fixture")
                .trim_start_matches("sha256:")
                .into(),
            tree_sha256: String::new(),
            files: 1,
            expanded_bytes: 10,
        };
        fs::write(base.join(&p.archive), b"fixture")?;
        fs::set_permissions(base.join(&p.archive), fs::Permissions::from_mode(0o644))?;
        fs::create_dir(base.join(p.hash()))?;
        fs::set_permissions(base.join(p.hash()), fs::Permissions::from_mode(0o755))?;
        fs::write(base.join(p.hash()).join("main.roc"), b"module []\n")?;
        fs::set_permissions(
            base.join(p.hash()).join("main.roc"),
            fs::Permissions::from_mode(0o644),
        )?;
        p.tree_sha256 = tree(&base.join(p.hash()))?
            .0
            .trim_start_matches("sha256:")
            .into();
        Ok(p)
    }

    #[test]
    fn package_admission_rehashes_archive_and_tree_and_refuses_extra_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let base = temp.path().canonicalize()?;
        let p = fixture(&base)?;
        admit_package(&base, &p)?;
        fs::write(base.join(&p.archive), b"changed")?;
        assert!(admit_package(&base, &p).is_err());
        fs::write(base.join(&p.archive), b"fixture")?;
        fs::write(base.join(p.hash()).join("main.roc"), b"poison []\n")?;
        assert!(admit_package(&base, &p).is_err());
        fs::write(base.join(p.hash()).join("main.roc"), b"module []\n")?;
        fs::write(base.join(p.hash()).join("extra.roc"), b"module []\n")?;
        assert!(admit_package(&base, &p).is_err());
        fs::remove_file(base.join(p.hash()).join("extra.roc"))?;
        fs::create_dir(base.join(p.hash()).join("extra"))?;
        assert!(admit_package(&base, &p).is_err());
        Ok(())
    }

    #[test]
    fn package_admission_refuses_symlinks_hardlinks_and_permission_changes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let base = temp.path().canonicalize()?;
        let p = fixture(&base)?;
        let main = base.join(p.hash()).join("main.roc");
        fs::set_permissions(&main, fs::Permissions::from_mode(0o600))?;
        assert!(admit_package(&base, &p).is_err());
        fs::set_permissions(&main, fs::Permissions::from_mode(0o644))?;
        fs::hard_link(&main, base.join("alias"))?;
        assert!(admit_package(&base, &p).is_err());
        fs::remove_file(base.join("alias"))?;
        fs::remove_file(&main)?;
        std::os::unix::fs::symlink(base.join(&p.archive), &main)?;
        assert!(admit_package(&base, &p).is_err());
        Ok(())
    }

    #[test]
    fn missing_offline_inputs_refuse_before_invocation_even_with_warm_default_cache() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let base = temp.path().canonicalize()?;
        let default = base.join("cli/.cache/roc/packages").join(pins()?[0].hash());
        fs::create_dir_all(&default)?;
        fs::write(default.join("main.roc"), b"poisoned default cache")?;
        fs::create_dir(base.join(DIRECTORY))?;
        let mut command = Command::new("never-invoked");
        assert!(configure(&base, &mut command).is_err());
        assert_eq!(command.get_args().count(), 0);
        Ok(())
    }

    #[test]
    fn source_catalog_covers_root_platform_and_its_complete_transitive_package() -> Result<()> {
        let packages = pins()?;
        let root = include_str!("../../../cli/main.roc");
        let runner = include_str!("../../../ops/Runner.roc");
        assert!(root.contains(&packages[0].url()));
        assert!(runner.contains(&packages[0].url()));
        assert_eq!(
            packages[1].url(),
            "https://github.com/roc-lang/http/releases/download/1.0.0/6ZUwqYhCS8PU9Mo6MF7oV82ET2o7KYb57CLKDq4cq4sS.tar.zst"
        );
        Ok(())
    }

    #[test]
    fn fresh_extractor_modes_are_published_without_weakening_receiver_admission() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let base = temp.path().canonicalize()?;
        let p = fixture(&base)?;
        let directory = base.join(p.hash());
        fs::set_permissions(
            directory.join("main.roc"),
            fs::Permissions::from_mode(0o600),
        )?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        assert!(admit_package(&base, &p).is_err());
        publish_modes(&directory, 0, &mut 0)?;
        admit_package(&base, &p)?;
        fs::set_permissions(
            directory.join("main.roc"),
            fs::Permissions::from_mode(0o600),
        )?;
        assert!(admit_package(&base, &p).is_err());
        Ok(())
    }
}
