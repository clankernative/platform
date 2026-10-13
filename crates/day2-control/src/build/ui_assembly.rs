use super::{InputFile, PinnedTree, pin_file};
use crate::{Digest, source::SourceSnapshot};
use anyhow::{Context, Result, ensure};
use day2::ui_lock::Lock as UiLock;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

const PIN_LIMIT: u64 = 1024 * 1024;
const PACKAGE_FILE_LIMIT: usize = 4096;
const BUNDLE_TOTAL_LIMIT: u64 = 64 * 1024 * 1024;
const BUNDLE_ITEM_LIMIT: u64 = 16 * 1024 * 1024;
const LOCK_PATH: &str = "ui/ui.lock.json";
const BUNDLE_RELATIVE: &str = "cli/build-dependencies/clanker-ui-0.1.0";

#[derive(Clone, Debug)]
pub(super) struct UiAssemblyInputs {
    platform_root: PathBuf,
    bundle: PinnedTree,
    identity: Value,
    provider: String,
    package_name: String,
    package_version: String,
    package_digest: Digest,
    target: String,
    #[cfg(test)]
    test_bundle: bool,
}

pub(super) fn active_ui_lock(source: &SourceSnapshot) -> Result<Option<Value>> {
    let Some(bytes) = source.files().get(LOCK_PATH) else {
        return Ok(None);
    };
    ensure!(
        bytes.len() as u64 <= PIN_LIMIT,
        "UI lock exceeds bounded size"
    );
    let lock: UiLock = serde_json::from_slice(bytes).context("invalid UI lock JSON")?;
    day2::ui_lock::validate(&lock)?;
    Ok(Some(serde_json::to_value(lock)?))
}

pub(super) fn validate_ui_activation(
    source: &SourceSnapshot,
    inputs: Option<&UiAssemblyInputs>,
) -> Result<bool> {
    let Some(lock) = active_ui_lock(source)? else {
        return Ok(false);
    };
    let inputs = inputs.context("UI lock requires the installed managed UI dependency")?;
    validate_active_ui_lock(&lock, inputs)?;
    Ok(true)
}

pub(super) fn validate_active_ui_lock(lock: &Value, inputs: &UiAssemblyInputs) -> Result<()> {
    let lock: UiLock = serde_json::from_value(lock.clone()).context("invalid UI lock")?;
    day2::ui_lock::validate(&lock)?;
    ensure!(
        lock.provider == inputs.provider,
        "UI provider identity differs from installed bundle"
    );
    ensure!(
        lock.package.name == inputs.package_name
            && lock.package.version == inputs.package_version
            && lock.package.digest == inputs.package_digest.as_str(),
        "UI package identity differs from installed bundle"
    );
    Ok(())
}

impl UiAssemblyInputs {
    pub(super) fn capture(platform_root: &Path) -> Result<Self> {
        let platform_root = platform_root
            .canonicalize()
            .context("resolve Platform root")?;
        let installed = day2::build_dependencies::installed(&platform_root)
            .context("managed clanker-ui build dependency is missing or invalid; install the reviewed Platform build dependency")?;
        let identity = installed.identity();
        let package_name = identity
            .pointer("/package/name")
            .and_then(Value::as_str)
            .context("managed bundle package name missing")?
            .to_owned();
        let package_version = identity
            .pointer("/package/version")
            .and_then(Value::as_str)
            .context("managed bundle package version missing")?
            .to_owned();
        let package_digest = Digest::try_from(
            identity
                .pointer("/package/digest")
                .and_then(Value::as_str)
                .context("managed bundle package digest missing")?
                .to_owned(),
        )?;
        let provider = identity
            .get("provider")
            .and_then(Value::as_str)
            .context("managed bundle provider missing")?
            .to_owned();
        let target = identity
            .get("target")
            .and_then(Value::as_str)
            .context("managed bundle target missing")?
            .to_owned();
        let bundle = capture_bundle(installed.bundle_root())?;
        Ok(Self {
            platform_root,
            bundle,
            identity,
            provider,
            package_name,
            package_version,
            package_digest,
            target,
            #[cfg(test)]
            test_bundle: false,
        })
    }

    pub(super) fn binding_identity(&self) -> Result<Value> {
        Ok(json!({"managed_bundle": self.identity, "bundle_digest": self.bundle.digest()}))
    }

    pub(super) fn input_manifest(&self) -> Result<Value> {
        Ok(json!({
            "managed_bundle": self.identity,
            "bundle_digest": self.bundle.digest(),
            "target": self.target,
            "files": self.bundle.files(),
        }))
    }

    pub(super) fn materialize(&self, job: &Path) -> Result<()> {
        #[cfg(not(test))]
        self.revalidate_installed()?;
        #[cfg(test)]
        if self.test_bundle {
            ensure!(
                capture_bundle(&self.bundle.root)?.digest() == self.bundle.digest(),
                "managed UI test bundle changed after capture"
            );
        } else {
            self.revalidate_installed()?;
        }
        let target = job.join("platform").join(BUNDLE_RELATIVE);
        fs::create_dir_all(
            target
                .parent()
                .context("managed bundle destination parent")?,
        )?;
        self.bundle.materialize(&target)?;
        Ok(())
    }

    fn revalidate_installed(&self) -> Result<()> {
        let installed = day2::build_dependencies::installed(&self.platform_root)
            .context("managed clanker-ui build dependency changed after capture")?;
        let current = capture_bundle(installed.bundle_root())?;
        ensure!(
            current.digest() == self.bundle.digest() && installed.identity() == self.identity,
            "managed clanker-ui build dependency changed after capture"
        );
        Ok(())
    }
}

fn capture_bundle(root: &Path) -> Result<PinnedTree> {
    ensure!(
        fs::symlink_metadata(root)?.file_type().is_dir(),
        "managed UI bundle root must be a real directory"
    );
    let root = root.canonicalize()?;
    let mut files = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut total = 0u64;
    collect_bundle(&root, &root, &mut files, &mut folded, &mut total, &mut 0)?;
    ensure!(!files.is_empty(), "empty managed UI bundle");
    let digest = Digest::of(&files)?;
    Ok(PinnedTree {
        root,
        files,
        digest,
    })
}

fn collect_bundle(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, InputFile>,
    folded: &mut BTreeSet<String>,
    total: &mut u64,
    scanned: &mut usize,
) -> Result<()> {
    ensure!(
        directory.strip_prefix(root)?.components().count() <= 16,
        "managed UI bundle nesting budget"
    );
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *scanned += 1;
        ensure!(
            *scanned <= PACKAGE_FILE_LIMIT * 2,
            "managed UI bundle entry budget"
        );
        let path = entry.path();
        let kind = entry.file_type()?;
        ensure!(
            !kind.is_symlink(),
            "managed UI bundle symlinks are forbidden"
        );
        if kind.is_dir() {
            collect_bundle(root, &path, files, folded, total, scanned)?;
        } else {
            ensure!(
                kind.is_file(),
                "managed UI bundle special files are forbidden"
            );
            let relative = path
                .strip_prefix(root)?
                .components()
                .map(|part| match part {
                    Component::Normal(value) => value.to_str().context("non-UTF8 UI bundle path"),
                    _ => anyhow::bail!("unsafe UI bundle path"),
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            ensure!(
                !relative.is_empty() && !relative.contains('\\'),
                "invalid UI bundle path"
            );
            ensure!(
                folded.insert(relative.to_lowercase()),
                "UI bundle case-fold collision"
            );
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(metadata.len() <= BUNDLE_ITEM_LIMIT, "UI bundle file budget");
            let pin = pin_file(&path)?;
            *total = total
                .checked_add(pin.bytes)
                .context("UI bundle size overflow")?;
            ensure!(*total <= BUNDLE_TOTAL_LIMIT, "UI bundle total size budget");
            files.insert(relative, pin);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitOid, source::SourceSnapshot};
    use std::collections::BTreeMap;

    fn test_lock() -> Result<Value> {
        let inputs = vec![day2::ui_lock::Input {
            path: "templates/index.html".into(),
            bytes: 7,
            digest: day2::digest(b"<main/>"),
        }];
        Ok(serde_json::to_value(UiLock {
            schema_version: 2,
            provider: "clanker-ui.native".into(),
            package: day2::ui_lock::LockedPackage {
                name: "@clanker/vanilla".into(),
                version: "0.7.0".into(),
                digest: day2::ui_lock::manifest_digest(&inputs)?,
                inputs,
            },
        })?)
    }

    fn test_inputs(root: &Path) -> Result<UiAssemblyInputs> {
        let bundle_root = root.join("bundle");
        fs::create_dir_all(bundle_root.join("package/templates"))?;
        fs::create_dir_all(bundle_root.join("bin"))?;
        fs::create_dir_all(bundle_root.join("legal"))?;
        fs::write(bundle_root.join("manifest.json"), b"manifest")?;
        fs::write(bundle_root.join("provider-pin.json"), b"provider pin")?;
        fs::write(bundle_root.join("bin/clanker-ui"), b"executable")?;
        fs::write(bundle_root.join("legal/LICENSE"), b"license")?;
        fs::write(bundle_root.join("legal/NOTICES.txt"), b"notices")?;
        fs::write(bundle_root.join("package/templates/index.html"), b"<main/>")?;
        let lock = test_lock()?;
        let package_digest = Digest::try_from(
            lock["package"]["digest"]
                .as_str()
                .context("fixture package digest")?
                .to_owned(),
        )?;
        let identity = json!({
            "provider":"clanker-ui.native", "target":"test-target",
            "package":{"name":"@clanker/vanilla","version":"0.7.0","digest":package_digest}
        });
        Ok(UiAssemblyInputs {
            platform_root: root.to_path_buf(),
            bundle: capture_bundle(&bundle_root)?,
            identity,
            provider: "clanker-ui.native".into(),
            package_name: "@clanker/vanilla".into(),
            package_version: "0.7.0".into(),
            package_digest,
            target: "test-target".into(),
            test_bundle: true,
        })
    }

    fn source(lock: Value) -> Result<SourceSnapshot> {
        Ok(SourceSnapshot::from_files(
            GitOid::try_from("a".repeat(40))?,
            BTreeMap::from([(LOCK_PATH.to_owned(), serde_json::to_vec(&lock)?)]),
        )?)
    }

    #[test]
    fn ui_lock_requires_schema_two_and_rejects_paths_and_unknown_fields() -> Result<()> {
        let input = test_lock()?;
        assert!(active_ui_lock(&source(input.clone())?)?.is_some());
        let mut old = input.clone();
        old["schemaVersion"] = json!(1);
        assert!(active_ui_lock(&source(old)?).is_err());
        let mut path = input.clone();
        path["package"]["path"] = json!("../../packages/vanilla");
        assert!(active_ui_lock(&source(path)?).is_err());
        let mut malformed_path = input.clone();
        malformed_path["package"]["inputs"][0]["path"] = json!("assets/foo:bar");
        assert!(active_ui_lock(&source(malformed_path)?).is_err());
        let mut stale_closure = input.clone();
        stale_closure["package"]["inputs"][0]["bytes"] = json!(8);
        assert!(active_ui_lock(&source(stale_closure)?).is_err());
        let mut unknown = input;
        unknown["extra"] = json!(true);
        assert!(active_ui_lock(&source(unknown)?).is_err());
        Ok(())
    }

    #[test]
    fn app_lock_binds_only_the_installed_provider_and_package_identity() -> Result<()> {
        let root = tempfile::tempdir()?;
        let approved = test_inputs(root.path())?;
        let lock = test_lock()?;
        let active = active_ui_lock(&source(lock.clone())?)?.unwrap();
        validate_active_ui_lock(&active, &approved)?;
        let mut wrong = lock;
        wrong["package"]["version"] = json!("9.9.9");
        assert!(validate_active_ui_lock(&wrong, &approved).is_err());
        assert!(validate_ui_activation(&source(active)?, None).is_err());
        Ok(())
    }

    #[test]
    fn captured_bundle_revalidates_and_materializes_at_the_managed_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        let approved = test_inputs(root.path())?;
        let job = root.path().join("job");
        fs::create_dir_all(&job)?;
        approved
            .materialize(&job)
            .context("initial bundle materialization")?;
        let staged = job.join("platform").join(BUNDLE_RELATIVE);
        assert_eq!(fs::read(staged.join("manifest.json"))?, b"manifest");
        assert_eq!(
            fs::read(staged.join("package/templates/index.html"))?,
            b"<main/>"
        );
        assert!(approved.materialize(&job).is_err());
        let changed = root.path().join("bundle/package/templates/index.html");
        fs::write(&changed, b"substitution").context("change captured bundle")?;
        let fresh_job = root.path().join("second-job");
        fs::create_dir_all(&fresh_job)?;
        assert!(
            approved
                .materialize(&fresh_job)
                .context("revalidate changed bundle")
                .is_err()
        );
        Ok(())
    }
}
