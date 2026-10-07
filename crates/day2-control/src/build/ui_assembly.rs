use super::{InputFile, PinnedTree, pin_file, write_pinned};
use crate::{Digest, Name, source::SourceSnapshot};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

const PIN_LIMIT: u64 = 1024 * 1024;
const PACKAGE_FILE_LIMIT: usize = 4096;
const PACKAGE_TOTAL_LIMIT: u64 = 32 * 1024 * 1024;
const PACKAGE_ITEM_LIMIT: u64 = 1024 * 1024;
const LOCK_PATH: &str = "ui/ui.lock.json";
const TARGET: &str = "macos-aarch64";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderPin {
    schema_version: u32,
    provider: String,
    assembly_protocol: u32,
    binding_abi: u32,
    targets: BTreeMap<String, TargetPin>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetPin {
    executable: String,
    digest: Digest,
}

#[derive(Clone, Debug)]
pub(super) struct UiAssemblyInputs {
    provider_pin_path: PathBuf,
    provider_pin_digest: Digest,
    provider: String,
    assembly_protocol: u32,
    binding_abi: u32,
    executable_path: PathBuf,
    executable: InputFile,
    package_key: Name,
    package: PinnedTree,
}

pub(super) fn active_ui_lock(source: &SourceSnapshot) -> Result<Option<Value>> {
    let Some(bytes) = source.files().get(LOCK_PATH) else {
        return Ok(None);
    };
    ensure!(
        bytes.len() as u64 <= PIN_LIMIT,
        "UI lock exceeds bounded size"
    );
    let lock: Value = serde_json::from_slice(bytes).context("invalid UI lock JSON")?;
    let object = lock.as_object().context("UI lock must be an object")?;
    ensure!(
        object.get("schemaVersion").and_then(Value::as_u64) == Some(1),
        "unsupported UI lock schema"
    );
    let provider = object
        .get("provider")
        .and_then(Value::as_str)
        .context("UI lock provider required")?;
    ensure!(safe_identity(provider), "invalid UI lock provider identity");
    let package = object
        .get("package")
        .and_then(Value::as_object)
        .context("UI lock package required")?;
    let path = package
        .get("path")
        .and_then(Value::as_str)
        .context("UI package path required")?;
    ensure!(
        !path.contains('\\') && path.len() <= 256,
        "invalid UI package path"
    );
    Ok(Some(lock))
}

pub(super) fn validate_ui_activation(
    source: &SourceSnapshot,
    inputs: Option<&UiAssemblyInputs>,
) -> Result<bool> {
    let Some(lock) = active_ui_lock(source)? else {
        return Ok(false);
    };
    let inputs = inputs.context("UI lock requires approved UI assembly capability")?;
    validate_active_ui_lock(&lock, inputs)?;
    Ok(true)
}

pub(super) fn validate_active_ui_lock(lock: &Value, inputs: &UiAssemblyInputs) -> Result<()> {
    ensure!(
        lock.get("provider").and_then(Value::as_str) == Some(inputs.provider.as_str()),
        "UI provider identity differs from approved provider pin"
    );
    let expected_path = format!("../../packages/{}", inputs.package_key.as_str());
    ensure!(
        lock.pointer("/package/path").and_then(Value::as_str) == Some(expected_path.as_str()),
        "UI package path differs from configured package key"
    );
    Ok(())
}

impl UiAssemblyInputs {
    pub(super) fn capture(configuration: &day2_capabilities::UiAssemblyProvider) -> Result<Self> {
        ensure!(
            Path::new(&configuration.provider_pin).is_absolute()
                && Path::new(&configuration.package_root).is_absolute(),
            "UI capability paths must be absolute"
        );
        ensure!(
            fs::symlink_metadata(&configuration.provider_pin)?
                .file_type()
                .is_file(),
            "provider pin must be a real regular file"
        );
        ensure!(
            fs::symlink_metadata(&configuration.package_root)?
                .file_type()
                .is_dir(),
            "UI package root must be a real directory"
        );
        let provider_pin_path = PathBuf::from(&configuration.provider_pin).canonicalize()?;
        let (pin_bytes, metadata) = bounded_regular(&provider_pin_path, PIN_LIMIT)?;
        ensure!(metadata.is_file(), "provider pin must be a regular file");
        let pin: ProviderPin =
            serde_json::from_slice(&pin_bytes).context("invalid UI provider pin")?;
        ensure!(
            pin.schema_version == 1 && pin.assembly_protocol == 2 && pin.binding_abi == 2,
            "unsupported UI provider pin protocol"
        );
        ensure!(
            safe_identity(&pin.provider),
            "invalid pinned UI provider identity"
        );
        let target = pin
            .targets
            .get(TARGET)
            .context("provider pin lacks macos-aarch64 target")?;
        let executable_path = resolve_executable(&provider_pin_path, &target.executable)?;
        let executable = pin_file(&executable_path)?;
        ensure!(
            executable.bytes <= 64 * 1024 * 1024,
            "UI provider executable exceeds 64 MiB"
        );
        ensure!(
            executable.executable,
            "UI provider executable permission required"
        );
        ensure!(
            executable.digest == target.digest,
            "UI provider executable digest mismatch"
        );
        let package_root = PathBuf::from(&configuration.package_root).canonicalize()?;
        let package = capture_package(&package_root)?;
        Ok(Self {
            provider_pin_path,
            provider_pin_digest: Digest::new(&pin_bytes),
            provider: pin.provider,
            assembly_protocol: pin.assembly_protocol,
            binding_abi: pin.binding_abi,
            executable_path,
            executable,
            package_key: configuration.package_key.clone(),
            package,
        })
    }

    pub(super) fn binding_identity(&self) -> Result<Value> {
        Ok(json!({
            "provider_pin": self.provider_pin_digest,
            "provider": self.provider,
            "assembly_protocol": self.assembly_protocol,
            "binding_abi": self.binding_abi,
            "target": TARGET,
            "executable": self.executable,
            "package_key": self.package_key,
            "package": self.package.digest(),
        }))
    }

    pub(super) fn input_manifest(&self) -> Result<Value> {
        Ok(json!({
            "provider_pin_digest": self.provider_pin_digest,
            "provider": self.provider,
            "assembly_protocol": self.assembly_protocol,
            "binding_abi": self.binding_abi,
            "target": {"key": TARGET, "executable": self.executable},
            "package_key": self.package_key,
            "package_digest": self.package.digest(),
            "package_files": self.package.files(),
        }))
    }

    pub(super) fn materialize(&self, job: &Path) -> Result<()> {
        let current = pin_file(&self.executable_path)?;
        ensure!(
            current == self.executable,
            "approved UI provider executable changed"
        );
        let (pin_bytes, _) = bounded_regular(&self.provider_pin_path, PIN_LIMIT)?;
        ensure!(
            Digest::new(&pin_bytes) == self.provider_pin_digest,
            "approved UI provider pin changed"
        );
        fs::create_dir(job.join("ui-provider"))?;
        write_pinned(
            &self.executable_path,
            &job.join("ui-provider/executable"),
            &self.executable,
        )?;
        let rewritten = json!({
            "schemaVersion": 1,
            "provider": self.provider,
            "assemblyProtocol": self.assembly_protocol,
            "bindingAbi": self.binding_abi,
            "targets": {TARGET: {"executable": "executable", "digest": self.executable.digest}},
        });
        write_new_readonly(
            &job.join("ui-provider/pin.json"),
            &serde_json::to_vec_pretty(&rewritten)?,
        )?;
        let packages = job.join("packages");
        fs::create_dir(&packages)?;
        materialize_package_tree(&self.package, &packages.join(self.package_key.as_str()))?;
        Ok(())
    }
}

fn materialize_package_tree(tree: &PinnedTree, target: &Path) -> Result<()> {
    fs::create_dir(target).context("fresh UI package destination required")?;
    for (relative, expected) in tree.files() {
        let source = checked_package_file(&tree.root, relative)?;
        write_pinned(&source, &target.join(relative), expected)?;
    }
    Ok(())
}

fn checked_package_file(root: &Path, relative: &str) -> Result<PathBuf> {
    ensure!(
        fs::symlink_metadata(root)?.file_type().is_dir(),
        "approved UI package root changed or became a symlink"
    );
    let parts = Path::new(relative).components().collect::<Vec<_>>();
    ensure!(!parts.is_empty(), "empty UI package path");
    let mut path = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(_) = part else {
            anyhow::bail!("unsafe UI package path");
        };
        path.push(part);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "UI package path contains a symlink"
        );
        if index + 1 == parts.len() {
            ensure!(metadata.is_file(), "UI package input is not a regular file");
        } else {
            ensure!(metadata.is_dir(), "UI package parent is not a directory");
        }
    }
    Ok(path)
}

fn capture_package(root: &Path) -> Result<PinnedTree> {
    ensure!(
        fs::symlink_metadata(root)?.file_type().is_dir(),
        "UI package root must be a real directory"
    );
    let root = root.canonicalize()?;
    let mut files = BTreeMap::new();
    let mut folded = BTreeSet::new();
    let mut total = 0u64;
    collect_package(&root, &root, &mut files, &mut folded, &mut total, &mut 0)?;
    ensure!(!files.is_empty(), "empty UI package tree");
    Ok(PinnedTree {
        root: root.clone(),
        digest: Digest::of(&files)?,
        files,
    })
}

fn collect_package(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, InputFile>,
    folded: &mut BTreeSet<String>,
    total: &mut u64,
    scanned: &mut usize,
) -> Result<()> {
    ensure!(
        directory.strip_prefix(root)?.components().count() <= 32,
        "UI package nesting budget"
    );
    // The final BTreeMap determines identity order; do not allocate an unbounded directory listing.
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *scanned += 1;
        ensure!(
            *scanned <= PACKAGE_FILE_LIMIT * 32,
            "UI package directory entry budget"
        );
        let path = entry.path();
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "UI package symlinks are forbidden");
        if kind.is_dir() {
            collect_package(root, &path, files, folded, total, scanned)?;
        } else {
            ensure!(kind.is_file(), "UI package special files are forbidden");
            let relative = path
                .strip_prefix(root)?
                .components()
                .map(|part| match part {
                    Component::Normal(value) => value.to_str().context("non-UTF8 UI package path"),
                    _ => anyhow::bail!("unsafe UI package path"),
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            ensure!(
                !relative.is_empty() && !relative.contains('\\'),
                "invalid UI package path"
            );
            insert_casefolded(folded, &relative)?;
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.len() <= PACKAGE_ITEM_LIMIT,
                "UI package file budget"
            );
            let pin = pin_file(&path)?;
            ensure!(
                pin.bytes <= PACKAGE_ITEM_LIMIT,
                "UI package file grew beyond budget"
            );
            *total = total
                .checked_add(pin.bytes)
                .context("UI package size overflow")?;
            ensure!(
                *total <= PACKAGE_TOTAL_LIMIT && files.len() < PACKAGE_FILE_LIMIT,
                "UI package tree budget"
            );
            files.insert(relative, pin);
        }
    }
    Ok(())
}

fn insert_casefolded(folded: &mut BTreeSet<String>, path: &str) -> Result<()> {
    ensure!(
        folded.insert(path.to_lowercase()),
        "UI package case-fold collision"
    );
    Ok(())
}

fn resolve_executable(pin_path: &Path, value: &str) -> Result<PathBuf> {
    ensure!(
        !value.is_empty() && !value.contains('\\'),
        "invalid pinned executable path"
    );
    let candidate = Path::new(value);
    if candidate.is_absolute() {
        Ok(candidate.to_path_buf())
    } else {
        ensure!(
            candidate
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
            "unsafe relative executable path"
        );
        Ok(pin_path.parent().context("pin parent")?.join(candidate))
    }
}

fn safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_ .".contains(&b))
        && !value.contains(' ')
}

fn bounded_regular(path: &Path, limit: u64) -> Result<(Vec<u8>, fs::Metadata)> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= limit,
        "bounded regular file required"
    );
    let file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "file exceeds size limit");
    Ok((bytes, metadata))
}

fn write_new_readonly(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    use std::io::Write;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitOid, source::SourceSnapshot};
    use day2_capabilities::UiAssemblyProvider;
    use std::collections::BTreeMap;

    fn config(root: &Path) -> Result<UiAssemblyProvider> {
        let executable = root.join("provider");
        fs::write(&executable, b"provider executable")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        }
        let pin = json!({
            "schemaVersion": 1,
            "provider": "clanker-vanilla",
            "assemblyProtocol": 2,
            "bindingAbi": 2,
            "targets": {TARGET: {"executable": "provider", "digest": Digest::new(b"provider executable")}}
        });
        fs::write(root.join("provider.json"), serde_json::to_vec(&pin)?)?;
        fs::create_dir(root.join("package"))?;
        fs::write(root.join("package/fragment.html"), b"<main>opaque</main>")?;
        Ok(UiAssemblyProvider {
            provider_pin: root.join("provider.json").display().to_string(),
            package_root: root.join("package").display().to_string(),
            package_key: Name::try_from("clanker-vanilla".to_owned())?,
        })
    }

    fn source(provider: &str, path: &str) -> Result<SourceSnapshot> {
        Ok(SourceSnapshot::from_files(
            GitOid::try_from("a".repeat(40))?,
            BTreeMap::from([(
                LOCK_PATH.to_owned(),
                serde_json::to_vec(
                    &json!({"schemaVersion": 1, "provider": provider, "package": {"path": path}}),
                )?,
            )]),
        )?)
    }

    #[test]
    fn pin_requires_assembly_protocol_two_and_binding_abi_two() -> Result<()> {
        let root = tempfile::tempdir()?;
        let configuration = config(root.path())?;
        let mut pin: Value = serde_json::from_slice(&fs::read(&configuration.provider_pin)?)?;
        pin["assemblyProtocol"] = json!(1);
        fs::write(&configuration.provider_pin, serde_json::to_vec(&pin)?)?;
        assert!(UiAssemblyInputs::capture(&configuration).is_err());
        pin["assemblyProtocol"] = json!(2);
        pin["bindingAbi"] = json!(1);
        fs::write(&configuration.provider_pin, serde_json::to_vec(&pin)?)?;
        assert!(UiAssemblyInputs::capture(&configuration).is_err());
        Ok(())
    }

    #[test]
    fn approved_inputs_validate_lock_and_materialize_fresh_readonly_staging() -> Result<()> {
        let root = tempfile::tempdir()?;
        let approved = UiAssemblyInputs::capture(&config(root.path())?)?;
        let lock = active_ui_lock(&source(
            "clanker-vanilla",
            "../../packages/clanker-vanilla",
        )?)?
        .unwrap();
        validate_active_ui_lock(&lock, &approved)?;
        let stage = root.path().join("job");
        fs::create_dir(&stage)?;
        approved.materialize(&stage)?;
        assert_eq!(
            fs::read(stage.join("packages/clanker-vanilla/fragment.html"))?,
            b"<main>opaque</main>"
        );
        let rewritten: Value =
            serde_json::from_slice(&fs::read(stage.join("ui-provider/pin.json"))?)?;
        assert_eq!(
            rewritten
                .pointer("/targets/macos-aarch64/executable")
                .and_then(Value::as_str),
            Some("executable")
        );
        assert_eq!(
            rewritten.pointer("/provider").and_then(Value::as_str),
            Some("clanker-vanilla")
        );
        assert!(
            fs::metadata(stage.join("ui-provider/pin.json"))?
                .permissions()
                .readonly()
        );
        assert!(approved.materialize(&stage).is_err());
        Ok(())
    }

    #[test]
    fn active_lock_requires_capability_identity_and_exact_configured_package_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        let approved = UiAssemblyInputs::capture(&config(root.path())?)?;
        let wrong_provider =
            active_ui_lock(&source("other-provider", "../../packages/clanker-vanilla")?)?.unwrap();
        assert!(validate_active_ui_lock(&wrong_provider, &approved).is_err());
        let wrong_path =
            active_ui_lock(&source("clanker-vanilla", "../../packages/other")?)?.unwrap();
        assert!(validate_active_ui_lock(&wrong_path, &approved).is_err());
        let locked = source("clanker-vanilla", "../../packages/clanker-vanilla")?;
        assert!(active_ui_lock(&locked)?.is_some());
        assert!(validate_ui_activation(&locked, None).is_err());
        let ordinary = SourceSnapshot::from_files(
            GitOid::try_from("b".repeat(40))?,
            BTreeMap::from([("App.roc".to_owned(), b"app".to_vec())]),
        )?;
        assert!(!validate_ui_activation(&ordinary, None)?);
        Ok(())
    }

    #[test]
    fn pin_executable_package_mutations_and_tree_collisions_fail_closed() -> Result<()> {
        let root = tempfile::tempdir()?;
        let configuration = config(root.path())?;
        let approved = UiAssemblyInputs::capture(&configuration)?;
        let approved_manifest = approved.input_manifest()?;
        fs::write(root.path().join("provider"), b"substituted executable")?;
        let job = root.path().join("job");
        fs::create_dir(&job)?;
        assert!(approved.materialize(&job).is_err());
        assert_eq!(approved.input_manifest()?, approved_manifest);

        fs::write(root.path().join("provider"), b"provider executable")?;
        fs::write(root.path().join("provider.json"), b"{}")?;
        let second_job = root.path().join("second-job");
        fs::create_dir(&second_job)?;
        assert!(approved.materialize(&second_job).is_err());

        let package = root.path().join("package/fragment.html");
        fs::write(&package, b"package substitution")?;
        let package_job = root.path().join("package-job");
        fs::create_dir(&package_job)?;
        assert!(approved.materialize(&package_job).is_err());

        let mut folded = BTreeSet::new();
        insert_casefolded(&mut folded, "A.html")?;
        assert!(insert_casefolded(&mut folded, "a.html").is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn package_symlinks_and_oversized_files_are_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        let package = root.path().join("package");
        fs::create_dir(&package)?;
        fs::write(
            package.join("large"),
            vec![0u8; PACKAGE_ITEM_LIMIT as usize + 1],
        )?;
        assert!(capture_package(&package).is_err());
        fs::remove_file(package.join("large"))?;
        fs::write(package.join("real"), b"x")?;
        let approved = capture_package(&package)?;
        let outside = root.path().join("outside");
        fs::write(&outside, b"x")?;
        fs::remove_file(package.join("real"))?;
        std::os::unix::fs::symlink(&outside, package.join("real"))?;
        assert!(materialize_package_tree(&approved, &root.path().join("stage")).is_err());
        std::os::unix::fs::symlink(&outside, package.join("link"))?;
        assert!(capture_package(&package).is_err());
        Ok(())
    }

    #[test]
    fn captured_provider_and_package_identities_change_the_runner_binding_material() -> Result<()> {
        let root = tempfile::tempdir()?;
        let configuration = config(root.path())?;
        let first = UiAssemblyInputs::capture(&configuration)?;
        let first_identity = first.binding_identity()?;
        fs::write(
            root.path().join("package/fragment.html"),
            b"changed package",
        )?;
        let second = UiAssemblyInputs::capture(&configuration)?;
        assert_ne!(first_identity, second.binding_identity()?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn capability_roots_and_replaced_package_roots_cannot_be_symlinks() -> Result<()> {
        let root = tempfile::tempdir()?;
        let configuration = config(root.path())?;
        let approved = UiAssemblyInputs::capture(&configuration)?;
        fs::rename(
            root.path().join("package"),
            root.path().join("real-package"),
        )?;
        std::os::unix::fs::symlink(
            root.path().join("real-package"),
            root.path().join("package"),
        )?;
        assert!(UiAssemblyInputs::capture(&configuration).is_err());
        assert!(materialize_package_tree(&approved.package, &root.path().join("stage")).is_err());
        fs::remove_file(root.path().join("package"))?;
        fs::rename(
            root.path().join("real-package"),
            root.path().join("package"),
        )?;
        fs::rename(
            root.path().join("provider.json"),
            root.path().join("real-pin.json"),
        )?;
        std::os::unix::fs::symlink(
            root.path().join("real-pin.json"),
            root.path().join("provider.json"),
        )?;
        assert!(UiAssemblyInputs::capture(&configuration).is_err());
        Ok(())
    }

    #[test]
    fn directory_entry_budget_includes_empty_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        fs::create_dir(root.path().join("empty"))?;
        let mut scanned = PACKAGE_FILE_LIMIT * 32;
        assert!(
            collect_package(
                root.path(),
                root.path(),
                &mut BTreeMap::new(),
                &mut BTreeSet::new(),
                &mut 0,
                &mut scanned
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn non_ui_sources_do_not_activate_ui_capture() -> Result<()> {
        let source = SourceSnapshot::from_files(
            GitOid::try_from("a".repeat(40))?,
            BTreeMap::from([("App.roc".to_owned(), b"app".to_vec())]),
        )?;
        assert!(active_ui_lock(&source)?.is_none());
        Ok(())
    }
}
