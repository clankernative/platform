//! Reviewed, bounded build-time dependency bundle for Platform-owned tools.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

const RELEASE: &str = "0.1.1";
const MAX_MANIFEST: u64 = 1_000_000;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const CATALOG: &[u8] = include_bytes!("../../../build-dependencies/clanker-ui.json");

#[derive(Clone)]
struct TargetPin {
    target: String,
    archive: String,
    archive_sha256: String,
    archive_bytes: u64,
    manifest_sha256: String,
    executable_sha256: String,
    executable_bytes: u64,
    chart_worker_sha256: String,
    chart_worker_bytes: u64,
    contracts_sha256: String,
    provider_pin_sha256: String,
}

pub struct DownloadPin {
    pub target: String,
    pub archive: String,
    pub sha256: String,
    pub bytes: u64,
}

fn catalog() -> Result<Value> {
    serde_json::from_slice(CATALOG).context("parse reviewed managed dependency catalog")
}

fn pin_for(target: &str) -> Result<TargetPin> {
    let catalog = catalog()?;
    let item = catalog["targets"]
        .get(target)
        .context("catalog does not review this target")?;
    let string = |key: &str| -> Result<String> {
        Ok(item[key]
            .as_str()
            .with_context(|| format!("catalog field {key}"))?
            .to_owned())
    };
    let number = |key: &str| -> Result<u64> {
        item[key]
            .as_u64()
            .with_context(|| format!("catalog field {key}"))
    };
    Ok(TargetPin {
        target: target.to_owned(),
        archive: string("archive")?,
        archive_sha256: string("archiveSha256")?,
        archive_bytes: number("archiveBytes")?,
        manifest_sha256: string("manifestSha256")?,
        executable_sha256: string("executableSha256")?,
        executable_bytes: number("executableBytes")?,
        chart_worker_sha256: string("chartWorkerSha256")?,
        chart_worker_bytes: number("chartWorkerBytes")?,
        contracts_sha256: catalog["presentationWorker"]["contractsSha256"]
            .as_str()
            .context("catalog presentation contract digest")?
            .to_owned(),
        provider_pin_sha256: string("providerPinSha256")?,
    })
}

pub fn download_pin() -> Result<DownloadPin> {
    let pin = target_pin()?;
    Ok(DownloadPin {
        target: pin.target,
        archive: pin.archive,
        sha256: pin.archive_sha256,
        bytes: pin.archive_bytes,
    })
}

fn target_pin() -> Result<TargetPin> {
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macos-aarch64",
        ("linux", "x86_64") => "linux-x86_64",
        _ => anyhow::bail!("managed clanker-ui dependency is unsupported on this target"),
    };
    pin_for(target)
}

#[derive(Clone, Debug)]
pub struct InstalledBundle {
    pub provider_pin_path: PathBuf,
    pub package_root: PathBuf,
    pub executable_path: PathBuf,
    bundle_root: PathBuf,
    identity: Value,
}

impl InstalledBundle {
    pub fn bundle_root(&self) -> &Path {
        &self.bundle_root
    }

    /// Stable redacted receipt suitable for inclusion in the native tool identity.
    pub fn identity(&self) -> Value {
        self.identity.clone()
    }
}

/// Validate an extracted staging bundle against the host's reviewed release pin.
pub fn verify_staged(bundle_root: &Path, target: &str) -> Result<InstalledBundle> {
    let pin = target_pin()?;
    ensure!(
        target == pin.target,
        "staged dependency target is unsupported on this host"
    );
    verify_bundle(bundle_root, pin)
}

/// Validate only Platform's fixed installation path. This function never downloads or repairs.
pub fn installed(platform_root: &Path) -> Result<InstalledBundle> {
    installed_with_pin(platform_root, target_pin()?)
}

fn installed_with_pin(platform_root: &Path, pin: TargetPin) -> Result<InstalledBundle> {
    ensure_directory_chain(&platform_root.join("cli/build-dependencies"))?;
    let bundle_root = platform_root.join(format!("cli/build-dependencies/clanker-ui-{RELEASE}"));
    verify_bundle(&bundle_root, pin)
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "expected regular file: {}",
        path.display()
    );
    ensure!(
        meta.len() <= limit,
        "file exceeds byte budget: {}",
        path.display()
    );
    let bytes = day2_assets::read_regular(path, limit)?;
    ensure!(
        bytes.len() as u64 == meta.len() && bytes.len() as u64 <= limit,
        "file changed while reading"
    );
    Ok(bytes)
}

fn ensure_directory_chain(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "managed dependency root must be absolute"
    );
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        ensure_real_directory(&current)?;
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "symlink/special directory forbidden: {}",
        path.display()
    );
    Ok(())
}

fn safe_relative(path: &str) -> Result<PathBuf> {
    ensure!(
        !path.is_empty() && !path.contains('\\') && !path.starts_with('/'),
        "invalid package-relative path"
    );
    ensure!(
        path.split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "unsafe package-relative path"
    );
    let parsed = Path::new(path);
    ensure!(
        parsed
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "unsafe package-relative path"
    );
    Ok(parsed.to_path_buf())
}

fn verify_bundle(bundle_root: &Path, pin: TargetPin) -> Result<InstalledBundle> {
    ensure_real_directory(bundle_root.parent().context("bundle parent")?)?;
    ensure_real_directory(bundle_root)?;
    let manifest_path = bundle_root.join("manifest.json");
    let manifest_bytes = read_regular(&manifest_path, MAX_MANIFEST)?;
    ensure!(
        sha(&manifest_bytes) == pin.manifest_sha256,
        "managed dependency manifest digest mismatch"
    );
    let manifest: Value =
        serde_json::from_slice(&manifest_bytes).context("parse reviewed bundle manifest")?;
    let catalog = catalog()?;
    let provider_path = bundle_root.join("provider-pin.json");
    let provider_bytes = read_regular(&provider_path, 4096)?;
    ensure!(
        sha(&provider_bytes) == pin.provider_pin_sha256,
        "managed dependency provider pin digest mismatch"
    );
    let provider: Value =
        serde_json::from_slice(&provider_bytes).context("parse reviewed provider pin")?;

    ensure!(
        manifest["schemaVersion"] == catalog["schemaVersion"] && manifest["target"] == pin.target,
        "managed dependency target/schema mismatch"
    );
    ensure!(
        manifest["toolVersion"] == catalog["release"]
            && manifest["sourceRevision"] == catalog["sourceRevision"],
        "managed dependency source identity mismatch"
    );
    ensure!(
        manifest["provider"] == catalog["provider"]
            && manifest["assemblyProtocol"] == catalog["assemblyProtocol"]
            && manifest["bindingAbi"] == catalog["bindingAbi"]
            && manifest["templateEngine"] == catalog["templateEngine"],
        "managed dependency protocol identity mismatch"
    );
    ensure!(
        manifest["package"]["name"] == catalog["name"]
            && manifest["package"]["version"] == catalog["version"]
            && manifest["package"]["digest"] == catalog["packageDigest"],
        "managed package identity mismatch"
    );
    ensure!(
        manifest["presentationWorker"]["abi"] == catalog["presentationWorker"]["abi"]
            && manifest["presentationWorker"]["executable"]["path"] == "bin/clanker-chart-worker"
            && manifest["presentationWorker"]["executable"]["bytes"] == pin.chart_worker_bytes
            && manifest["presentationWorker"]["executable"]["digest"]
                == format!("sha256:{}", pin.chart_worker_sha256),
        "managed chart worker manifest mismatch"
    );
    let contracts_digest = sha(&serde_json::to_vec(
        &manifest["presentationWorker"]["contracts"],
    )?);
    ensure!(
        contracts_digest == pin.contracts_sha256,
        "managed presentation contract digest mismatch"
    );
    ensure!(
        manifest["executable"]["path"] == "bin/clanker-ui"
            && manifest["executable"]["bytes"] == pin.executable_bytes
            && manifest["executable"]["digest"] == format!("sha256:{}", pin.executable_sha256),
        "managed executable manifest mismatch"
    );
    ensure!(
        provider["schemaVersion"] == catalog["schemaVersion"]
            && provider["provider"] == catalog["provider"]
            && provider["assemblyProtocol"] == catalog["assemblyProtocol"]
            && provider["bindingAbi"] == catalog["bindingAbi"],
        "managed provider identity mismatch"
    );
    ensure!(
        provider["targets"][pin.target.as_str()]["executable"] == "bin/clanker-ui"
            && provider["targets"][pin.target.as_str()]["digest"]
                == format!("sha256:{}", pin.executable_sha256),
        "managed provider target mismatch"
    );

    let entries = manifest["entries"]
        .as_array()
        .context("manifest entries missing")?;
    ensure!(
        entries.len() as u64
            == catalog["inputCount"]
                .as_u64()
                .context("catalog inputCount")?,
        "managed package input count mismatch"
    );
    let mut expected = BTreeSet::from([
        "manifest.json".to_owned(),
        "provider-pin.json".to_owned(),
        "bin/clanker-ui".to_owned(),
        "bin/clanker-chart-worker".to_owned(),
        "legal/LICENSE".to_owned(),
        "legal/NOTICES.txt".to_owned(),
    ]);
    let package_root = bundle_root.join("package");
    ensure_real_directory(&package_root)?;
    ensure_real_directory(&bundle_root.join("legal"))?;
    ensure_real_directory(&bundle_root.join("bin"))?;
    let mut inputs = BTreeMap::new();
    let mut total = 0u64;
    for entry in entries {
        let path = entry["path"].as_str().context("manifest path missing")?;
        let relative = safe_relative(path)?;
        ensure!(
            inputs.insert(path.to_owned(), entry.clone()).is_none(),
            "duplicate manifest path"
        );
        let bytes_count = entry["bytes"]
            .as_u64()
            .context("manifest byte length missing")?;
        ensure!(
            bytes_count <= MAX_FILE,
            "manifest input exceeds file budget"
        );
        total = total
            .checked_add(bytes_count)
            .context("package byte budget overflow")?;
        ensure!(total <= MAX_PACKAGE_BYTES, "package exceeds byte budget");
        let digest = entry["digest"]
            .as_str()
            .context("manifest digest missing")?;
        ensure!(
            digest.starts_with("sha256:") && digest.len() == 71,
            "invalid manifest digest"
        );
        let file = package_root.join(&relative);
        ensure_file_ancestors(&package_root, &relative)?;
        let bytes = read_regular(&file, MAX_FILE)?;
        ensure!(
            bytes.len() as u64 == bytes_count && format!("sha256:{}", sha(&bytes)) == digest,
            "managed package input mismatch: {path}"
        );
        ensure!(
            expected.insert(format!("package/{path}")),
            "duplicate bundle path"
        );
    }
    let legal = manifest["legal"]
        .as_array()
        .context("manifest legal closure missing")?;
    ensure!(
        legal.len() == 2,
        "managed legal closure entry count mismatch"
    );
    let mut legal_paths = BTreeSet::new();
    for entry in legal {
        let path = entry["path"].as_str().context("legal path missing")?;
        ensure!(
            ["legal/LICENSE", "legal/NOTICES.txt"].contains(&path),
            "unreviewed legal closure path"
        );
        ensure!(
            legal_paths.insert(path.to_owned()),
            "duplicate legal closure path"
        );
        let bytes_count = entry["bytes"].as_u64().context("legal byte size missing")?;
        ensure!(bytes_count <= MAX_FILE, "legal file exceeds byte budget");
        let digest = entry["digest"].as_str().context("legal digest missing")?;
        ensure!(
            digest.starts_with("sha256:") && digest.len() == 71,
            "invalid legal digest"
        );
        let bytes = read_regular(&bundle_root.join(path), bytes_count)?;
        ensure!(
            bytes.len() as u64 == bytes_count && format!("sha256:{}", sha(&bytes)) == digest,
            "managed legal closure mismatch"
        );
    }
    ensure!(
        legal_paths == BTreeSet::from(["legal/LICENSE".to_owned(), "legal/NOTICES.txt".to_owned()]),
        "managed legal closure incomplete"
    );
    let executable_total = pin
        .executable_bytes
        .checked_add(pin.chart_worker_bytes)
        .context("executable closure byte budget overflow")?;
    ensure!(
        executable_total <= MAX_EXECUTABLE_BYTES,
        "executable closure exceeds byte budget"
    );
    let executable = bundle_root.join("bin/clanker-ui");
    let executable_bytes = read_regular(&executable, pin.executable_bytes)?;
    ensure!(
        executable_bytes.len() as u64 == pin.executable_bytes
            && sha(&executable_bytes) == pin.executable_sha256,
        "managed executable digest mismatch"
    );
    check_executable(&executable, &executable_bytes, &pin.target)?;
    let chart_worker = bundle_root.join("bin/clanker-chart-worker");
    let chart_worker_bytes = read_regular(&chart_worker, pin.chart_worker_bytes)?;
    ensure!(
        chart_worker_bytes.len() as u64 == pin.chart_worker_bytes
            && sha(&chart_worker_bytes) == pin.chart_worker_sha256,
        "managed chart worker digest mismatch"
    );
    check_executable(&chart_worker, &chart_worker_bytes, &pin.target)?;
    let mut actual = BTreeSet::new();
    let mut visited = 0usize;
    collect_files(bundle_root, bundle_root, &mut actual, 0, &mut visited)?;
    ensure!(
        actual == expected,
        "managed bundle contains missing or unlisted files"
    );

    let identity = json!({
        "provider": catalog["provider"], "release": catalog["release"], "target": pin.target,
        "catalogDigest": format!("sha256:{}", sha(CATALOG)),
        "manifestDigest": format!("sha256:{}", pin.manifest_sha256),
        "providerPinDigest": format!("sha256:{}", pin.provider_pin_sha256),
        "archiveDigest": format!("sha256:{}", pin.archive_sha256),
        "presentationWorker": {"abi": catalog["presentationWorker"]["abi"], "contractsSha256": catalog["presentationWorker"]["contractsSha256"], "executable": {"path": "bin/clanker-chart-worker", "bytes": pin.chart_worker_bytes, "digest": format!("sha256:{}", pin.chart_worker_sha256)} },
        "inputCount": catalog["inputCount"],
        "package": {"name":catalog["name"], "version":catalog["version"], "digest":catalog["packageDigest"]}
    });
    Ok(InstalledBundle {
        provider_pin_path: provider_path,
        package_root,
        executable_path: executable,
        bundle_root: bundle_root.to_path_buf(),
        identity,
    })
}

fn ensure_file_ancestors(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component);
        ensure_real_directory(&current)?;
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut BTreeSet<String>,
    depth: usize,
    visited: &mut usize,
) -> Result<()> {
    ensure!(depth <= 32, "managed bundle tree depth budget exceeded");
    let before = files.len();
    let mut entries = 0usize;
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        entries += 1;
        ensure!(entries <= 2048, "bundle directory entry budget exceeded");
        *visited = visited
            .checked_add(1)
            .context("bundle entry count overflow")?;
        ensure!(
            *visited <= 4096,
            "managed bundle tree entry budget exceeded"
        );
        let path = entry.path();
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "symlink forbidden in managed bundle");
        if kind.is_dir() {
            ensure_real_directory(&path)?;
            collect_files(root, &path, files, depth + 1, visited)?;
        } else {
            ensure!(kind.is_file(), "special file forbidden in managed bundle");
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            ensure!(files.insert(relative), "duplicate bundle file");
        }
    }
    ensure!(
        current == root || files.len() > before,
        "empty directory in managed bundle"
    );
    Ok(())
}

#[cfg(unix)]
fn check_executable(path: &Path, bytes: &[u8], target: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    ensure!(mode & 0o111 != 0, "managed executable is not executable");
    match target {
        "macos-aarch64" => ensure!(
            bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
                || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf]),
            "managed executable is not Mach-O"
        ),
        "linux-x86_64" => ensure!(
            bytes.len() >= 20 && &bytes[..4] == b"\x7fELF" && bytes[18..20] == [0x3e, 0x00],
            "managed executable is not ELF x86_64"
        ),
        _ => anyhow::bail!("unsupported managed executable target"),
    }
    Ok(())
}
#[cfg(not(unix))]
fn check_executable(_path: &Path, _bytes: &[u8], _target: &str) -> Result<()> {
    anyhow::bail!("unsupported managed executable platform")
}

/// Write a schema-2 app-owned lock for the single reviewed package.
pub fn write_lock(platform_root: &Path, source: &Path) -> Result<Value> {
    let bundle = installed(platform_root)?;
    let source = if source.is_absolute() {
        source.to_path_buf()
    } else {
        std::env::current_dir()?.join(source)
    };
    let app = safe_existing_directory(&source)?;
    let ui = app.join("ui");
    match fs::symlink_metadata(&ui) {
        Ok(meta) => ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "app ui path must be a real directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&ui)?,
        Err(error) => return Err(error.into()),
    }
    let lock_path = ui.join("ui.lock.json");
    let manifest: Value = serde_json::from_slice(&read_regular(
        &bundle.bundle_root.join("manifest.json"),
        MAX_MANIFEST,
    )?)?;
    let lock = lock_value(&manifest)?;
    let checked: crate::ui_lock::Lock = serde_json::from_value(lock.clone())?;
    crate::ui_lock::validate(&checked)?;
    let bytes = serde_json::to_vec_pretty(&lock)?;
    match fs::symlink_metadata(&lock_path) {
        Ok(meta) => {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "UI lock must be a regular file"
            );
            let existing = read_regular(&lock_path, 2_000_000)?;
            let existing: Value =
                serde_json::from_slice(&existing).context("parse existing UI lock")?;
            ensure!(
                existing == lock,
                "UI package pin differs; perform a deliberate reviewed upgrade before replacing it"
            );
            return Ok(lock);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut temp = tempfile::NamedTempFile::new_in(&ui)?;
    use std::io::Write;
    temp.write_all(&bytes)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(&lock_path)
        .context("UI lock was created concurrently or could not be published; retry to verify the existing pin")?;
    Ok(lock)
}

fn lock_value(manifest: &Value) -> Result<Value> {
    let catalog = catalog()?;
    let inputs = manifest["entries"]
        .as_array()
        .context("manifest entries missing")?
        .iter()
        .map(|entry| {
            let path = entry["path"]
                .as_str()
                .context("manifest input path missing")?;
            safe_relative(path)?;
            let bytes = entry["bytes"]
                .as_u64()
                .context("manifest input byte size missing")?;
            let digest = entry["digest"]
                .as_str()
                .context("manifest input digest missing")?;
            Ok(json!({"path":path,"bytes":bytes,"digest":digest}))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"schemaVersion":2,"provider":catalog["provider"],"package":{"name":catalog["name"],"version":catalog["version"],"digest":catalog["packageDigest"],"inputs":inputs}}),
    )
}

fn safe_existing_directory(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "app source must be an absolute path");
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "symlink/special app path ancestor forbidden"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    ensure_real_directory(path)?;
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_non_normal_package_paths() {
        for path in ["", "../escape", "a/../../b", "/absolute", "a\\b", "./dot"] {
            assert!(safe_relative(path).is_err(), "accepted {path:?}");
        }
    }

    proptest! {
        #[test]
        fn path_acceptance_never_admits_parent_or_absolute_components(parts in prop::collection::vec("[a-z]{1,12}", 1..8)) {
            let clean = parts.join("/");
            prop_assert!(safe_relative(&clean).is_ok());
            let parent = format!("../{clean}");
            let absolute = format!("/{clean}");
            prop_assert!(safe_relative(&parent).is_err());
            prop_assert!(safe_relative(&absolute).is_err());
        }
    }

    #[test]
    fn lock_inputs_preserve_reviewed_manifest_paths_sizes_and_digests() {
        let manifest = serde_json::json!({"entries":[{"path":"components/a/file.js","bytes":27,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]});
        let lock = lock_value(&manifest).unwrap();
        assert_eq!(lock["schemaVersion"], 2);
        assert_eq!(
            lock["package"]["digest"],
            "sha256:8f90ff7a2da0a1e476d57ae26c5a6dad9acf67bd86b7625e98c0a097c42e7325"
        );
        assert_eq!(lock["package"]["inputs"][0]["bytes"], 27);
        assert_eq!(
            lock["package"]["inputs"][0],
            serde_json::json!({"path":"components/a/file.js","bytes":27,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
        );
    }

    fn reviewed_fixture(root: &Path) -> (TargetPin, String) {
        let catalog = catalog().unwrap();
        let target = target_pin().unwrap().target;
        let bundle = root.join(format!("cli/build-dependencies/clanker-ui-{RELEASE}"));
        let package = bundle.join("package");
        fs::create_dir_all(package.join("files")).unwrap();
        fs::create_dir_all(bundle.join("bin")).unwrap();
        fs::create_dir_all(bundle.join("legal")).unwrap();

        let mut entries = Vec::new();
        for index in 0..455 {
            let path = format!("files/input-{index:03}.txt");
            fs::write(package.join(&path), b"x").unwrap();
            entries.push(json!({"path":path,"bytes":1,"digest":format!("sha256:{}",sha(b"x"))}));
        }
        let legal = [
            ("legal/LICENSE", b"license".as_slice()),
            ("legal/NOTICES.txt", b"notices".as_slice()),
        ];
        let legal_entries = legal
            .iter()
            .map(|(path, bytes)| {
                fs::write(bundle.join(path), bytes).unwrap();
                json!({"path":path,"bytes":bytes.len(),"digest":format!("sha256:{}",sha(bytes))})
            })
            .collect::<Vec<_>>();
        let mut executable = vec![0u8; 64];
        if target == "macos-aarch64" {
            executable[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        } else {
            executable[..4].copy_from_slice(b"\x7fELF");
            executable[18..20].copy_from_slice(&[0x3e, 0x00]);
        }
        fs::write(bundle.join("bin/clanker-ui"), &executable).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                bundle.join("bin/clanker-ui"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let executable_sha = sha(&executable);
        let mut chart_worker = vec![0u8; 64];
        if target == "macos-aarch64" {
            chart_worker[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        } else {
            chart_worker[..4].copy_from_slice(b"\x7fELF");
            chart_worker[18..20].copy_from_slice(&[0x3e, 0x00]);
        }
        fs::write(bundle.join("bin/clanker-chart-worker"), &chart_worker).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                bundle.join("bin/clanker-chart-worker"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let chart_worker_sha = sha(&chart_worker);
        let contracts =
            json!({"fixture_contract":{"input":{"string":"string"},"output":{"string":"string"}}});
        let contracts_sha = sha(&serde_json::to_vec(&contracts).unwrap());
        let manifest = json!({
            "schemaVersion":catalog["schemaVersion"],"target":target,"toolVersion":catalog["release"],
            "sourceRevision":catalog["sourceRevision"],"provider":catalog["provider"],
            "assemblyProtocol":catalog["assemblyProtocol"],"bindingAbi":catalog["bindingAbi"],
            "templateEngine":catalog["templateEngine"],
            "executable":{"path":"bin/clanker-ui","bytes":executable.len(),"digest":format!("sha256:{executable_sha}")},
            "presentationWorker":{"abi":catalog["presentationWorker"]["abi"],"executable":{"path":"bin/clanker-chart-worker","bytes":chart_worker.len(),"digest":format!("sha256:{chart_worker_sha}")},"contracts":contracts},
            "package":{"name":catalog["name"],"version":catalog["version"],"digest":catalog["packageDigest"]},
            "legal":legal_entries,"entries":entries
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(bundle.join("manifest.json"), &manifest_bytes).unwrap();
        let provider = json!({
            "schemaVersion":catalog["schemaVersion"],"provider":catalog["provider"],
            "assemblyProtocol":catalog["assemblyProtocol"],"bindingAbi":catalog["bindingAbi"],
            "targets":{target.clone():{"executable":"bin/clanker-ui","digest":format!("sha256:{executable_sha}")}}
        });
        let provider_bytes = serde_json::to_vec(&provider).unwrap();
        fs::write(bundle.join("provider-pin.json"), &provider_bytes).unwrap();
        let pin = TargetPin {
            target,
            archive: "fixture.tar.gz".into(),
            archive_sha256: String::new(),
            archive_bytes: 0,
            manifest_sha256: sha(&manifest_bytes),
            executable_sha256: executable_sha,
            executable_bytes: executable.len() as u64,
            chart_worker_sha256: chart_worker_sha,
            chart_worker_bytes: chart_worker.len() as u64,
            contracts_sha256: contracts_sha,
            provider_pin_sha256: sha(&provider_bytes),
        };
        (pin, format!("sha256:{}", sha(&manifest_bytes)))
    }

    #[test]
    fn installed_accepts_exact_offline_fixture_and_rejects_changed_or_missing_inputs() {
        let valid = tempfile::tempdir().unwrap();
        let (pin, manifest_digest) = reviewed_fixture(valid.path());
        let valid_root = valid.path().canonicalize().unwrap();
        let installed = installed_with_pin(&valid_root, pin.clone()).unwrap();
        assert_eq!(installed.identity()["manifestDigest"], manifest_digest);
        assert_eq!(
            installed.identity()["package"]["digest"],
            "sha256:8f90ff7a2da0a1e476d57ae26c5a6dad9acf67bd86b7625e98c0a097c42e7325"
        );

        let changed = tempfile::tempdir().unwrap();
        let (changed_pin, _) = reviewed_fixture(changed.path());
        let changed_root = changed.path().canonicalize().unwrap();
        fs::write(
            changed_root
                .join("cli/build-dependencies/clanker-ui-0.1.1/package/files/input-000.txt"),
            b"tampered",
        )
        .unwrap();
        assert!(installed_with_pin(&changed_root, changed_pin).is_err());

        let missing = tempfile::tempdir().unwrap();
        let (missing_pin, _) = reviewed_fixture(missing.path());
        let missing_root = missing.path().canonicalize().unwrap();
        fs::remove_file(
            missing_root
                .join("cli/build-dependencies/clanker-ui-0.1.1/package/files/input-000.txt"),
        )
        .unwrap();
        assert!(installed_with_pin(&missing_root, missing_pin).is_err());
    }

    #[test]
    fn installed_rejects_chart_worker_tampering_missing_files_and_unreviewed_contracts() {
        let tampered = tempfile::tempdir().unwrap();
        let (pin, _) = reviewed_fixture(tampered.path());
        let root = tampered.path().canonicalize().unwrap();
        let worker_path = root.join(format!(
            "cli/build-dependencies/clanker-ui-{RELEASE}/bin/clanker-chart-worker"
        ));
        fs::write(&worker_path, b"tampered").unwrap();
        assert!(installed_with_pin(&root, pin).is_err());

        let missing = tempfile::tempdir().unwrap();
        let (pin, _) = reviewed_fixture(missing.path());
        let root = missing.path().canonicalize().unwrap();
        let worker_path = root.join(format!(
            "cli/build-dependencies/clanker-ui-{RELEASE}/bin/clanker-chart-worker"
        ));
        fs::remove_file(worker_path).unwrap();
        assert!(installed_with_pin(&root, pin).is_err());

        #[cfg(unix)]
        {
            let mode = tempfile::tempdir().unwrap();
            let (pin, _) = reviewed_fixture(mode.path());
            let root = mode.path().canonicalize().unwrap();
            let worker_path = root.join(format!(
                "cli/build-dependencies/clanker-ui-{RELEASE}/bin/clanker-chart-worker"
            ));
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&worker_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(installed_with_pin(&root, pin).is_err());
        }

        let oversized = tempfile::tempdir().unwrap();
        let (mut pin, _) = reviewed_fixture(oversized.path());
        let root = oversized.path().canonicalize().unwrap();
        let manifest_path = root.join(format!(
            "cli/build-dependencies/clanker-ui-{RELEASE}/manifest.json"
        ));
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        pin.chart_worker_bytes = MAX_EXECUTABLE_BYTES - pin.executable_bytes + 1;
        manifest["presentationWorker"]["executable"]["bytes"] = json!(pin.chart_worker_bytes);
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(manifest_path, &bytes).unwrap();
        pin.manifest_sha256 = sha(&bytes);
        let error = installed_with_pin(&root, pin).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("executable closure exceeds byte budget")
        );

        for field in ["abi", "contracts"] {
            let changed = tempfile::tempdir().unwrap();
            let (mut pin, _) = reviewed_fixture(changed.path());
            let root = changed.path().canonicalize().unwrap();
            let manifest_path = root.join(format!(
                "cli/build-dependencies/clanker-ui-{RELEASE}/manifest.json"
            ));
            let mut manifest: Value =
                serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
            if field == "abi" {
                manifest["presentationWorker"]["abi"] = json!(2);
            } else {
                manifest["presentationWorker"]["contracts"]["fixture_contract"]["input"] =
                    json!("changed");
            }
            let bytes = serde_json::to_vec(&manifest).unwrap();
            fs::write(manifest_path, &bytes).unwrap();
            pin.manifest_sha256 = sha(&bytes);
            assert!(
                installed_with_pin(&root, pin).is_err(),
                "accepted changed {field}"
            );
        }
    }

    #[test]
    fn installed_rejects_missing_and_wrong_target_without_network() {
        let temp = tempfile::tempdir().unwrap();
        assert!(installed(temp.path()).is_err());
        assert!(verify_staged(temp.path(), "unsupported-target").is_err());
        assert!(
            target_pin().unwrap().target == "macos-aarch64"
                || target_pin().unwrap().target == "linux-x86_64"
        );
    }
}
