//! Private compiler outputs for Linux image qualification. The producer builds
//! these once; the actual consumer runs them without Rust or Bazel installed.
//! This bundle is never part of the published application SDK or a test receipt.
#[cfg(target_os = "linux")]
use super::install_linux_test_programs;
use super::{suite_targets, verification_source_identity};
use anyhow::{Context, Result, ensure};
use day2::digest;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

const DIRECTORY: &str = crate::bazel::TESTS;
const MANIFEST: &str = "linux-qualification.json";
pub(super) const SUITES: &[&str] = &[
    "linux-delegation",
    "linux-sandbox",
    "linux-worker",
    "linux-http",
    "linux-backup",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct File {
    path: PathBuf,
    digest: String,
    bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    format: u32,
    sources: String,
    workflow: String,
    toolchain: String,
    target: String,
    outputs: BTreeMap<String, File>,
}

fn targets(root: &Path) -> Result<BTreeMap<String, crate::bazel::Target>> {
    let mut targets = BTreeMap::new();
    for suite in SUITES {
        for target in suite_targets(root, suite)?.1 {
            targets.insert(target.label.clone(), target);
        }
    }
    Ok(targets)
}

fn output(target: &crate::bazel::Target) -> PathBuf {
    if target.test {
        crate::bazel::test_output(target)
    } else {
        Path::new(crate::bazel::PROGRAMS).join(&target.target)
    }
}

fn identity(root: &Path, outputs: BTreeMap<String, File>) -> Result<Prepared> {
    Ok(Prepared {
        format: 1,
        sources: verification_source_identity(root, "qualify-linux")?,
        workflow: day2::automation::source_digest(),
        toolchain: day2::automation::toolchain_digest(),
        target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        outputs,
    })
}

/// Admit the materialized SDK closure before spending time building images.
pub(crate) fn admit_capture(root: &Path) -> Result<()> {
    targets(root).context("captured native Rust test inventory")?;
    identity(root, BTreeMap::new()).context("captured native verification source inventory")?;
    Ok(())
}

pub(crate) fn prepare(root: &Path) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "native Linux test producer required"
    );
    let selected = targets(root)?;
    let expected = identity(root, BTreeMap::new())?;
    let built = crate::bazel::build(
        root,
        &selected.values().cloned().collect::<Vec<_>>(),
        Duration::from_secs(3600),
    )?;
    let mut outputs = BTreeMap::new();
    for (label, target) in selected {
        let source = built
            .get(&label)
            .context("built Linux test output required")?;
        let path = output(&target);
        ensure!(source == &path, "declared Linux test output path required");
        let bytes = day2_assets::read_regular(&root.join(&path), 256 << 20)?;
        outputs.insert(
            label,
            File {
                path,
                digest: digest(&bytes),
                bytes: bytes.len() as u64,
            },
        );
    }
    // Native supervisors discover only their trusted fixed-sibling launchers.
    // The SDK programs themselves remain the ordinary producer outputs.
    #[cfg(target_os = "linux")]
    install_linux_test_programs(root, &built)?;
    ensure!(
        identity(root, BTreeMap::new())?.sources == expected.sources,
        "Linux test sources changed during compilation"
    );
    let prepared = Prepared {
        outputs,
        ..expected
    };
    fs::write(
        root.join(DIRECTORY).join(MANIFEST),
        serde_json::to_vec_pretty(&prepared)?,
    )?;
    load(root)?;
    Ok(())
}

fn admit_file(root: &Path, file: &File, target: crate::native_toolchain::Target) -> Result<()> {
    let path = root.join(&file.path);
    ensure!(
        path.canonicalize()? == path && file.bytes > 0 && file.bytes <= 256 << 20,
        "bounded regular Linux test output required"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::symlink_metadata(&path)?.permissions().mode() & 0o7777;
    ensure!(
        mode & 0o111 != 0 && mode & !0o777 == 0,
        "Linux test output permission changed"
    );
    let bytes = day2_assets::read_regular(&path, 256 << 20)?;
    ensure!(
        bytes.len() as u64 == file.bytes && digest(&bytes) == file.digest,
        "Linux test output bytes changed"
    );
    crate::native_toolchain::verify_executable_target(target, &path)
}

fn admit(
    root: &Path,
    prepared: &Prepared,
    expected: &Prepared,
    targets: &BTreeMap<String, crate::bazel::Target>,
    native: crate::native_toolchain::Target,
) -> Result<BTreeMap<String, PathBuf>> {
    ensure!(
        prepared.format == 1
            && prepared.sources == expected.sources
            && prepared.workflow == expected.workflow
            && prepared.toolchain == expected.toolchain
            && prepared.target == expected.target
            && prepared.target.starts_with("linux-"),
        "Linux test bundle belongs to another source, workflow, toolchain or target"
    );
    ensure!(
        prepared.outputs.keys().eq(targets.keys()),
        "complete declared Linux test output inventory required"
    );
    let mut outputs = BTreeMap::new();
    for (label, target) in targets {
        let file = &prepared.outputs[label];
        ensure!(
            file.path == output(target),
            "Linux test output path changed"
        );
        admit_file(root, file, native)?;
        if target.package == "day2-sandbox" && !target.test {
            admit_file(
                root,
                &File {
                    path: Path::new(DIRECTORY).join(&target.target),
                    ..file.clone()
                },
                native,
            )?;
        }
        outputs.insert(label.clone(), file.path.clone());
    }
    Ok(outputs)
}

pub(super) fn load(root: &Path) -> Result<BTreeMap<String, PathBuf>> {
    ensure!(
        cfg!(target_os = "linux"),
        "native Linux test consumer required"
    );
    let prepared: Prepared = day2::json::decode(&day2_assets::read_regular(
        &root.join(DIRECTORY).join(MANIFEST),
        65_536,
    )?)?;
    admit(
        root,
        &prepared,
        &identity(root, BTreeMap::new())?,
        &targets(root)?,
        crate::native_toolchain::load(root)?.target,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn native_capture_preserves_complete_linux_test_source_identity() -> Result<()> {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()?;
        let temp = tempfile::tempdir()?;
        let toolchains = temp.path().join("toolchains");
        fs::create_dir(&toolchains)?;
        // Capture transport needs file identities, not an executed compiler.
        fs::write(toolchains.join("roc"), b"unexecuted capture fixture")?;
        if cfg!(target_os = "macos") {
            fs::create_dir_all(toolchains.join("darwin/usr/lib"))?;
            fs::write(
                toolchains.join("darwin/usr/lib/libSystem.tbd"),
                b"capture fixture",
            )?;
        }
        let inputs = day2_control::build::PlatformInputs::capture(&source, &toolchains)?;
        let workspace = temp.path().join("workspace");
        inputs.materialize(&workspace)?;
        let captured = workspace.join("platform").canonicalize()?;
        admit_capture(&captured)?;
        let expected = identity(&source, BTreeMap::new())?.sources;
        assert_eq!(identity(&captured, BTreeMap::new())?.sources, expected);
        let pin = captured.join(".github/temporal-linux.sha256");
        let original = fs::read(&pin)?;
        fs::set_permissions(&pin, fs::Permissions::from_mode(0o644))?;
        fs::write(&pin, b"changed checksum metadata")?;
        assert_ne!(identity(&captured, BTreeMap::new())?.sources, expected);
        fs::remove_file(&pin)?;
        let error = admit_capture(&captured)
            .expect_err("missing checksum pin must fail before image builds");
        assert!(format!("{error:#}").contains(".github/temporal-linux.sha256"));
        fs::write(&pin, original)?;
        let rust_test = captured.join("crates/day2/tests/linux_worker.rs");
        fs::set_permissions(&rust_test, fs::Permissions::from_mode(0o644))?;
        fs::write(rust_test, b"changed Rust harness source")?;
        assert_ne!(identity(&captured, BTreeMap::new())?.sources, expected);
        Ok(())
    }

    #[test]
    fn linux_test_bundle_rejects_foreign_identity_inventory_paths_and_bytes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        fs::create_dir_all(root.join(DIRECTORY))?;
        let target = crate::bazel::Target {
            package: "day2".into(),
            directory: "crates/day2".into(),
            target: "day2_integration".into(),
            kind: vec!["test".into()],
            label: "//crates/day2:integration".into(),
            test: true,
            source: "crates/day2/tests/integration.rs".into(),
        };
        let mut bytes = vec![0; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18] = 62;
        let path = output(&target);
        fs::write(root.join(&path), &bytes)?;
        fs::set_permissions(root.join(&path), fs::Permissions::from_mode(0o555))?;
        let file = File {
            path: path.clone(),
            digest: digest(&bytes),
            bytes: bytes.len() as u64,
        };
        let mut prepared = Prepared {
            format: 1,
            sources: digest(b"source"),
            workflow: digest(b"workflow"),
            toolchain: digest(b"toolchain"),
            target: "linux-x86_64".into(),
            outputs: BTreeMap::from([(target.label.clone(), file.clone())]),
        };
        let mut targets = BTreeMap::from([(target.label.clone(), target)]);
        let launcher = crate::bazel::Target {
            package: "day2-sandbox".into(),
            directory: "crates/day2-sandbox".into(),
            target: "day2-sandbox".into(),
            kind: vec!["bin".into()],
            label: "//crates/day2-sandbox:day2-sandbox".into(),
            test: false,
            source: "crates/day2-sandbox/src/main.rs".into(),
        };
        let program = output(&launcher);
        let sibling = root.join(DIRECTORY).join(&launcher.target);
        fs::create_dir_all(root.join(crate::bazel::PROGRAMS))?;
        for path in [root.join(&program), sibling.clone()] {
            fs::write(&path, &bytes)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
        }
        prepared.outputs.insert(
            launcher.label.clone(),
            File {
                path: program.clone(),
                ..file.clone()
            },
        );
        targets.insert(launcher.label.clone(), launcher);
        let native = crate::native_toolchain::Target::LinuxX64;
        let check = |value: &Prepared| admit(&root, value, &prepared, &targets, native);
        assert_eq!(
            check(&prepared)?.get("//crates/day2:integration"),
            Some(&path)
        );
        let original = serde_json::to_value(&prepared)?;
        for field in ["format", "sources", "workflow", "toolchain", "target"] {
            let mut altered = original.clone();
            altered[field] = if field == "format" {
                json!(2)
            } else {
                json!("another release")
            };
            assert!(check(&serde_json::from_value(altered)?).is_err(), "{field}");
        }
        for change in ["missing", "extra", "path", "digest", "bytes"] {
            let mut altered: Prepared = serde_json::from_value(original.clone())?;
            let label = targets.keys().next().unwrap();
            match change {
                "missing" => {
                    altered.outputs.clear();
                }
                "extra" => {
                    altered
                        .outputs
                        .insert("//foreign:test".into(), file.clone());
                }
                "path" => altered.outputs.get_mut(label).unwrap().path = "../../foreign".into(),
                "digest" => altered.outputs.get_mut(label).unwrap().digest = digest(b"other"),
                "bytes" => altered.outputs.get_mut(label).unwrap().bytes += 1,
                _ => unreachable!(),
            }
            assert!(check(&altered).is_err(), "{change}");
        }
        fs::set_permissions(root.join(&path), fs::Permissions::from_mode(0o644))?;
        assert!(check(&prepared).is_err());
        fs::set_permissions(root.join(&path), fs::Permissions::from_mode(0o755))?;
        fs::write(root.join(&path), b"changed binary")?;
        assert!(check(&prepared).is_err());
        fs::remove_file(root.join(&path))?;
        assert!(check(&prepared).is_err());
        let other = root.join("foreign");
        fs::write(&other, &bytes)?;
        symlink(&other, root.join(&path))?;
        assert!(check(&prepared).is_err());
        fs::remove_file(root.join(&path))?;
        fs::write(root.join(&path), &bytes)?;
        fs::set_permissions(root.join(&path), fs::Permissions::from_mode(0o555))?;
        assert!(
            admit(
                &root,
                &prepared,
                &prepared,
                &targets,
                crate::native_toolchain::Target::LinuxArm64
            )
            .is_err()
        );
        fs::set_permissions(&sibling, fs::Permissions::from_mode(0o755))?;
        fs::write(&sibling, b"substituted launcher")?;
        assert!(check(&prepared).is_err());
        fs::write(&sibling, &bytes)?;
        check(&prepared)?;
        fs::remove_file(root.join(&program))?;
        assert!(check(&prepared).is_err());
        Ok(())
    }
}
