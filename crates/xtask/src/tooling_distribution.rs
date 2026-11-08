//! Immutable native build inputs and the operator-only CLI distribution.
//! ops/Tooling.roc orders production. A tooling image opts into consumption
//! explicitly: missing or altered outputs never trigger a compiler fallback.
use super::*;
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const DIRECTORY: &str = "build-out/tooling";
const MANIFEST: &str = "distribution.json";
const ARCHIVE: &str = "libhost.a";
const OPERATOR: &str = "operator.tar.gz";
const MODE: &str = "DAY2_PRECOMPILED_TOOLING";
const OPERATOR_FILES: &[&str] = &[
    "cli/day2",
    "cli/day2-host",
    "cli/day2-workflows",
    "cli/day2-workflows.json",
    "licenses/LICENSE",
    "licenses/THIRD-PARTY-NOTICES.txt",
    "licenses/dependency-inventory.json",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    digest: String,
    bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Distribution {
    format: u32,
    target: String,
    inputs: String,
    workflow_sources: String,
    toolchain: String,
    worker: File,
    operator: File,
    operator_files: BTreeMap<String, File>,
}

fn target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn identity(bytes: &[u8]) -> File {
    File {
        digest: digest(bytes),
        bytes: bytes.len() as u64,
    }
}

fn inputs(root: &Path) -> Result<String> {
    Ok(digest(&serde_json::to_vec(
        &build_native::platform_sources(root)?,
    )?))
}

fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    day2_assets::read_regular(path, limit)
}

fn verify(path: &Path, expected: &File, limit: u64) -> Result<Vec<u8>> {
    day2_assets::hash_part(&expected.digest)?;
    ensure!(
        expected.bytes > 0 && expected.bytes <= limit,
        "tooling output byte budget"
    );
    let bytes = bounded(path, limit)?;
    ensure!(
        bytes.len() as u64 == expected.bytes && digest(&bytes) == expected.digest,
        "precompiled tooling output changed: {}",
        path.display()
    );
    Ok(bytes)
}

/// The image's explicit mode prevents a missing cache from compiling platform
/// code in an application job. Developer source builds retain their build path.
pub(crate) fn precompiled_worker(root: &Path) -> Result<Option<PathBuf>> {
    match std::env::var(MODE) {
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Ok(value) if value == "1" => {}
        _ => bail!("{MODE} must be 1 or unset"),
    }
    Ok(Some(admit_worker(root, &inputs(root)?, &target())?))
}

fn admit_worker(root: &Path, expected_inputs: &str, expected_target: &str) -> Result<PathBuf> {
    let directory = root.join(DIRECTORY);
    let manifest: Distribution = day2::json::decode(&bounded(&directory.join(MANIFEST), 65_536)?)?;
    ensure!(
        manifest.format == 1 && manifest.target == expected_target,
        "precompiled tooling target mismatch"
    );
    ensure!(
        manifest.inputs == expected_inputs
            && manifest.workflow_sources == day2::automation::source_digest()
            && manifest.toolchain == day2::automation::toolchain_digest(),
        "precompiled tooling inputs changed; publish a new platform tooling image"
    );
    let path = directory.join(ARCHIVE);
    let bytes = verify(&path, &manifest.worker, 256 << 20)?;
    ensure!(
        bytes.starts_with(b"!<arch>\n"),
        "precompiled worker is not a static archive"
    );
    Ok(path)
}

fn package(root: &Path, worker: &Path, expected_inputs: &str) -> Result<serde_json::Value> {
    ensure!(
        inputs(root)? == expected_inputs,
        "tooling inputs changed during compilation"
    );
    let pin = native_toolchain::load(root)?;
    let runner = day2::automation::checked_runner(&root.join("cli/day2-workflows"))?;
    native_toolchain::verify_executable_target(pin.target, &runner)?;
    let directory = root.join(DIRECTORY);
    fs::create_dir(&directory).context("fresh tooling distribution required")?;
    let worker_bytes = bounded(worker, 256 << 20)?;
    ensure!(
        worker_bytes.starts_with(b"!<arch>\n"),
        "worker must be a static archive"
    );
    fs::write(directory.join(ARCHIVE), &worker_bytes)?;
    let mut operator_files = BTreeMap::new();
    let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for name in OPERATOR_FILES {
        let source = name.strip_prefix("licenses/").unwrap_or(name);
        let executable = name.starts_with("cli/") && !name.ends_with(".json");
        let bytes = bounded(
            &root.join(source),
            if executable { 256 << 20 } else { 16 << 20 },
        )?;
        if executable {
            native_toolchain::verify_executable_target(pin.target, &root.join(source))?;
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(if executable { 0o555 } else { 0o444 });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append_data(&mut header, name, bytes.as_slice())?;
        operator_files.insert((*name).to_owned(), identity(&bytes));
    }
    let operator = archive.into_inner()?.finish()?;
    ensure!(operator.len() <= 256 << 20, "operator package byte budget");
    fs::write(directory.join(OPERATOR), &operator)?;
    let distribution = Distribution {
        format: 1,
        target: target(),
        inputs: expected_inputs.to_owned(),
        workflow_sources: day2::automation::source_digest(),
        toolchain: day2::automation::toolchain_digest(),
        worker: identity(&worker_bytes),
        operator: identity(&operator),
        operator_files,
    };
    let bytes = serde_json::to_vec_pretty(&distribution)?;
    fs::write(directory.join(MANIFEST), &bytes)?;
    Ok(
        serde_json::json!({"distribution":digest(&bytes),"operator":distribution.operator,
        "worker":distribution.worker,"target":distribution.target}),
    )
}

pub(crate) fn execute(root: &Path) -> Result<()> {
    ensure!(
        std::env::var_os(MODE).is_none(),
        "cannot produce tooling from a consumption-only image"
    );
    let runner = workflows::build(root)?;
    let mut worker = None;
    let captured_inputs = inputs(root)?;
    let mut done = BTreeSet::new();
    day2::automation::run(&runner, &["export-tooling"], |request| {
        let parameters: BTreeMap<String, serde_json::Value> = request.decode()?;
        ensure!(
            parameters.is_empty() && done.insert(request.action.clone()),
            "closed tooling recipe required"
        );
        match request.action.as_str() {
            "tooling-cli" => {
                build_cli(root)?;
                Ok(serde_json::json!({}))
            }
            "tooling-worker" => {
                ensure!(
                    done.contains("tooling-cli"),
                    "current operator CLI required"
                );
                worker = Some(bazel::worker_archive(
                    root,
                    None,
                    std::time::Duration::from_secs(1800),
                )?);
                Ok(serde_json::json!({}))
            }
            "tooling-package" => package(
                root,
                worker.as_deref().context("compiled worker required")?,
                &captured_inputs,
            ),
            _ => bail!("unknown tooling capability"),
        }
    })?;
    ensure!(
        done == BTreeSet::from([
            "tooling-cli".into(),
            "tooling-worker".into(),
            "tooling-package".into()
        ]),
        "incomplete tooling recipe"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precompiled_worker_requires_exact_sources_target_workflow_and_bytes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join(DIRECTORY);
        fs::create_dir_all(&directory)?;
        let worker = b"!<arch>\ncompiled native worker";
        fs::write(directory.join(ARCHIVE), worker)?;
        let manifest = Distribution {
            format: 1,
            target: target(),
            inputs: digest(b"platform inputs"),
            workflow_sources: day2::automation::source_digest(),
            toolchain: day2::automation::toolchain_digest(),
            worker: identity(worker),
            operator: identity(b"operator"),
            operator_files: BTreeMap::new(),
        };
        let original = serde_json::to_value(&manifest)?;
        fs::write(directory.join(MANIFEST), serde_json::to_vec(&manifest)?)?;
        assert_eq!(
            admit_worker(root.path(), &manifest.inputs, &target())?,
            directory.join(ARCHIVE)
        );
        assert!(admit_worker(root.path(), &digest(b"changed sources"), &target()).is_err());
        assert!(admit_worker(root.path(), &manifest.inputs, "another-target").is_err());
        for field in ["workflow_sources", "toolchain", "inputs"] {
            let mut changed = original.clone();
            changed[field] = serde_json::json!(digest(b"another release"));
            fs::write(directory.join(MANIFEST), serde_json::to_vec(&changed)?)?;
            assert!(
                admit_worker(root.path(), &manifest.inputs, &target()).is_err(),
                "{field}"
            );
        }
        fs::write(directory.join(MANIFEST), serde_json::to_vec(&manifest)?)?;
        fs::write(directory.join(ARCHIVE), b"!<arch>\nwrong worker")?;
        assert!(admit_worker(root.path(), &manifest.inputs, &target()).is_err());
        fs::remove_file(directory.join(ARCHIVE))?;
        assert!(admit_worker(root.path(), &manifest.inputs, &target()).is_err());
        Ok(())
    }

    #[test]
    fn distribution_output_rejects_missing_altered_and_symlinked_bytes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("file");
        fs::write(&path, b"compiled bytes")?;
        let expected = identity(b"compiled bytes");
        assert_eq!(verify(&path, &expected, 64)?, b"compiled bytes");
        fs::write(&path, b"altered bytes!")?;
        assert!(verify(&path, &expected, 64).is_err());
        fs::remove_file(&path)?;
        assert!(verify(&path, &expected, 64).is_err());
        #[cfg(unix)]
        {
            let other = root.path().join("other");
            fs::write(&other, b"compiled bytes")?;
            std::os::unix::fs::symlink(&other, &path)?;
            assert!(verify(&path, &expected, 64).is_err());
        }
        Ok(())
    }
}
