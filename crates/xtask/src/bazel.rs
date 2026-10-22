//! The sole platform Rust build backend. The checked target catalog describes
//! outputs; Bazel supplies the actual configured graph and compiler artifacts.
use crate::{install_cli_file, run_with_budget};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

const CATALOG: &str = "build/bazel/targets.json";
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
pub(crate) const PROGRAMS: &str = "build-out/bin";
pub(crate) const TESTS: &str = "build-out/tests";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub package: String,
    pub directory: PathBuf,
    pub target: String,
    pub kind: Vec<String>,
    pub label: String,
    pub test: bool,
    pub source: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    format: u32,
    targets: Vec<Target>,
}

fn relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

pub(crate) fn targets(root: &Path) -> Result<Vec<Target>> {
    let path = root.join(CATALOG);
    let metadata = fs::symlink_metadata(&path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= MAX_CATALOG_BYTES as u64,
        "Bazel target catalog type/size"
    );
    let catalog: Catalog = day2::json::decode(&fs::read(path)?)?;
    ensure!(
        catalog.format == 1 && !catalog.targets.is_empty(),
        "Bazel target catalog format"
    );
    let mut labels = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for target in &catalog.targets {
        ensure!(
            relative(&target.directory)
                && relative(&target.source)
                && target.source.starts_with(&target.directory),
            "Bazel source leaves package"
        );
        ensure!(
            target
                .label
                .starts_with(&format!("//{}:", target.directory.display()))
                && !target.label.contains(['\n', '\r', ' '])
                && labels.insert(&target.label),
            "Bazel target label identity"
        );
        ensure!(
            keys.insert((&target.package, &target.target, &target.kind, target.test)),
            "duplicate Bazel target kind"
        );
        ensure!(
            [
                vec!["lib".to_owned()],
                vec!["staticlib".to_owned()],
                vec!["bin".to_owned()],
                vec!["test".to_owned()]
            ]
            .contains(&target.kind),
            "unsupported Bazel target kind"
        );
        ensure!(
            fs::symlink_metadata(root.join(&target.source))?
                .file_type()
                .is_file(),
            "Bazel target source required"
        );
    }
    Ok(catalog.targets)
}

pub(crate) fn command() -> Command {
    {
        let mut command =
            Command::new(std::env::var_os("DAY2_BAZEL_BINARY").unwrap_or_else(|| "bazel".into()));
        command.args(["--batch", "--nosystem_rc", "--nohome_rc"]);
        command
    }
}

pub(crate) fn program(root: &Path, name: &str) -> PathBuf {
    root.join(PROGRAMS)
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

pub(crate) fn test_output(target: &Target) -> PathBuf {
    Path::new(TESTS).join(format!(
        "{}--{}",
        target.package,
        target.label.rsplit(':').next().unwrap_or("")
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    label: String,
    files: Vec<PathBuf>,
}

/// Resolve only successfully built targets. Missing, duplicate or foreign
/// configured labels never become an admitted output inventory.
pub(crate) fn build(
    root: &Path,
    selected: &[Target],
    budget: Duration,
) -> Result<BTreeMap<String, PathBuf>> {
    build_profile(root, selected, budget, false, None)
}

fn build_profile(
    root: &Path,
    selected: &[Target],
    budget: Duration,
    release: bool,
    isolated_job: Option<&Path>,
) -> Result<BTreeMap<String, PathBuf>> {
    let started = std::time::Instant::now();
    ensure!(!selected.is_empty(), "nonempty Bazel build required");
    let expected: BTreeSet<_> = selected.iter().map(|target| target.label.clone()).collect();
    ensure!(
        expected.len() == selected.len(),
        "duplicate requested Bazel target"
    );
    let mut build = build_command("build", isolated_job)?;
    if release {
        build.arg("--compilation_mode=opt");
    }
    build.args(&expected);
    // Test results are never reusable; only compilation actions use the cache.
    crate::build_capture::run(root, &mut build, budget)?;
    let expression = format!(
        "set({})",
        expected.iter().cloned().collect::<Vec<_>>().join(" ")
    );
    let mut query = build_command("cquery", isolated_job)?;
    query.args(["--output=starlark", "--starlark:expr=json.encode({\"label\":str(target.label),\"files\":[f.path for f in target.files.to_list()]})"]);
    if release {
        query.arg("--compilation_mode=opt");
    }
    query.arg(expression);
    let remaining = budget
        .checked_sub(started.elapsed())
        .context("Bazel build budget exhausted")?;
    let output = capture_query(root, &mut query, remaining, MAX_CATALOG_BYTES)?;
    let mut result = BTreeMap::new();
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let files: Files = day2::json::decode(line)?;
        let label = files
            .label
            .strip_prefix("@@")
            .map(|value| value.to_owned())
            .unwrap_or(files.label);
        ensure!(
            expected.contains(&label) && !result.contains_key(&label),
            "foreign or duplicate Bazel output label"
        );
        let target = selected
            .iter()
            .find(|target| target.label == label)
            .context("Bazel target selection")?;
        let mut files = files.files.into_iter().filter(|path| {
            !path
                .extension()
                .is_some_and(|extension| extension == "rmeta")
        });
        let path = files.next().context("Bazel output missing")?;
        ensure!(
            files.next().is_none() && relative(&path) && path.starts_with("bazel-out"),
            "exactly one declared Bazel output required"
        );
        let actual = root.join(&path).canonicalize()?;
        ensure!(
            fs::symlink_metadata(&actual)?.file_type().is_file(),
            "Bazel output must be regular"
        );
        let destination = if target.test {
            root.join(test_output(target))
        } else if target.kind == ["bin"] {
            program(root, &target.target)
        } else {
            root.join("build-out/lib")
                .join(path.file_name().context("Bazel output name")?)
        };
        fs::create_dir_all(destination.parent().context("Bazel output directory")?)?;
        install_cli_file(&actual, &destination)?;
        result.insert(label, destination.strip_prefix(root)?.to_owned());
    }
    ensure!(
        result.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "complete Bazel output inventory required"
    );
    Ok(result)
}

pub(crate) fn programs(root: &Path, packages: &[&str]) -> Result<()> {
    let selected = targets(root)?
        .into_iter()
        .filter(|target| {
            !target.test && target.kind == ["bin"] && packages.contains(&target.package.as_str())
        })
        .collect::<Vec<_>>();
    build(root, &selected, Duration::from_secs(12_600))?;
    Ok(())
}

pub(crate) fn lint(root: &Path) -> Result<()> {
    let mut command = command();
    command.arg("build");
    configuration_arguments(&mut command);
    command.args([
        "--aspects=@rules_rust//rust:defs.bzl%rust_clippy_aspect",
        "--output_groups=clippy_checks",
        "--@rules_rust//rust/settings:clippy_flag=-Dwarnings",
        "--@rules_rust//rust/settings:clippy.toml=//:architecture/clippy.toml",
        "//:all_programs",
        "//:test_binaries",
        "//crates/worker:lib",
    ]);
    run_with_budget(root, &mut command, Duration::from_secs(12_600))
}

pub(crate) fn docs(root: &Path) -> Result<()> {
    let mut command = command();
    command.arg("test");
    configuration_arguments(&mut command);
    command.args([
        "--cache_test_results=no",
        "--test_arg=--test-threads=1",
        "//:doc_tests",
    ]);
    run_with_budget(root, &mut command, Duration::from_secs(12_600))
}

pub(crate) fn format(root: &Path, check: bool) -> Result<()> {
    let mut command = command();
    command.args(["run", "@rules_rust//:rustfmt", "--"]);
    if check {
        command.args(["--", "--check"]);
    }
    run_with_budget(root, &mut command, Duration::from_secs(600))
}

fn capture_query(
    root: &Path,
    command: &mut Command,
    budget: Duration,
    maximum: usize,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let temporary = tempfile::NamedTempFile::new()?;
    command.stdout(temporary.as_file().try_clone()?);
    run_with_budget(root, command, budget)?;
    let mut output = Vec::new();
    std::fs::File::open(temporary.path())?
        .take(maximum as u64 + 1)
        .read_to_end(&mut output)?;
    ensure!(output.len() <= maximum, "Bazel query byte budget");
    Ok(output)
}

pub(crate) fn worker_archive(root: &Path, isolated_job: Option<&Path>) -> Result<PathBuf> {
    let selected = targets(root)?
        .into_iter()
        .filter(|target| {
            target.package == "day2-roc-worker" && !target.test && target.kind == ["staticlib"]
        })
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "one current native worker archive target required"
    );
    let outputs = build_profile(
        root,
        &selected,
        Duration::from_secs(600),
        true,
        isolated_job,
    )?;
    Ok(root.join(
        outputs
            .get(&selected[0].label)
            .context("built worker archive required")?,
    ))
}

/// CI resource selection is closed and host-specific. It is applied to every
/// subprocess, including cquery and worker archive builds, not just the caller.
pub(crate) fn configuration_arguments(command: &mut Command) {
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        command.arg(if cfg!(target_os = "macos") {
            "--config=ci-mac"
        } else {
            "--config=ci-linux"
        });
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            command
                .arg(format!(
                    "--disk_cache={}",
                    home.join(".cache/bazel-disk").display()
                ))
                .arg(format!(
                    "--repository_cache={}",
                    home.join(".cache/bazel-repo").display()
                ));
        }
    }
}

pub(crate) fn tool(root: &Path, name: &str) -> Result<PathBuf> {
    ensure!(
        ["rustc", "rustdoc"].contains(&name),
        "closed compiler tool selection"
    );
    let label = format!("@rules_rust//rust/toolchain:current_{name}_files");
    let mut build = command();
    build.arg("build");
    configuration_arguments(&mut build);
    build.arg(&label);
    run_with_budget(root, &mut build, Duration::from_secs(600))?;
    let mut query = command();
    query.args(["cquery", "--output=files"]);
    configuration_arguments(&mut query);
    query.arg(label);
    let output = capture_query(root, &mut query, Duration::from_secs(120), 16 * 1024)?;
    let paths = std::str::from_utf8(&output)?
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        paths.len() == 1 && relative(Path::new(paths[0])),
        "one actual configured compiler tool required"
    );
    let mut info = command();
    info.args(["info", "execution_root"]);
    configuration_arguments(&mut info);
    let execution_root = capture_query(root, &mut info, Duration::from_secs(120), 16 * 1024)?;
    let execution_root = PathBuf::from(std::str::from_utf8(&execution_root)?.trim());
    ensure!(
        execution_root.is_absolute(),
        "absolute Bazel execution root required"
    );
    let tool = execution_root.join(paths[0]).canonicalize()?;
    ensure!(
        fs::symlink_metadata(&tool)?.file_type().is_file(),
        "actual regular Bazel compiler required"
    );
    Ok(tool)
}

pub(crate) fn configured_output(root: &Path, label: &str) -> Result<PathBuf> {
    let mut query = command();
    query.args(["cquery", "--output=files"]);
    configuration_arguments(&mut query);
    query.arg(label);
    let output = capture_query(root, &mut query, Duration::from_secs(120), 16 * 1024)?;
    let files = std::str::from_utf8(&output)?
        .lines()
        .filter(|line| !line.is_empty() && !line.ends_with(".rmeta"))
        .collect::<Vec<_>>();
    ensure!(
        files.len() == 1
            && relative(Path::new(files[0]))
            && Path::new(files[0]).starts_with("bazel-out"),
        "one configured workspace output required"
    );
    Ok(root.join(files[0]).canonicalize()?)
}

pub(crate) fn configuration(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut files = BTreeMap::new();
    for name in [
        ".bazelrc",
        ".bazelversion",
        "BUILD.bazel",
        "MODULE.bazel",
        "MODULE.bazel.lock",
        "Cargo.toml",
        "Cargo.lock",
    ] {
        files.insert(name.to_owned(), day2::digest(&fs::read(root.join(name))?));
    }
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeMap<String, String>,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth < 32, "Bazel configuration depth budget");
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(!kind.is_symlink(), "Bazel configuration aliases forbidden");
            if kind.is_dir() {
                visit(root, &entry.path(), files, depth + 1)?;
            } else if entry.file_name() == "BUILD.bazel"
                || entry.file_name() == "Cargo.toml"
                || directory.starts_with(root.join("build/bazel"))
            {
                let path = entry.path();
                files.insert(
                    path.strip_prefix(root)?.to_string_lossy().into_owned(),
                    day2::digest(&fs::read(path)?),
                );
            }
        }
        Ok(())
    }
    for directory in ["build/bazel", "crates", "cli/checks"] {
        visit(root, &root.join(directory), &mut files, 0)?;
    }
    Ok(files)
}

/// Stage the standalone, checksum-pinned launcher for private offline builds.
/// Bazelisk and the operator's download cache never enter an isolated job.
pub(crate) fn standalone(root: &Path) -> Result<PathBuf> {
    use std::io::Write;
    let pins: serde_json::Value =
        day2::json::decode(&fs::read(root.join("build/bazel/toolchain.json"))?)?;
    ensure!(
        pins["version"] == "9.3.0"
            && fs::read_to_string(root.join(".bazelversion"))?.trim() == "9.3.0",
        "standalone Bazel pin changed"
    );
    let host = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let pin = &pins["hosts"][&host];
    let asset = pin["asset"]
        .as_str()
        .context("supported Bazel host required")?;
    let expected = pin["sha256"].as_str().context("Bazel checksum required")?;
    let bytes = pin["bytes"].as_u64().context("Bazel size required")?;
    ensure!(
        asset.starts_with("bazel-9.3.0-") && !asset.contains('/') && bytes <= 100 * 1024 * 1024,
        "bounded fixed Bazel asset required"
    );
    let directory = root.join(".cache/bazel-toolchain");
    fs::create_dir_all(&directory)?;
    let destination = directory.join(asset);
    let valid = || -> Result<bool> {
        let metadata = fs::symlink_metadata(&destination)?;
        Ok(metadata.file_type().is_file()
            && metadata.len() == bytes
            && day2::digest(&fs::read(&destination)?) == format!("sha256:{expected}"))
    };
    if !valid().unwrap_or(false) {
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()?;
        let response = client
            .get(format!(
                "https://github.com/bazelbuild/bazel/releases/download/9.3.0/{asset}"
            ))
            .send()?
            .error_for_status()?;
        let received = std::io::copy(
            &mut std::io::Read::take(response, bytes + 1),
            &mut temporary,
        )?;
        ensure!(
            received == bytes
                && day2::digest(&fs::read(temporary.path())?) == format!("sha256:{expected}"),
            "downloaded Bazel bytes differ from pin"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o555))?;
        }
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(&destination)?;
    }
    ensure!(valid()?, "standalone Bazel pin failed");
    destination.canonicalize().map_err(Into::into)
}

pub(crate) fn offline_repositories(root: &Path) -> Result<PathBuf> {
    let vendor = root.join(".cache/bazel-vendor");
    let mut command = command();
    command
        .arg("vendor")
        .arg(format!("--vendor_dir={}", vendor.display()))
        .args(["--compilation_mode=opt", "//crates/worker:lib"]);
    configuration_arguments(&mut command);
    run_with_budget(root, &mut command, Duration::from_secs(600))?;
    vendor.canonicalize().map_err(Into::into)
}

fn build_command(verb: &str, isolated_job: Option<&Path>) -> Result<Command> {
    let mut command = if let Some(job) = isolated_job {
        let job = job.canonicalize()?;
        let binary = job.join("bazel/bazel");
        let mut command = day2::sandbox::build_host(&job, &binary)?;
        command
            .args(["--batch", "--nosystem_rc", "--nohome_rc"])
            .arg(format!(
                "--output_user_root={}",
                job.join("bazel-output").display()
            ))
            .arg(verb)
            .arg("--repository_disable_download")
            .arg("--lockfile_mode=error")
            .arg(format!(
                "--vendor_dir={}",
                job.join("repositories").display()
            ))
            .arg("--disk_cache=")
            .arg("--remote_cache=")
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env("HOME", job.join("home"))
            .env("TMPDIR", job.join("tmp"))
            .env("PATH", "/usr/bin:/bin")
            .env("OPENSSL_CONF", "/dev/null");
        command
    } else {
        let mut command = command();
        command.arg(verb);
        command
    };
    if isolated_job.is_none() {
        configuration_arguments(&mut command);
    }
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> Result<tempfile::TempDir> {
        let root = tempfile::tempdir()?;
        for directory in ["build/bazel", "crates/example", "cli/checks"] {
            fs::create_dir_all(root.path().join(directory))?;
        }
        for name in [
            ".bazelrc",
            ".bazelversion",
            "BUILD.bazel",
            "MODULE.bazel",
            "MODULE.bazel.lock",
            "Cargo.toml",
            "Cargo.lock",
            "crates/example/BUILD.bazel",
            "build/bazel/targets.json",
            "build/bazel/toolchain.json",
            "build/bazel/rust.bzl",
            "build/bazel/context.patch",
        ] {
            fs::write(root.path().join(name), b"reviewed input")?;
        }
        Ok(root)
    }

    #[test]
    fn build_identity_changes_for_targets_profiles_patches_tool_pins_and_lock() -> Result<()> {
        let root = workspace()?;
        let original = configuration(root.path())?;
        for name in original.keys() {
            fs::write(root.path().join(name), b"changed input")?;
            assert_ne!(
                original,
                configuration(root.path())?,
                "unbound build input: {name}"
            );
            fs::write(root.path().join(name), b"reviewed input")?;
        }
        assert_eq!(original, configuration(root.path())?);
        fs::remove_file(root.path().join("MODULE.bazel.lock"))?;
        assert!(configuration(root.path()).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn build_configuration_refuses_aliased_inputs() -> Result<()> {
        let root = workspace()?;
        std::os::unix::fs::symlink("rust.bzl", root.path().join("build/bazel/alias.bzl"))?;
        assert!(configuration(root.path()).is_err());
        Ok(())
    }
}
