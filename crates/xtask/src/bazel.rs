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
        for name in [&target.package, &target.target] {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && !name.starts_with('-')
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
                "bounded package/target name required"
            );
        }
        let rule = target.label.rsplit(':').next().context("Bazel rule name")?;
        ensure!(
            !rule.is_empty()
                && rule
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
                && target.label.matches(':').count() == 1,
            "bounded exact Bazel rule name required"
        );
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

pub(crate) fn command(root: &Path) -> Command {
    {
        let mut command = Command::new("bazel");
        command
            .args(["--batch", "--nosystem_rc", "--nohome_rc"])
            .arg(format!(
                "--output_base={}",
                root.join(".cache/bazel-executor").display()
            ));
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Profile {
    Development,
    Release,
    Distribution,
}

impl Profile {
    fn configure(self, command: &mut Command) {
        match self {
            Self::Development => {}
            Self::Release => {
                command.arg("--config=release");
            }
            Self::Distribution => {
                command.arg("--config=distribution");
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    label: String,
    files: Vec<PathBuf>,
    source: PathBuf,
    crate_name: String,
    crate_type: String,
    test: bool,
    dependencies: Vec<Dependency>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dependency {
    pub(crate) label: String,
    pub(crate) name: String,
    pub(crate) source: PathBuf,
}

fn normalize_label(label: &str) -> &str {
    label.strip_prefix("@@").unwrap_or(label)
}

fn producer(target: &Target, output: &Files) -> Result<()> {
    ensure!(
        target.label == normalize_label(&output.label)
            && target.source == output.source
            && target.target.replace('-', "_") == output.crate_name
            && target.test == output.test,
        "configured Rust producer/source/test identity differs from catalog"
    );
    if !target.test {
        let matched = match target.kind[0].as_str() {
            "lib" => ["rlib", "lib"].contains(&output.crate_type.as_str()),
            "staticlib" => output.crate_type == "staticlib",
            "bin" => output.crate_type == "bin",
            _ => false,
        };
        ensure!(matched, "configured Rust crate type differs");
    }
    Ok(())
}

fn descriptors(
    root: &Path,
    selected: &[Target],
    profile: Profile,
    isolated_job: Option<&Path>,
    budget: Duration,
) -> Result<Vec<Files>> {
    let expected = selected
        .iter()
        .map(|target| target.label.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        !expected.is_empty() && expected.len() == selected.len(),
        "unique configured producer selection required"
    );
    let expression = format!(
        "set({})",
        expected.iter().copied().collect::<Vec<_>>().join(" ")
    );
    let mut query = build_command(root, "cquery", isolated_job)?;
    query.args([
        "--output=starlark",
        "--starlark:file=build/bazel/outputs.cquery",
    ]);
    profile.configure(&mut query);
    query.arg(expression);
    let output = capture_query(root, &mut query, budget, MAX_CATALOG_BYTES)?;
    let mut observed = BTreeSet::new();
    let mut records = Vec::new();
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let record: Files = day2::json::decode(line)?;
        let label = normalize_label(&record.label);
        ensure!(
            observed.insert(label.to_owned()),
            "duplicate configured Rust producer"
        );
        let target = selected
            .iter()
            .find(|target| target.label == label)
            .context("foreign configured Rust producer")?;
        producer(target, &record)?;
        records.push(record);
    }
    ensure!(
        observed.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "complete configured Rust producer inventory required"
    );
    Ok(records)
}

pub(crate) fn production_dependencies(root: &Path) -> Result<BTreeMap<String, Vec<Dependency>>> {
    let selected = targets(root)?
        .into_iter()
        .filter(|target| !target.test)
        .collect::<Vec<_>>();
    Ok(descriptors(
        root,
        &selected,
        Profile::Development,
        None,
        Duration::from_secs(600),
    )?
    .into_iter()
    .map(|record| {
        (
            normalize_label(&record.label).to_owned(),
            record.dependencies,
        )
    })
    .collect())
}

/// Resolve only successfully built targets. Missing, duplicate or foreign
/// configured labels never become an admitted output inventory.
pub(crate) fn build(
    root: &Path,
    selected: &[Target],
    budget: Duration,
) -> Result<BTreeMap<String, PathBuf>> {
    build_profile(root, selected, budget, Profile::Development, None)
}

fn build_profile(
    root: &Path,
    selected: &[Target],
    budget: Duration,
    profile: Profile,
    isolated_job: Option<&Path>,
) -> Result<BTreeMap<String, PathBuf>> {
    let started = std::time::Instant::now();
    ensure!(!selected.is_empty(), "nonempty Bazel build required");
    let expected = selected
        .iter()
        .map(|target| target.label.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        expected.len() == selected.len(),
        "duplicate requested Bazel target"
    );
    let mut build = build_command(root, "build", isolated_job)?;
    profile.configure(&mut build);
    build.args(&expected);
    crate::build_capture::run(root, &mut build, budget)?;
    let remaining = budget
        .checked_sub(started.elapsed())
        .context("Bazel build budget exhausted")?;
    let records = descriptors(root, selected, profile, isolated_job, remaining)?;
    let output_root = match isolated_job {
        Some(job) => job.join("bazel-output"),
        None => root.join(".cache/bazel-executor"),
    }
    .canonicalize()?;
    let mut result = BTreeMap::new();
    for record in records {
        let label = normalize_label(&record.label).to_owned();
        let target = selected
            .iter()
            .find(|target| target.label == label)
            .context("requested producer")?;
        ensure!(
            record.files.len() == 1,
            "one configured Rust output required"
        );
        let path = &record.files[0];
        let actual = confined_output(root, path, &output_root)?;
        let destination = if target.test {
            root.join(test_output(target))
        } else if target.kind == ["bin"] {
            if profile == Profile::Development {
                program(root, &target.target)
            } else {
                root.join("build-out/release/bin").join(&target.target)
            }
        } else {
            root.join("build-out/lib")
                .join(path.file_name().context("Rust output name")?)
        };
        fs::create_dir_all(destination.parent().context("Rust output directory")?)?;
        install_cli_file(&actual, &destination)?;
        ensure!(
            result
                .insert(label, destination.strip_prefix(root)?.to_owned())
                .is_none(),
            "duplicate installed output"
        );
    }
    ensure!(
        result.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "complete installed Rust output inventory required"
    );
    Ok(result)
}

/// One manual harness build/launch. Full verification still selects and orders
/// its campaigns in the Roc recipe; this accepts only a declared Rust test.
pub(crate) fn test_target(
    root: &Path,
    label: &str,
    arguments: Option<&[String]>,
) -> Result<PathBuf> {
    let catalog = targets(root)?;
    let selected = catalog
        .iter()
        .find(|target| target.label == label && target.test)
        .context("declared Rust test label required")?;
    if let Some(arguments) = arguments {
        validate_test_arguments(arguments)?;
    }
    let mut compile = vec![selected.clone()];
    compile.extend(
        catalog
            .iter()
            .filter(|target| {
                !target.test
                    && target.kind == ["bin"]
                    && (target.package == selected.package || target.package == "day2-sandbox")
            })
            .cloned(),
    );
    let budget = Duration::from_secs(12_600);
    let started = std::time::Instant::now();
    let outputs = build(root, &compile, budget)?;
    #[cfg(target_os = "linux")]
    crate::verification::install_linux_test_programs(root, &outputs)?;
    let executable = root.join(outputs.get(label).context("built Rust harness required")?);
    if let Some(arguments) = arguments {
        let mut command = Command::new(&executable);
        command.args(arguments);
        if cfg!(target_os = "macos")
            && selected.package == "day2-control"
            && selected.target == "control_integration"
        {
            command.env("DAY2_TEST_RUSTC", tool(root, "rustc")?);
        }
        run_with_budget(
            root,
            &mut command,
            budget
                .checked_sub(started.elapsed())
                .context("Rust test budget exhausted")?,
        )?;
    }
    Ok(executable)
}

fn validate_test_arguments(arguments: &[String]) -> Result<()> {
    ensure!(arguments.len() <= 32, "Rust test argument count");
    for argument in arguments {
        ensure!(
            [
                "--exact",
                "--ignored",
                "--include-ignored",
                "--nocapture",
                "--list",
                "--test-threads=1",
                "--test-threads=2",
                "--test-threads=3",
                "--test-threads=4"
            ]
            .contains(&argument.as_str())
                || (!argument.is_empty()
                    && argument.len() <= 256
                    && !argument.starts_with('-')
                    && argument
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_:.-".contains(&byte))),
            "unsupported Rust test option or filter"
        );
    }
    Ok(())
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
    let started = std::time::Instant::now();
    let budget = Duration::from_secs(12_600);
    let selected = targets(root)?;
    let labels = selected
        .iter()
        .map(|target| target.label.clone())
        .collect::<Vec<_>>();
    let mut command = command(root);
    command.arg("build");
    configuration_arguments(&mut command);
    clippy_arguments(&mut command);
    command.arg("--@rules_rust//rust/settings:clippy_flag=-Dwarnings");
    // Filegroup roots do not traverse srcs in the Clippy aspect.
    command.args(&labels);
    run_with_budget(root, &mut command, budget)?;
    admit_clippy_outputs(
        root,
        &root.join(".cache/bazel-executor"),
        &labels,
        false,
        budget
            .checked_sub(started.elapsed())
            .context("Clippy budget exhausted")?,
    )
}

pub(crate) fn clippy_arguments(command: &mut Command) {
    command.args([
        "--aspects=@rules_rust//rust:defs.bzl%rust_clippy_aspect",
        "--output_groups=clippy_checks,clippy_output",
        "--@rules_rust//rust/settings:clippy_output_diagnostics=true",
    ]);
}

/// Read the declared diagnostic outputs even after a successful cached action.
/// Console output alone does not repeat configuration warnings on cache hits.
pub(crate) fn admit_clippy_outputs(
    root: &Path,
    output_base: &Path,
    labels: &[String],
    strict: bool,
    budget: Duration,
) -> Result<()> {
    use std::io::Read;
    ensure!(
        !labels.is_empty(),
        "nonempty Clippy producer inventory required"
    );
    let mut query = command(root);
    query
        .arg(format!("--output_base={}", output_base.display()))
        .args(["cquery", "--output=files"]);
    configuration_arguments(&mut query);
    clippy_arguments(&mut query);
    query.arg("--output_groups=clippy_output");
    if strict {
        query.args([
            "--@rules_rust//rust/settings:clippy.toml=//:architecture/clippy.toml",
            "--@rules_rust//rust/settings:clippy_flag=--cap-lints=forbid",
        ]);
    }
    query.arg("--@rules_rust//rust/settings:clippy_flag=-Dwarnings");
    query.arg(format!("config(set({}), target)", labels.join(" ")));
    let files = capture_query(root, &mut query, budget, MAX_CATALOG_BYTES)?;
    let paths = std::str::from_utf8(&files)?
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<BTreeSet<_>>();
    ensure!(
        paths.len() == labels.len(),
        "complete distinct Clippy diagnostic inventory required"
    );
    for name in paths {
        ensure!(
            name.ends_with(".clippy.diagnostics"),
            "declared Clippy diagnostic output required"
        );
        let path = confined_output(root, Path::new(name), output_base)?;
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_CATALOG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        admit_clippy_json(&bytes)?;
    }
    Ok(())
}

fn admit_clippy_json(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_CATALOG_BYTES,
        "Clippy diagnostic byte budget"
    );
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: serde_json::Value = day2::json::decode(line)?;
        if value["$message_type"] == "artifact" {
            ensure!(
                matches!(value["emit"].as_str(), Some("dep-info" | "metadata"))
                    && value["artifact"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty())
                    && value.get("level").is_none(),
                "Clippy metadata artifact notification required"
            );
            continue;
        }
        ensure!(
            value["$message_type"] == "diagnostic",
            "Clippy diagnostic record required"
        );
        match value["level"].as_str() {
            Some("note" | "help") => {}
            Some("warning" | "error" | "failure-note") => anyhow::bail!(
                "strict compiler diagnostic: {}",
                value["message"]
                    .as_str()
                    .unwrap_or("diagnostic message unavailable")
            ),
            _ => anyhow::bail!("unknown Clippy diagnostic record"),
        }
    }
    Ok(())
}

pub(crate) fn docs(root: &Path) -> Result<()> {
    let mut command = command(root);
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
    let mut command = command(root);
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
        Profile::Release,
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
        ["rustc", "rustdoc", "cargo"].contains(&name),
        "closed compiler tool selection"
    );
    let label = format!("@rules_rust//rust/toolchain:current_{name}_files");
    let mut build = command(root);
    build.arg("build");
    configuration_arguments(&mut build);
    build.arg(&label);
    run_with_budget(root, &mut build, Duration::from_secs(600))?;
    let mut query = command(root);
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
    let mut info = command(root);
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
    let selected = targets(root)?
        .into_iter()
        .filter(|target| target.label == label)
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "one declared configured producer required"
    );
    let records = descriptors(
        root,
        &selected,
        Profile::Development,
        None,
        Duration::from_secs(120),
    )?;
    ensure!(
        records.len() == 1 && records[0].files.len() == 1,
        "one configured Rust output required"
    );
    confined_output(
        root,
        &records[0].files[0],
        &root.join(".cache/bazel-executor"),
    )
}

fn confined_output(root: &Path, path: &Path, output_root: &Path) -> Result<PathBuf> {
    ensure!(
        relative(path) && path.starts_with("bazel-out"),
        "confined declared Rust output required"
    );
    let actual = root.join(path).canonicalize()?;
    ensure!(
        actual.starts_with(output_root.canonicalize()?)
            && fs::symlink_metadata(&actual)?.file_type().is_file(),
        "Rust output leaves its owned compiler context or is not regular"
    );
    Ok(actual)
}

fn configuration_bytes(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() <= 4 * 1024 * 1024,
        "regular bounded Bazel configuration required"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "Bazel configuration byte budget"
    );
    Ok(bytes)
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
        files.insert(
            name.to_owned(),
            day2::digest(&configuration_bytes(&root.join(name))?),
        );
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
                    day2::digest(&configuration_bytes(&path)?),
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
    let mut command = command(root);
    command
        .arg("vendor")
        .arg(format!("--vendor_dir={}", vendor.display()))
        .args(["--config=release", "//crates/worker:lib"]);
    configuration_arguments(&mut command);
    run_with_budget(root, &mut command, Duration::from_secs(600))?;
    vendor.canonicalize().map_err(Into::into)
}

fn build_command(root: &Path, verb: &str, isolated_job: Option<&Path>) -> Result<Command> {
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
        let mut command = command(root);
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

    #[test]
    fn retained_clippy_configuration_warning_refuses_every_cache_read() -> Result<()> {
        admit_clippy_json(b"")?;
        admit_clippy_json(
            br#"{"$message_type":"artifact","artifact":"lib.rmeta","emit":"metadata"}"#,
        )?;
        let warning = br#"{"$message_type":"diagnostic","level":"warning","message":"invalid disallowed path: misspelled_now"}"#;
        for _ in 0..2 {
            assert!(admit_clippy_json(warning).is_err());
        }
        for record in [
            br#"{"$message_type":"diagnostic","level":"error","message":"ambient effect"}"#.as_slice(),
            br#"{"$message_type":"diagnostic","level":"unknown"}"#.as_slice(),
            br#"{"$message_type":"artifact","artifact":"lib.rmeta","emit":"unknown"}"#.as_slice(),
            br#"{"$message_type":"artifact","artifact":"lib.rmeta","emit":"metadata","level":"warning"}"#.as_slice(),
            b"malformed".as_slice(),
        ] {
            assert!(admit_clippy_json(record).is_err());
        }
        Ok(())
    }

    #[test]
    fn manual_rust_tests_refuse_unreviewed_harness_options() -> Result<()> {
        validate_test_arguments(&["module::case".into(), "--exact".into(), "--ignored".into()])?;
        for argument in [
            "--skip",
            "--test-threads=1000",
            "--format=json",
            "--logfile=private",
            "--unstable-options",
            "../another-program",
        ] {
            assert!(validate_test_arguments(&[argument.into()]).is_err());
        }
        Ok(())
    }

    #[test]
    fn configured_output_refuses_another_source_target_name_test_or_crate_kind() -> Result<()> {
        let target = Target {
            package: "example".to_owned(),
            directory: "crates/example".into(),
            target: "example".to_owned(),
            kind: vec!["bin".to_owned()],
            label: "//crates/example:example".to_owned(),
            test: false,
            source: "crates/example/src/main.rs".into(),
        };
        let valid = || Files {
            label: "@@//crates/example:example".to_owned(),
            files: vec!["bazel-out/config/bin/crates/example/example".into()],
            source: target.source.clone(),
            crate_name: "example".to_owned(),
            crate_type: "bin".to_owned(),
            test: false,
            dependencies: vec![],
        };
        producer(&target, &valid())?;
        let mut changed = valid();
        changed.label = "@@//crates/foreign:example".to_owned();
        assert!(producer(&target, &changed).is_err());
        let mut changed = valid();
        changed.source = "crates/example/src/unreviewed.rs".into();
        assert!(producer(&target, &changed).is_err());
        let mut changed = valid();
        changed.crate_name = "another".to_owned();
        assert!(producer(&target, &changed).is_err());
        let mut changed = valid();
        changed.test = true;
        assert!(producer(&target, &changed).is_err());
        let mut changed = valid();
        changed.crate_type = "rlib".to_owned();
        assert!(producer(&target, &changed).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn build_configuration_refuses_aliased_inputs() -> Result<()> {
        let root = workspace()?;
        std::os::unix::fs::symlink("rust.bzl", root.path().join("build/bazel/alias.bzl"))?;
        assert!(configuration(root.path()).is_err());
        fs::remove_file(root.path().join("build/bazel/alias.bzl"))?;
        fs::remove_file(root.path().join(".bazelrc"))?;
        std::os::unix::fs::symlink(".bazelversion", root.path().join(".bazelrc"))?;
        assert!(configuration(root.path()).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn configured_output_refuses_absolute_traversal_foreign_or_directory_leaves() -> Result<()> {
        let root = tempfile::tempdir()?;
        let owned = root
            .path()
            .join(".cache/bazel-executor/execroot/_main/bazel-out");
        fs::create_dir_all(&owned)?;
        fs::write(owned.join("program"), b"actual owned output")?;
        std::os::unix::fs::symlink(&owned, root.path().join("bazel-out"))?;
        confined_output(
            root.path(),
            Path::new("bazel-out/program"),
            &root.path().join(".cache/bazel-executor"),
        )?;
        for path in ["/bin/echo", "bazel-out/../program", "bazel-out"] {
            assert!(
                confined_output(
                    root.path(),
                    Path::new(path),
                    &root.path().join(".cache/bazel-executor")
                )
                .is_err()
            );
        }
        let foreign = tempfile::NamedTempFile::new()?;
        std::os::unix::fs::symlink(foreign.path(), owned.join("foreign"))?;
        assert!(
            confined_output(
                root.path(),
                Path::new("bazel-out/foreign"),
                &root.path().join(".cache/bazel-executor")
            )
            .is_err()
        );
        Ok(())
    }
}

/// Cargo is used only as crate_universe's dependency-input reader. This closed
/// metadata operation cannot compile, run or test a platform target.
pub(crate) fn dependency_metadata(root: &Path, no_dependencies: bool) -> Result<Vec<u8>> {
    let cargo = tool(root, "cargo")?;
    let rustc = tool(root, "rustc")?;
    let home = root.join(".cache/dependency-inputs");
    fs::create_dir_all(home.join("tmp"))?;
    let mut command = Command::new(cargo);
    command.args(["metadata", "--locked", "--format-version=1"]);
    if no_dependencies {
        command.arg("--no-deps");
    }
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("HOME", &home)
        .env("CARGO_HOME", &home)
        .env("TMPDIR", home.join("tmp"))
        .env("RUSTC", rustc)
        .env("PATH", "/usr/bin:/bin");
    capture_query(
        root,
        &mut command,
        Duration::from_secs(600),
        16 * 1024 * 1024,
    )
}

/// One closed image compilation operation; Docker retains image assembly order.
pub(crate) fn image_programs(root: &Path, enrollment_only: bool) -> Result<()> {
    let names: &[&str] = if enrollment_only {
        &["day2-native-enrollment", "day2-native-enrollment-qualify"]
    } else {
        &[
            "day2-health",
            "day2-inspect",
            "day2-security-shell",
            "day2-native-enrollment",
            "day2-epoch-controller",
            "day2-serve",
            "day2-sandbox",
            "day2-sandbox-probe",
            "day2-backup",
            "day2-provision-credentials",
        ]
    };
    let selected = targets(root)?
        .into_iter()
        .filter(|target| {
            !target.test && target.kind == ["bin"] && names.contains(&target.target.as_str())
        })
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == names.len(),
        "complete fixed runtime-image program set required"
    );
    build_profile(
        root,
        &selected,
        Duration::from_secs(12600),
        if enrollment_only {
            Profile::Release
        } else {
            Profile::Distribution
        },
        None,
    )?;
    Ok(())
}
